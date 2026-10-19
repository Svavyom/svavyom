//go:build libvirt

// Package libvirtro is the production READ-ONLY libvirt adapter of the host agent (VM inventory slice, ADR-011).
//
// It opens a libvirt read-only connection (virConnectOpenReadOnly), so the libvirt daemon itself refuses every
// mutating call on it, and it exposes only hypervisor.Reader: list and lookup. It uses the libvirt Go bindings
// (libvirt.org/go/libvirt, already in go.mod), never `virsh`, never parsed command output, never domain XML.
// Allowed URIs are the local system hypervisor and, for tests, the in-process test driver; nothing remote.
// Built only with -tags libvirt (cgo, libvirt-dev); the unprivileged API process never links it.
package libvirtro

import (
	"context"
	"encoding/xml"
	"errors"
	"regexp"
	"sort"
	"strings"
	"sync"

	libvirt "libvirt.org/go/libvirt"

	"example.invalid/dedicatedcloud/backend/internal/hypervisor"
	"example.invalid/dedicatedcloud/backend/internal/provision"
)

// URIs accepted by Open.
const (
	SystemURI = "qemu:///system"
	TestURI   = "test:///default"
)

// safeName is the domain-name grammar the API can represent (VM id pattern). A host domain outside it can neither be shown
// nor addressed safely, and an inventory must never look complete when it is not: List FAILS (HostError, without the
// name) if any domain is unrepresentable, and Lookup reports such a name as not found. A later story may adopt stable
// libvirt UUIDs as resource ids.
var safeName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$`)

// Reader is the read-only adapter.
type Reader struct {
	mu   sync.Mutex
	conn *libvirt.Connect
}

var _ hypervisor.Reader = (*Reader)(nil)

// Open connects read-only. Any URI other than SystemURI or TestURI is Prohibited and nothing is attempted.
func Open(uri string) (*Reader, error) {
	if uri != SystemURI && uri != TestURI {
		return nil, hypervisor.NewError(hypervisor.Prohibited, "open", "", "uri not allowed")
	}
	conn, err := libvirt.NewConnectReadOnly(uri)
	if err != nil {
		return nil, mapErr("open", "", err)
	}
	return &Reader{conn: conn}, nil
}

// Close releases the connection.
func (r *Reader) Close() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.conn != nil {
		_, _ = r.conn.Close()
		r.conn = nil
	}
}

func mapErr(op, name string, err error) error {
	var lerr libvirt.Error
	if !errors.As(err, &lerr) {
		return hypervisor.NewError(hypervisor.HostError, op, name, "unexpected error")
	}
	switch lerr.Code {
	case libvirt.ERR_NO_DOMAIN:
		return hypervisor.NewError(hypervisor.NotFound, op, name, "no such domain")
	case libvirt.ERR_OPERATION_TIMEOUT:
		return hypervisor.NewError(hypervisor.Timeout, op, name, "libvirt timeout")
	case libvirt.ERR_NO_CONNECT, libvirt.ERR_SYSTEM_ERROR, libvirt.ERR_RPC, libvirt.ERR_INTERNAL_ERROR,
		libvirt.ERR_AUTH_FAILED, libvirt.ERR_AUTH_UNAVAILABLE, libvirt.ERR_OPERATION_DENIED:
		return hypervisor.NewError(hypervisor.Unavailable, op, name, "libvirt unavailable")
	default:
		return hypervisor.NewError(hypervisor.HostError, op, name, "libvirt error")
	}
}

func toState(s libvirt.DomainState) hypervisor.State {
	switch s {
	case libvirt.DOMAIN_RUNNING, libvirt.DOMAIN_BLOCKED:
		return hypervisor.StateRunning
	case libvirt.DOMAIN_SHUTOFF:
		return hypervisor.StateShutoff
	case libvirt.DOMAIN_PAUSED, libvirt.DOMAIN_PMSUSPENDED:
		return hypervisor.StatePaused
	case libvirt.DOMAIN_CRASHED:
		return hypervisor.StateCrashed
	default: // DOMAIN_SHUTDOWN (shutting down: the API has no such state), NOSTATE and anything newer
		return hypervisor.StateUnknown
	}
}

func (r *Reader) connection(op string) (*libvirt.Connect, error) {
	if r.conn == nil {
		return nil, hypervisor.NewError(hypervisor.Unavailable, op, "", "closed")
	}
	return r.conn, nil
}

// Lookup returns one domain by name.
func (r *Reader) Lookup(ctx context.Context, name string) (hypervisor.Domain, error) {
	if err := ctx.Err(); err != nil {
		return hypervisor.Domain{}, hypervisor.NewError(hypervisor.Timeout, "lookup", "", "cancelled")
	}
	if !safeName.MatchString(name) {
		return hypervisor.Domain{}, hypervisor.NewError(hypervisor.NotFound, "lookup", "", "no such domain")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	conn, err := r.connection("lookup")
	if err != nil {
		return hypervisor.Domain{}, err
	}
	dom, err := conn.LookupDomainByName(name)
	if err != nil {
		return hypervisor.Domain{}, mapErr("lookup", "", err)
	}
	defer func() { _ = dom.Free() }()
	st, _, err := dom.GetState()
	if err != nil {
		return hypervisor.Domain{}, mapErr("lookup", "", err)
	}
	return describe(conn, dom, name, st)
}

// describe adds what the definition and the lease table say about a domain: identity, size, Svavyom's ownership marker and (for
// a running domain) an IPv4 lease. An unreadable definition is an error, never a silently thinner answer.
func describe(conn *libvirt.Connect, dom *libvirt.Domain, name string, st libvirt.DomainState) (hypervisor.Domain, error) {
	out := hypervisor.Domain{Name: name, State: toState(st)}
	x, err := dom.GetXMLDesc(0)
	if err != nil {
		return hypervisor.Domain{}, mapErr("describe", name, err)
	}
	pd, perr := provision.ParseDomain(x)
	if perr != nil {
		return hypervisor.Domain{}, hypervisor.NewError(hypervisor.HostError, "describe", "", "unreadable definition")
	}
	out.VCPUs, out.MemoryMiB, out.UUID = pd.VCPUs, pd.MemoryMiB, pd.UUID
	out.Managed, out.Fingerprint, out.ImageID = pd.Managed, pd.Fingerprint, pd.ImageID
	out.Network, out.MAC = pd.Network, pd.MAC
	if pd.Managed {
		observeStorage(conn, dom, x, pd, &out)
		for _, dd := range pd.Data {
			out.DataVolumes = append(out.DataVolumes, dd.Volume)
		}
		out.Media, out.ISOSHA256 = pd.Media, pd.ISO
		out.Graphics, out.RescueSHA256 = pd.Graphics, pd.Rescue
	}
	if st == libvirt.DOMAIN_RUNNING {
		// Cumulative guest CPU time for the usage sampler (DR-022). Unreadable means "no figure", never a failure of the observation.
		if info, err := dom.GetInfo(); err == nil && info.CpuTime <= 1<<62 {
			out.CPUTimeNs = int64(info.CpuTime)
		}
		guestUsage(conn, dom, &out)
		// Observation only: a missing or unsupported lease source is simply "no address yet".
		if addrs, err := dom.ListAllInterfaceAddresses(libvirt.DOMAIN_INTERFACE_ADDRESSES_SRC_LEASE); err == nil {
			for _, a := range addrs {
				// A guest that was restored or reinstalled keeps its MAC but may present a new DHCP client id, so the lease table can
				// hold several leases for one MAC. The newest expiry is the live one; the table's own order says nothing.
				if ip := newestLease(conn, a.Hwaddr); ip != "" {
					out.IPv4 = ip
					break
				}
				for _, ip := range a.Addrs {
					if ip.Type == libvirt.IP_ADDR_TYPE_IPV4 && provision.IsIPv4(ip.Addr) {
						out.IPv4 = ip.Addr
						break
					}
				}
				if out.IPv4 != "" {
					break
				}
			}
		}
	}
	return out, nil
}

// newestLease returns the IPv4 address of the lease with the latest expiry for mac across the active networks, or "".
func newestLease(conn *libvirt.Connect, mac string) string {
	if mac == "" {
		return ""
	}
	nets, err := conn.ListAllNetworks(libvirt.CONNECT_LIST_NETWORKS_ACTIVE)
	if err != nil {
		return ""
	}
	best, bestExp := "", int64(-1)
	for i := range nets {
		leases, lerr := nets[i].GetDHCPLeases()
		_ = nets[i].Free()
		if lerr != nil {
			continue
		}
		for _, l := range leases {
			if strings.EqualFold(l.Mac, mac) && l.Type == libvirt.IP_ADDR_TYPE_IPV4 && provision.IsIPv4(l.IPaddr) && l.ExpiryTime.Unix() > bestExp {
				best, bestExp = l.IPaddr, l.ExpiryTime.Unix()
			}
		}
	}
	return best
}

// List returns every domain (running and defined) whose name the typed API can represent, sorted by name.
func (r *Reader) List(ctx context.Context) ([]hypervisor.Domain, error) {
	if err := ctx.Err(); err != nil {
		return nil, hypervisor.NewError(hypervisor.Timeout, "list", "", "cancelled")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	conn, err := r.connection("list")
	if err != nil {
		return nil, err
	}
	doms, err := conn.ListAllDomains(0)
	if err != nil {
		return nil, mapErr("list", "", err)
	}
	out := make([]hypervisor.Domain, 0, len(doms))
	var failure error
	for i := range doms {
		name, nerr := doms[i].GetName()
		st, _, serr := doms[i].GetState()
		var d hypervisor.Domain
		var derr error
		if failure == nil && nerr == nil && serr == nil && safeName.MatchString(name) {
			d, derr = describe(conn, &doms[i], name, st)
		}
		_ = doms[i].Free()
		if failure != nil {
			continue
		}
		switch {
		case nerr != nil:
			failure = mapErr("list", "", nerr)
		case serr != nil:
			failure = mapErr("list", "", serr)
		case !safeName.MatchString(name):
			failure = hypervisor.NewError(hypervisor.HostError, "list", "", "inventory contains a domain this version cannot represent")
		case derr != nil:
			failure = derr
		default:
			out = append(out, d)
		}
	}
	if failure != nil {
		return nil, failure
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

type rootDiskDoc struct {
	Disks []struct {
		Device string `xml:"device,attr"`
		Source struct {
			File string `xml:"file,attr"`
		} `xml:"source"`
	} `xml:"devices>disk"`
}

type snapshotDoc struct {
	Name         string `xml:"name"`
	Description  string `xml:"description"`
	CreationTime int64  `xml:"creationTime"`
}

// observeStorage adds what a managed domain's storage looks like: the root disk's virtual size (from the volume libvirt knows at the path the
// definition names) and its own snapshots (Svavyom's name prefix and a description naming this domain's UUID). Observation only: anything that
// cannot be read is simply left out, never guessed.
func observeStorage(conn *libvirt.Connect, dom *libvirt.Domain, x string, pd provision.Domain, out *hypervisor.Domain) {
	var d rootDiskDoc
	if xml.Unmarshal([]byte(x), &d) == nil {
		for _, disk := range d.Disks {
			if disk.Device != "disk" || disk.Source.File == "" {
				continue
			}
			if v, err := conn.LookupStorageVolByPath(disk.Source.File); err == nil {
				if info, err := v.GetInfo(); err == nil && info.Capacity <= 1<<50 {
					out.DiskBytes = int64(info.Capacity) // #nosec G115 -- bounded above
				}
				_ = v.Free()
			}
			break
		}
	}
	snaps, err := dom.ListAllSnapshots(0)
	if err != nil {
		return
	}
	for i := range snaps {
		sx, xerr := snaps[i].GetXMLDesc(0)
		_ = snaps[i].Free()
		if xerr != nil {
			continue
		}
		var sd snapshotDoc
		if xml.Unmarshal([]byte(sx), &sd) != nil || !strings.HasPrefix(sd.Name, "svs-") || sd.Description != "svavyom:"+pd.UUID || len(out.Snapshots) >= 16 {
			continue
		}
		out.Snapshots = append(out.Snapshots, hypervisor.Snapshot{ID: strings.TrimPrefix(sd.Name, "svs-"), Created: sd.CreationTime})
	}
	sort.Slice(out.Snapshots, func(i, j int) bool { return out.Snapshots[i].Created < out.Snapshots[j].Created })
}

var _ hypervisor.NetworkReader = (*Reader)(nil)

// Networks returns every libvirt network, described by its stored definition (managed or not) with the number of domains attached to it. It is
// read-only: the connection is libvirt's read-only one. A network this version cannot describe fails the whole inventory instead of being hidden.
func (r *Reader) Networks(ctx context.Context) ([]hypervisor.Network, error) {
	if err := ctx.Err(); err != nil {
		return nil, hypervisor.NewError(hypervisor.Timeout, "networks", "", "cancelled")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	conn, err := r.connection("networks")
	if err != nil {
		return nil, err
	}
	count := map[string]int{}
	doms, err := conn.ListAllDomains(0)
	if err != nil {
		return nil, mapErr("networks", "", err)
	}
	for i := range doms {
		x, xerr := doms[i].GetXMLDesc(0)
		_ = doms[i].Free()
		if xerr != nil {
			for j := i + 1; j < len(doms); j++ {
				_ = doms[j].Free()
			}
			return nil, mapErr("networks", "", xerr)
		}
		if pd, perr := provision.ParseDomain(x); perr == nil && pd.Network != "" {
			count[pd.Network]++
		}
	}
	nets, err := conn.ListAllNetworks(0)
	if err != nil {
		return nil, mapErr("networks", "", err)
	}
	out := make([]hypervisor.Network, 0, len(nets))
	var failure error
	for i := range nets {
		if failure == nil {
			x, xerr := nets[i].GetXMLDesc(0)
			active, aerr := nets[i].IsActive()
			auto, uerr := nets[i].GetAutostart()
			switch {
			case xerr != nil:
				failure = mapErr("networks", "", xerr)
			case aerr != nil:
				failure = mapErr("networks", "", aerr)
			case uerr != nil:
				failure = mapErr("networks", "", uerr)
			default:
				info, perr := provision.ParseNetwork(x, active, auto)
				if perr != nil {
					failure = hypervisor.NewError(hypervisor.HostError, "networks", "", "unreadable network definition")
					break
				}
				n := hypervisor.Network{Name: info.Name, UUID: info.UUID, Managed: info.Managed, Active: active, Autostart: auto, Mode: info.Mode, Bridge: info.Bridge,
					Gateway: info.Gateway, DHCPStart: info.DHCPStart, DHCPEnd: info.DHCPEnd, AttachedVMs: count[info.Name]}
				if info.Subnet.IsValid() {
					n.Subnet = info.Subnet.String()
				}
				for _, h := range info.Hosts {
					n.Reservations = append(n.Reservations, hypervisor.Reservation{MAC: h.MAC, IP: h.IP})
				}
				out = append(out, n)
			}
		}
		_ = nets[i].Free()
	}
	if failure != nil {
		return nil, failure
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// guestUsage adds the memory in use and the cumulative disk and network bytes of a running domain from libvirt's read-only domain statistics
// (DR-023 D5). An unreadable or unsupported statistic leaves its figure at 0, which means "no figure"; it never fails the observation.
func guestUsage(conn *libvirt.Connect, dom *libvirt.Domain, out *hypervisor.Domain) {
	all, err := conn.GetAllDomainStats([]*libvirt.Domain{dom}, libvirt.DOMAIN_STATS_BALLOON|libvirt.DOMAIN_STATS_BLOCK|libvirt.DOMAIN_STATS_INTERFACE, 0)
	if err != nil {
		return
	}
	defer func() {
		for i := range all {
			if all[i].Domain != nil {
				_ = all[i].Domain.Free()
			}
		}
	}()
	if len(all) != 1 {
		return
	}
	st := all[0]
	if b := st.Balloon; b != nil {
		switch {
		case b.AvailableSet && b.UnusedSet && b.Available >= b.Unused:
			out.MemUsedMiB = clampMiB((b.Available - b.Unused) / 1024)
		case b.RssSet:
			out.MemUsedMiB = clampMiB(b.Rss / 1024)
		}
	}
	var disk, net uint64
	for _, blk := range st.Block {
		if blk.BackingIndexSet { // a backing image of the chain, not the disk the guest sees
			continue
		}
		if blk.RdBytesSet {
			disk += blk.RdBytes
		}
		if blk.WrBytesSet {
			disk += blk.WrBytes
		}
	}
	for _, n := range st.Net {
		if n.RxBytesSet {
			net += n.RxBytes
		}
		if n.TxBytesSet {
			net += n.TxBytes
		}
	}
	out.DiskIOBytes, out.NetIOBytes = clampBytes(disk), clampBytes(net)
}

func clampMiB(v uint64) int64 {
	if v > 1<<30 {
		return 0
	}
	return int64(v) // #nosec G115 -- bounded above
}

func clampBytes(v uint64) int64 {
	if v > 1<<62 {
		return 0
	}
	return int64(v) // #nosec G115 -- bounded above
}

var _ hypervisor.DataVolumeReader = (*Reader)(nil)

// DataVolumes lists the Svavyom data volumes of every storage pool, by their own name and virtual size. It is read-only. A volume this process cannot
// describe fails the whole listing instead of being hidden.
func (r *Reader) DataVolumes(ctx context.Context) ([]hypervisor.DataVolume, error) {
	if err := ctx.Err(); err != nil {
		return nil, hypervisor.NewError(hypervisor.Timeout, "volumes", "", "cancelled")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	conn, err := r.connection("volumes")
	if err != nil {
		return nil, err
	}
	pools, err := conn.ListAllStoragePools(libvirt.CONNECT_LIST_STORAGE_POOLS_ACTIVE)
	if err != nil {
		return nil, mapErr("volumes", "", err)
	}
	seen := map[string]bool{}
	out := []hypervisor.DataVolume{}
	var failure error
	for i := range pools {
		if failure == nil {
			vols, verr := pools[i].ListAllStorageVolumes(0)
			if verr != nil {
				failure = mapErr("volumes", "", verr)
			}
			for j := range vols {
				if failure == nil {
					name, nerr := vols[j].GetName()
					if nerr != nil {
						failure = mapErr("volumes", "", nerr)
					} else if own, ok := provision.ParseDataVolumeName(name); ok && !seen[own] {
						info, ierr := vols[j].GetInfo()
						switch {
						case ierr != nil:
							failure = mapErr("volumes", "", ierr)
						case info.Capacity == 0 || info.Capacity > 1<<50:
							failure = hypervisor.NewError(hypervisor.HostError, "volumes", "", "unreadable volume")
						default:
							seen[own] = true
							out = append(out, hypervisor.DataVolume{Name: own, CapacityBytes: int64(info.Capacity)}) // #nosec G115 -- bounded above
						}
					}
				}
				_ = vols[j].Free()
			}
		}
		_ = pools[i].Free()
	}
	if failure != nil {
		return nil, failure
	}
	return out, nil
}
