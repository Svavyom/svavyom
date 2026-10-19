package simhost

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"net/netip"
	"regexp"
	"sort"
	"strings"

	"example.invalid/dedicatedcloud/backend/internal/hypervisor"
	"example.invalid/dedicatedcloud/backend/internal/provision"
)

// DefaultNetwork is the simulated host's pre-existing (foreign, never mutated) NAT network: the one the test configurations name.
const (
	DefaultNetwork = "svavyom-nat"
	defaultSubnet  = "192.168.122.0/24"
)

// SimNet is a simulated managed or foreign libvirt network (the definition XML as defined; reservations and flags are kept beside it).
type SimNet struct {
	XML       string              `json:"xml"`
	Active    bool                `json:"active"`
	Autostart bool                `json:"autostart"`
	Hosts     []provision.NetHost `json:"hosts,omitempty"`
}

func (h *Host) defaultNetwork(st *State) provision.NetworkInfo {
	return provision.NetworkInfo{Name: DefaultNetwork, UUID: "00000000-0000-4000-8000-000000000001", Active: !st.NetworkDown, Autostart: true, Mode: "nat", Bridge: "virbr-sim",
		Subnet: netip.MustParsePrefix(defaultSubnet), Gateway: "192.168.122.1", DHCPStart: "192.168.122.10", DHCPEnd: "192.168.122.250"}
}

func simNetInfo(name string, n SimNet) (provision.NetworkInfo, error) {
	info, err := provision.ParseNetwork(n.XML, n.Active, n.Autostart)
	if err != nil {
		return provision.NetworkInfo{}, err
	}
	info.Name = name
	info.Hosts = append([]provision.NetHost(nil), n.Hosts...)
	return info, nil
}

// ListNetworks implements provision.HostOps: the default network plus every defined one.
func (h *Host) ListNetworks(_ context.Context) ([]provision.NetworkInfo, error) {
	st := h.Load()
	out := []provision.NetworkInfo{h.defaultNetwork(&st)}
	for name, n := range st.Networks {
		info, err := simNetInfo(name, n)
		if err != nil {
			return nil, hypervisor.NewError(hypervisor.HostError, "networks", "", "unreadable network")
		}
		out = append(out, info)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// LookupNetwork implements provision.HostOps.
func (h *Host) LookupNetwork(_ context.Context, name string) (provision.NetworkInfo, error) {
	st := h.Load()
	if name == DefaultNetwork {
		return h.defaultNetwork(&st), nil
	}
	n, ok := st.Networks[name]
	if !ok {
		return provision.NetworkInfo{}, nf("network")
	}
	info, err := simNetInfo(name, n)
	if err != nil {
		return provision.NetworkInfo{}, hypervisor.NewError(hypervisor.HostError, "network", "", "unreadable network")
	}
	return info, nil
}

// DefineNetwork implements provision.HostOps.
func (h *Host) DefineNetwork(_ context.Context, x string) error {
	info, err := provision.ParseNetwork(x, false, false)
	if err != nil || info.Name == "" {
		return hypervisor.NewError(hypervisor.Validation, "define-network", "", "bad definition")
	}
	return h.update(func(st *State) error {
		if info.Name == DefaultNetwork {
			return hypervisor.NewError(hypervisor.Conflict, "define-network", "", "exists")
		}
		if st.Networks == nil {
			st.Networks = map[string]SimNet{}
		}
		if old, ok := st.Networks[info.Name]; ok {
			oi, _ := simNetInfo(info.Name, old)
			if oi.UUID != info.UUID {
				return hypervisor.NewError(hypervisor.Conflict, "define-network", "", "exists")
			}
			old.XML = x
			st.Networks[info.Name] = old
			return nil
		}
		st.Networks[info.Name] = SimNet{XML: x}
		return nil
	})
}

func (h *Host) mutateNet(op, name string, fn func(*SimNet, *State) error) error {
	return h.update(func(st *State) error {
		n, ok := st.Networks[name]
		if !ok {
			return nf(op)
		}
		if err := fn(&n, st); err != nil {
			return err
		}
		st.Networks[name] = n
		return nil
	})
}

// StartNetwork implements provision.HostOps.
func (h *Host) StartNetwork(_ context.Context, name string) error {
	return h.mutateNet("start-network", name, func(n *SimNet, _ *State) error {
		if n.Active {
			return hypervisor.NewError(hypervisor.Conflict, "start-network", "", "already active")
		}
		n.Active = true
		return nil
	})
}

// StopNetwork implements provision.HostOps.
func (h *Host) StopNetwork(_ context.Context, name string) error {
	return h.mutateNet("stop-network", name, func(n *SimNet, _ *State) error {
		if !n.Active {
			return hypervisor.NewError(hypervisor.Conflict, "stop-network", "", "not active")
		}
		n.Active = false
		return nil
	})
}

// SetNetworkAutostart implements provision.HostOps.
func (h *Host) SetNetworkAutostart(_ context.Context, name string, on bool) error {
	return h.mutateNet("autostart", name, func(n *SimNet, _ *State) error { n.Autostart = on; return nil })
}

// UndefineNetwork implements provision.HostOps.
func (h *Host) UndefineNetwork(_ context.Context, name string) error {
	return h.update(func(st *State) error {
		n, ok := st.Networks[name]
		if !ok {
			return nf("undefine-network")
		}
		if n.Active {
			return hypervisor.NewError(hypervisor.Conflict, "undefine-network", "", "active")
		}
		delete(st.Networks, name)
		return nil
	})
}

// AddNetworkHost implements provision.HostOps. A running guest of that MAC "renews" at once and takes the reserved address.
func (h *Host) AddNetworkHost(_ context.Context, network, mac, ip string) error {
	return h.mutateNet("add-host", network, func(n *SimNet, st *State) error {
		for _, x := range n.Hosts {
			if x.MAC == mac || x.IP == ip {
				return hypervisor.NewError(hypervisor.Conflict, "add-host", "", "exists")
			}
		}
		n.Hosts = append(n.Hosts, provision.NetHost{MAC: mac, IP: ip})
		for name, d := range st.Domains {
			if d.Running && provision.MAC(d.UUID) == mac {
				d.IP = ip
				st.Domains[name] = d
			}
		}
		return nil
	})
}

// RemoveNetworkHost implements provision.HostOps.
func (h *Host) RemoveNetworkHost(_ context.Context, network, mac, ip string) error {
	return h.mutateNet("remove-host", network, func(n *SimNet, _ *State) error {
		keep := n.Hosts[:0]
		found := false
		for _, x := range n.Hosts {
			if x.MAC == mac && x.IP == ip {
				found = true
				continue
			}
			keep = append(keep, x)
		}
		if !found {
			return nf("remove-host")
		}
		n.Hosts = keep
		return nil
	})
}

// NetworkLeases implements provision.HostOps: one lease per running guest on the network.
func (h *Host) NetworkLeases(_ context.Context, network string) ([]provision.NetLease, error) {
	st := h.Load()
	var out []provision.NetLease
	for _, d := range st.Domains {
		pd, err := provision.ParseDomain(d.XML)
		if err == nil && d.Running && d.IP != "" && pd.Network == network {
			out = append(out, provision.NetLease{MAC: provision.MAC(d.UUID), IP: d.IP})
		}
	}
	for _, l := range st.ExtraLeases {
		if l.Network == network {
			out = append(out, provision.NetLease{MAC: l.MAC, IP: l.IP})
		}
	}
	return out, nil
}

var (
	simMemRE  = regexp.MustCompile(`(<memory unit='MiB'>)\d+(</memory>)`)
	simCurRE  = regexp.MustCompile(`(<currentMemory unit='MiB'>)\d+(</currentMemory>)`)
	simVcpuRE = regexp.MustCompile(`(<vcpu placement='static'>)\d+(</vcpu>)`)
)

// SetDomainCompute implements provision.HostOps.
func (h *Host) SetDomainCompute(_ context.Context, name string, vcpus, memoryMiB int) error {
	return h.update(func(st *State) error {
		d, ok := st.Domains[name]
		if !ok {
			return nf("compute")
		}
		if d.Running {
			return hypervisor.NewError(hypervisor.Conflict, "compute", "", "running")
		}
		d.VCPUs, d.MemoryMiB = vcpus, memoryMiB
		d.XML = simMemRE.ReplaceAllString(d.XML, fmt.Sprintf("${1}%d${2}", memoryMiB))
		d.XML = simCurRE.ReplaceAllString(d.XML, fmt.Sprintf("${1}%d${2}", memoryMiB))
		d.XML = simVcpuRE.ReplaceAllString(d.XML, fmt.Sprintf("${1}%d${2}", vcpus))
		st.Domains[name] = d
		return nil
	})
}

// ListDomains implements provision.HostOps.
func (h *Host) ListDomains(ctx context.Context) ([]provision.DomainInfo, error) {
	st := h.Load()
	names := make([]string, 0, len(st.Domains))
	for n := range st.Domains {
		names = append(names, n)
	}
	sort.Strings(names)
	out := make([]provision.DomainInfo, 0, len(names))
	for _, n := range names {
		d, err := h.LookupDomain(ctx, n)
		if err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, nil
}

// simIP picks the guest's address on its network: its static reservation if it has one, otherwise a deterministic address in the DHCP range.
func simIP(st *State, d Domain) string {
	pd, err := provision.ParseDomain(d.XML)
	sum := sha256.Sum256([]byte(d.UUID))
	h16 := uint32(binary.BigEndian.Uint16(sum[:2]))
	if err != nil || pd.Network == "" || pd.Network == DefaultNetwork {
		return fmt.Sprintf("192.168.122.%d", 10+h16%200)
	}
	n, ok := st.Networks[pd.Network]
	if !ok {
		return fmt.Sprintf("192.168.122.%d", 10+h16%200)
	}
	for _, x := range n.Hosts {
		if x.MAC == provision.MAC(d.UUID) {
			return x.IP
		}
	}
	info, err := simNetInfo(pd.Network, n)
	if err != nil || info.DHCPStart == "" {
		return fmt.Sprintf("192.168.122.%d", 10+h16%200)
	}
	a, _ := netip.ParseAddr(info.DHCPStart)
	b, _ := netip.ParseAddr(info.DHCPEnd)
	as, bs := a.As4(), b.As4()
	lo := uint32(as[0])<<24 | uint32(as[1])<<16 | uint32(as[2])<<8 | uint32(as[3])
	hi := uint32(bs[0])<<24 | uint32(bs[1])<<16 | uint32(bs[2])<<8 | uint32(bs[3])
	v := lo + h16%(hi-lo+1)
	var out [4]byte
	binary.BigEndian.PutUint32(out[:], v)
	return netip.AddrFrom4(out).String()
}

// Networks implements hypervisor.NetworkReader (the read-only view of the networks).
func (r Reader) Networks(ctx context.Context) ([]hypervisor.Network, error) {
	st := r.H.Load()
	infos, err := r.H.ListNetworks(ctx)
	if err != nil {
		return nil, err
	}
	count := map[string]int{}
	for _, d := range st.Domains {
		if pd, err := provision.ParseDomain(d.XML); err == nil && pd.Network != "" {
			count[pd.Network]++
		}
	}
	out := make([]hypervisor.Network, 0, len(infos))
	for _, n := range infos {
		hn := hypervisor.Network{Name: n.Name, UUID: n.UUID, Managed: n.Managed, Active: n.Active, Autostart: n.Autostart, Mode: n.Mode, Bridge: n.Bridge,
			Gateway: n.Gateway, DHCPStart: n.DHCPStart, DHCPEnd: n.DHCPEnd, AttachedVMs: count[n.Name]}
		if n.Subnet.IsValid() {
			hn.Subnet = n.Subnet.String()
		}
		for _, x := range n.Hosts {
			hn.Reservations = append(hn.Reservations, hypervisor.Reservation{MAC: x.MAC, IP: x.IP})
		}
		out = append(out, hn)
	}
	return out, nil
}

var _ hypervisor.NetworkReader = Reader{}

// AddForeignNetwork defines a pre-existing network that Svavyom did not create (no ownership marker) for tests.
func (h *Host) AddForeignNetwork(name, subnetGateway, netmask string, active bool) error {
	x := fmt.Sprintf("<network><name>%s</name><uuid>00000000-0000-4000-8000-0000000000f%d</uuid><forward mode='nat'/><bridge name='virbr-%s'/><ip address='%s' netmask='%s'/></network>",
		name, len(name)%10, strings.ReplaceAll(name, "_", "-"), subnetGateway, netmask)
	return h.update(func(st *State) error {
		if st.Networks == nil {
			st.Networks = map[string]SimNet{}
		}
		st.Networks[name] = SimNet{XML: x, Active: active}
		return nil
	})
}

// ExtraLease is a simulated lease held by a machine that is not one of the simulated domains.
type ExtraLease struct {
	Network, MAC, IP string
}

// DataVolumes implements hypervisor.DataVolumeReader (the read-only view of the data volumes).
func (r Reader) DataVolumes(context.Context) ([]hypervisor.DataVolume, error) {
	st := r.H.Load()
	seen := map[string]bool{}
	out := []hypervisor.DataVolume{}
	for k, v := range st.Volumes {
		file := k[strings.LastIndex(k, "/")+1:]
		if n, ok := provision.ParseDataVolumeName(file); ok && !seen[n] {
			seen[n] = true
			out = append(out, hypervisor.DataVolume{Name: n, CapacityBytes: v.Capacity})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

var _ hypervisor.DataVolumeReader = Reader{}
