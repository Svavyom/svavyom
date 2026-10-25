// Package simhost is a file-backed SIMULATION of a libvirt host for the provisioning slice: storage volumes, one network, one
// pool and domains live in a JSON state file, so they survive the death of the process that mutated them. It implements
// provision.HostOps (mutation) and hypervisor.Reader (observation) and is used by the test-only helper and fixture agent and
// by fault-injection tests. It is NOT libvirt and proves nothing about libvirt or KVM.
package simhost

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"example.invalid/dedicatedcloud/backend/internal/hypervisor"
	"example.invalid/dedicatedcloud/backend/internal/provision"
)

// Domain is a simulated domain.
type Domain struct {
	UUID        string `json:"uuid"`
	Fingerprint string `json:"fingerprint"`
	Managed     bool   `json:"managed"`
	Image       string `json:"image"`
	Running     bool   `json:"running"`
	VCPUs       int    `json:"vcpus"`
	MemoryMiB   int    `json:"memory_mib"`
	IP          string `json:"ip"`
	Root        string `json:"root"`
	Seed        string `json:"seed"`
	XML         string `json:"xml"`
	// Reboots counts guest reboot requests (a simulation observable). SlowStop makes ShutdownDomain accepted but ineffective,
	// like a guest that ignores the power button.
	Reboots  int  `json:"reboots"`
	SlowStop bool `json:"slow_stop"`
	// IgnoreReboot makes a reboot request ineffective: the guest never resets, so the reset is never seen.
	IgnoreReboot bool `json:"ignore_reboot"`
}

// Volume is a simulated storage volume. Data is the volume's file content (a real qcow2 overlay header plus a payload for a root volume), so
// download, upload, backup and restore move real bytes through the real parsers.
type Volume struct {
	Capacity int64  `json:"capacity"`
	Backing  string `json:"backing"`
	SeedSHA  string `json:"seed_sha256"`
	SeedLen  int    `json:"seed_len"`
	Data     []byte `json:"data,omitempty"`
	// Allocation overrides the reported allocation when non-zero (a test knob).
	Allocation int64 `json:"allocation,omitempty"`
}

// Snapshot is a simulated internal snapshot: the disk content at that time.
type Snapshot struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Created     int64  `json:"created"`
	Volume      string `json:"volume"` // "pool/name" of the root volume it covers
	Data        []byte `json:"data"`
	Capacity    int64  `json:"capacity"`
}

// State is the whole simulated host.
type State struct {
	NetworkDown bool              `json:"network_down"`
	PoolDown    bool              `json:"pool_down"`
	Domains     map[string]Domain `json:"domains"`
	Volumes     map[string]Volume `json:"volumes"` // "pool/name"
	// Snapshots by domain name.
	Snapshots map[string][]Snapshot `json:"snapshots,omitempty"`
	// PoolCapacity is the simulated pool size (default 1 TiB); PoolAvailable overrides the computed free space when non-zero (a nearly full pool).
	PoolCapacity  int64 `json:"pool_capacity,omitempty"`
	PoolAvailable int64 `json:"pool_available,omitempty"`
	// Networks are the defined libvirt networks other than the default (managed and foreign); ExtraLeases are leases of machines that are not
	// simulated domains.
	Networks    map[string]SimNet `json:"networks,omitempty"`
	ExtraLeases []ExtraLease      `json:"extra_leases,omitempty"`
}

// Host is a simulated host rooted at a state directory.
type Host struct {
	Dir string
	mu  sync.Mutex
}

// New returns a host whose state lives in dir (created 0700).
func New(dir string) (*Host, error) {
	if !filepath.IsAbs(dir) || filepath.Clean(dir) != dir {
		return nil, errors.New("simhost: state dir must be a clean absolute path")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	return &Host{Dir: dir}, nil
}

func (h *Host) path() string { return filepath.Join(h.Dir, "simhost.json") }

// Load reads the state (an absent file is an empty, healthy host).
func (h *Host) Load() State {
	st := State{Domains: map[string]Domain{}, Volumes: map[string]Volume{}}
	if b, err := os.ReadFile(h.path()); err == nil {
		_ = json.Unmarshal(b, &st)
	}
	if st.Domains == nil {
		st.Domains = map[string]Domain{}
	}
	if st.Volumes == nil {
		st.Volumes = map[string]Volume{}
	}
	if st.Snapshots == nil {
		st.Snapshots = map[string][]Snapshot{}
	}
	return st
}

// Save writes the state atomically.
func (h *Host) Save(st State) error {
	b, err := json.Marshal(st)
	if err != nil {
		return err
	}
	tmp := h.path() + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, h.path())
}

func (h *Host) update(fn func(*State) error) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	st := h.Load()
	if err := fn(&st); err != nil {
		return err
	}
	return h.Save(st)
}

func nf(op string) error { return hypervisor.NewError(hypervisor.NotFound, op, "", "not found") }

// NetworkActive implements provision.HostOps.
func (h *Host) NetworkActive(_ context.Context, _ string) (bool, error) {
	return !h.Load().NetworkDown, nil
}

// PoolActive implements provision.HostOps.
func (h *Host) PoolActive(_ context.Context, _ string) (bool, error) { return !h.Load().PoolDown, nil }

// LookupDomain implements provision.HostOps.
func (h *Host) LookupDomain(_ context.Context, name string) (provision.DomainInfo, error) {
	d, ok := h.Load().Domains[name]
	if !ok {
		return provision.DomainInfo{}, nf("lookup")
	}
	info := provision.DomainInfo{Name: name, UUID: d.UUID, Fingerprint: d.Fingerprint, Managed: d.Managed, Running: d.Running, Root: d.Root, Seed: d.Seed, XML: d.XML, VCPUs: d.VCPUs, MemoryMiB: d.MemoryMiB, ImageID: d.Image}
	if pd, err := provision.ParseDomain(d.XML); err == nil {
		info.Data, info.Media, info.ISO, info.ISOs, info.Graphics, info.Rescue = pd.Data, pd.Media, pd.ISO, pd.ISOs, pd.Graphics, pd.Rescue
	}
	return info, nil
}

// LookupVolume implements provision.HostOps.
func (h *Host) LookupVolume(_ context.Context, pool, name string) (provision.VolumeInfo, error) {
	v, ok := h.Load().Volumes[pool+"/"+name]
	if !ok {
		return provision.VolumeInfo{}, nf("lookup-volume")
	}
	// The simulation places every volume in one directory per pool; it has no filesystem, so it reports a clean regular file.
	dir := "/sim/" + pool
	return provision.VolumeInfo{CapacityBytes: v.Capacity, AllocationBytes: allocation(v), BackingPath: v.Backing, Name: name, Path: dir + "/" + name, PoolPath: dir,
		FSChecked: true, Regular: true, Canonical: true}, nil
}

// CreateRootVolume implements provision.HostOps.
func (h *Host) CreateRootVolume(_ context.Context, pool, name string, capacity int64, backing string) error {
	return h.update(func(st *State) error {
		k := pool + "/" + name
		if _, ok := st.Volumes[k]; ok {
			return hypervisor.NewError(hypervisor.Conflict, "create-volume", "", "exists")
		}
		st.Volumes[k] = Volume{Capacity: capacity, Backing: backing, Data: Overlay(backing, capacity, "fresh-"+name)}
		return nil
	})
}

// CreateDataVolume implements provision.HostOps.
func (h *Host) CreateDataVolume(_ context.Context, pool, name string, capacity int64) error {
	if _, ok := provision.ParseDataVolumeName(name); !ok {
		return hypervisor.NewError(hypervisor.Validation, "create-volume", "", "name")
	}
	return h.update(func(st *State) error {
		k := pool + "/" + name
		if _, ok := st.Volumes[k]; ok {
			return hypervisor.NewError(hypervisor.Conflict, "create-volume", "", "exists")
		}
		st.Volumes[k] = Volume{Capacity: capacity}
		return nil
	})
}

// AttachDataDisk implements provision.HostOps: the device element is added to the stored definition of a domain that is not running.
func (h *Host) AttachDataDisk(_ context.Context, domain, volume, path, dev string) error {
	x, err := provision.DataDiskXML(volume, provision.VolumeSource{Name: provision.DataVolumeName(volume), Path: path, PoolPath: filepath.Dir(path)}, dev)
	if err != nil {
		return hypervisor.NewError(hypervisor.Validation, "attach", "", "device")
	}
	return h.update(func(st *State) error {
		d, ok := st.Domains[domain]
		if !ok {
			return nf("attach")
		}
		if d.Running {
			return hypervisor.NewError(hypervisor.Conflict, "attach", "", "running")
		}
		if _, have := provision.DataDiskPath(d.XML, volume); have {
			return nil
		}
		i := strings.LastIndex(d.XML, "</devices>")
		if i < 0 {
			return hypervisor.NewError(hypervisor.HostError, "attach", "", "definition")
		}
		d.XML = d.XML[:i] + "    " + x + "\n  " + d.XML[i:]
		st.Domains[domain] = d
		return nil
	})
}

// DetachDataDisk implements provision.HostOps.
func (h *Host) DetachDataDisk(_ context.Context, domain, volume string) error {
	return h.update(func(st *State) error {
		d, ok := st.Domains[domain]
		if !ok {
			return nf("detach")
		}
		if d.Running {
			return hypervisor.NewError(hypervisor.Conflict, "detach", "", "running")
		}
		path, have := provision.DataDiskPath(d.XML, volume)
		if !have {
			return nil
		}
		at := strings.Index(d.XML, "<source file='"+path+"'/>")
		start := strings.LastIndex(d.XML[:max(at, 0)], "<disk ")
		end := strings.Index(d.XML[max(at, 0):], "</disk>")
		if at < 0 || start < 0 || end < 0 {
			return hypervisor.NewError(hypervisor.HostError, "detach", "", "definition")
		}
		d.XML = d.XML[:start] + d.XML[at+end+len("</disk>"):]
		st.Domains[domain] = d
		return nil
	})
}

// CreateSeedVolume implements provision.HostOps.
func (h *Host) CreateSeedVolume(_ context.Context, pool, name string, capacity int64) error {
	return h.update(func(st *State) error {
		k := pool + "/" + name
		if _, ok := st.Volumes[k]; ok {
			return hypervisor.NewError(hypervisor.Conflict, "create-volume", "", "exists")
		}
		st.Volumes[k] = Volume{Capacity: capacity}
		return nil
	})
}

// UploadSeed implements provision.HostOps.
func (h *Host) UploadSeed(_ context.Context, pool, name string, iso []byte) error {
	return h.update(func(st *State) error {
		k := pool + "/" + name
		v, ok := st.Volumes[k]
		if !ok || int64(len(iso)) > v.Capacity {
			return nf("upload")
		}
		sum := sha256.Sum256(iso)
		v.SeedSHA, v.SeedLen = fmt.Sprintf("%x", sum), len(iso)
		st.Volumes[k] = v
		return nil
	})
}

// DefineDomain implements provision.HostOps by parsing the generated XML (which also checks the template).
func (h *Host) DefineDomain(_ context.Context, x string) error {
	d, err := provision.ParseDomain(x)
	if err != nil || d.Name == "" || d.UUID == "" || d.VCPUs == 0 || d.MemoryMiB == 0 {
		return hypervisor.NewError(hypervisor.Validation, "define", "", "bad definition")
	}
	dom := Domain{UUID: d.UUID, VCPUs: d.VCPUs, MemoryMiB: d.MemoryMiB, Managed: d.Managed, Fingerprint: d.Fingerprint, Image: d.ImageID, Root: d.Root, Seed: d.Seed, XML: x}
	return h.update(func(st *State) error {
		if old, ok := st.Domains[d.Name]; ok {
			// libvirt replaces the stored definition of an existing domain of the same name and UUID (a reinstall); another UUID is a conflict.
			if old.UUID != dom.UUID {
				return hypervisor.NewError(hypervisor.Conflict, "define", "", "exists")
			}
			dom.Running, dom.IP, dom.Reboots, dom.SlowStop, dom.IgnoreReboot = old.Running, old.IP, old.Reboots, old.SlowStop, old.IgnoreReboot
		}
		st.Domains[d.Name] = dom
		return nil
	})
}

// StartDomain implements provision.HostOps: the guest "boots" and obtains a deterministic DHCP lease.
func (h *Host) StartDomain(_ context.Context, name string) error {
	return h.update(func(st *State) error {
		d, ok := st.Domains[name]
		if !ok {
			return nf("start")
		}
		d.Running = true
		d.IP = simIP(st, d)
		st.Domains[name] = d
		return nil
	})
}

var _ provision.HostOps = (*Host)(nil)

// Reader is the read-only view (what the fixture agent serves).
type Reader struct{ H *Host }

// Lookup implements hypervisor.Reader.
func (r Reader) Lookup(_ context.Context, name string) (hypervisor.Domain, error) {
	st := r.H.Load()
	d, ok := st.Domains[name]
	if !ok {
		return hypervisor.Domain{}, hypervisor.NewError(hypervisor.NotFound, "lookup", "", "no such domain")
	}
	return toDomain(&st, name, d), nil
}

// List implements hypervisor.Reader.
func (r Reader) List(context.Context) ([]hypervisor.Domain, error) {
	st := r.H.Load()
	out := make([]hypervisor.Domain, 0, len(st.Domains))
	for n, d := range st.Domains {
		out = append(out, toDomain(&st, n, d))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func toDomain(st *State, name string, d Domain) hypervisor.Domain {
	s := hypervisor.StateShutoff
	ip := ""
	if d.Running {
		s, ip = hypervisor.StateRunning, d.IP
	}
	out := hypervisor.Domain{Name: name, State: s, VCPUs: d.VCPUs, MemoryMiB: d.MemoryMiB, UUID: d.UUID, Fingerprint: d.Fingerprint,
		Managed: d.Managed, ImageID: d.Image, IPv4: ip}
	if d.Running && d.VCPUs > 0 {
		// A simulated guest that keeps a quarter of its vCPUs busy, so the usage sampler has something to show (simulation only).
		out.CPUTimeNs = time.Now().UnixNano() / 4 * int64(d.VCPUs)
		out.MemUsedMiB = int64(d.MemoryMiB) / 4
		out.DiskIOBytes = time.Now().UnixNano() / 1000 * 3 // about 3 MB/s
		out.NetIOBytes = time.Now().UnixNano() / 1000
	}
	if pd, err := provision.ParseDomain(d.XML); err == nil {
		out.Network, out.MAC = pd.Network, pd.MAC
		if d.Managed {
			for _, dd := range pd.Data {
				out.DataVolumes = append(out.DataVolumes, dd.Volume)
			}
			out.Media, out.ISOSHA256, out.ISOSHA256s = pd.Media, pd.ISO, pd.ISOs
			out.Graphics, out.RescueSHA256 = pd.Graphics, pd.Rescue
		}
	}
	if d.Managed {
		if k, ok := rootKey(st, d); ok {
			out.DiskBytes = st.Volumes[k].Capacity
		}
		for _, sn := range st.Snapshots[name] {
			if strings.HasPrefix(sn.Name, "svs-") && sn.Description == "svavyom:"+d.UUID {
				out.Snapshots = append(out.Snapshots, hypervisor.Snapshot{ID: strings.TrimPrefix(sn.Name, "svs-"), Created: sn.Created})
			}
		}
	}
	return out
}

var _ hypervisor.Reader = Reader{}

// DefineManaged adds a stopped, Svavyom-managed domain directly (test setup).
func (h *Host) DefineManaged(name string) error {
	return h.update(func(st *State) error {
		st.Domains[name] = Domain{UUID: "9a9a9a9a-2222-4333-8444-5555555555ab", Fingerprint: fmt.Sprintf("%064x", 1), Managed: true, VCPUs: 1, MemoryMiB: 512}
		return nil
	})
}

// ShutdownDomain implements provision.HostOps: the guest powers off unless SlowStop is set.
func (h *Host) ShutdownDomain(_ context.Context, name string) error {
	return h.update(func(st *State) error {
		d, ok := st.Domains[name]
		if !ok {
			return nf("shutdown")
		}
		if !d.Running {
			return hypervisor.NewError(hypervisor.Conflict, "shutdown", "", "not running")
		}
		if !d.SlowStop {
			d.Running, d.IP = false, ""
			st.Domains[name] = d
		}
		return nil
	})
}

// RebootDomain implements provision.HostOps: the guest resets unless IgnoreReboot is set, in which case the reset is never seen.
func (h *Host) RebootDomain(_ context.Context, name string, _ time.Duration) error {
	ignored := false
	err := h.update(func(st *State) error {
		d, ok := st.Domains[name]
		if !ok {
			return nf("reboot")
		}
		if !d.Running {
			return hypervisor.NewError(hypervisor.Conflict, "reboot", "", "not running")
		}
		d.Reboots++
		ignored = d.IgnoreReboot
		st.Domains[name] = d
		return nil
	})
	if err == nil && ignored {
		return hypervisor.NewError(hypervisor.Timeout, "reboot", "", "the guest reset was not observed")
	}
	return err
}

// DestroyDomain implements provision.HostOps.
func (h *Host) DestroyDomain(_ context.Context, name string) error {
	return h.update(func(st *State) error {
		d, ok := st.Domains[name]
		if !ok {
			return nf("destroy")
		}
		if !d.Running {
			return hypervisor.NewError(hypervisor.Conflict, "destroy", "", "not running")
		}
		d.Running, d.IP = false, ""
		st.Domains[name] = d
		return nil
	})
}

// UndefineDomain implements provision.HostOps.
func (h *Host) UndefineDomain(_ context.Context, name string) error {
	return h.update(func(st *State) error {
		d, ok := st.Domains[name]
		if !ok {
			return nf("undefine")
		}
		if d.Running {
			return hypervisor.NewError(hypervisor.Conflict, "undefine", "", "running")
		}
		delete(st.Domains, name)
		return nil
	})
}

// DeleteVolume implements provision.HostOps.
func (h *Host) DeleteVolume(_ context.Context, pool, name string) error {
	return h.update(func(st *State) error {
		k := pool + "/" + name
		if _, ok := st.Volumes[k]; !ok {
			return nf("delete-volume")
		}
		delete(st.Volumes, k)
		return nil
	})
}

// Update changes one domain in place (test setup: a guest that ignores the power button, a tampered definition).
func (h *Host) Update(name string, fn func(*Domain)) error {
	return h.update(func(st *State) error {
		d, ok := st.Domains[name]
		if !ok || fn == nil {
			return nf("update")
		}
		fn(&d)
		st.Domains[name] = d
		return nil
	})
}

// Add adds a domain exactly as given (test setup: a foreign or unmanaged domain).
func (h *Host) Add(name string, d Domain) error {
	return h.update(func(st *State) error { st.Domains[name] = d; return nil })
}

// AddVolume adds a volume exactly as given (test setup: a neighbouring volume that must survive).
func (h *Host) AddVolume(pool, name string, v Volume) error {
	return h.update(func(st *State) error { st.Volumes[pool+"/"+name] = v; return nil })
}

// SetPoolAvailable overrides the simulated pool's free space (0 restores the computed value).
func (h *Host) SetPoolAvailable(n int64) error {
	return h.update(func(st *State) error { st.PoolAvailable = n; return nil })
}

// AddSnapshot adds a snapshot exactly as given (test setup: a snapshot somebody else made).
func (h *Host) AddSnapshot(domain string, s Snapshot) error {
	return h.update(func(st *State) error { st.Snapshots[domain] = append(st.Snapshots[domain], s); return nil })
}

// SetAllocation makes the simulated volume report n bytes of allocation (test setup: a volume far larger than the backup store's filesystem).
func (h *Host) SetAllocation(pool, name string, n int64) error {
	return h.update(func(st *State) error {
		v := st.Volumes[pool+"/"+name]
		v.Allocation = n
		st.Volumes[pool+"/"+name] = v
		return nil
	})
}

func allocation(v Volume) int64 {
	if v.Allocation != 0 {
		return v.Allocation
	}
	return int64(len(v.Data))
}
