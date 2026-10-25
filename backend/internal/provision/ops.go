package provision

import (
	"context"
	"errors"
	"io"
	"path/filepath"
	"time"

	"example.invalid/dedicatedcloud/backend/internal/hypervisor"
)

// DomainInfo is what the step runner needs to know about an existing domain.
type DomainInfo struct {
	// Name is the domain's name; Data lists the standalone data volumes its definition carries (DR-023 D2).
	Name string
	Data []DataDisk
	// Media is "iso" for a VM created from installation media; ISO is the digest of the media attached now ("" when none).
	Media, ISO string
	// ISOs is the digest of every installation medium attached, in guest target order (DR-031); ISO is the one that boots next, else the first.
	ISOs []string
	// Graphics is true when the definition has a VNC console; Rescue is the digest of the rescue media while the VM is in rescue mode.
	Graphics          bool
	Rescue            string
	UUID, Fingerprint string
	Managed           bool
	Running           bool
	// Root and Seed are the volume names of the domain's two disks, set only when the definition names exactly Svavyom's own volumes
	// for this domain's UUID (ParseDomain). XML is the domain definition as the host reports it, for ownership proofs (CheckDomainSources).
	Root, Seed string
	XML        string
	// The domain's own recorded definition: size and the image named by the ownership marker.
	VCPUs, MemoryMiB int
	ImageID          string
}

// VolumeInfo is what the step runner needs to know about an existing storage volume.
type VolumeInfo struct {
	CapacityBytes   int64
	AllocationBytes int64  // bytes actually used on the host (thin allocation); 0 when the host does not report it
	BackingPath     string // "" when the volume has no backing file

	// Placement, as the host reports it for a file-backed pool (CT-PRODUCT-DELIVERY-009). Name is the volume's own name as libvirt
	// returns it; Path the resolved filesystem path of the volume and PoolPath the pool's target directory. The last four come from
	// inspecting Path without following a symlink: FSChecked is false when the path could not be inspected by this process.
	Name, Path, PoolPath        string
	FSChecked, Regular, Symlink bool
	Canonical                   bool // Path equals its fully resolved form: no symlink in any component
}

// HostOps is the narrow set of host operations provisioning uses. Implementations: libvirt storage/domain APIs (package
// libvirtmut, build tag libvirt) and a file-backed simulation (package simhost). All errors are *hypervisor.Error; "does not
// exist" is category NotFound. No method takes a path or XML from outside this package's own derivations.
type HostOps interface {
	NetworkActive(ctx context.Context, name string) (bool, error)
	PoolActive(ctx context.Context, name string) (bool, error)
	LookupDomain(ctx context.Context, name string) (DomainInfo, error)
	LookupVolume(ctx context.Context, pool, name string) (VolumeInfo, error)
	// CreateRootVolume creates a copy-on-write qcow2 volume of capacityBytes backed by backingPath (a verified catalog image).
	CreateRootVolume(ctx context.Context, pool, name string, capacityBytes int64, backingPath string) error
	// CreateSeedVolume creates an empty raw volume of capacityBytes.
	CreateSeedVolume(ctx context.Context, pool, name string, capacityBytes int64) error
	// UploadSeed stores iso at the start of an existing seed volume, replacing any earlier content. It is idempotent: an upload
	// interrupted half way is repaired by running it again, which is why Provision always re-uploads after a crash.
	UploadSeed(ctx context.Context, pool, name string, iso []byte) error
	DefineDomain(ctx context.Context, xml string) error
	StartDomain(ctx context.Context, name string) error
	// ShutdownDomain asks the guest to power off (ACPI); it returns when the request was accepted, not when the guest is off.
	ShutdownDomain(ctx context.Context, name string) error
	// RebootDomain asks the guest to reboot and waits up to wait for the hypervisor to report that the guest was reset (libvirt's reboot
	// event: an ACPI reboot resets the machine inside the same QEMU process, so no domain id or process changes). It returns nil only
	// when that was SEEN, and Timeout when it was not (the outcome is then unknown).
	RebootDomain(ctx context.Context, name string, wait time.Duration) error
	// DestroyDomain powers the domain off immediately (no guest cooperation). It deletes nothing.
	DestroyDomain(ctx context.Context, name string) error
	// UndefineDomain removes the persistent definition of an inactive domain. It never touches storage.
	UndefineDomain(ctx context.Context, name string) error
	// DeleteVolume removes one storage volume from the pool by name.
	DeleteVolume(ctx context.Context, pool, name string) error

	// PoolStats reports the capacity of the configured pool.
	PoolStats(ctx context.Context, pool string) (PoolStats, error)
	// ListVolumes returns the names of every volume of the pool (the caller filters to what it may touch).
	ListVolumes(ctx context.Context, pool string) ([]string, error)
	// ResizeVolume sets the virtual size of an existing volume. It never shrinks (the host refuses).
	ResizeVolume(ctx context.Context, pool, name string, capacityBytes int64) error
	// ListSnapshots returns the domain's snapshots (all of them, whoever made them).
	ListSnapshots(ctx context.Context, domain string) ([]SnapshotInfo, error)
	// CreateSnapshot takes an internal snapshot of the STOPPED domain's disks.
	CreateSnapshot(ctx context.Context, domain, name, description string) error
	// RevertSnapshot returns the STOPPED domain to the named snapshot.
	RevertSnapshot(ctx context.Context, domain, name string) error
	// DeleteSnapshot removes one snapshot.
	DeleteSnapshot(ctx context.Context, domain, name string) error
	// DownloadVolume streams the volume's bytes into w and returns how many were written.
	DownloadVolume(ctx context.Context, pool, name string, w io.Writer) (int64, error)
	// UploadVolume replaces the content of an existing volume with exactly size bytes read from r.
	UploadVolume(ctx context.Context, pool, name string, r io.Reader, size int64) error

	// CreateDataVolume creates an empty qcow2 data volume of capacityBytes (DR-023 D2).
	CreateDataVolume(ctx context.Context, pool, name string, capacityBytes int64) error
	// AttachDataDisk adds the data volume's file as the disk dev of the STOPPED domain's persistent definition; DetachDataDisk removes it.
	// Both build the device from the validated arguments and nothing else (no caller XML).
	AttachDataDisk(ctx context.Context, domain, volume, path, dev string) error
	DetachDataDisk(ctx context.Context, domain, volume string) error

	// ListDomains returns every domain with its stored definition (the caller filters to what it may touch).
	ListDomains(ctx context.Context) ([]DomainInfo, error)
	// ListNetworks returns every libvirt network, parsed (managed or not).
	ListNetworks(ctx context.Context) ([]NetworkInfo, error)
	// LookupNetwork returns one network by name (NotFound when absent).
	LookupNetwork(ctx context.Context, name string) (NetworkInfo, error)
	// DefineNetwork persistently defines a network from XML rendered by NetworkXML (libvirt replaces a network of the same name and UUID).
	DefineNetwork(ctx context.Context, xml string) error
	// StartNetwork activates a defined, inactive network.
	StartNetwork(ctx context.Context, name string) error
	// StopNetwork deactivates an active network (it stays defined).
	StopNetwork(ctx context.Context, name string) error
	// SetNetworkAutostart turns the network's autostart on or off.
	SetNetworkAutostart(ctx context.Context, name string, on bool) error
	// UndefineNetwork removes the definition of an inactive network.
	UndefineNetwork(ctx context.Context, name string) error
	// AddNetworkHost adds a static DHCP reservation (live and persistent); RemoveNetworkHost removes it.
	AddNetworkHost(ctx context.Context, network, mac, ip string) error
	RemoveNetworkHost(ctx context.Context, network, mac, ip string) error
	// NetworkLeases returns the current DHCP leases of the network.
	NetworkLeases(ctx context.Context, network string) ([]NetLease, error)
	// SetDomainCompute sets the persistent vCPU count and memory (MiB) of a stopped domain, both the maximum and the current value.
	SetDomainCompute(ctx context.Context, name string, vcpus, memoryMiB int) error
}

// NetLease is one DHCP lease as the host reports it.
type NetLease struct {
	MAC, IP string
	Expiry  int64 // unix seconds
}

// PoolStats are the byte counts of a storage pool as the host reports them.
type PoolStats struct {
	CapacityBytes, AvailableBytes, AllocationBytes int64
	// Type is the libvirt pool type ("dir", "fs", "netfs", "logical", ...); empty when the host did not say.
	Type string
}

// SnapshotSupport reports whether Svavyom's internal qcow2 snapshots can work on a pool of this type (DR-023 D6): they live inside the qcow2
// root disk, so the pool must hold plain files ("dir", "fs" or "netfs"). A block-backed pool cannot hold them; an unreported type is unknown.
func SnapshotSupport(poolType string) string {
	switch poolType {
	case "dir", "fs", "netfs":
		return "available"
	case "":
		return "unknown"
	}
	return "unavailable"
}

// SnapshotInfo is one domain snapshot as the host reports it.
type SnapshotInfo struct {
	Name        string
	Description string
	Created     int64 // unix seconds
}

// Steps, in order. A hook receives the name of each step after it completed (fault injection and progress).
const (
	StepImageVerified = "image-verified"
	StepPreflight     = "preflight"
	StepRootVolume    = "root-volume"
	StepSeedVolume    = "seed-volume"
	StepDomainDefined = "domain-defined"
	StepStarted       = "started"
	// StepRestoreUploaded follows the upload of a backed-up overlay into the new root volume.
	StepRestoreUploaded = "restore-uploaded"
)

// Hook observes completed steps. It must not block; fault injection may terminate the process from it.
type Hook func(step string)

func typed(c hypervisor.Category, op string) error {
	return hypervisor.NewError(c, op, "", "provisioning")
}

// typedWhy is typed with a fixed (never host-derived) reason, so a refusal says which check refused.
func typedWhy(c hypervisor.Category, op, why string) error {
	return hypervisor.NewError(c, op, "", why)
}

func isNotFound(err error) bool { return hypervisor.CategoryOf(err) == hypervisor.NotFound }

// Readiness is the answer of Preflight.
type Readiness struct {
	Network string // available | unavailable | unknown
	Pool    string
}

func state(ok bool, err error) string {
	switch {
	case err != nil:
		return "unknown"
	case ok:
		return "available"
	}
	return "unavailable"
}

// Preflight reports whether the configured network and pool are active. It mutates nothing.
func Preflight(ctx context.Context, ops HostOps, cfg Config) Readiness {
	n, nerr := ops.NetworkActive(ctx, cfg.Network)
	p, perr := ops.PoolActive(ctx, cfg.Pool)
	return Readiness{Network: state(n, nerr), Pool: state(p, perr)}
}

// Provision creates the VM described by s: verify the catalog image, check the host is ready, then create the root volume,
// the seed volume and the (stopped) domain. It is safe to run again after any interruption: every step first looks at what
// already exists and only proceeds when the object is provably this VM's (named from its creation UUID, with the expected
// capacity and backing file), and nothing is ever deleted or overwritten. Anything it cannot prove is a Conflict.
func Provision(ctx context.Context, ops HostOps, cfg Config, cat *Catalog, s Spec, scratchDir string, hook Hook) error {
	return provisionAs(ctx, ops, cfg, cat, s, scratchDir, hook, provisionOpts{validate: Spec.ValidateAnyMedia, render: DomainXML})
}

// provisionOpts parameterises Provision for a restore: the limits that apply to an existing VM, the matching renderer, and the bytes of a
// backed-up root overlay to upload into the freshly created root volume.
type provisionOpts struct {
	validate    func(Spec) error
	render      func(Config, Spec, BackingImage, DiskSources) (string, error)
	rootContent func() (io.ReadCloser, int64, error)
}

func provisionAs(ctx context.Context, ops HostOps, cfg Config, cat *Catalog, s Spec, scratchDir string, hook Hook, opts provisionOpts) error {
	if hook == nil {
		hook = func(string) {}
	}
	if err := cfg.Validate(); err != nil || opts.validate(s) != nil {
		return typed(hypervisor.Validation, "provision")
	}
	im, err := cat.Usable(s.ImageID)
	if err != nil {
		return typed(hypervisor.Validation, "provision")
	}
	if im.SHA256 != s.ImageSHA256 || s.DiskGiB < im.MinDiskGiB {
		return typed(hypervisor.Conflict, "provision") // the catalog moved on since the operation was accepted
	}
	if im.IsISO() {
		if opts.rootContent != nil || s.SSHPublicKey != "" {
			return typed(hypervisor.Validation, "provision") // no restore of installation media, and no SSH key for an ISO install
		}
		s.Media = MediaISO
		return provisionISO(ctx, ops, cfg, cat, im, s, hook)
	}
	if s.SSHPublicKey == "" {
		return typed(hypervisor.Validation, "provision") // a cloud image is reached with the one key the caller gave
	}
	backing, err := cat.Backing(im) // trust policy, size, SHA-256 and a canonical, symlink-free path
	if err != nil {
		return typed(hypervisor.Conflict, "provision")
	}
	imagePath := backing.Path
	hook(StepImageVerified)

	if done, err := ready(ctx, ops, cfg, s, hook); done || err != nil {
		return err
	}

	wantCapacity := int64(s.DiskGiB) << 30
	root := RootVolumeName(s.UUID)
	switch v, err := ops.LookupVolume(ctx, cfg.Pool, root); {
	case err == nil:
		if v.CapacityBytes != wantCapacity || v.BackingPath != imagePath {
			return typed(hypervisor.Conflict, "provision")
		}
	case isNotFound(err):
		if err := ops.CreateRootVolume(ctx, cfg.Pool, root, wantCapacity, imagePath); err != nil {
			return err
		}
	default:
		return err
	}
	if opts.rootContent != nil {
		// A restore: the backed-up overlay replaces the (empty) new root volume's content. It is always sent again after an interruption, so a half-uploaded
		// volume is never trusted; the capacity and backing file the host reports afterwards must still be exactly the intended ones.
		rc, size, err := opts.rootContent()
		if err != nil {
			return typed(hypervisor.Conflict, "provision")
		}
		uerr := ops.UploadVolume(ctx, cfg.Pool, root, rc, size)
		_ = rc.Close()
		if uerr != nil {
			return uerr
		}
		if v, err := ops.LookupVolume(ctx, cfg.Pool, root); err != nil || v.CapacityBytes != wantCapacity || v.BackingPath != imagePath {
			return typed(hypervisor.Conflict, "provision")
		}
		hook(StepRestoreUploaded)
	}
	rootSrc, err := resolveVolume(ctx, ops, cfg, root)
	if err != nil {
		return err
	}
	hook(StepRootVolume)

	seed := SeedVolumeName(s.UUID)
	switch v, err := ops.LookupVolume(ctx, cfg.Pool, seed); {
	case err == nil:
		if v.CapacityBytes != SeedCapacityBytes {
			return typed(hypervisor.Conflict, "provision")
		}
	case isNotFound(err):
		if err := ops.CreateSeedVolume(ctx, cfg.Pool, seed, SeedCapacityBytes); err != nil {
			return err
		}
	default:
		return err
	}
	// The seed content is (re)written every time this step runs: a crash between creating the volume and finishing the upload
	// would otherwise leave a seed that looks complete and is not. The volume is named from this VM's creation UUID.
	iso, berr := BuildSeed(s, scratchDir)
	if berr != nil {
		return typed(hypervisor.HostError, "provision")
	}
	if err := ops.UploadSeed(ctx, cfg.Pool, seed, iso); err != nil {
		return err
	}
	hook(StepSeedVolume)

	seedSrc, err := resolveVolume(ctx, ops, cfg, seed)
	if err != nil {
		return err
	}

	// Neither path may have moved between creation/upload and definition: resolve both once at the end and require that each answer
	// equals the one the same volume gave when it was created (root) or uploaded (seed), then define from the final answers only.
	final, err := resolveSources(ctx, ops, cfg, s)
	if err != nil {
		return err
	}
	if final != (DiskSources{Root: rootSrc, Seed: seedSrc}) {
		return typed(hypervisor.Conflict, "provision")
	}
	xml, err := opts.render(cfg, s, backing, final)
	if err != nil {
		return typed(hypervisor.Validation, "provision")
	}
	if err := ops.DefineDomain(ctx, xml); err != nil {
		return err
	}
	hook(StepDomainDefined)
	return nil
}

// ready is the shared start of a create: the network and pool are ready (the configured network, or an active Svavyom-managed one), and the domain
// does not exist yet. done is true when this very create already finished (the domain is there and is this VM's).
func ready(ctx context.Context, ops HostOps, cfg Config, s Spec, hook Hook) (done bool, err error) {
	r := Preflight(ctx, ops, cfg)
	if s.Network != cfg.Network {
		// A VM may attach to the configured network or to a Svavyom-managed one; any other libvirt network is refused. The managed network must be active.
		n, nerr := ops.LookupNetwork(ctx, s.Network)
		switch {
		case isNotFound(nerr) || (nerr == nil && !n.Managed):
			return false, typedWhy(hypervisor.Validation, "provision", "not a network a VM may attach to")
		case nerr != nil:
			return false, nerr
		}
		r.Network = "unavailable"
		if n.Active {
			r.Network = "available"
		}
	}
	if r.Network != "available" || r.Pool != "available" {
		return false, typed(hypervisor.Unavailable, "provision") // nothing has been created
	}
	hook(StepPreflight)

	switch d, err := ops.LookupDomain(ctx, s.Name); {
	case err == nil:
		if d.Managed && d.UUID == s.UUID && d.Fingerprint == s.Fingerprint {
			return true, nil // this very create already finished
		}
		return false, typed(hypervisor.Conflict, "provision") // a domain of that name that is not ours
	case !isNotFound(err):
		return false, err
	}
	return false, nil
}

// provisionISO creates a VM from installation media (DR-023 D3): a blank qcow2 root disk of the chosen size, the verified ISO attached as a read-only CD
// that the VM boots from first, and no seed and no cloud-init. Like Provision it can be run again after any interruption and never deletes anything.
func provisionISO(ctx context.Context, ops HostOps, cfg Config, cat *Catalog, im Image, s Spec, hook Hook) error {
	isoPath, err := cat.Verify(im) // trust policy, size and SHA-256 of the media
	if err != nil {
		return typed(hypervisor.Conflict, "provision")
	}
	if real, rerr := filepath.EvalSymlinks(isoPath); rerr != nil || real != isoPath {
		return typed(hypervisor.Conflict, "provision")
	}
	hook(StepImageVerified)
	if done, err := ready(ctx, ops, cfg, s, hook); done || err != nil {
		return err
	}
	wantCapacity := int64(s.DiskGiB) << 30
	root := RootVolumeName(s.UUID)
	switch v, err := ops.LookupVolume(ctx, cfg.Pool, root); {
	case err == nil:
		if v.CapacityBytes != wantCapacity || v.BackingPath != "" {
			return typed(hypervisor.Conflict, "provision")
		}
	case isNotFound(err):
		if err := ops.CreateRootVolume(ctx, cfg.Pool, root, wantCapacity, ""); err != nil {
			return err
		}
	default:
		return err
	}
	rootSrc, err := resolveVolume(ctx, ops, cfg, root)
	if err != nil {
		return err
	}
	hook(StepRootVolume)
	xml, err := DomainXMLISO(cfg, s, ISOImage{Path: isoPath, SHA256: im.SHA256}, rootSrc)
	if err != nil {
		return typed(hypervisor.Validation, "provision")
	}
	if err := ops.DefineDomain(ctx, xml); err != nil {
		return err
	}
	hook(StepDomainDefined)
	return nil
}

// resolveVolume asks the host where the named volume of this VM lives and accepts only a path that is provably that volume's file.
func resolveVolume(ctx context.Context, ops HostOps, cfg Config, name string) (VolumeSource, error) {
	v, err := ops.LookupVolume(ctx, cfg.Pool, name)
	if err != nil {
		return VolumeSource{}, err
	}
	r, err := ResolveVolumeSource(name, v)
	if err != nil {
		return VolumeSource{}, typed(hypervisor.Conflict, "provision")
	}
	return r, nil
}

// resolveSources resolves both qualification disks of s.
func resolveSources(ctx context.Context, ops HostOps, cfg Config, s Spec) (DiskSources, error) {
	root, err := resolveVolume(ctx, ops, cfg, RootVolumeName(s.UUID))
	if err != nil {
		return DiskSources{}, err
	}
	seed, err := resolveVolume(ctx, ops, cfg, SeedVolumeName(s.UUID))
	if err != nil {
		return DiskSources{}, err
	}
	return DiskSources{Root: root, Seed: seed}, nil
}

// Start boots a Svavyom-managed domain. A domain without the ownership marker is refused (Prohibited); a domain that is
// already running is success (idempotent).
func Start(ctx context.Context, ops HostOps, name string, hook Hook) error {
	if hook == nil {
		hook = func(string) {}
	}
	if !VMNameRE.MatchString(name) {
		return typed(hypervisor.Validation, "start")
	}
	d, err := ops.LookupDomain(ctx, name)
	if err != nil {
		return err
	}
	if !d.Managed {
		return typed(hypervisor.Prohibited, "start")
	}
	if d.Running {
		return nil
	}
	// A VM does not start on a network that is not active; saying so is clearer than libvirt's own failure.
	if pd, perr := ParseDomain(d.XML); perr == nil && pd.Network != "" {
		if n, nerr := ops.LookupNetwork(ctx, pd.Network); nerr == nil && !n.Active {
			return typedWhy(hypervisor.Conflict, "start", "the VM's network is not active")
		}
	}
	if err := ops.StartDomain(ctx, name); err != nil {
		return err
	}
	hook(StepStarted)
	return nil
}

var _ = errors.New
