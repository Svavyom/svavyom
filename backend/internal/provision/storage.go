package provision

import (
	"context"
	"io"
	"os"
	"regexp"
	"time"

	"example.invalid/dedicatedcloud/backend/internal/backupstore"
	"example.invalid/dedicatedcloud/backend/internal/hypervisor"
)

// Step names reported by the storage operations (hook points and progress).
const (
	StepResized            = "resized"
	StepSnapshotted        = "snapshotted"
	StepReverted           = "reverted"
	StepSnapshotDeleted    = "snapshot-deleted"
	StepBackupWritten      = "backup-written"
	StepReinstallCommitted = "reinstall-committed"
	StepReinstallCleaned   = "reinstall-cleaned"
)

// MaxSnapshots is the most snapshots Svavyom keeps per VM (each one lives inside the root overlay and grows it).
const MaxSnapshots = 8

// poolReserve is the free space a pool must keep beyond a requested growth.
const poolReserve = 256 << 20

// SnapshotIDRE is the grammar of a snapshot id (server generated at submission).
var SnapshotIDRE = regexp.MustCompile(`^snap-[0-9a-f]{12}$`)

func snapshotName(id string) string { return "svs-" + id }

func snapshotDescription(uuid string) string { return "svavyom:" + uuid }

// stopped returns the proven-owned, STOPPED domain.
func stopped(ctx context.Context, ops HostOps, name, op string) (DomainInfo, error) {
	d, err := managed(ctx, ops, name, op)
	if err != nil {
		return DomainInfo{}, err
	}
	if d.Running {
		return DomainInfo{}, typedWhy(hypervisor.Conflict, op, "the VM is not stopped") // storage operations act on a Stopped VM only
	}
	return d, nil
}

// snapshotsOf returns this VM's own snapshots (provably: Svavyom's name prefix and a description naming exactly this UUID) and the
// number of snapshots that are not its own. Foreign snapshots are never touched, but their presence blocks operations that qcow2 or
// ownership make unsafe.
func snapshotsOf(ctx context.Context, ops HostOps, d DomainInfo, name string) (ours []SnapshotInfo, foreign int, err error) {
	all, err := ops.ListSnapshots(ctx, name)
	if err != nil {
		return nil, 0, err
	}
	for _, s := range all {
		if len(s.Name) == len("svs-snap-")+12 && SnapshotIDRE.MatchString(s.Name[4:]) && s.Name[:4] == "svs-" && s.Description == snapshotDescription(d.UUID) {
			ours = append(ours, s)
		} else {
			foreign++
		}
	}
	return ours, foreign, nil
}

// rootProof resolves the VM's current root volume and requires the stored definition to name exactly that file.
func rootProof(ctx context.Context, ops HostOps, cfg Config, d DomainInfo, op string) (VolumeInfo, VolumeSource, error) {
	if d.Root == "" {
		return VolumeInfo{}, VolumeSource{}, typedWhy(hypervisor.Conflict, op, "the definition names no root volume")
	}
	v, err := ops.LookupVolume(ctx, cfg.Pool, d.Root)
	if err != nil {
		return VolumeInfo{}, VolumeSource{}, err
	}
	src, err := ResolveVolumeSource(d.Root, v)
	if err != nil {
		return VolumeInfo{}, VolumeSource{}, typedWhy(hypervisor.Conflict, op, "the root volume is not provably Svavyom's")
	}
	if CheckDomainRootSource(d.XML, src) != nil {
		return VolumeInfo{}, VolumeSource{}, typedWhy(hypervisor.Conflict, op, "the definition does not name the root volume's file")
	}
	return v, src, nil
}

// Resize grows the root volume of a STOPPED, snapshot-free VM to newGiB. Growing is idempotent (already that size is success); shrinking is
// refused; the pool must have the growth plus a reserve free. The base image is never touched. It does not claim that the guest's partition or
// filesystem grew: that stays the guest administrator's step.
func Resize(ctx context.Context, ops HostOps, cfg Config, name string, newGiB int, hook Hook) error {
	if hook == nil {
		hook = func(string) {}
	}
	if newGiB < 1 || newGiB > MaxDiskGiB {
		return typed(hypervisor.Validation, "resize")
	}
	d, err := stopped(ctx, ops, name, "resize")
	if err != nil {
		return err
	}
	_, foreign, err := snapshotsOf(ctx, ops, d, name)
	if err != nil {
		return err
	}
	all, err := ops.ListSnapshots(ctx, name)
	if err != nil {
		return err
	}
	if len(all) > 0 || foreign > 0 {
		return typedWhy(hypervisor.Conflict, "resize", "the volume has snapshots") // qcow2 cannot resize an image that holds snapshots
	}
	v, _, err := rootProof(ctx, ops, cfg, d, "resize")
	if err != nil {
		return err
	}
	want := int64(newGiB) << 30
	switch {
	case v.CapacityBytes == want:
		return nil
	case want < v.CapacityBytes:
		return typed(hypervisor.Validation, "resize") // shrinking is not offered
	}
	st, err := ops.PoolStats(ctx, cfg.Pool)
	if err != nil {
		return err
	}
	if st.AvailableBytes < want-v.CapacityBytes+poolReserve {
		return typedWhy(hypervisor.Conflict, "resize", "the pool cannot take the growth") // the pool cannot take the growth
	}
	if err := ops.ResizeVolume(ctx, cfg.Pool, d.Root, want); err != nil {
		return err
	}
	hook(StepResized)
	after, err := ops.LookupVolume(ctx, cfg.Pool, d.Root)
	if err != nil {
		return err
	}
	if after.CapacityBytes != want {
		return typed(hypervisor.HostError, "resize")
	}
	return nil
}

// Snapshot takes a stopped-VM snapshot with the server-generated id. An existing snapshot of that id is success; the per-VM limit and any
// foreign snapshot are conflicts.
func Snapshot(ctx context.Context, ops HostOps, name, id string, hook Hook) error {
	if hook == nil {
		hook = func(string) {}
	}
	if !SnapshotIDRE.MatchString(id) {
		return typed(hypervisor.Validation, "snapshot")
	}
	d, err := stopped(ctx, ops, name, "snapshot")
	if err != nil {
		return err
	}
	ours, foreign, err := snapshotsOf(ctx, ops, d, name)
	if err != nil {
		return err
	}
	for _, s := range ours {
		if s.Name == snapshotName(id) {
			return nil
		}
	}
	if foreign > 0 || len(ours) >= MaxSnapshots {
		return typed(hypervisor.Conflict, "snapshot")
	}
	if err := ops.CreateSnapshot(ctx, name, snapshotName(id), snapshotDescription(d.UUID)); err != nil {
		return err
	}
	hook(StepSnapshotted)
	after, _, err := snapshotsOf(ctx, ops, d, name)
	if err != nil {
		return err
	}
	for _, s := range after {
		if s.Name == snapshotName(id) {
			return nil
		}
	}
	return typed(hypervisor.HostError, "snapshot")
}

// RestoreSnapshot returns a STOPPED VM to one of its own snapshots. Restoring replaces the disk content and, with it, the definition libvirt stored in
// the snapshot, so the VM's recorded size and devices return to what they were then.
func RestoreSnapshot(ctx context.Context, ops HostOps, name, id string, hook Hook) error {
	if hook == nil {
		hook = func(string) {}
	}
	if !SnapshotIDRE.MatchString(id) {
		return typed(hypervisor.Validation, "restore_snapshot")
	}
	d, err := stopped(ctx, ops, name, "restore_snapshot")
	if err != nil {
		return err
	}
	ours, _, err := snapshotsOf(ctx, ops, d, name)
	if err != nil {
		return err
	}
	found := false
	for _, s := range ours {
		found = found || s.Name == snapshotName(id)
	}
	if !found {
		return typed(hypervisor.NotFound, "restore_snapshot") // missing, or somebody else's: never reverted
	}
	if err := ops.RevertSnapshot(ctx, name, snapshotName(id)); err != nil {
		return err
	}
	hook(StepReverted)
	after, err := ops.LookupDomain(ctx, name)
	if err != nil {
		return err
	}
	if !after.Managed || after.UUID != d.UUID || after.Running {
		return typed(hypervisor.HostError, "restore_snapshot")
	}
	return nil
}

// DeleteSnapshot removes one of the VM's own snapshots. Absent is success (a retry after an unknown outcome); somebody else's is never deleted.
func DeleteSnapshot(ctx context.Context, ops HostOps, name, id string, hook Hook) error {
	if hook == nil {
		hook = func(string) {}
	}
	if !SnapshotIDRE.MatchString(id) {
		return typed(hypervisor.Validation, "delete_snapshot")
	}
	d, err := stopped(ctx, ops, name, "delete_snapshot")
	if err != nil {
		return err
	}
	ours, _, err := snapshotsOf(ctx, ops, d, name)
	if err != nil {
		return err
	}
	for _, s := range ours {
		if s.Name == snapshotName(id) {
			if err := ops.DeleteSnapshot(ctx, name, s.Name); err != nil {
				return err
			}
			hook(StepSnapshotDeleted)
			return nil
		}
	}
	return nil
}

// BackupInput is what a backup records about the tool that made it.
type BackupInput struct {
	Version string // product version string
	Now     func() time.Time
}

// Backup copies the root overlay of a STOPPED, snapshot-free VM into the backup store as backup id. The copy is verified as a root overlay of the
// VM's own base image and virtual size before it is committed; a backup that already exists intact is success; anything that fails leaves no
// visible backup.
func Backup(ctx context.Context, ops HostOps, cfg Config, cat *Catalog, store *backupstore.Store, name, id string, in BackupInput, hook Hook) error {
	if hook == nil {
		hook = func(string) {}
	}
	if !backupstore.ValidID(id) || store == nil {
		return typed(hypervisor.Validation, "backup")
	}
	d, err := stopped(ctx, ops, name, "backup")
	if err != nil {
		return err
	}
	if d.Media == MediaISO {
		return typedWhy(hypervisor.Conflict, "backup", "a VM installed from media has no catalog image to restore onto") // backups of such VMs are not offered
	}
	all, err := ops.ListSnapshots(ctx, name)
	if err != nil {
		return err
	}
	if len(all) > 0 {
		return typed(hypervisor.Conflict, "backup") // a copy of an overlay that holds snapshots carries them along, hidden
	}
	if b, verr := store.Verify(id); verr == nil && b.Manifest.VM.UUID == d.UUID {
		return nil // this very backup already finished
	}
	im, ok := cat.Get(d.ImageID)
	if !ok {
		return typed(hypervisor.Conflict, "backup")
	}
	backing, err := cat.Backing(im)
	if err != nil {
		return typed(hypervisor.Conflict, "backup")
	}
	v, _, err := rootProof(ctx, ops, cfg, d, "backup")
	if err != nil {
		return err
	}
	if v.CapacityBytes%(1<<30) != 0 || v.CapacityBytes/(1<<30) < 1 || v.CapacityBytes/(1<<30) > MaxDiskGiB || v.BackingPath != backing.Path {
		return typed(hypervisor.Conflict, "backup")
	}
	diskGiB := int(v.CapacityBytes >> 30)
	need := v.AllocationBytes
	if need <= 0 {
		need = 1 << 30
	}
	w, err := store.Begin(id, need)
	switch err {
	case nil:
	case backupstore.ErrSpace:
		return typed(hypervisor.Conflict, "backup")
	case backupstore.ErrExists:
		return typed(hypervisor.Conflict, "backup") // an id taken by a backup of something else
	default:
		return typed(hypervisor.Unavailable, "backup")
	}
	if _, derr := ops.DownloadVolume(ctx, cfg.Pool, d.Root, w); derr != nil {
		w.Abort()
		return derr
	}
	if cerr := w.Check(func(r io.ReaderAt, size int64) error {
		_, e := CheckOverlay(r, size, backing, diskGiB)
		return e
	}); cerr != nil {
		w.Abort()
		return typed(hypervisor.HostError, "backup")
	}
	now := time.Now
	if in.Now != nil {
		now = in.Now
	}
	tool := in.Version
	if tool == "" {
		tool = "svavyom"
	}
	vmNetwork := cfg.Network
	if pd, perr := ParseDomain(d.XML); perr == nil && pd.Network != "" {
		vmNetwork = pd.Network
	}
	if _, err := w.Commit(backupstore.Manifest{CreatedAt: now().UTC().Format(time.RFC3339), Tool: tool,
		VM:   backupstore.VM{Name: name, UUID: d.UUID, Fingerprint: d.Fingerprint, ImageID: im.ID, ImageSHA256: im.SHA256, LoginUser: im.LoginUser, VCPUs: d.VCPUs, MemoryMiB: d.MemoryMiB, DiskGiB: diskGiB, Network: vmNetwork},
		Root: backupstore.Root{VirtualSizeBytes: v.CapacityBytes}}); err != nil {
		return typed(hypervisor.HostError, "backup")
	}
	hook(StepBackupWritten)
	return nil
}

// RestoreSpec is the identity and access a restore creates. Everything else comes from the backup.
type RestoreSpec struct {
	Name         string
	UUID         string
	Fingerprint  string
	SSHPublicKey string // normalised
}

// Restore creates a NEW VM from a verified backup: a new identity, a new root overlay of the backup's base image into which the backed-up content is
// uploaded, a new seed with the supplied key, and a stopped domain. It refuses a damaged backup, an image that is no longer in the catalog or
// usable, an overlay that does not belong to that image, and a name that is taken (the ordinary Provision conflict). It can be run again after any
// interruption.
func Restore(ctx context.Context, ops HostOps, cfg Config, cat *Catalog, store *backupstore.Store, backupID string, r RestoreSpec, scratchDir string, hook Hook) error {
	if store == nil || !backupstore.ValidID(backupID) {
		return typed(hypervisor.Validation, "restore")
	}
	b, err := store.Verify(backupID)
	switch err {
	case nil:
	case backupstore.ErrNotFound:
		return typed(hypervisor.NotFound, "restore")
	default:
		return typed(hypervisor.Validation, "restore") // damaged or incomplete: never restored
	}
	m := b.Manifest
	im, err := cat.Usable(m.VM.ImageID)
	if err != nil || im.SHA256 != m.VM.ImageSHA256 {
		return typed(hypervisor.Conflict, "restore")
	}
	backing, err := cat.Backing(im)
	if err != nil {
		return typed(hypervisor.Conflict, "restore")
	}
	spec := Spec{Name: r.Name, UUID: r.UUID, Fingerprint: r.Fingerprint, VCPUs: m.VM.VCPUs, MemoryMiB: m.VM.MemoryMiB, ImageID: im.ID, ImageSHA256: im.SHA256,
		DiskGiB: m.VM.DiskGiB, SSHPublicKey: r.SSHPublicKey, Network: m.VM.Network}
	if spec.ValidateExisting() != nil {
		return typed(hypervisor.Validation, "restore")
	}
	f, err := b.OpenRoot()
	if err != nil {
		return typed(hypervisor.Validation, "restore")
	}
	fi, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return typed(hypervisor.Validation, "restore")
	}
	if _, oerr := CheckOverlay(f, fi.Size(), backing, m.VM.DiskGiB); oerr != nil {
		_ = f.Close()
		return typed(hypervisor.Validation, "restore")
	}
	_ = f.Close()
	opts := provisionOpts{validate: Spec.ValidateExisting, render: DomainXMLExisting, rootContent: func() (io.ReadCloser, int64, error) {
		rf, err := os.Open(b.RootPath()) // #nosec G304 -- inside the validated store, fixed name
		if err != nil {
			return nil, 0, err
		}
		return rf, fi.Size(), nil
	}}
	return provisionAs(ctx, ops, cfg, cat, spec, scratchDir, hook, opts)
}

// ReinstallSpec is what a reinstall needs besides the VM itself.
type ReinstallSpec struct {
	ImageID      string
	ImageSHA256  string
	SSHPublicKey string // normalised
	Rev          string // server-generated revision token naming the new volumes
}

// Reinstall replaces the root disk of a STOPPED, snapshot-free VM with a fresh overlay of a REAL-HOST-QUALIFIED image, keeping the VM's identity,
// size, network and MAC. The new root and seed are built next to the old ones under the revision token; the stored domain definition is replaced
// in one step (the commit point); only then are the old volumes removed. An interruption before the commit leaves the old disk in use and the new
// volumes to be reused by a retry (same token); after it, a retry finishes the cleanup. Base images are never touched.
func Reinstall(ctx context.Context, ops HostOps, cfg Config, cat *Catalog, name string, rs ReinstallSpec, scratchDir string, hook Hook) error {
	if hook == nil {
		hook = func(string) {}
	}
	if !RevRE.MatchString(rs.Rev) || cfg.Validate() != nil {
		return typed(hypervisor.Validation, "reinstall")
	}
	d, err := stopped(ctx, ops, name, "reinstall")
	if err != nil {
		return err
	}
	if d.Media == MediaISO {
		return typedWhy(hypervisor.Conflict, "reinstall", "a VM installed from media has no image to reinstall from")
	}
	if len(d.Data) > 0 {
		return typedWhy(hypervisor.Conflict, "reinstall", "detach the VM's data volumes first") // the new definition would silently drop them
	}
	all, err := ops.ListSnapshots(ctx, name)
	if err != nil {
		return err
	}
	if len(all) > 0 {
		return typed(hypervisor.Conflict, "reinstall") // the snapshots belong to the disk that is being replaced
	}
	im, err := cat.Usable(rs.ImageID)
	if err != nil || im.State != StateQualified || im.SHA256 != rs.ImageSHA256 {
		return typed(hypervisor.Conflict, "reinstall") // only an image a real-host run qualified is offered for a reinstall
	}
	backing, err := cat.Backing(im)
	if err != nil {
		return typed(hypervisor.Conflict, "reinstall")
	}
	newRoot, newSeed := RootVolumeNameRev(d.UUID, rs.Rev), SeedVolumeNameRev(d.UUID, rs.Rev)
	committed := d.Root == newRoot && d.Seed == newSeed
	if !committed && d.Root != RootVolumeName(d.UUID) && !isRev(d.UUID, d.Root, "root") {
		return typed(hypervisor.Conflict, "reinstall")
	}
	if !committed {
		old, _, err := rootProof(ctx, ops, cfg, d, "reinstall")
		if err != nil {
			return err
		}
		if old.CapacityBytes%(1<<30) != 0 {
			return typed(hypervisor.Conflict, "reinstall")
		}
		diskGiB := int(old.CapacityBytes >> 30)
		if diskGiB < im.MinDiskGiB {
			return typed(hypervisor.Conflict, "reinstall")
		}
		pd, perr := ParseDomain(d.XML)
		if perr != nil || pd.Network == "" {
			return typed(hypervisor.Conflict, "reinstall")
		}
		spec := Spec{Name: name, UUID: d.UUID, Fingerprint: d.Fingerprint, VCPUs: d.VCPUs, MemoryMiB: d.MemoryMiB, ImageID: im.ID, ImageSHA256: im.SHA256,
			DiskGiB: diskGiB, SSHPublicKey: rs.SSHPublicKey, Network: pd.Network}
		if spec.ValidateExisting() != nil || d.Fingerprint == "" {
			return typed(hypervisor.Validation, "reinstall")
		}
		want := old.CapacityBytes
		switch v, err := ops.LookupVolume(ctx, cfg.Pool, newRoot); {
		case err == nil:
			if v.CapacityBytes != want || v.BackingPath != backing.Path {
				return typed(hypervisor.Conflict, "reinstall")
			}
		case isNotFound(err):
			if err := ops.CreateRootVolume(ctx, cfg.Pool, newRoot, want, backing.Path); err != nil {
				return err
			}
		default:
			return err
		}
		switch v, err := ops.LookupVolume(ctx, cfg.Pool, newSeed); {
		case err == nil:
			if v.CapacityBytes != SeedCapacityBytes {
				return typed(hypervisor.Conflict, "reinstall")
			}
		case isNotFound(err):
			if err := ops.CreateSeedVolume(ctx, cfg.Pool, newSeed, SeedCapacityBytes); err != nil {
				return err
			}
		default:
			return err
		}
		iso, berr := BuildSeed(spec, scratchDir)
		if berr != nil {
			return typed(hypervisor.HostError, "reinstall")
		}
		if err := ops.UploadSeed(ctx, cfg.Pool, newSeed, iso); err != nil {
			return err
		}
		rootSrc, err := resolveVolume(ctx, ops, cfg, newRoot)
		if err != nil {
			return err
		}
		seedSrc, err := resolveVolume(ctx, ops, cfg, newSeed)
		if err != nil {
			return err
		}
		xml, err := DomainXMLExisting(cfg, spec, backing, DiskSources{Root: rootSrc, Seed: seedSrc})
		if err != nil {
			return typed(hypervisor.Validation, "reinstall")
		}
		if err := ops.DefineDomain(ctx, xml); err != nil { // the commit point: the definition names the new disks from now on
			return err
		}
		hook(StepReinstallCommitted)
	}
	return sweepVolumes(ctx, ops, cfg, name, hook)
}

func isRev(uuid, name, role string) bool {
	u, r, rev, ok := ParseVolumeName(name)
	return ok && u == uuid && r == role && rev != ""
}

// sweepVolumes removes, from the pool, every volume named for this VM's UUID that the domain's CURRENT definition does not use: the old disks after a
// reinstall, or half-built new ones after an interrupted attempt. The domain definition is re-read first, and a volume is removed only if its name
// parses as a Svavyom volume of exactly this UUID.
func sweepVolumes(ctx context.Context, ops HostOps, cfg Config, name string, hook Hook) error {
	d, err := ops.LookupDomain(ctx, name)
	if err != nil {
		return err
	}
	if !d.Managed || !uuidRE.MatchString(d.UUID) || d.Root == "" || d.Seed == "" {
		return typed(hypervisor.Conflict, "reinstall")
	}
	names, err := ops.ListVolumes(ctx, cfg.Pool)
	if err != nil {
		return err
	}
	for _, n := range names {
		u, _, _, ok := ParseVolumeName(n)
		if !ok || u != d.UUID || n == d.Root || n == d.Seed {
			continue
		}
		if err := ops.DeleteVolume(ctx, cfg.Pool, n); err != nil && !isNotFound(err) {
			return err
		}
	}
	hook(StepReinstallCleaned)
	return nil
}
