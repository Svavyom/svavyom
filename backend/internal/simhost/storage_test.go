package simhost_test

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"example.invalid/dedicatedcloud/backend/internal/backupstore"
	"example.invalid/dedicatedcloud/backend/internal/hypervisor"
	"example.invalid/dedicatedcloud/backend/internal/provision"
	"example.invalid/dedicatedcloud/backend/internal/simhost"
)

func (r *rig) rootName() string { return provision.RootVolumeName(r.spec.UUID) }

func (r *rig) stopped(t *testing.T) {
	t.Helper()
	if err := r.provision(nil); err != nil {
		t.Fatal(err)
	}
}

func (r *rig) store(t *testing.T) *backupstore.Store {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "backups")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	real, _ := filepath.EvalSymlinks(dir)
	s, err := backupstore.Open(real)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// qualify marks the rig's image real-host qualified and reloads the catalog.
func (r *rig) qualify(t *testing.T) {
	t.Helper()
	if _, err := provision.SetState(provision.DevPolicy(), r.cfg.CatalogDir, r.image.ID, provision.StateQualified, "qr-test"); err != nil {
		t.Fatal(err)
	}
	cat, err := provision.LoadTrustedCatalog(provision.DevPolicy(), r.cfg.CatalogDir)
	if err != nil {
		t.Fatal(err)
	}
	r.cat = cat
}

func (r *rig) vol(name string) simhost.Volume { return r.host.Load().Volumes[r.cfg.Pool+"/"+name] }

// ---- resize ------------------------------------------------------------------------------------------------------------------

func TestResizeGrowsOnlyAndOnlyWhenSafe(t *testing.T) {
	ctx := context.Background()
	r := newRig(t)
	r.stopped(t)
	if err := provision.Resize(ctx, r.counter, r.cfg, "web-1", 30, nil); err != nil {
		t.Fatal(err)
	}
	if v := r.vol(r.rootName()); v.Capacity != 30<<30 {
		t.Fatalf("capacity %d", v.Capacity)
	}
	if err := provision.Resize(ctx, r.counter, r.cfg, "web-1", 30, nil); err != nil {
		t.Fatalf("the same size is a no-op: %v", err)
	}
	for name, tc := range map[string]struct {
		gib  int
		want hypervisor.Category
	}{"shrink": {10, hypervisor.Validation}, "zero": {0, hypervisor.Validation}, "over the ceiling": {provision.MaxDiskGiB + 1, hypervisor.Validation}} {
		if err := provision.Resize(ctx, r.counter, r.cfg, "web-1", tc.gib, nil); cat(err) != tc.want {
			t.Errorf("%s: %v", name, err)
		}
	}
	if r.vol(r.rootName()).Capacity != 30<<30 {
		t.Fatal("a refused resize changed the volume")
	}
	// pool too full for the growth
	if err := r.host.SetPoolAvailable(100 << 20); err != nil {
		t.Fatal(err)
	}
	if err := provision.Resize(ctx, r.counter, r.cfg, "web-1", 100, nil); cat(err) != hypervisor.Conflict {
		t.Fatalf("a pool without room: %v", err)
	}
	_ = r.host.SetPoolAvailable(0)
	// a snapshot blocks it (qcow2 cannot resize an image that holds snapshots)
	if err := provision.Snapshot(ctx, r.counter, "web-1", "snap-0123456789ab", nil); err != nil {
		t.Fatal(err)
	}
	if err := provision.Resize(ctx, r.counter, r.cfg, "web-1", 40, nil); cat(err) != hypervisor.Conflict {
		t.Fatalf("resize with a snapshot: %v", err)
	}
	// running and foreign VMs
	_ = provision.DeleteSnapshot(ctx, r.counter, "web-1", "snap-0123456789ab", nil)
	if err := provision.Start(ctx, r.counter, "web-1", nil); err != nil {
		t.Fatal(err)
	}
	if err := provision.Resize(ctx, r.counter, r.cfg, "web-1", 40, nil); cat(err) != hypervisor.Conflict {
		t.Fatalf("a running VM: %v", err)
	}
	_ = r.host.Add("foreign", simhost.Domain{UUID: "9a9a9a9a-2222-4333-8444-5555555555ab", VCPUs: 1, MemoryMiB: 64})
	if err := provision.Resize(ctx, r.counter, r.cfg, "foreign", 40, nil); cat(err) != hypervisor.Prohibited {
		t.Fatalf("a foreign domain: %v", err)
	}
}

// ---- snapshots ---------------------------------------------------------------------------------------------------------------

func TestSnapshotRestoreDeleteAndTheirLimits(t *testing.T) {
	ctx := context.Background()
	r := newRig(t)
	r.stopped(t)
	_ = r.host.SetPayload(r.cfg.Pool, r.rootName(), "state-A")
	const a, b = "snap-aaaaaaaaaaaa", "snap-bbbbbbbbbbbb"
	if err := provision.Snapshot(ctx, r.counter, "web-1", a, nil); err != nil {
		t.Fatal(err)
	}
	if err := provision.Snapshot(ctx, r.counter, "web-1", a, nil); err != nil {
		t.Fatalf("the same snapshot twice is one snapshot: %v", err)
	}
	if n := len(r.host.Load().Snapshots["web-1"]); n != 1 {
		t.Fatalf("%d snapshots", n)
	}
	_ = r.host.SetPayload(r.cfg.Pool, r.rootName(), "state-B")
	if err := provision.RestoreSnapshot(ctx, r.counter, "web-1", a, nil); err != nil {
		t.Fatal(err)
	}
	if got := r.host.Payload(r.cfg.Pool, r.rootName()); got != "state-A" {
		t.Fatalf("restored payload %q", got)
	}
	if err := provision.RestoreSnapshot(ctx, r.counter, "web-1", b, nil); cat(err) != hypervisor.NotFound {
		t.Fatalf("an unknown snapshot: %v", err)
	}
	// a snapshot somebody else made is never restored or deleted, and blocks new ones
	_ = r.host.AddSnapshot("web-1", simhost.Snapshot{Name: "svs-" + b, Description: "somebody else's", Volume: r.cfg.Pool + "/" + r.rootName()})
	if err := provision.RestoreSnapshot(ctx, r.counter, "web-1", b, nil); cat(err) != hypervisor.NotFound {
		t.Fatalf("a foreign snapshot with our name pattern: %v", err)
	}
	if err := provision.DeleteSnapshot(ctx, r.counter, "web-1", b, nil); err != nil || len(r.host.Load().Snapshots["web-1"]) != 2 {
		t.Fatalf("a foreign snapshot must survive a delete of its id: %v", err)
	}
	if err := provision.Snapshot(ctx, r.counter, "web-1", "snap-cccccccccccc", nil); cat(err) != hypervisor.Conflict {
		t.Fatalf("a foreign snapshot blocks new ones: %v", err)
	}
	st := r.host.Load()
	st.Snapshots["web-1"] = st.Snapshots["web-1"][:1]
	_ = r.host.Save(st)
	if err := provision.DeleteSnapshot(ctx, r.counter, "web-1", a, nil); err != nil {
		t.Fatal(err)
	}
	if err := provision.DeleteSnapshot(ctx, r.counter, "web-1", a, nil); err != nil {
		t.Fatalf("deleting an absent snapshot is a no-op: %v", err)
	}
	// the per-VM limit
	for i := 0; i < provision.MaxSnapshots; i++ {
		id := "snap-" + strings.Repeat(string("0123456789ab"[i]), 12)
		if err := provision.Snapshot(ctx, r.counter, "web-1", id, nil); err != nil {
			t.Fatalf("%d: %v", i, err)
		}
	}
	if err := provision.Snapshot(ctx, r.counter, "web-1", "snap-999999999999", nil); cat(err) != hypervisor.Conflict {
		t.Fatalf("over the limit: %v", err)
	}
	for _, bad := range []string{"", "snap-xyz", "svs-snap-aaaaaaaaaaaa", "snap-AAAAAAAAAAAA", "../x"} {
		if err := provision.Snapshot(ctx, r.counter, "web-1", bad, nil); cat(err) != hypervisor.Validation {
			t.Errorf("id %q: %v", bad, err)
		}
	}
	// running VMs are neither snapshotted nor restored
	_ = provision.Start(ctx, r.counter, "web-1", nil)
	for name, err := range map[string]error{"snapshot": provision.Snapshot(ctx, r.counter, "web-1", "snap-dddddddddddd", nil), "restore": provision.RestoreSnapshot(ctx, r.counter, "web-1", a, nil)} {
		if cat(err) != hypervisor.Conflict {
			t.Errorf("%s of a running VM: %v", name, err)
		}
	}
}

// ---- backup and restore ------------------------------------------------------------------------------------------------------

const bk1 = "bk-0123456789abcdef"

func TestBackupDeleteRestoreRoundTrip(t *testing.T) {
	ctx := context.Background()
	r := newRig(t)
	st := r.store(t)
	r.stopped(t)
	// a disk size that is NOT in the create-time choice lists: restore must work for any grown VM (regression: the seed builder used the create lists)
	if err := provision.Resize(ctx, r.counter, r.cfg, "web-1", 30, nil); err != nil {
		t.Fatal(err)
	}
	_ = r.host.SetPayload(r.cfg.Pool, r.rootName(), "precious-data")
	if err := provision.Backup(ctx, r.counter, r.cfg, r.cat, st, "web-1", bk1, provision.BackupInput{Version: "test"}, nil); err != nil {
		t.Fatal(err)
	}
	if err := provision.Backup(ctx, r.counter, r.cfg, r.cat, st, "web-1", bk1, provision.BackupInput{}, nil); err != nil {
		t.Fatalf("a finished backup run again is a no-op: %v", err)
	}
	b, err := st.Verify(bk1)
	if err != nil || b.Manifest.VM.Name != "web-1" || b.Manifest.VM.DiskGiB != 30 || b.Manifest.VM.ImageID != "debian-13" || b.Manifest.VM.LoginUser != "debian" {
		t.Fatalf("%+v %v", b, err)
	}
	if strings.Contains(string(mustRead(t, filepath.Join(st.Dir(), bk1, backupstore.ManifestFile))), "ssh-ed25519") {
		t.Fatal("the manifest carries an SSH key")
	}
	if err := provision.Delete(ctx, r.counter, r.cfg, "web-1", nil); err != nil {
		t.Fatal(err)
	}
	if len(r.host.Load().Volumes) != 0 {
		t.Fatal("delete left volumes")
	}
	// restore to a NEW identity
	nr := provision.RestoreSpec{Name: "web-2", UUID: "2b2b2b2b-3333-4444-8555-6666666666cd", Fingerprint: strings.Repeat("cd", 32), SSHPublicKey: r.spec.SSHPublicKey}
	var steps []string
	if err := provision.Restore(ctx, r.counter, r.cfg, r.cat, st, bk1, nr, r.scratch, func(s string) { steps = append(steps, s) }); err != nil {
		t.Fatal(err)
	}
	d := r.host.Load().Domains["web-2"]
	if d.Running || !d.Managed || d.UUID != nr.UUID || d.VCPUs != 2 || d.MemoryMiB != 1024 {
		t.Fatalf("%+v", d)
	}
	if got := r.host.Payload(r.cfg.Pool, provision.RootVolumeName(nr.UUID)); got != "precious-data" {
		t.Fatalf("restored payload %q", got)
	}
	if v := r.vol(provision.RootVolumeName(nr.UUID)); v.Capacity != 30<<30 || !strings.HasSuffix(v.Backing, r.cat.Images[0].File) {
		t.Fatalf("restored volume %+v", v)
	}
	if !contains(steps, provision.StepRestoreUploaded) || !contains(steps, provision.StepDomainDefined) {
		t.Fatalf("steps %v", steps)
	}
	if err := provision.Restore(ctx, r.counter, r.cfg, r.cat, st, bk1, nr, r.scratch, nil); err != nil {
		t.Fatalf("restore run again after it finished is a no-op: %v", err)
	}
	if n := len(r.host.Load().Domains); n != 1 {
		t.Fatalf("%d domains", n)
	}
	// a second restore under another name works too; the same name with another identity collides
	nr2 := nr
	nr2.UUID, nr2.Fingerprint = "3c3c3c3c-3333-4444-8555-6666666666ce", strings.Repeat("ce", 32)
	if err := provision.Restore(ctx, r.counter, r.cfg, r.cat, st, bk1, nr2, r.scratch, nil); cat(err) != hypervisor.Conflict {
		t.Fatalf("a name that is taken by another VM: %v", err)
	}
	if len(r.host.Load().Domains) != 1 {
		t.Fatal("the collision created something")
	}
	// the base image and the backup are untouched by a restore
	if _, err := st.Verify(bk1); err != nil {
		t.Fatalf("restoring damaged the backup: %v", err)
	}
}

func contains(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

func mustRead(t *testing.T, p string) []byte {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestBackupAndRestoreRefusals(t *testing.T) {
	ctx := context.Background()
	r := newRig(t)
	st := r.store(t)
	r.stopped(t)
	// running, snapshots, foreign, bad ids, no store
	if err := provision.Backup(ctx, r.counter, r.cfg, r.cat, nil, "web-1", bk1, provision.BackupInput{}, nil); cat(err) != hypervisor.Validation {
		t.Errorf("no store: %v", err)
	}
	for _, bad := range []string{"", "bk-1", "../x", "bk-0123456789abcdeg"} {
		if err := provision.Backup(ctx, r.counter, r.cfg, r.cat, st, "web-1", bad, provision.BackupInput{}, nil); cat(err) != hypervisor.Validation {
			t.Errorf("id %q: %v", bad, err)
		}
	}
	_ = provision.Snapshot(ctx, r.counter, "web-1", "snap-aaaaaaaaaaaa", nil)
	if err := provision.Backup(ctx, r.counter, r.cfg, r.cat, st, "web-1", bk1, provision.BackupInput{}, nil); cat(err) != hypervisor.Conflict {
		t.Errorf("a VM with snapshots: %v", err)
	}
	_ = provision.DeleteSnapshot(ctx, r.counter, "web-1", "snap-aaaaaaaaaaaa", nil)
	_ = provision.Start(ctx, r.counter, "web-1", nil)
	if err := provision.Backup(ctx, r.counter, r.cfg, r.cat, st, "web-1", bk1, provision.BackupInput{}, nil); cat(err) != hypervisor.Conflict {
		t.Errorf("a running VM: %v", err)
	}
	_ = provision.ForceOff(ctx, r.counter, "web-1", nil)
	_ = r.host.Add("foreign", simhost.Domain{UUID: "9a9a9a9a-2222-4333-8444-5555555555ab", VCPUs: 1, MemoryMiB: 64})
	if err := provision.Backup(ctx, r.counter, r.cfg, r.cat, st, "foreign", bk1, provision.BackupInput{}, nil); cat(err) != hypervisor.Prohibited {
		t.Errorf("a foreign domain: %v", err)
	}
	if l, _ := st.List(); len(l) != 0 {
		t.Fatalf("a refused backup left %v", l)
	}
	// a download that fails halfway leaves no visible backup
	if err := provision.Backup(ctx, r.counter, r.cfg, r.cat, st, "web-1", bk1, provision.BackupInput{}, nil); err != nil {
		t.Fatal(err)
	}
	nr := provision.RestoreSpec{Name: "web-2", UUID: "2b2b2b2b-3333-4444-8555-6666666666cd", Fingerprint: strings.Repeat("cd", 32), SSHPublicKey: r.spec.SSHPublicKey}
	root := filepath.Join(st.Dir(), bk1, backupstore.RootFile)
	for name, damage := range map[string]func(){
		"checksum mismatch": func() { b := mustRead(t, root); b[len(b)-1] ^= 0xff; _ = os.WriteFile(root, b, 0o600) },
		"truncated":         func() { _ = os.Truncate(root, 50) },
		"deleted":           func() { _ = os.Remove(root) },
	} {
		backup := mustRead(t, root)
		damage()
		if err := provision.Restore(ctx, r.counter, r.cfg, r.cat, st, bk1, nr, r.scratch, nil); cat(err) != hypervisor.Validation {
			t.Errorf("%s: %v", name, err)
		}
		if _, ok := r.host.Load().Domains["web-2"]; ok {
			t.Fatalf("%s: a damaged backup created a VM", name)
		}
		_ = os.WriteFile(root, backup, 0o600)
	}
	if err := provision.Restore(ctx, r.counter, r.cfg, r.cat, st, "bk-ffffffffffffffff", nr, r.scratch, nil); cat(err) != hypervisor.NotFound {
		t.Errorf("unknown backup: %v", err)
	}
	// the manifest points at an image that is no longer there
	if _, err := provision.SetState(provision.DevPolicy(), r.cfg.CatalogDir, r.image.ID, provision.StateDisabled, ""); err != nil {
		t.Fatal(err)
	}
	cat2, _ := provision.LoadTrustedCatalog(provision.DevPolicy(), r.cfg.CatalogDir)
	if err := provision.Restore(ctx, r.counter, r.cfg, cat2, st, bk1, nr, r.scratch, nil); cat(err) != hypervisor.Conflict {
		t.Errorf("a disabled base image: %v", err)
	}
	// a backup whose overlay belongs to ANOTHER base image is refused
	if err := os.WriteFile(root, simhost.Overlay("/elsewhere/other.qcow2", 20<<30, "x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := provision.Restore(ctx, r.counter, r.cfg, r.cat, st, bk1, nr, r.scratch, nil); cat(err) != hypervisor.Validation {
		t.Errorf("a swapped overlay: %v", err)
	}
}

func TestBackupWithoutSpaceLeavesNothing(t *testing.T) {
	ctx := context.Background()
	r := newRig(t)
	st := r.store(t)
	r.stopped(t)
	st2, _ := backupstore.Open(st.Dir())
	_ = st2
	// the simulated volume reports a huge allocation, which the (real) filesystem of the store cannot hold
	state := r.host.Load()
	v := state.Volumes[r.cfg.Pool+"/"+r.rootName()]
	v.Data = append(v.Data, bytes.Repeat([]byte("x"), 10)...)
	state.Volumes[r.cfg.Pool+"/"+r.rootName()] = v
	_ = r.host.Save(state)
	free, _ := st.FreeBytes()
	_ = r.host.SetAllocation(r.cfg.Pool, r.rootName(), free+(1<<30))
	if err := provision.Backup(ctx, r.counter, r.cfg, r.cat, st, "web-1", bk1, provision.BackupInput{}, nil); cat(err) != hypervisor.Conflict {
		t.Fatalf("%v", err)
	}
	if ents, _ := os.ReadDir(st.Dir()); len(ents) != 0 {
		t.Fatalf("left %v", ents)
	}
}

// ---- reinstall ---------------------------------------------------------------------------------------------------------------

func TestReinstallReplacesTheDiskAndKeepsTheIdentity(t *testing.T) {
	ctx := context.Background()
	r := newRig(t)
	r.stopped(t)
	r.qualify(t)
	if err := provision.Resize(ctx, r.counter, r.cfg, "web-1", 30, nil); err != nil { // also a size outside the create lists
		t.Fatal(err)
	}
	_ = r.host.SetPayload(r.cfg.Pool, r.rootName(), "old-install")
	before := r.host.Load().Domains["web-1"]
	rs := provision.ReinstallSpec{ImageID: "debian-13", ImageSHA256: r.image.SHA256, SSHPublicKey: r.spec.SSHPublicKey, Rev: "0a1b2c3d"}
	var steps []string
	if err := provision.Reinstall(ctx, r.counter, r.cfg, r.cat, "web-1", rs, r.scratch, func(s string) { steps = append(steps, s) }); err != nil {
		t.Fatal(err)
	}
	after := r.host.Load()
	d := after.Domains["web-1"]
	if d.UUID != before.UUID || d.Fingerprint != before.Fingerprint || d.VCPUs != before.VCPUs || d.MemoryMiB != before.MemoryMiB || d.Running {
		t.Fatalf("identity changed: %+v -> %+v", before, d)
	}
	newRoot := provision.RootVolumeNameRev(r.spec.UUID, rs.Rev)
	if d.Root != newRoot || d.Seed != provision.SeedVolumeNameRev(r.spec.UUID, rs.Rev) {
		t.Fatalf("the domain still names %s / %s", d.Root, d.Seed)
	}
	if got := r.host.Payload(r.cfg.Pool, newRoot); strings.Contains(got, "old-install") {
		t.Fatalf("the new disk carries the old install: %q", got)
	}
	for k := range after.Volumes {
		if strings.HasSuffix(k, r.rootName()) || strings.HasSuffix(k, provision.SeedVolumeName(r.spec.UUID)) {
			t.Fatalf("the old volume %s survived", k)
		}
	}
	if len(after.Volumes) != 2 {
		t.Fatalf("%d volumes", len(after.Volumes))
	}
	if !contains(steps, provision.StepReinstallCommitted) || !contains(steps, provision.StepReinstallCleaned) {
		t.Fatalf("%v", steps)
	}
	if err := provision.Reinstall(ctx, r.counter, r.cfg, r.cat, "web-1", rs, r.scratch, nil); err != nil {
		t.Fatalf("a finished reinstall run again is a no-op: %v", err)
	}
	if len(r.host.Load().Volumes) != 2 {
		t.Fatal("the repeat created volumes")
	}
	// the VM still deletes cleanly, with its new pair
	if err := provision.Delete(ctx, r.counter, r.cfg, "web-1", nil); err != nil || len(r.host.Load().Volumes) != 0 {
		t.Fatalf("delete after reinstall: %v %d", err, len(r.host.Load().Volumes))
	}
}

func TestReinstallRefusals(t *testing.T) {
	ctx := context.Background()
	r := newRig(t)
	r.stopped(t)
	rs := provision.ReinstallSpec{ImageID: "debian-13", ImageSHA256: r.image.SHA256, SSHPublicKey: r.spec.SSHPublicKey, Rev: "0a1b2c3d"}
	if err := provision.Reinstall(ctx, r.counter, r.cfg, r.cat, "web-1", rs, r.scratch, nil); cat(err) != hypervisor.Conflict {
		t.Fatalf("an image that is only compatibility-declared: %v", err)
	}
	r.qualify(t)
	for name, tc := range map[string]struct {
		mut  func(*provision.ReinstallSpec)
		want hypervisor.Category
	}{
		"bad token":     {func(s *provision.ReinstallSpec) { s.Rev = "zz" }, hypervisor.Validation},
		"other digest":  {func(s *provision.ReinstallSpec) { s.ImageSHA256 = strings.Repeat("0", 64) }, hypervisor.Conflict},
		"unknown image": {func(s *provision.ReinstallSpec) { s.ImageID = "nope" }, hypervisor.Conflict},
		"bad key":       {func(s *provision.ReinstallSpec) { s.SSHPublicKey = "not a key" }, hypervisor.Validation},
	} {
		x := rs
		tc.mut(&x)
		if err := provision.Reinstall(ctx, r.counter, r.cfg, r.cat, "web-1", x, r.scratch, nil); cat(err) != tc.want {
			t.Errorf("%s: %v", name, err)
		}
	}
	if len(r.host.Load().Volumes) != 2 {
		t.Fatalf("a refused reinstall created volumes: %d", len(r.host.Load().Volumes))
	}
	_ = provision.Snapshot(ctx, r.counter, "web-1", "snap-aaaaaaaaaaaa", nil)
	if err := provision.Reinstall(ctx, r.counter, r.cfg, r.cat, "web-1", rs, r.scratch, nil); cat(err) != hypervisor.Conflict {
		t.Errorf("a VM with snapshots: %v", err)
	}
	_ = provision.DeleteSnapshot(ctx, r.counter, "web-1", "snap-aaaaaaaaaaaa", nil)
	_ = provision.Start(ctx, r.counter, "web-1", nil)
	if err := provision.Reinstall(ctx, r.counter, r.cfg, r.cat, "web-1", rs, r.scratch, nil); cat(err) != hypervisor.Conflict {
		t.Errorf("a running VM: %v", err)
	}
}

func TestReinstallResumesAfterACrashAtEveryStep(t *testing.T) {
	ctx := context.Background()
	for _, crash := range []string{provision.StepReinstallCommitted} {
		r := newRig(t)
		r.stopped(t)
		r.qualify(t)
		rs := provision.ReinstallSpec{ImageID: "debian-13", ImageSHA256: r.image.SHA256, SSHPublicKey: r.spec.SSHPublicKey, Rev: "0a1b2c3d"}
		func() {
			defer func() { _ = recover() }()
			_ = provision.Reinstall(ctx, r.counter, r.cfg, r.cat, "web-1", rs, r.scratch, func(s string) {
				if s == crash {
					panic("simulated process death")
				}
			})
		}()
		// after the commit, the old pair is still in the pool but the domain uses the new one
		if d := r.host.Load().Domains["web-1"]; d.Root != provision.RootVolumeNameRev(r.spec.UUID, rs.Rev) || len(r.host.Load().Volumes) != 4 {
			t.Fatalf("after the crash: %s, %d volumes", d.Root, len(r.host.Load().Volumes))
		}
		if err := provision.Reinstall(ctx, r.counter, r.cfg, r.cat, "web-1", rs, r.scratch, nil); err != nil {
			t.Fatalf("resume: %v", err)
		}
		if len(r.host.Load().Volumes) != 2 {
			t.Fatalf("the resume did not clean up: %d volumes", len(r.host.Load().Volumes))
		}
	}
	// a crash BEFORE the commit leaves the old disk in use; a retry reuses the half-built new volumes
	r := newRig(t)
	r.stopped(t)
	r.qualify(t)
	rs := provision.ReinstallSpec{ImageID: "debian-13", ImageSHA256: r.image.SHA256, SSHPublicKey: r.spec.SSHPublicKey, Rev: "0a1b2c3d"}
	failing := &failDefine{counting: r.counter}
	if err := provision.Reinstall(ctx, failing, r.cfg, r.cat, "web-1", rs, r.scratch, nil); err == nil {
		t.Fatal("the injected failure did not surface")
	}
	if d := r.host.Load().Domains["web-1"]; d.Root != r.rootName() {
		t.Fatalf("an uncommitted reinstall changed the domain: %s", d.Root)
	}
	if err := provision.Reinstall(ctx, r.counter, r.cfg, r.cat, "web-1", rs, r.scratch, nil); err != nil {
		t.Fatalf("retry: %v", err)
	}
	if len(r.host.Load().Volumes) != 2 {
		t.Fatalf("%d volumes", len(r.host.Load().Volumes))
	}
}

// failDefine fails the domain redefinition, as a process that died right before the commit.
type failDefine struct{ *counting }

func (f *failDefine) DefineDomain(context.Context, string) error {
	return hypervisor.NewError(hypervisor.Timeout, "define", "", "injected")
}

func TestDeleteSweepsLeftoversOfAnInterruptedReinstall(t *testing.T) {
	ctx := context.Background()
	r := newRig(t)
	r.stopped(t)
	// a half-built reinstall pair that never got committed, and a neighbour that is not ours
	_ = r.host.AddVolume(r.cfg.Pool, provision.RootVolumeNameRev(r.spec.UUID, "deadbeef"), simhost.Volume{Capacity: 20 << 30})
	_ = r.host.AddVolume(r.cfg.Pool, provision.SeedVolumeNameRev(r.spec.UUID, "deadbeef"), simhost.Volume{Capacity: provision.SeedCapacityBytes})
	_ = r.host.AddVolume(r.cfg.Pool, "svavyom-8a8a8a8a-2222-4333-8444-5555555555ab-root.qcow2", simhost.Volume{Capacity: 1})
	_ = r.host.AddVolume(r.cfg.Pool, "neighbour.qcow2", simhost.Volume{Capacity: 1})
	if err := provision.Delete(ctx, r.counter, r.cfg, "web-1", nil); err != nil {
		t.Fatal(err)
	}
	left := r.host.Load().Volumes
	if len(left) != 2 {
		t.Fatalf("expected exactly the two volumes that are not this VM's, left %v", left)
	}
	for k := range left {
		if !strings.HasSuffix(k, "neighbour.qcow2") && !strings.Contains(k, "8a8a8a8a") {
			t.Fatalf("an unexpected volume survived or was removed: %s", k)
		}
	}
}
