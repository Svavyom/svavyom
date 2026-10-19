package mutagent

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"example.invalid/dedicatedcloud/backend/internal/hypervisor"
	"example.invalid/dedicatedcloud/backend/internal/provision"
)

// withBackups gives the rig a backup directory (owner-only, outside the catalog and the state directory), as the operator's configuration would.
func (r *rig) withBackups() string {
	r.t.Helper()
	dir, err := os.MkdirTemp("", "bk")
	if err != nil {
		r.t.Fatal(err)
	}
	r.t.Cleanup(func() { _ = os.RemoveAll(dir) })
	real, _ := filepath.EvalSymlinks(dir)
	cfg := r.cfg
	cfg.BackupDir = real
	b, _ := json.Marshal(cfg)
	if err := os.WriteFile(r.cfgPath, b, 0o600); err != nil {
		r.t.Fatal(err)
	}
	r.cfg = cfg
	return real
}

func (r *rig) qualify() {
	r.t.Helper()
	if _, err := provision.SetState(provision.DevPolicy(), r.cfg.CatalogDir, "debian-13", provision.StateQualified, "qr-test"); err != nil {
		r.t.Fatal(err)
	}
}

const (
	snapA = "snap-0123456789ab"
	bkA   = "bk-0123456789abcdef"
)

func TestStorageOperationsThroughTheSupervisor(t *testing.T) {
	r := newRig(t, 30*time.Second, "")
	ctx := context.Background()
	r.withBackups()
	if err := r.client.Provision(ctx, r.spec); err != nil {
		t.Fatal(err)
	}
	st, err := r.client.Stats(ctx)
	if err != nil || st.PoolCapacity <= 0 || !st.BackupsKnown || st.BackupFree <= 0 {
		t.Fatalf("%+v %v", st, err)
	}
	if err := r.client.Resize(ctx, "web-1", 30); err != nil {
		t.Fatal(err)
	}
	if err := r.client.Resize(ctx, "web-1", 10); cat(err) != hypervisor.Validation {
		t.Fatalf("shrink: %v", err)
	}
	if err := r.client.Resize(ctx, "ghost", 30); cat(err) != hypervisor.NotFound {
		t.Fatalf("%v", err)
	}
	if err := r.client.Snapshot(ctx, "web-1", snapA); err != nil || len(r.sim.Load().Snapshots["web-1"]) != 1 {
		t.Fatalf("snapshot: %v", err)
	}
	if err := r.client.RestoreSnapshot(ctx, "web-1", snapA); err != nil {
		t.Fatal(err)
	}
	if err := r.client.DeleteSnapshot(ctx, "web-1", snapA); err != nil || len(r.sim.Load().Snapshots["web-1"]) != 0 {
		t.Fatalf("delete snapshot: %v", err)
	}
	if err := r.client.Backup(ctx, "web-1", bkA); err != nil {
		t.Fatal(err)
	}
	l, err := r.client.ListBackups(ctx)
	if err != nil || len(l) != 1 || l[0].ID != bkA || l[0].VM != "web-1" || l[0].DiskGiB != 30 || !l[0].Valid || l[0].SizeBytes <= 0 {
		t.Fatalf("%+v %v", l, err)
	}
	newUUID := "2b2b2b2b-3333-4444-8555-6666666666cd"
	if err := r.client.Restore(ctx, "web-2", bkA, Restore{UUID: newUUID, Fingerprint: strings.Repeat("cd", 32), SSHPublicKey: r.spec.SSHPublicKey}); err != nil {
		t.Fatal(err)
	}
	if d := r.sim.Load().Domains["web-2"]; !d.Managed || d.UUID != newUUID || d.Running {
		t.Fatalf("%+v", d)
	}
	r.qualify()
	if err := r.client.Reinstall(ctx, "web-1", Reinstall{ImageID: "debian-13", ImageSHA256: r.spec.ImageSHA256, SSHPublicKey: r.spec.SSHPublicKey, Rev: "0a1b2c3d"}); err != nil {
		t.Fatal(err)
	}
	if d := r.sim.Load().Domains["web-1"]; d.Root != provision.RootVolumeNameRev(r.spec.UUID, "0a1b2c3d") {
		t.Fatalf("%+v", d)
	}
	if err := r.client.DeleteBackup(ctx, bkA); err != nil {
		t.Fatal(err)
	}
	if l, _ := r.client.ListBackups(ctx); len(l) != 0 {
		t.Fatalf("%+v", l)
	}
	if err := r.client.DeleteBackup(ctx, bkA); err != nil {
		t.Fatalf("deleting a deleted backup is a no-op: %v", err)
	}
}

func TestBackupOperationsRefuseWithoutAStore(t *testing.T) {
	r := newRig(t, 30*time.Second, "")
	ctx := context.Background()
	if err := r.client.Provision(ctx, r.spec); err != nil {
		t.Fatal(err)
	}
	if err := r.client.Backup(ctx, "web-1", bkA); cat(err) == "" {
		t.Fatal("a backup without a configured store succeeded")
	}
	if l, err := r.client.ListBackups(ctx); err != nil || len(l) != 0 {
		t.Fatalf("an unconfigured store lists as empty: %v %v", l, err)
	}
	if st, err := r.client.Stats(ctx); err != nil || st.BackupsKnown {
		t.Fatalf("%+v %v", st, err)
	}
}

// TestStorageProtocolIsClosed exercises Valid directly: each operation takes exactly its own fields.
func TestStorageProtocolIsClosed(t *testing.T) {
	key := func() string {
		r := newRig(t, time.Second, "")
		return r.spec.SSHPublicKey
	}()
	uuid := "2b2b2b2b-3333-4444-8555-6666666666cd"
	fp := strings.Repeat("cd", 32)
	good := []Request{
		{V: 1, Op: OpResize, Name: "web-1", DiskGiB: 30}, {V: 1, Op: OpSnapshot, Name: "web-1", ID: snapA}, {V: 1, Op: OpRestoreSnapshot, Name: "web-1", ID: snapA},
		{V: 1, Op: OpDeleteSnapshot, Name: "web-1", ID: snapA}, {V: 1, Op: OpBackup, Name: "web-1", ID: bkA}, {V: 1, Op: OpDeleteBackup, ID: bkA}, {V: 1, Op: OpListBackups}, {V: 1, Op: OpStats},
		{V: 1, Op: OpReinstall, Name: "web-1", Reinstall: &Reinstall{ImageID: "debian-13", ImageSHA256: fp, SSHPublicKey: key, Rev: "0a1b2c3d"}},
		{V: 1, Op: OpRestore, Name: "web-2", ID: bkA, Restore: &Restore{UUID: uuid, Fingerprint: fp, SSHPublicKey: key}},
	}
	for _, q := range good {
		if !q.Valid() {
			t.Errorf("%s rejected: %+v", q.Op, q)
		}
	}
	bad := map[string]Request{
		"resize zero":          {V: 1, Op: OpResize, Name: "web-1"},
		"resize huge":          {V: 1, Op: OpResize, Name: "web-1", DiskGiB: provision.MaxDiskGiB + 1},
		"resize with id":       {V: 1, Op: OpResize, Name: "web-1", DiskGiB: 30, ID: snapA},
		"snapshot bad id":      {V: 1, Op: OpSnapshot, Name: "web-1", ID: "snap-xyz"},
		"snapshot no id":       {V: 1, Op: OpSnapshot, Name: "web-1"},
		"snapshot disk":        {V: 1, Op: OpSnapshot, Name: "web-1", ID: snapA, DiskGiB: 5},
		"backup bad id":        {V: 1, Op: OpBackup, Name: "web-1", ID: "../x"},
		"backup snapid":        {V: 1, Op: OpBackup, Name: "web-1", ID: snapA},
		"delete_backup name":   {V: 1, Op: OpDeleteBackup, Name: "web-1", ID: bkA},
		"list with name":       {V: 1, Op: OpListBackups, Name: "web-1"},
		"stats with id":        {V: 1, Op: OpStats, ID: bkA},
		"reinstall no body":    {V: 1, Op: OpReinstall, Name: "web-1"},
		"reinstall bad rev":    {V: 1, Op: OpReinstall, Name: "web-1", Reinstall: &Reinstall{ImageID: "debian-13", ImageSHA256: fp, SSHPublicKey: key, Rev: "zz"}},
		"reinstall bad key":    {V: 1, Op: OpReinstall, Name: "web-1", Reinstall: &Reinstall{ImageID: "debian-13", ImageSHA256: fp, SSHPublicKey: "ssh-ed25519 AAAA", Rev: "0a1b2c3d"}},
		"reinstall option key": {V: 1, Op: OpReinstall, Name: "web-1", Reinstall: &Reinstall{ImageID: "debian-13", ImageSHA256: fp, SSHPublicKey: `command="id" ` + key, Rev: "0a1b2c3d"}},
		"restore no body":      {V: 1, Op: OpRestore, Name: "web-2", ID: bkA},
		"restore bad uuid":     {V: 1, Op: OpRestore, Name: "web-2", ID: bkA, Restore: &Restore{UUID: "nope", Fingerprint: fp, SSHPublicKey: key}},
		"restore bad name":     {V: 1, Op: OpRestore, Name: "Web", ID: bkA, Restore: &Restore{UUID: uuid, Fingerprint: fp, SSHPublicKey: key}},
		"start with id":        {V: 1, Op: OpStart, Name: "web-1", ID: bkA},
		"stop with resize":     {V: 1, Op: OpStop, Name: "web-1", DiskGiB: 5},
		"unknown op":           {V: 1, Op: "format", Name: "web-1"},
	}
	for name, q := range bad {
		if q.Valid() {
			t.Errorf("%s accepted", name)
		}
	}
}
