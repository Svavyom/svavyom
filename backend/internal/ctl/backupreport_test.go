package ctl

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"example.invalid/dedicatedcloud/backend/internal/backupstore"
	"example.invalid/dedicatedcloud/backend/internal/schedule"
	"example.invalid/dedicatedcloud/backend/internal/sqlitedb"
)

func bkID(i int) string { return fmt.Sprintf("bk-%016x", i) }

// writeBackups makes real backups (manifest, checksum, root copy) of vm in dir with the store's own writer and returns their ids, oldest first.
func writeBackups(t *testing.T, dir, vm string, from, n int) []string {
	t.Helper()
	st, err := backupstore.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	for i := from; i < from+n; i++ {
		w, err := st.Begin(bkID(i), 8)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte("backup-1")); err != nil {
			t.Fatal(err)
		}
		m := backupstore.Manifest{CreatedAt: fmt.Sprintf("2026-10-%02dT10:00:00Z", 1+i%28), Tool: "svavyom test",
			VM: backupstore.VM{Name: vm, UUID: "9a9a9a9a-2222-4333-8444-5555555555ab", Fingerprint: strings.Repeat("ab", 32), ImageID: "ubuntu-24.04",
				ImageSHA256: strings.Repeat("cd", 32), LoginUser: "ubuntu", VCPUs: 1, MemoryMiB: 1024, DiskGiB: 10, Network: "default"}, Root: backupstore.Root{VirtualSizeBytes: 10 << 30}}
		if _, err := w.Commit(m); err != nil {
			t.Fatal(err)
		}
		ids = append(ids, bkID(i))
	}
	return ids
}

// An operator whose scheduler lost track of backups (the retention bug of preview.13 and earlier) sees them: per VM what is on disk, what the scheduler tracks and keeps, what
// is beyond its limit, and the ids of the untracked ones. The report reads and changes nothing.
func TestBackupReportShowsWhatTheRetentionBugLeftBehind(t *testing.T) {
	h := newHost(t)
	h.write("/etc/svavyom/provision.json", `{"catalog_dir":"/var/lib/svavyom/images","pool":"svavyom","network":"default","domain_type":"kvm","libvirt_uri":"qemu:///system","state_dir":"/var/lib/svavyom/state","backup_dir":"/var/lib/svavyom/backups","trust":{"deploy_uid":0,"runtime_identities":[{"name":"api","uid":987,"gids":[987]},{"name":"agent","uid":986,"gids":[986]},{"name":"mutation","uid":985,"gids":[985,113]},{"name":"console","uid":984,"gids":[984,113]}]}}`)
	dir := filepath.Join(h.root, "var/lib/svavyom/backups")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	web := writeBackups(t, dir, "web-1", 1, 8)     // 8 on disk, keep 3: the scheduler tracks only the newest 3 (it forgot the older 5)
	db := writeBackups(t, dir, "db-1", 20, 2)      // 2 on disk, keep 5, both tracked: nothing wrong
	hand := writeBackups(t, dir, "scratch", 40, 1) // a VM with no schedule
	if err := os.MkdirAll(filepath.Dir(h.env.dbPath()), 0o755); err != nil {
		t.Fatal(err)
	}
	conn, err := sqlitedb.Open(h.env.dbPath())
	if err != nil {
		t.Fatal(err)
	}
	st, err := schedule.OpenSQLite(context.Background(), conn)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	for vm, keep := range map[string]int{"web-1": 3, "db-1": 5} {
		if err := st.Put(ctx, schedule.Schedule{VM: vm, Spec: schedule.Spec{EveryHours: 24, KeepLocal: keep}, SetBy: "admin", CreatedAt: time.Now(), NextRun: time.Now()}); err != nil {
			t.Fatal(err)
		}
	}
	for _, id := range web[5:] {
		_ = st.Made(ctx, id, "web-1", "run", time.Now())
	}
	for _, id := range db {
		_ = st.Made(ctx, id, "db-1", "run", time.Now())
	}
	_ = st.Made(ctx, bkID(999), "web-1", "run", time.Now()) // a record whose backup is gone
	_ = conn.Close()

	before := snapshotTree(t, h.root)
	var out bytes.Buffer
	if err := BackupReportRun(ctx, h.env, "", false, &out); err != nil {
		t.Fatalf("%v\n%s", err, out.String())
	}
	text := out.String()
	for _, want := range []string{"Backups in /var/lib/svavyom/backups: 11", "web-1", "keep 3", "untracked", web[0], web[4], "1 scheduler record(s) name a backup that is no longer in the store"} {
		if !strings.Contains(text, want) {
			t.Fatalf("the report lacks %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, web[5]) || strings.Contains(text, db[0]) || strings.Contains(text, hand[0]) {
		t.Fatalf("a tracked backup, or a VM without a schedule, was listed as lost:\n%s", text)
	}
	if after := snapshotTree(t, h.root); after != before {
		bl, al := strings.Split(before, "\n"), strings.Split(after, "\n")
		seen := map[string]bool{}
		for _, l := range bl {
			seen[l] = true
		}
		var diff []string
		for _, l := range al {
			if !seen[l] {
				diff = append(diff, l)
			}
		}
		t.Fatalf("the report changed the host: %v", diff)
	}

	var js bytes.Buffer
	if err := BackupReportRun(ctx, h.env, "", true, &js); err != nil {
		t.Fatal(err)
	}
	var rep BackupReport
	if err := json.Unmarshal(js.Bytes(), &rep); err != nil {
		t.Fatalf("%v\n%s", err, js.String())
	}
	byVM := map[string]BackupVMReport{}
	for _, v := range rep.VMs {
		byVM[v.VM] = v
	}
	w := byVM["web-1"]
	if w.Backups != 8 || w.Tracked != 3 || w.Untracked != 5 || w.Excess != 5 || w.KeepLocal != 3 || !w.Scheduled || len(w.UntrackedIDs) != 5 {
		t.Fatalf("web-1: %+v", w)
	}
	if d := byVM["db-1"]; d.Excess != 0 || d.Untracked != 0 || d.Tracked != 2 {
		t.Fatalf("db-1 has nothing wrong: %+v", d)
	}
	if s := byVM["scratch"]; s.Scheduled || s.Excess != 0 || s.Backups != 1 {
		t.Fatalf("scratch: %+v", s)
	}
	if rep.TotalBackups != 11 || len(rep.RecordsWithoutBackup) != 1 || rep.RecordsWithoutBackup[0] != bkID(999) {
		t.Fatalf("%+v", rep)
	}
}

// While the service has the database open (its -wal and -shm exist) the report reads it too, and still leaves nothing new behind.
func TestBackupReportWorksWhileTheServiceHoldsTheDatabase(t *testing.T) {
	h := newHost(t)
	h.write("/etc/svavyom/provision.json", `{"catalog_dir":"/var/lib/svavyom/images","pool":"svavyom","network":"default","domain_type":"kvm","libvirt_uri":"qemu:///system","state_dir":"/var/lib/svavyom/state","backup_dir":"/var/lib/svavyom/backups","trust":{"deploy_uid":0,"runtime_identities":[{"name":"api","uid":987,"gids":[987]},{"name":"agent","uid":986,"gids":[986]},{"name":"mutation","uid":985,"gids":[985,113]},{"name":"console","uid":984,"gids":[984,113]}]}}`)
	dir := filepath.Join(h.root, "var/lib/svavyom/backups")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	ids := writeBackups(t, dir, "web-1", 1, 4)
	if err := os.MkdirAll(filepath.Dir(h.env.dbPath()), 0o755); err != nil {
		t.Fatal(err)
	}
	conn, err := sqlitedb.Open(h.env.dbPath())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	st, err := schedule.OpenSQLite(context.Background(), conn)
	if err != nil {
		t.Fatal(err)
	}
	_ = st.Put(context.Background(), schedule.Schedule{VM: "web-1", Spec: schedule.Spec{EveryHours: 24, KeepLocal: 2}, SetBy: "admin", CreatedAt: time.Now(), NextRun: time.Now()})
	_ = st.Made(context.Background(), ids[3], "web-1", "run", time.Now())
	if _, err := os.Stat(h.env.dbPath() + "-shm"); err != nil {
		t.Skipf("the driver keeps no -shm here: %v", err)
	}
	var out bytes.Buffer
	if err := BackupReportRun(context.Background(), h.env, "", false, &out); err != nil {
		t.Fatalf("%v\n%s", err, out.String())
	}
	if !strings.Contains(out.String(), "keep 2") || !strings.Contains(out.String(), ids[0]) {
		t.Fatalf("%s", out.String())
	}
}

func TestBackupReportRefusesWhatItCannotRead(t *testing.T) {
	h := newHost(t)
	var out bytes.Buffer
	if err := BackupReportRun(context.Background(), h.env, "", false, &out); err == nil {
		t.Fatal("no configuration must be an error")
	}
	h.write("/etc/svavyom/provision.json", `{"catalog_dir":"/var/lib/svavyom/images","pool":"svavyom","network":"default","domain_type":"kvm","libvirt_uri":"qemu:///system","state_dir":"/var/lib/svavyom/state","trust":{"deploy_uid":0,"runtime_identities":[{"name":"api","uid":987,"gids":[987]},{"name":"agent","uid":986,"gids":[986]},{"name":"mutation","uid":985,"gids":[985,113]},{"name":"console","uid":984,"gids":[984,113]}]}}`)
	if err := BackupReportRun(context.Background(), h.env, "", false, &out); err == nil || !strings.Contains(err.Error(), "no local backup store") {
		t.Fatalf("no backup_dir: %v", err)
	}
	h.write("/etc/svavyom/provision.json", `{"catalog_dir":"/var/lib/svavyom/images","pool":"svavyom","network":"default","domain_type":"kvm","libvirt_uri":"qemu:///system","state_dir":"/var/lib/svavyom/state","backup_dir":"/var/lib/svavyom/backups","trust":{"deploy_uid":0,"runtime_identities":[{"name":"api","uid":987,"gids":[987]},{"name":"agent","uid":986,"gids":[986]},{"name":"mutation","uid":985,"gids":[985,113]},{"name":"console","uid":984,"gids":[984,113]}]}}`)
	if err := BackupReportRun(context.Background(), h.env, "", false, &out); err == nil {
		t.Fatal("a missing backup directory must be an error")
	}
}

// Entries that are not backups are skipped, never trusted: a stray directory, a manifest for another id, a malformed or oversized manifest.
func TestTheListingSkipsWhatIsNotABackup(t *testing.T) {
	dir := t.TempDir()
	writeBackupsAt := func() { _ = writeBackups }
	_ = writeBackupsAt
	if err := os.MkdirAll(filepath.Join(dir, "not-a-backup"), 0o700); err != nil {
		t.Fatal(err)
	}
	bad := filepath.Join(dir, bkID(7))
	if err := os.MkdirAll(bad, 0o700); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(filepath.Join(bad, "manifest.json"), []byte(`{"backup_id":"`+bkID(8)+`"}`), 0o600)
	_ = os.WriteFile(filepath.Join(dir, "stray-file"), []byte("x"), 0o600)
	got, err := readBackupListing(dir)
	if err != nil || len(got) != 0 {
		t.Fatalf("%v %v", got, err)
	}
}
