package ctl

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"example.invalid/dedicatedcloud/backend/internal/sqlitedb"
)

func dbHost(t *testing.T) (*testHost, string) {
	t.Helper()
	h, listen := serverHost(t)
	if out, err := install(t, h, listen, makeArtifact(t, "0.1.0", curSchema, nil), nil); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	db := openDB(t, h)
	_ = db.Close()
	return h, listen
}

func opCount(t *testing.T, path string) int {
	t.Helper()
	db, err := sqlitedb.OpenReadOnly(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var n int
	if err := db.QueryRow(`SELECT count(*) FROM operations`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func addOp(t *testing.T, h *testHost, id string) {
	t.Helper()
	db, err := sqlitedb.Open(h.root + "/var/lib/svavyom/api/svavyom.db")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`INSERT INTO operations (id, project_id, resource_kind, resource_id, type, status, idempotency_key, requested_by, generation, attempts, error_category, created_at, updated_at)
		VALUES (?,'default','VM','web-9','create','succeeded',?,'alice',1,1,'',1,1)`, id, "k-"+id); err != nil {
		t.Fatal(err)
	}
}

func TestDBBackupMakesAVerifiedCopyAndListsIt(t *testing.T) {
	h, _ := dbHost(t)
	var out bytes.Buffer
	m, err := DBBackup(context.Background(), h.env, DBBackupOptions{}, &out)
	if err != nil {
		t.Fatalf("%v\n%s", err, out.String())
	}
	if !strings.Contains(out.String(), "integrity ok") || m.SHA256 == "" || m.SchemaVersion["operation"] == 0 {
		t.Fatalf("%+v\n%s", m, out.String())
	}
	if fi, err := os.Stat(h.root + DBBackupDir + "/" + m.ID + ".sqlite"); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("%v %v", fi, err)
	}
	l, err := h.env.ListDBBackups()
	if err != nil || len(l) != 1 || l[0].ID != m.ID || h.env.VerifyDBBackup(context.Background(), l[0]) != nil {
		t.Fatalf("%+v %v", l, err)
	}
	// a damaged copy no longer verifies
	if err := os.WriteFile(h.root+DBBackupDir+"/"+m.ID+".sqlite", []byte("not a database"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := h.env.VerifyDBBackup(context.Background(), l[0]); err == nil || !strings.Contains(err.Error(), "SHA-256") {
		t.Fatalf("%v", err)
	}
}

func TestDBBackupKeepsOnlyTheNewestWhenAsked(t *testing.T) {
	h, _ := dbHost(t)
	for i := 0; i < 3; i++ {
		h.now = h.now.Add(time.Minute)
		if _, err := DBBackup(context.Background(), h.env, DBBackupOptions{Keep: 2}, &bytes.Buffer{}); err != nil {
			t.Fatal(err)
		}
	}
	l, _ := h.env.ListDBBackups()
	if len(l) != 2 {
		t.Fatalf("%+v", l)
	}
	ents, _ := filepath.Glob(h.root + DBBackupDir + "/*.sqlite")
	if len(ents) != 2 {
		t.Fatalf("the pruned copy's file must be gone: %v", ents)
	}
}

func TestDBBackupNeedsRootAndADatabase(t *testing.T) {
	h, _ := dbHost(t)
	h.env.Euid = func() int { return 1000 }
	if _, err := DBBackup(context.Background(), h.env, DBBackupOptions{}, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "sudo") {
		t.Fatalf("%v", err)
	}
	if _, err := DBBackup(context.Background(), newHost(t).env, DBBackupOptions{}, &bytes.Buffer{}); err == nil {
		t.Fatal("no database, no copy")
	}
}

func TestDBRestoreDryRunChangesNothingAndApplyBringsTheCopyBack(t *testing.T) {
	h, _ := dbHost(t)
	addOp(t, h, "op-before")
	m, err := DBBackup(context.Background(), h.env, DBBackupOptions{}, &bytes.Buffer{})
	if err != nil {
		t.Fatal(err)
	}
	addOp(t, h, "op-after")
	live := h.root + "/var/lib/svavyom/api/svavyom.db"
	if opCount(t, live) != 2 {
		t.Fatal("setup")
	}
	var out bytes.Buffer
	if err := DBRestore(context.Background(), h.env, DBRestoreOptions{ID: m.ID}, &out); err != nil || !strings.Contains(out.String(), "PLAN (nothing is changed without --apply)") {
		t.Fatalf("%v\n%s", err, out.String())
	}
	if opCount(t, live) != 2 || h.run.called("systemctl stop") != 0 {
		t.Fatal("a dry run must change nothing")
	}
	out.Reset()
	stopsBefore, restartsBefore := h.run.called("systemctl stop"), h.run.called("systemctl restart")
	if err := DBRestore(context.Background(), h.env, DBRestoreOptions{ID: "latest", Apply: true}, &out); err != nil {
		t.Fatalf("%v\n%s", err, out.String())
	}
	if opCount(t, live) != 1 {
		t.Fatal("the copy was not put back")
	}
	if h.run.called("systemctl stop") <= stopsBefore || h.run.called("systemctl restart") <= restartsBefore {
		t.Fatalf("the services must be stopped and started: %v", h.run.calls)
	}
	if replaced, _ := filepath.Glob(live + ".replaced-*"); len(replaced) != 1 {
		t.Fatalf("the replaced database must be kept: %v", replaced)
	}
	l, _ := h.env.ListDBBackups()
	pre := 0
	for _, x := range l {
		if strings.HasPrefix(x.ID, "pre-restore-") {
			pre++
			if h.env.VerifyDBBackup(context.Background(), x) != nil {
				t.Fatal("the pre-restore copy must verify")
			}
		}
	}
	if pre != 1 {
		t.Fatalf("one pre-restore copy expected: %+v", l)
	}
}

func TestDBRestoreRefusals(t *testing.T) {
	h, _ := dbHost(t)
	m, _ := DBBackup(context.Background(), h.env, DBBackupOptions{}, &bytes.Buffer{})
	live := h.root + "/var/lib/svavyom/api/svavyom.db"
	// a tampered copy
	p := h.root + DBBackupDir + "/" + m.ID + ".sqlite"
	orig, _ := os.ReadFile(p)
	_ = os.WriteFile(p, append(orig, 0), 0o600)
	if err := DBRestore(context.Background(), h.env, DBRestoreOptions{ID: m.ID, Apply: true}, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "SHA-256") {
		t.Fatalf("%v", err)
	}
	_ = os.WriteFile(p, orig, 0o600)
	// a copy from a newer build
	meta := m
	meta.SchemaVersion = map[string]int{"operation": meta.SchemaVersion["operation"] + 5}
	if err := DBRestore(context.Background(), h.env, DBRestoreOptions{ID: "nope", Apply: true}, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "no such database copy") {
		t.Fatalf("%v", err)
	}
	if err := rewriteMeta(h, meta); err != nil {
		t.Fatal(err)
	}
	if err := DBRestore(context.Background(), h.env, DBRestoreOptions{ID: m.ID, Apply: true}, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "newer build") {
		t.Fatalf("%v", err)
	}
	// not root
	h.env.Euid = func() int { return 1000 }
	if err := DBRestore(context.Background(), h.env, DBRestoreOptions{ID: m.ID, Apply: true}, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "root") {
		t.Fatalf("%v", err)
	}
	if h.run.called("systemctl stop") != 0 {
		t.Fatal("a refused restore must not stop anything")
	}
	if _, err := os.Stat(live); err != nil {
		t.Fatal("the live database must be untouched")
	}
}

func rewriteMeta(h *testHost, m DBBackupMeta) error {
	b, _ := jsonIndent(m)
	return os.WriteFile(h.root+DBBackupDir+"/"+m.ID+".json", b, 0o600)
}

func jsonIndent(v any) ([]byte, error) { return json.MarshalIndent(v, "", "  ") }

func TestUpgradeRefreshesTheDirectoryDefinitionsForANewService(t *testing.T) {
	h, listen := serverHost(t)
	if out, err := install(t, h, listen, makeArtifact(t, "0.1.0", curSchema, nil), nil); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	art := makeArtifact(t, "0.2.0", curSchema, func(f map[string][]byte) {
		f["packages/ubuntu/tmpfiles.d/svavyom.conf"] = []byte("d /etc/svavyom 0755 root root -\nd /run/svavyom/offsite 2750 svavyom-mut svavyom-api -\n")
	})
	if out, err := upgrade(t, h, listen, art, nil); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	got, err := os.ReadFile(h.root + TmpfilesFile)
	if err != nil || !strings.Contains(string(got), "/run/svavyom/offsite") {
		t.Fatalf("the upgrade must install the new directory definitions: %v\n%s", err, got)
	}
	if h.run.called("systemd-tmpfiles --create") < 2 {
		t.Fatalf("and apply them: %v", h.run.calls)
	}
}

func TestStartingServicesSkipsAUnitTheInstalledVersionDoesNotHave(t *testing.T) {
	h, listen := serverHost(t)
	if out, err := install(t, h, listen, makeArtifact(t, "0.1.0", curSchema, nil), nil); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if err := os.Remove(h.root + UnitDir + "/svavyom-offsite.service"); err != nil { // what a rollback to a version without the unit leaves
		t.Fatal(err)
	}
	before, enabledBefore := h.run.called("systemctl restart -- svavyom-offsite"), h.run.called("systemctl enable -- svavyom-offsite")
	if err := h.env.startAll(context.Background()); err != nil {
		t.Fatalf("a rollback must not fail on a unit that version never had: %v", err)
	}
	if h.run.called("systemctl restart -- svavyom-offsite") != before || h.run.called("systemctl enable -- svavyom-offsite") != enabledBefore {
		t.Fatal("the missing unit must be left alone")
	}
}
