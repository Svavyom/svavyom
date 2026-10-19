package ctl

import (
	"bytes"
	"context"
	"database/sql"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"example.invalid/dedicatedcloud/backend/internal/auth"
	"example.invalid/dedicatedcloud/backend/internal/operation"
	"example.invalid/dedicatedcloud/backend/internal/provision"
	"example.invalid/dedicatedcloud/backend/internal/sqlitedb"
)

var curSchema = map[string]int{"operation": operation.SchemaVersion(), "auth": auth.SchemaVersion()}

// serverHost is a host whose API unit points at a live loopback health endpoint, so waitHealthy can pass.
func serverHost(t *testing.T) (*testHost, string) {
	t.Helper()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(`{"status":"scaffold"}`)) }))
	t.Cleanup(ts.Close)
	h := newHost(t)
	h.run.reply["systemctl is-active"] = "active\n"
	h.run.reply["systemctl is-enabled"] = "enabled\n"
	for _, p := range []string{"/var/lib/svavyom/images", "/var/lib/svavyom/state", "/var/lib/svavyom/pool", UnitDir, "/etc/sysusers.d", "/etc/tmpfiles.d", "/usr/libexec", "/usr/share"} {
		if err := os.MkdirAll(h.root+p, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	return h, strings.TrimPrefix(ts.URL, "http://")
}

func install(t *testing.T, h *testHost, listen, artifact string, extra func(*InstallOptions)) (string, error) {
	t.Helper()
	o := InstallOptions{Artifact: artifact, Apply: true, Listen: listen}
	if extra != nil {
		extra(&o)
	}
	var out bytes.Buffer
	err := Install(context.Background(), h.env, o, &out)
	return out.String(), err
}

func TestInstallDryRunPrintsThePlanAndChangesNothing(t *testing.T) {
	h, listen := serverHost(t)
	art := makeArtifact(t, "0.1.0", curSchema, nil)
	before := snapshotTree(t, h.root)
	var out bytes.Buffer
	if err := Install(context.Background(), h.env, InstallOptions{Artifact: art, Listen: listen}, &out); err != nil {
		t.Fatalf("%v\n%s", err, out.String())
	}
	if after := snapshotTree(t, h.root); after != before {
		t.Fatal("a dry run changed the file system")
	}
	for _, want := range []string{"PLAN (nothing is changed without --apply)", "install the 7 binaries", "systemd units", "write /etc/svavyom/provision.json if it does not exist", "start the services in order"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("the plan lacks %q:\n%s", want, out.String())
		}
	}
	for _, c := range h.run.calls {
		if !strings.HasPrefix(c, "virsh -r ") {
			t.Errorf("a dry run ran %q", c)
		}
	}
}

func TestInstallAppliesTheArtifactCorrectlyAndIdempotently(t *testing.T) {
	h, listen := serverHost(t)
	art := makeArtifact(t, "0.1.0", curSchema, nil)
	out, err := install(t, h, listen, art, func(o *InstallOptions) { o.EnableMutation, o.BackupDir = true, "/var/lib/svavyom/backups" })
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	for _, b := range Binaries {
		fi, err := os.Stat(h.root + LibexecDir + "/" + b)
		if err != nil || fi.Mode().Perm() != 0o755 {
			t.Errorf("%s: %v %v", b, fi, err)
		}
	}
	if body, _ := h.read("/usr/share/svavyom/web/assets/app.js"); !strings.Contains(body, "0.1.0") {
		t.Error("web assets not installed")
	}
	api, _ := h.read(UnitDir + "/svavyom-api.service")
	if strings.Contains(api, "@") || !strings.Contains(api, "User=987") || !strings.Contains(api, "--listen "+listen) {
		t.Errorf("api unit:\n%s", api)
	}
	if feat, _ := h.read(UnitDir + "/svavyom-api.service.d/features.conf"); !strings.Contains(feat, "--experimental-mutation") || strings.Contains(feat, "--experimental-console") {
		t.Errorf("feature drop-in:\n%s", feat)
	}
	if bk, _ := h.read(UnitDir + "/svavyom-mutation.service.d/backup.conf"); !strings.Contains(bk, "ReadWritePaths=/var/lib/svavyom/backups") {
		t.Errorf("backup drop-in:\n%s", bk)
	}
	if v, _ := h.read(VersionFile); strings.TrimSpace(v) != "0.1.0" {
		t.Errorf("version %q", v)
	}
	cfgPath := h.root + ConfigFile
	cfg, err := provision.LoadConfig(cfgPath)
	if err != nil || cfg.Pool != "svavyom" || cfg.Network != "default" || cfg.BackupDir != "/var/lib/svavyom/backups" || cfg.Trust == nil || len(cfg.Trust.Runtime) != 4 {
		t.Fatalf("%+v %v", cfg, err)
	}
	if fi, _ := os.Stat(h.root + "/var/lib/svavyom/backups"); fi == nil || fi.Mode().Perm() != 0o700 {
		t.Error("the backup store must be created 0700")
	}
	// the services are started in dependency order
	var order []string
	for _, c := range h.run.calls {
		if strings.HasPrefix(c, "systemctl restart -- ") {
			order = append(order, strings.TrimPrefix(c, "systemctl restart -- "))
		}
	}
	if strings.Join(order, ",") != strings.Join(Units, ",") {
		t.Errorf("start order %v", order)
	}
	if h.run.called("systemd-sysusers") != 1 || h.run.called("systemd-tmpfiles --create") != 1 || h.run.called("systemctl daemon-reload") != 1 {
		t.Errorf("%v", h.run.calls)
	}
	// nothing ran as a shell, and nothing touched libvirt networks or VMs
	for _, c := range h.run.calls {
		for _, bad := range []string{"sh -c", "bash", "net-destroy", "net-undefine", "destroy ", "undefine ", "chmod 777", "usermod"} {
			if strings.Contains(c, bad) {
				t.Errorf("unexpected command %q", c)
			}
		}
	}
	// a re-run is a no-op for the files and never overwrites the configuration
	h.write(ConfigFile, strings.Replace(mustRead(t, cfgPath), `"svavyom"`, `"my-pool"`, 1))
	snap := snapshotTree(t, h.root)
	if out, err = install(t, h, listen, art, func(o *InstallOptions) { o.EnableMutation, o.BackupDir = true, "/var/lib/svavyom/backups" }); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if got, _ := provision.LoadConfig(cfgPath); got.Pool != "my-pool" {
		t.Fatal("an existing configuration was overwritten")
	}
	_ = snap
}

func mustRead(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestInstallRefusals(t *testing.T) {
	h, listen := serverHost(t)
	art := makeArtifact(t, "0.1.0", curSchema, nil)
	// a tampered artifact
	bad := makeArtifact(t, "0.1.0", curSchema, nil)
	_ = os.WriteFile(filepath.Join(bad, "bin/api"), []byte("evil"), 0o755)
	if _, err := install(t, h, listen, bad, nil); err == nil {
		t.Fatal("a tampered artifact was installed")
	}
	if h.exists(LibexecDir + "/api") {
		t.Fatal("a refused install left files")
	}
	// not root
	h.env.Euid = func() int { return 1000 }
	if _, err := install(t, h, listen, art, nil); err == nil || !strings.Contains(err.Error(), "root") {
		t.Fatalf("--apply must need root: %v", err)
	}
	h.env.Euid = func() int { return 0 }
	// preflight FAIL is never overridden; NOT_READY only with the flag
	h.write("/sys/module/apparmor/parameters/enabled", "N\n")
	if _, err := install(t, h, listen, art, func(o *InstallOptions) { o.AllowNotReady = true }); err == nil || !strings.Contains(err.Error(), "FAIL") {
		t.Fatalf("a failed preflight was overridden: %v", err)
	}
	h.write("/sys/module/apparmor/parameters/enabled", "Y\n")
	delete(h.paths, "qemu-system-x86_64")
	if _, err := install(t, h, listen, art, nil); err == nil || !strings.Contains(err.Error(), "NOT_READY") {
		t.Fatalf("%v", err)
	}
	if _, err := install(t, h, listen, art, func(o *InstallOptions) { o.AllowNotReady = true }); err != nil {
		t.Fatalf("--allow-not-ready should proceed on NOT_READY: %v", err)
	}
	// a non-loopback listener without TLS
	h2, _ := serverHost(t)
	if _, err := install(t, h2, "0.0.0.0:8443", art, nil); err == nil || !strings.Contains(err.Error(), "TLS") {
		t.Fatalf("%v", err)
	}
	for name, mut := range map[string]func(*InstallOptions){
		"bad pool":    func(o *InstallOptions) { o.Pool = "a b" },
		"bad network": func(o *InstallOptions) { o.Network = "../x" },
		"bad host":    func(o *InstallOptions) { o.TLSSelfSigned = "a b;c" },
		"bad backup":  func(o *InstallOptions) { o.BackupDir = "relative" },
		"bad listen":  func(o *InstallOptions) { o.Listen = "nonsense" },
	} {
		h3, l3 := serverHost(t)
		if _, err := install(t, h3, l3, art, mut); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}

func TestInstallCreatesATLSPairWithTheRightModes(t *testing.T) {
	h, _ := serverHost(t)
	art := makeArtifact(t, "0.1.0", curSchema, nil)
	// 0.0.0.0 with a self-signed pair: the status check cannot reach a real server, so only the files are examined (the health wait is not part of this test)
	o := InstallOptions{Artifact: art, Apply: true, Listen: "0.0.0.0:8443", TLSSelfSigned: "svavyom.lab.example"}
	h.run.fail["systemctl is-active"] = false
	var out bytes.Buffer
	_ = Install(context.Background(), h.env, o, &out)
	ki, err := os.Stat(h.root + "/etc/svavyom/tls/key.pem")
	if err != nil || ki.Mode().Perm() != 0o640 {
		t.Fatalf("key: %v %v", ki, err)
	}
	if ci, _ := os.Stat(h.root + "/etc/svavyom/tls/cert.pem"); ci == nil || ci.Mode().Perm() != 0o644 {
		t.Fatal("cert mode")
	}
	key1 := mustRead(t, h.root+"/etc/svavyom/tls/key.pem")
	if !strings.Contains(key1, "BEGIN PRIVATE KEY") {
		t.Fatal("no key written")
	}
	if err := h.env.selfSignedTLS("other.example"); err != nil || mustRead(t, h.root+"/etc/svavyom/tls/key.pem") != key1 {
		t.Fatal("an existing key was replaced")
	}
	if strings.Contains(out.String(), "BEGIN PRIVATE KEY") {
		t.Fatal("key material was printed")
	}
}

func TestInstallCreatesThePoolOnlyWhenAskedAndMissing(t *testing.T) {
	h, listen := serverHost(t)
	art := makeArtifact(t, "0.1.0", curSchema, nil)
	h.run.failN["virsh -c qemu:///system pool-info"] = 1
	if out, err := install(t, h, listen, art, func(o *InstallOptions) { o.CreatePool, o.Pool = true, "labpool" }); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if h.run.called("virsh -c qemu:///system pool-define") != 1 || h.run.called("virsh -c qemu:///system pool-start") != 1 || h.run.called("virsh -c qemu:///system pool-autostart") != 1 {
		t.Fatalf("%v", h.run.calls)
	}
	h2, l2 := serverHost(t)
	if _, err := install(t, h2, l2, art, nil); err != nil {
		t.Fatal(err)
	}
	if h2.run.called("virsh -c qemu:///system pool-define") != 0 {
		t.Fatal("a pool was defined without being asked")
	}
}

func openDB(t *testing.T, h *testHost) *sql.DB {
	t.Helper()
	p := h.root + "/var/lib/svavyom/api/svavyom.db"
	_ = os.MkdirAll(filepath.Dir(p), 0o700)
	db, err := sqlitedb.Open(p)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := operation.OpenSQLite(context.Background(), db); err != nil {
		t.Fatal(err)
	}
	return db
}

func upgrade(t *testing.T, h *testHost, listen, art string, extra func(*UpgradeOptions)) (string, error) {
	t.Helper()
	o := UpgradeOptions{InstallOptions: InstallOptions{Artifact: art, Apply: true, Listen: listen}}
	if extra != nil {
		extra(&o)
	}
	var out bytes.Buffer
	err := Upgrade(context.Background(), h.env, o, &out)
	return out.String(), err
}

func TestUpgradeBacksUpAppliesAndKeepsTheRollbackPath(t *testing.T) {
	h, listen := serverHost(t)
	if out, err := install(t, h, listen, makeArtifact(t, "0.1.0", curSchema, nil), nil); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	db := openDB(t, h)
	_, _ = db.Exec(`INSERT INTO operations (id, project_id, resource_kind, resource_id, type, status, idempotency_key, requested_by, generation, attempts, error_category, created_at, updated_at)
		VALUES ('op-1','default','VM','web-1','create','succeeded','k1','alice',1,1,'',1,1)`)
	_ = db.Close()
	h.run.calls = nil
	out, err := upgrade(t, h, listen, makeArtifact(t, "0.2.0", curSchema, nil), nil)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if v, _ := h.read(VersionFile); strings.TrimSpace(v) != "0.2.0" {
		t.Fatalf("version %q", v)
	}
	if b, _ := h.read(LibexecDir + "/api"); !strings.Contains(b, "0.2.0") {
		t.Fatal("new binary not installed")
	}
	bl, err := h.env.ListBackups()
	if err != nil || len(bl) != 1 || bl[0].FromVersion != "0.1.0" || bl[0].ToVersion != "0.2.0" || !bl[0].HasDB {
		t.Fatalf("%+v %v", bl, err)
	}
	dir := h.root + BackupRoot + "/" + bl[0].ID
	if b, _ := os.ReadFile(dir + "/libexec/api"); !strings.Contains(string(b), "0.1.0") {
		t.Fatal("the backup must hold the previous binary")
	}
	if fi, _ := os.Stat(dir + "/database.sqlite"); fi == nil || fi.Mode().Perm() != 0o600 {
		t.Fatal("database copy missing or not 0600")
	}
	if _, err := os.Stat(dir + "/config/tls"); err == nil {
		t.Fatal("a backup must not contain the TLS directory")
	}
	if fi, _ := os.Stat(h.root + BackupRoot + "/" + bl[0].ID); fi == nil || fi.Mode().Perm() != 0o700 {
		t.Fatal("backup directory must be 0700")
	}
	// stop in reverse order, start in order
	var stops, starts []string
	for _, c := range h.run.calls {
		if strings.HasPrefix(c, "systemctl stop -- ") {
			stops = append(stops, strings.TrimPrefix(c, "systemctl stop -- "))
		}
		if strings.HasPrefix(c, "systemctl restart -- ") {
			starts = append(starts, strings.TrimPrefix(c, "systemctl restart -- "))
		}
	}
	if strings.Join(stops, ",") != strings.Join(reverse(Units), ",") || strings.Join(starts, ",") != strings.Join(Units, ",") {
		t.Errorf("stops %v starts %v", stops, starts)
	}
	// the database content survived untouched
	d2, _ := sqlitedb.OpenReadOnly(h.root + "/var/lib/svavyom/api/svavyom.db")
	var n int
	_ = d2.QueryRow(`SELECT count(*) FROM operations`).Scan(&n)
	_ = d2.Close()
	if n != 1 {
		t.Fatal("the upgrade lost operations")
	}
}

func TestUpgradeRefusals(t *testing.T) {
	h, listen := serverHost(t)
	art1 := makeArtifact(t, "0.1.0", curSchema, nil)
	if _, err := upgrade(t, h, listen, art1, nil); err == nil || !strings.Contains(err.Error(), "no installed version") {
		t.Fatalf("%v", err)
	}
	if out, err := install(t, h, listen, art1, nil); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if _, err := upgrade(t, h, listen, art1, nil); err == nil || !strings.Contains(err.Error(), "already installed") {
		t.Fatalf("%v", err)
	}
	if _, err := upgrade(t, h, listen, makeArtifact(t, "0.0.9", curSchema, nil), nil); err == nil || !strings.Contains(err.Error(), "older") {
		t.Fatalf("a downgrade must be refused: %v", err)
	}
	if _, err := upgrade(t, h, listen, makeArtifact(t, "0.0.9", curSchema, nil), func(o *UpgradeOptions) { o.AllowDowngrade = true }); err != nil {
		t.Fatalf("an explicit downgrade should work: %v", err)
	}
	db := openDB(t, h)
	_ = db.Close()
	older := map[string]int{"operation": operation.SchemaVersion() - 1, "auth": auth.SchemaVersion()}
	if _, err := upgrade(t, h, listen, makeArtifact(t, "0.3.0", older, nil), nil); err == nil || !strings.Contains(err.Error(), "database schema") {
		t.Fatalf("an artifact that cannot read the database schema must be refused: %v", err)
	}
	if v, _ := h.read(VersionFile); strings.TrimSpace(v) != "0.0.9" {
		t.Fatalf("a refused upgrade changed the installation: %q", v)
	}
	h.write(ConfigFile, "{broken")
	if _, err := upgrade(t, h, listen, makeArtifact(t, "0.4.0", curSchema, nil), nil); err == nil || !strings.Contains(err.Error(), "does not validate") {
		t.Fatalf("an invalid configuration must block the upgrade: %v", err)
	}
	if bl, _ := h.env.ListBackups(); len(bl) != 1 { // only the explicit downgrade made one
		t.Fatalf("refusals must not create backups: %d", len(bl))
	}
}

func TestFailedUpgradeRollsBackAutomatically(t *testing.T) {
	h, listen := serverHost(t)
	if out, err := install(t, h, listen, makeArtifact(t, "0.1.0", curSchema, nil), nil); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	h.run.failN["systemctl restart -- svavyom-console.service"] = 1 // the new version's console fails to start
	out, err := upgrade(t, h, listen, makeArtifact(t, "0.2.0", curSchema, nil), nil)
	if err == nil || !strings.Contains(err.Error(), "rolled back") {
		t.Fatalf("%v\n%s", err, out)
	}
	if v, _ := h.read(VersionFile); strings.TrimSpace(v) != "0.1.0" {
		t.Fatalf("version %q after rollback", v)
	}
	if b, _ := h.read(LibexecDir + "/api"); !strings.Contains(b, "0.1.0") {
		t.Fatal("the old binary was not restored")
	}
	if w, _ := h.read("/usr/share/svavyom/web/index.html"); !strings.Contains(w, "0.1.0") {
		t.Fatal("the old web assets were not restored")
	}
	if !strings.Contains(out, "UPGRADE FAILED") || !strings.Contains(out, "rolled back to 0.1.0") {
		t.Fatalf("the failure and the recovery must be stated:\n%s", out)
	}
	// a crash-looping unit is in systemd's start-limit state: the failed state must be cleared before the previous version is started again
	for i, c := range h.run.calls {
		if strings.HasPrefix(c, "systemctl restart -- ") && (i < 2 || h.run.calls[i-2] != "systemctl reset-failed -- "+strings.TrimPrefix(c, "systemctl restart -- ")) {
			t.Errorf("%q was not preceded by reset-failed", c)
		}
	}
	// both attempts started the four services in order; the last start is the old version's
	if h.run.called("systemctl restart -- svavyom-api.service") < 1 {
		t.Fatal("the old services were not restarted")
	}
}

func TestRollbackRefusesAcrossAnIrreversibleSchemaChange(t *testing.T) {
	h, listen := serverHost(t)
	if out, err := install(t, h, listen, makeArtifact(t, "0.1.0", curSchema, nil), nil); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	db := openDB(t, h)
	_ = db.Close()
	if out, err := upgrade(t, h, listen, makeArtifact(t, "0.2.0", curSchema, nil), nil); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	// the new version migrated the database past what 0.1.0 could read
	db2, _ := sqlitedb.Open(h.root + "/var/lib/svavyom/api/svavyom.db")
	_, _ = db2.Exec(`UPDATE schema_migrations SET version = version + 3 WHERE component = 'operation'`)
	_, _ = db2.Exec(`INSERT INTO operations (id, project_id, resource_kind, resource_id, type, status, idempotency_key, requested_by, generation, attempts, error_category, created_at, updated_at)
		VALUES ('op-new','default','VM','web-9','create','succeeded','k9','alice',1,1,'',1,1)`)
	_ = db2.Close()
	var out bytes.Buffer
	err := Rollback(context.Background(), h.env, RollbackOptions{Apply: true}, &out)
	if err == nil || !strings.Contains(err.Error(), "irreversible") || !strings.Contains(err.Error(), "--restore-db") {
		t.Fatalf("%v", err)
	}
	if v, _ := h.read(VersionFile); strings.TrimSpace(v) != "0.2.0" {
		t.Fatal("a refused rollback changed the installation")
	}
	// with the explicit flag the old database copy comes back; the current one is kept aside
	out.Reset()
	if err := Rollback(context.Background(), h.env, RollbackOptions{Apply: true, RestoreDB: true}, &out); err != nil {
		t.Fatalf("%v\n%s", err, out.String())
	}
	if v, _ := h.read(VersionFile); strings.TrimSpace(v) != "0.1.0" {
		t.Fatalf("version %q", v)
	}
	d3, _ := sqlitedb.OpenReadOnly(h.root + "/var/lib/svavyom/api/svavyom.db")
	vs, _ := sqlitedb.Versions(context.Background(), d3)
	var n int
	_ = d3.QueryRow(`SELECT count(*) FROM operations WHERE id = 'op-new'`).Scan(&n)
	_ = d3.Close()
	if vs["operation"] != operation.SchemaVersion() || n != 0 {
		t.Fatalf("the pre-upgrade database was not restored: %v %d", vs, n)
	}
	matches, _ := filepath.Glob(h.root + "/var/lib/svavyom/api/svavyom.db.replaced-*")
	if len(matches) != 1 {
		t.Fatalf("the replaced database must be kept: %v", matches)
	}
	if err := Rollback(context.Background(), newHost(t).env, RollbackOptions{}, &out); err == nil {
		t.Fatal("rollback without a backup must say so")
	}
}

func TestRollbackNeverTouchesVMStorage(t *testing.T) {
	h, listen := serverHost(t)
	sentinel := map[string]string{"/var/lib/svavyom/pool/disk.qcow2": "VM-DISK", "/var/lib/svavyom/images/operator-notes.txt": "{}", "/var/lib/svavyom/backups/bk-1/root.qcow2": "BACKUP"}
	for p, c := range sentinel {
		h.write(p, c)
	}
	if out, err := install(t, h, listen, makeArtifact(t, "0.1.0", curSchema, nil), nil); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if out, err := upgrade(t, h, listen, makeArtifact(t, "0.2.0", curSchema, nil), nil); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	var out bytes.Buffer
	if err := Rollback(context.Background(), h.env, RollbackOptions{Apply: true}, &out); err != nil {
		t.Fatalf("%v\n%s", err, out.String())
	}
	for p, c := range sentinel {
		if b, ok := h.read(p); !ok || b != c {
			t.Errorf("%s changed", p)
		}
	}
	bl, _ := h.env.ListBackups()
	for _, b := range bl {
		for _, f := range b.Files {
			if strings.Contains(f, "pool") || strings.Contains(f, "qcow2") || strings.Contains(f, "tls") {
				t.Errorf("backup holds %s", f)
			}
		}
	}
}

func TestUninstallKeepsDataAndPurgeNeedsTheToken(t *testing.T) {
	h, listen := serverHost(t)
	keep := map[string]string{"/var/lib/svavyom/pool/disk.qcow2": "VM-DISK", "/var/lib/svavyom/images/operator-notes.txt": "{}", "/var/lib/svavyom/images/store/x.qcow2": "BASE", "/var/lib/svavyom/backups/bk/root": "BK"}
	for p, c := range keep {
		h.write(p, c)
	}
	if out, err := install(t, h, listen, makeArtifact(t, "0.1.0", curSchema, nil), nil); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	db := openDB(t, h)
	_ = db.Close()
	var out bytes.Buffer
	// dry run
	snap := snapshotTree(t, h.root)
	if err := Uninstall(context.Background(), h.env, UninstallOptions{}, &out); err != nil || snapshotTree(t, h.root) != snap {
		t.Fatalf("a dry run changed something: %v", err)
	}
	if err := Uninstall(context.Background(), h.env, UninstallOptions{Apply: true, Purge: true}, &out); err == nil || !strings.Contains(err.Error(), PurgeToken) {
		t.Fatalf("a purge without the token: %v", err)
	}
	if err := Uninstall(context.Background(), h.env, UninstallOptions{Apply: true, ConfirmPurge: PurgeToken}, &out); err == nil {
		t.Fatal("a token without --purge must be refused")
	}
	if !h.exists(LibexecDir + "/api") {
		t.Fatal("a refused uninstall removed files")
	}
	out.Reset()
	if err := Uninstall(context.Background(), h.env, UninstallOptions{Apply: true}, &out); err != nil {
		t.Fatalf("%v\n%s", err, out.String())
	}
	for _, p := range []string{LibexecDir + "/api", LibexecDir + "/VERSION", UnitDir + "/svavyom-api.service", "/usr/share/svavyom/web/index.html", SysusersFile} {
		if h.exists(p) {
			t.Errorf("%s was not removed", p)
		}
	}
	for _, p := range []string{ConfigFile, "/var/lib/svavyom/api/svavyom.db"} {
		if !h.exists(p) {
			t.Errorf("%s must be kept by default", p)
		}
	}
	for p, c := range keep {
		if b, ok := h.read(p); !ok || b != c {
			t.Errorf("%s was touched", p)
		}
	}
	if !strings.Contains(out.String(), "KEPT") || h.run.called("userdel") != 0 {
		t.Fatalf("default uninstall deletes no account:\n%s", out.String())
	}
	// purge removes Svavyom's own data only
	if err := Uninstall(context.Background(), h.env, UninstallOptions{Apply: true, Purge: true, ConfirmPurge: PurgeToken}, &out); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{ConfigFile, "/var/lib/svavyom/api/svavyom.db"} {
		if h.exists(p) {
			t.Errorf("%s survived the purge", p)
		}
	}
	for p, c := range keep {
		if b, ok := h.read(p); !ok || b != c {
			t.Errorf("the purge touched %s", p)
		}
	}
	if h.run.called("userdel svavyom-api") != 1 {
		t.Fatal("purge removes the service accounts")
	}
	for _, c := range h.run.calls {
		if strings.Contains(c, "virsh") && !strings.HasPrefix(c, "virsh -r ") && !strings.Contains(c, "pool-") {
			t.Errorf("uninstall touched libvirt: %q", c)
		}
	}
}

func TestSemverOrdering(t *testing.T) {
	for _, c := range []struct {
		a, b string
		less bool
	}{{"0.1.0", "0.2.0", true}, {"0.2.0", "0.1.0", false}, {"0.1.0-preview.0", "0.1.0", true}, {"0.1.0", "0.1.0-preview.0", false}, {"1.0.0", "0.9.9", false}, {"0.1.0", "0.1.0", false}, {"0.1.9", "0.1.10", true},
		// pre-release identifiers are numbers: preview.10 is newer than preview.9 (found when upgrading the qualification host)
		{"0.1.0-preview.9", "0.1.0-preview.10", true}, {"0.1.0-preview.10", "0.1.0-preview.9", false}, {"0.1.0-preview.10", "0.1.0-preview.10", false},
		{"0.1.0-preview.2", "0.1.0-preview.11", true}, {"0.1.0-alpha.1", "0.1.0-alpha.beta", true}, {"0.1.0-alpha", "0.1.0-alpha.1", true}, {"0.1.0-rc.1", "0.1.0", true}} {
		if semverLess(c.a, c.b) != c.less {
			t.Errorf("%s < %s should be %v", c.a, c.b, c.less)
		}
	}
}

func TestInstallHonoursTheFreeSpaceThreshold(t *testing.T) {
	h, listen := serverHost(t)
	art := makeArtifact(t, "0.1.0", curSchema, nil)
	if _, err := install(t, h, listen, art, func(o *InstallOptions) { o.MinFreeGiB = 1000 }); err == nil || !strings.Contains(err.Error(), "FAIL") {
		t.Fatalf("the threshold must be enforced: %v", err)
	}
	if h.exists(LibexecDir + "/api") {
		t.Fatal("a refused install left files")
	}
	if out, err := install(t, h, listen, art, func(o *InstallOptions) { o.MinFreeGiB = 100 }); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
}

// TestInstallRendersTheRealPackageTemplates renders the repository's own unit and configuration templates (not the test stubs), so a template change that the
// renderer cannot fill is caught here instead of on an operator's host.
func TestInstallRendersTheRealPackageTemplates(t *testing.T) {
	h, listen := serverHost(t)
	root := "../../../packages/ubuntu/"
	art := makeArtifact(t, "0.1.0", curSchema, func(files map[string][]byte) {
		for name := range files {
			if strings.HasPrefix(name, "packages/") {
				delete(files, name)
			}
		}
		err := filepath.Walk(root, func(p string, fi os.FileInfo, err error) error {
			if err != nil || fi.IsDir() {
				return err
			}
			b, rerr := os.ReadFile(p)
			if rerr != nil {
				return rerr
			}
			files["packages/ubuntu/"+filepath.ToSlash(strings.TrimPrefix(p, root))] = b
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	})
	if out, err := install(t, h, listen, art, func(o *InstallOptions) { o.EnableMutation, o.EnableConsole = true, true }); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	for _, u := range Units {
		body, ok := h.read(UnitDir + "/" + u)
		if !ok || placeholderRE.MatchString(body) || !strings.Contains(body, "ExecStart=") {
			t.Errorf("%s did not render:\n%s", u, body)
		}
	}
	api, _ := h.read(UnitDir + "/svavyom-api.service")
	if strings.Contains(api, "--tls-cert") || !strings.Contains(api, "--listen "+listen) {
		t.Errorf("a loopback listener must be plain HTTP:\n%s", api)
	}
	cfg, err := provision.LoadConfig(h.root + ConfigFile)
	if err != nil || cfg.Trust == nil || len(cfg.Trust.Runtime) != 4 {
		t.Fatalf("%+v %v", cfg, err)
	}
	if !h.exists(SysusersFile) || !h.exists(TmpfilesFile) {
		t.Error("account and directory definitions were not installed")
	}
}
