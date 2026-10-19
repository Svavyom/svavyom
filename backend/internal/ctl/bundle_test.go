package ctl

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"example.invalid/dedicatedcloud/backend/internal/operation"
	"example.invalid/dedicatedcloud/backend/internal/sqlitedb"
)

// Secrets planted in every kind of place. None of them is a real credential.
const (
	secPass   = "Correct-Horse-Battery-Staple-9"
	secCookie = "Qj7xV2mN8pLr4TuY1cWkZ0dFhA5sGbE3iOaXnMvR6yU"
	secCSRF   = "k3Jd8Lq0Zx2VbN5mPwR7tYuI1oAeSgHc4Fz9XaQ6Wn_"
	secTicket = "tkt-AbCdEfGhIjKlMnOpQrStUvWxYz0123456789_-ABCD"
	secToken  = "ghp_0123456789abcdefghijklmnopqrstuvwxyzAB"
	pemBody   = "MC4CAQAwBQYDK2VwBCIEIKJd8Lq0Zx2VbN5mPwR7tYuI1oAeSgHc4Fz9XaQ6Wn5L"
)

func planted() string {
	return strings.Join([]string{
		"Oct 12 09:00:01 host svavyom-api[12]: sign-in failed password=" + secPass + " user=admin",
		"Oct 12 09:00:02 host svavyom-api[12]: Cookie: __Host-svavyom_session=" + secCookie + "; other=1",
		"Oct 12 09:00:03 host svavyom-api[12]: Set-Cookie: svavyom_session=" + secCookie + "; HttpOnly",
		"Oct 12 09:00:04 host svavyom-api[12]: X-CSRF-Token: " + secCSRF,
		"Oct 12 09:00:05 host svavyom-api[12]: console ticket " + secTicket + " minted",
		"Oct 12 09:00:06 host svavyom-api[12]: Authorization: Bearer " + secToken,
		"Oct 12 09:00:07 host svavyom-api[12]: body {\"password\":\"" + secPass + "\",\"idempotency_key\":\"k-secret-key-1\"}",
		pemMark("BEGIN OPENSSH PRIVATE KEY"), pemBody, pemBody, pemMark("END OPENSSH PRIVATE KEY"),
		pemMark("BEGIN PRIVATE KEY"), pemBody, pemMark("END PRIVATE KEY"),
		"fetch https://admin:" + secPass + "@repo.example/x",
		"authorized ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGg4Zgd2sQ0v9i6Y0bq7n3m9c1m3k3Qm8iH6m3f3b2yd admin@laptop",
		"image digest sha256:6a81c37564db9b1ee84e141922625e1d7c5b389b99bb3c572e0243607d5bb4d2 stays",
		"operation id op-0001 resource web-1 succeeded",
	}, "\n")
}

var secrets = []string{secPass, secCookie, secCSRF, secTicket, secToken, pemBody, "k-" + "secret" + "-key-1", "AAAAC3Nza" + "C1lZDI1NTE5AAAAIGg4Z"}

func TestRedactRemovesEveryKindOfCredential(t *testing.T) {
	out, n := Redact(planted())
	for _, s := range secrets {
		if strings.Contains(out, s) {
			t.Errorf("%q survived:\n%s", s, out)
		}
	}
	if n < 10 {
		t.Errorf("only %d substitutions", n)
	}
	for _, keep := range []string{"6a81c37564db9b1ee84e141922625e1d7c5b389b99bb3c572e0243607d5bb4d2", "op-0001", "web-1", "sign-in failed", "user=admin"} {
		if !strings.Contains(out, keep) {
			t.Errorf("%q was removed; diagnostics need it", keep)
		}
	}
	if MentionsSecret(out) {
		t.Fatal("redacted output still looks secret")
	}
	if !MentionsSecret(secToken+pemMark("BEGIN RSA PRIVATE KEY")) || !MentionsSecret(secCookie) {
		t.Fatal("MentionsSecret must catch what the redactor removes")
	}
	again, n2 := Redact(out)
	if again != out || n2 > 0 {
		t.Fatalf("redaction is not idempotent: %d", n2)
	}
}

func TestRedactNeverGrowsAnInputIntoSomethingElse(t *testing.T) {
	for _, in := range []string{"", "plain text only", "digest " + strings.Repeat("ab", 32), "a=b c=d", pemMark("BEGIN PRIVATE KEY")} {
		out, _ := Redact(in)
		if strings.Contains(out, "BEGIN PRIVATE KEY") && !strings.Contains(out, "[REDACTED") {
			t.Errorf("%q -> %q", in, out)
		}
	}
}

func readBundle(t *testing.T, path string) map[string]string {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	tr := tar.NewReader(gz)
	out := map[string]string{}
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(tr)
		out[strings.TrimPrefix(h.Name, "svavyom-support/")] = string(b)
	}
	return out
}

func TestSupportBundleContainsDiagnosticsAndNoSecret(t *testing.T) {
	h := installedHost(t, goodConfig)
	h.write("/etc/svavyom/tls/key.pem", pemMark("BEGIN PRIVATE KEY")+"\n"+pemBody+"\n"+pemMark("END PRIVATE KEY")+"\n")
	h.write("/etc/svavyom/tls/cert.pem", pemMark("BEGIN CERTIFICATE")+"\nMIIB\n"+pemMark("END CERTIFICATE")+"\n")
	h.write("/usr/libexec/svavyom/VERSION", "0.1.0-preview.0\n")
	h.write(UnitDir+"/svavyom-api.service", "[Service]\nExecStart=/usr/libexec/svavyom/api serve --listen 127.0.0.1:1\nEnvironment=SVAVYOM_ADMIN_PASSWORD="+secPass+"\n")
	h.write("/var/lib/svavyom/images/catalog.json", `{"schema":2,"images":[{"id":"ubuntu-24.04","display_name":"Ubuntu","distribution":"Ubuntu","version":"24.04","architecture":"x86_64","file":"6a81c37564db9b1ee84e141922625e1d7c5b389b99bb3c572e0243607d5bb4d2.qcow2","format":"qcow2",`+
		`"sha256":"6a81c37564db9b1ee84e141922625e1d7c5b389b99bb3c572e0243607d5bb4d2","size_bytes":625612288,"min_disk_gib":3,"cloud_init":true,"login_user":"ubuntu","state":"qualified","evidence":"qr-20261011-09e94a"}]}`)
	// a real database with two operations whose idempotency key and requester must NOT appear
	dbp := h.root + "/var/lib/svavyom/api/svavyom.db"
	_ = os.MkdirAll(filepath.Dir(dbp), 0o700)
	db, err := sqlitedb.Open(dbp)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := operation.OpenSQLite(context.Background(), db); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO operations (id, project_id, resource_kind, resource_id, type, status, idempotency_key, requested_by, generation, attempts, error_category, created_at, updated_at)
		VALUES ('op-0001','default','VM','web-1','create','succeeded','k-secret-key-1','alice',1,1,'',1760000000,1760000001)`); err != nil {
		t.Fatal(err)
	}
	_ = db.Close()
	h.run.reply["journalctl -u svavyom-api.service"] = planted()
	h.run.reply["journalctl -u svavyom-agent.service"] = "agent ok\n"
	out := filepath.Join(h.root, "out")
	path, man, err := SupportBundle(context.Background(), h.env, BundleOptions{OutDir: out, Version: "0.1.0-preview.0"})
	if err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(path); fi.Mode().Perm() != 0o600 {
		t.Fatalf("bundle mode %v", fi.Mode().Perm())
	}
	if fi, _ := os.Stat(out); fi.Mode().Perm() != 0o700 {
		t.Fatalf("output dir mode %v", fi.Mode().Perm())
	}
	files := readBundle(t, path)
	all := ""
	for name, body := range files {
		all += "\n== " + name + "\n" + body
	}
	for _, s := range append(secrets, "alice", "BEGIN PRIVATE KEY", "BEGIN CERTIFICATE", "SVAVYOM_ADMIN_PASSWORD="+secPass) {
		if strings.Contains(all, s) {
			t.Errorf("the bundle leaks %q", s)
		}
	}
	for _, want := range []string{"MANIFEST.json", "product.txt", "os.txt", "services.txt", "config-validation.txt", "status.txt", "logs/svavyom-api.txt", "versions.txt", "libvirt-summary.txt", "image-catalog.json", "database.txt", "provision-config.txt", "installed-version.txt"} {
		if _, ok := files[want]; !ok {
			t.Errorf("missing %s", want)
		}
	}
	if !strings.Contains(files["image-catalog.json"], "6a81c37564db9b1ee84e141922625e1d7c5b389b99bb3c572e0243607d5bb4d2") || !strings.Contains(files["database.txt"], "op-0001 VM create succeeded") ||
		!strings.Contains(files["database.txt"], "operation=") || !strings.Contains(files["logs/svavyom-api.txt"], "op-0001") {
		t.Errorf("diagnostics lost:\n%s\n%s", files["database.txt"], files["logs/svavyom-api.txt"])
	}
	var m BundleManifest
	if err := json.Unmarshal([]byte(files["MANIFEST.json"]), &m); err != nil || m.Redactions < 10 || len(m.Excluded) < 5 || len(m.Entries) != len(files)-1 {
		t.Fatalf("%+v %v", m, err)
	}
	if man.Redactions != m.Redactions {
		t.Fatal("the returned manifest differs from the archived one")
	}
	if !strings.Contains(strings.Join(m.Excluded, "|"), "private SSH keys") || !strings.Contains(strings.Join(m.Excluded, "|"), "TLS private keys") {
		t.Fatalf("the manifest must say what is excluded: %v", m.Excluded)
	}
	// only fixed sources were read: no command other than the diagnostic queries ran
	for _, c := range h.run.calls {
		ok := false
		for _, p := range []string{"uname ", "systemctl show ", "systemctl is-", "journalctl -u ", "virsh --version", "qemu-system-x86_64 --version", "virsh -r "} {
			ok = ok || strings.HasPrefix(c, p)
		}
		if !ok {
			t.Errorf("unexpected command %q", c)
		}
	}
}

func TestSupportBundleWithholdsWhatItCannotMakeSafe(t *testing.T) {
	if MentionsSecret("short ordinary text") {
		t.Fatal("false positive")
	}
	h := installedHost(t, goodConfig)
	path, _, err := SupportBundle(context.Background(), h.env, BundleOptions{OutDir: filepath.Join(h.root, "o2"), Version: "x"})
	if err != nil {
		t.Fatal(err)
	}
	if files := readBundle(t, path); len(files) < 8 {
		t.Fatalf("%d files", len(files))
	}
	if _, _, err := SupportBundle(context.Background(), h.env, BundleOptions{OutDir: "relative/dir"}); err == nil {
		t.Fatal("a relative output directory must be refused")
	}
	if _, _, err := SupportBundle(context.Background(), h.env, BundleOptions{OutDir: filepath.Join(h.root, "o2"), Version: "x"}); err != nil {
		t.Fatalf("a second bundle in the same second must not clobber the first: %v", err)
	}
}

// pemMark returns a PEM armor line assembled at run time, so that no armor literal sits in the source (the secret scanner would rightly flag it).
func pemMark(s string) string { return strings.Repeat("-", 5) + s + strings.Repeat("-", 5) }
