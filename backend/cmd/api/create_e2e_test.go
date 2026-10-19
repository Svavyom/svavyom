package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"example.invalid/dedicatedcloud/backend/internal/agent"
	"example.invalid/dedicatedcloud/backend/internal/mutagent"
	"example.invalid/dedicatedcloud/backend/internal/provision"
	"example.invalid/dedicatedcloud/backend/internal/provision/provtest"
	"example.invalid/dedicatedcloud/backend/internal/simhost"
)

// The whole wiring of `api serve --experimental-mutation` with real processes where it matters: the API server, the operation
// worker, a real mutation supervisor that starts a real (simulated-host) helper process per request, and the read-only agent
// protocol over a Unix socket. Simulation: no libvirt.

func TestServeWithExperimentalMutationCreatesAndStartsAVM(t *testing.T) {
	root, err := os.MkdirTemp("", "e2e")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	catDir, state := filepath.Join(root, "images"), filepath.Join(root, "state")
	_ = os.MkdirAll(catDir, 0o750)
	_ = os.MkdirAll(state, 0o700)
	srcImg := filepath.Join(root, "debian.qcow2")
	_ = os.WriteFile(srcImg, provtest.Qcow2("body"), 0o640)
	var out, errb bytes.Buffer
	if code := run(context.Background(), []string{"register-image", "--insecure-dev-single-identity", "--catalog-dir", catDir, "--id", "debian-13", "--display-name", "Debian 13", "--distribution", "Debian",
		"--version", "13", "--source", srcImg, "--login-user", "debian", "--min-disk-gib", "3", "--cloud-init"}, nil, &out, &errb); code != 0 || !strings.Contains(out.String(), "registered debian-13") {
		t.Fatalf("register-image: %d %q %q", code, out.String(), errb.String())
	}
	pc := provision.Config{CatalogDir: catDir, Pool: "svavyom", Network: "svavyom-nat", DomainType: "test", LibvirtURI: "test:///default", StateDir: state}
	pcb, _ := json.Marshal(pc)
	pcPath := filepath.Join(root, "provision.json")
	_ = os.WriteFile(pcPath, pcb, 0o600)

	helper := filepath.Join(root, "helper")
	if b, err := exec.Command("go", "build", "-o", helper, "example.invalid/dedicatedcloud/backend/cmd/mutation-helper-sim").CombinedOutput(); err != nil { // #nosec G204
		t.Fatalf("build helper: %v\n%s", err, b)
	}
	uid := []uint32{uint32(os.Getuid())} // #nosec G115
	sim, _ := simhost.New(filepath.Join(state, "sim"))
	roSock, mutSock := filepath.Join(root, "ro.sock"), filepath.Join(root, "mut.sock")
	ro, err := agent.Listen(roSock, simhost.Reader{H: sim}, uid)
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = ro.Serve() }()
	t.Cleanup(ro.Close)
	sup, err := mutagent.Listen(mutagent.SupervisorConfig{Trust: provision.DevPolicy(), Socket: mutSock, AllowUIDs: uid, HelperPath: helper, HelperArgs: []string{"--config", pcPath, "--insecure-dev-single-identity"}, TrustedFiles: []string{pcPath},
		Env: []string{"SVAVYOM_SIM_HOST=1"}, Deadline: 20 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = sup.Serve() }()
	t.Cleanup(sup.Close)

	db := filepath.Join(root, "svavyom.db")
	if code, _, e := runCmd(t, passwordFile(t, testPassword), "bootstrap-admin", "--db", db, "--username", "admin"); code != 0 {
		t.Fatal(e)
	}
	addr := freeAddr(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan int, 1)
	serveErr := &syncBuf{}
	go func() {
		done <- run(ctx, []string{"serve", "--db", db, "--listen", addr, "--agent-socket", roSock, "--provision-config", pcPath,
			"--mutation-socket", mutSock, "--experimental-mutation", "--insecure-dev-single-identity"}, nil, io.Discard, serveErr)
	}()
	base := "http://" + addr
	deadline := time.Now().Add(15 * time.Second)
	for {
		if res, err := http.Get(base + "/healthz"); err == nil {
			res.Body.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("server did not start: %s", serveErr.String())
		}
		time.Sleep(20 * time.Millisecond)
	}
	jar, _ := cookiejar.New(nil)
	c := &http.Client{Jar: jar}
	var csrf string
	do := func(method, path, body string) (int, []byte) {
		r, _ := http.NewRequest(method, base+path, strings.NewReader(body))
		if body != "" {
			r.Header.Set("Content-Type", "application/json")
		}
		if csrf != "" {
			r.Header.Set("X-CSRF-Token", csrf)
		}
		res, err := c.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		if tk := res.Header.Get("X-CSRF-Token"); tk != "" {
			csrf = tk
		}
		b, _ := io.ReadAll(res.Body)
		return res.StatusCode, b
	}
	do("GET", "/api/v1/auth/session", "")
	if st, b := do("POST", "/api/v1/auth/session", `{"username":"admin","password":"`+testPassword+`"}`); st != 200 {
		t.Fatalf("%d %s", st, b)
	}
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	sp, _ := ssh.NewPublicKey(pub)
	key := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sp)))
	poll := func(id, want string) {
		for i := 0; i < 400; i++ {
			_, b := do("GET", "/api/v1/operations/"+id, "")
			var m map[string]any
			_ = json.Unmarshal(b, &m)
			if m["status"] == want {
				return
			}
			time.Sleep(25 * time.Millisecond)
		}
		t.Fatalf("operation %s never reached %s", id, want)
	}
	st, b := do("POST", "/api/v1/operations", `{"type":"create","kind":"VM","id":"web-1","idempotency_key":"c1","create":{"vcpus":1,"memory_mib":512,"image_id":"debian-13","disk_gib":10,"ssh_public_key":"`+key+`"}}`)
	var op struct{ ID string }
	if st != 202 || json.Unmarshal(b, &op) != nil {
		t.Fatalf("%d %s", st, b)
	}
	poll(op.ID, "succeeded")
	if _, b := do("GET", "/api/v1/vms/web-1", ""); !strings.Contains(string(b), `"power":"stopped"`) || !strings.Contains(string(b), `"managed":true`) || !strings.Contains(string(b), `"login_user":"debian"`) {
		t.Fatalf("%s", b)
	}
	st, b = do("POST", "/api/v1/operations", `{"type":"start","kind":"VM","id":"web-1","idempotency_key":"s1"}`)
	if st != 202 || json.Unmarshal(b, &op) != nil {
		t.Fatalf("%d %s", st, b)
	}
	poll(op.ID, "succeeded")
	if _, b := do("GET", "/api/v1/vms/web-1", ""); !strings.Contains(string(b), `"power":"running"`) || !strings.Contains(string(b), `"ip_address":"192.168.122.`) {
		t.Fatalf("%s", b)
	}
	cancel()
	if code := <-done; code != 0 {
		t.Fatalf("shutdown code %d", code)
	}
}

func TestExperimentalMutationNeedsBothSocketsAndStaysClosedByDefault(t *testing.T) {
	db := filepath.Join(t.TempDir(), "svavyom.db")
	root := t.TempDir()
	pc := provision.Config{CatalogDir: root, Pool: "p", Network: "n", DomainType: "test", LibvirtURI: "test:///default", StateDir: root}
	b, _ := json.Marshal(pc)
	pcPath := filepath.Join(root, "p.json")
	_ = os.WriteFile(pcPath, b, 0o600)
	var errb bytes.Buffer
	if code := run(context.Background(), []string{"serve", "--db", db, "--provision-config", pcPath, "--experimental-mutation"}, nil, io.Discard, &errb); code != 2 || !strings.Contains(errb.String(), "needs") {
		t.Fatalf("%d %q", code, errb.String())
	}
	// Without the flag, creation is closed and says so.
	base, stop := startServer(t, "--provision-config", pcPath)
	defer stop()
	jar, _ := cookiejar.New(nil)
	c := &http.Client{Jar: jar}
	res, _ := c.Get(base + "/api/v1/auth/session")
	tok := res.Header.Get("X-CSRF-Token")
	res.Body.Close()
	r, _ := http.NewRequest("POST", base+"/api/v1/auth/session", strings.NewReader(`{"username":"admin","password":"`+testPassword+`"}`))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-CSRF-Token", tok)
	res, _ = c.Do(r)
	csrf := res.Header.Get("X-CSRF-Token")
	res.Body.Close()
	r, _ = http.NewRequest("POST", base+"/api/v1/operations", strings.NewReader(`{"type":"start","kind":"VM","id":"web-1","idempotency_key":"k"}`))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-CSRF-Token", csrf)
	res, _ = c.Do(r)
	if res.StatusCode != 422 {
		t.Fatalf("a default installation must refuse mutation: %d", res.StatusCode)
	}
	res.Body.Close()
}

func TestMutationModeRefusesWithoutTheOperatorOwnedTrustModel(t *testing.T) {
	root := t.TempDir()
	pc := provision.Config{CatalogDir: root, Pool: "p", Network: "n", DomainType: "test", LibvirtURI: "test:///default", StateDir: root}
	write := func(c provision.Config) string {
		b, _ := json.Marshal(c)
		p := filepath.Join(root, "p.json")
		_ = os.WriteFile(p, b, 0o600)
		return p
	}
	serveArgs := func(pcPath string, extra ...string) []string {
		return append([]string{"serve", "--db", filepath.Join(t.TempDir(), "svavyom.db"), "--provision-config", pcPath, "--agent-socket", "/nonexistent/ro.sock",
			"--mutation-socket", "/nonexistent/mut.sock", "--experimental-mutation"}, extra...)
	}
	// 1. No trust declaration and no explicit development flag: production mutation mode is refused.
	var errb bytes.Buffer
	if code := run(context.Background(), serveArgs(write(pc)), nil, io.Discard, &errb); code != 2 || !strings.Contains(errb.String(), "trust") {
		t.Fatalf("%d %q", code, errb.String())
	}
	// 2. A trust declaration, but the anchors are owned by this very (API) identity: refused, naming labels and no path.
	pc.Trust = &provision.TrustSpec{DeployUID: uint32(os.Getuid()) + 1, Runtime: []provision.TrustIdentity{ // #nosec G115
		{Name: "api", UID: uint32(os.Getuid())}, {Name: "agent", UID: 4000}, {Name: "mutation", UID: 4001}}} // #nosec G115
	errb.Reset()
	if code := run(context.Background(), serveArgs(write(pc)), nil, io.Discard, &errb); code != 2 || !strings.Contains(errb.String(), "trust anchors") {
		t.Fatalf("%d %q", code, errb.String())
	}
	if strings.Contains(errb.String(), root) {
		t.Fatalf("the message leaked a path: %q", errb.String())
	}
}

func TestImageAdministrationNeedsTheProductionTrustModelOrTheExplicitDevFlag(t *testing.T) {
	dir := t.TempDir()
	var out, errb bytes.Buffer
	// A bare catalog directory is only accepted together with the development flag.
	if code := run(context.Background(), []string{"register-image", "--catalog-dir", dir, "--id", "x"}, nil, &out, &errb); code != 2 {
		t.Fatalf("a bare --catalog-dir was accepted: %d %q", code, errb.String())
	}
	if code := run(context.Background(), []string{"image-state", "--catalog-dir", dir, "--id", "x", "--state", "disabled"}, nil, &out, &errb); code != 2 {
		t.Fatalf("a bare --catalog-dir was accepted: %d", code)
	}
}

func TestRegisterImageRefusesUnsafeInput(t *testing.T) {
	dir := t.TempDir()
	_ = os.Chmod(dir, 0o750)
	_ = os.WriteFile(filepath.Join(dir, "raw.img"), []byte("not qcow2"), 0o640)
	_ = os.Symlink(filepath.Join(dir, "raw.img"), filepath.Join(dir, "link.qcow2"))
	for name, args := range map[string][]string{
		"not qcow2": {"--id", "a", "--source", filepath.Join(dir, "raw.img")}, "traversal": {"--id", "a", "--source", dir + "/../x.qcow2"}, "missing": {"--id", "a", "--source", filepath.Join(dir, "none.qcow2")},
		"symlink": {"--id", "a", "--source", filepath.Join(dir, "link.qcow2")}, "relative source": {"--id", "a", "--source", "raw.img"},
		"relative dir": {"--id", "a", "--source", filepath.Join(dir, "raw.img"), "--catalog-dir", "rel"},
	} {
		full := append([]string{"register-image", "--insecure-dev-single-identity", "--catalog-dir", dir, "--display-name", "A", "--distribution", "D", "--version", "1", "--login-user", "u", "--min-disk-gib", "3"}, args...)
		var out, errb bytes.Buffer
		if code := run(context.Background(), full, nil, &out, &errb); code == 0 {
			t.Errorf("%s accepted: %s", name, out.String())
		}
	}
}
