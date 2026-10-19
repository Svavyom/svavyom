package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const testPassword = "correct horse battery"

func passwordFile(t *testing.T, pw string) *os.File {
	t.Helper()
	p := filepath.Join(t.TempDir(), "pw")
	if err := os.WriteFile(p, []byte(pw+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(p)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	return f
}

func runCmd(t *testing.T, stdin *os.File, args ...string) (int, string, string) {
	t.Helper()
	var out, errb bytes.Buffer
	code := run(context.Background(), args, stdin, &out, &errb)
	return code, out.String(), errb.String()
}

func TestBootstrapCreatesExactlyOneAdministratorAndNeverEchoesThePassword(t *testing.T) {
	db := filepath.Join(t.TempDir(), "svavyom.db")
	code, out, errs := runCmd(t, passwordFile(t, testPassword), "bootstrap-admin", "--db", db, "--username", "admin")
	if code != 0 || !strings.Contains(out, "administrator created") {
		t.Fatalf("%d %q %q", code, out, errs)
	}
	code, out, errs = runCmd(t, passwordFile(t, "another long password"), "bootstrap-admin", "--db", db, "--username", "second")
	if code != 1 || !strings.Contains(errs, "already exists") {
		t.Fatalf("replay: %d %q %q", code, out, errs)
	}
	for _, s := range []string{out, errs} {
		if strings.Contains(s, testPassword) || strings.Contains(s, "another long password") {
			t.Fatal("password echoed")
		}
	}
}

func TestConcurrentBootstrapOnlyOneSucceeds(t *testing.T) {
	db := filepath.Join(t.TempDir(), "svavyom.db")
	var ok atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 6; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			var out, errb bytes.Buffer
			if run(context.Background(), []string{"bootstrap-admin", "--db", db, "--username", "admin"}, passwordFile(t, testPassword+strings.Repeat("x", i)), &out, &errb) == 0 {
				ok.Add(1)
			}
		}()
	}
	wg.Wait()
	if ok.Load() != 1 {
		t.Fatalf("%d bootstraps succeeded", ok.Load())
	}
}

func TestBootstrapRefusesBadInputAndTerminals(t *testing.T) {
	db := filepath.Join(t.TempDir(), "svavyom.db")
	for name, c := range map[string]struct {
		pw   string
		args []string
	}{
		"short password":  {"short", []string{"--username", "admin"}},
		"bad username":    {testPassword, []string{"--username", "Admin;"}},
		"missing user":    {testPassword, nil},
		"password as arg": {testPassword, []string{"--username", "admin", "--password", testPassword}},
	} {
		code, _, errs := runCmd(t, passwordFile(t, c.pw), append([]string{"bootstrap-admin", "--db", db}, c.args...)...)
		if code == 0 {
			t.Errorf("%s accepted", name)
		}
		if strings.Contains(errs, testPassword) {
			t.Errorf("%s: password echoed", name)
		}
	}
	tty, err := os.Open("/dev/null") // a character device, like a terminal
	if err != nil {
		t.Skip(err)
	}
	defer tty.Close()
	if code, _, errs := runCmd(t, tty, "bootstrap-admin", "--db", db, "--username", "admin"); code != 2 || !strings.Contains(errs, "terminal") {
		t.Fatalf("character device stdin accepted: %d %q", code, errs)
	}
}

func TestResetPasswordRequiresAnAdministrator(t *testing.T) {
	db := filepath.Join(t.TempDir(), "svavyom.db")
	if code, _, errs := runCmd(t, passwordFile(t, testPassword), "reset-admin-password", "--db", db); code != 1 || !strings.Contains(errs, "no administrator") {
		t.Fatalf("%d %q", code, errs)
	}
	runCmd(t, passwordFile(t, testPassword), "bootstrap-admin", "--db", db, "--username", "admin")
	if code, out, _ := runCmd(t, passwordFile(t, "a brand new password"), "reset-admin-password", "--db", db); code != 0 || !strings.Contains(out, "sessions revoked") {
		t.Fatalf("%d %q", code, out)
	}
}

func freeAddr(t *testing.T) string {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().String()
}

type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) { s.mu.Lock(); defer s.mu.Unlock(); return s.b.Write(p) }

func (s *syncBuf) String() string { s.mu.Lock(); defer s.mu.Unlock(); return s.b.String() }

func startServer(t *testing.T, extra ...string) (base string, stop func() int) {
	t.Helper()
	db := filepath.Join(t.TempDir(), "svavyom.db")
	if code, _, errs := runCmd(t, passwordFile(t, testPassword), "bootstrap-admin", "--db", db, "--username", "admin"); code != 0 {
		t.Fatal(errs)
	}
	addr := freeAddr(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan int, 1)
	go func() {
		done <- run(ctx, append([]string{"serve", "--db", db, "--listen", addr, "--host-name", "lab"}, extra...), nil, io.Discard, &syncBuf{})
	}()
	deadline := time.Now().Add(10 * time.Second)
	for {
		if res, err := http.Get("http://" + addr + "/healthz"); err == nil {
			res.Body.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("server did not start")
		}
		time.Sleep(20 * time.Millisecond)
	}
	return "http://" + addr, func() int { cancel(); return <-done }
}

func TestServeEndToEndSignInAndHostSummary(t *testing.T) {
	base, stop := startServer(t)
	jar, _ := cookiejar.New(nil)
	c := &http.Client{Jar: jar}
	req := func(method, path, body, csrf string) (*http.Response, []byte) {
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
		b, _ := io.ReadAll(res.Body)
		return res, b
	}
	if res, _ := req("GET", "/api/v1/hosts", "", ""); res.StatusCode != 401 {
		t.Fatalf("anonymous hosts: %d", res.StatusCode)
	}
	res, _ := req("GET", "/api/v1/auth/session", "", "")
	res, body := req("POST", "/api/v1/auth/session", `{"username":"admin","password":"`+testPassword+`"}`, res.Header.Get("X-CSRF-Token"))
	if res.StatusCode != 200 {
		t.Fatalf("sign-in %d %s", res.StatusCode, body)
	}
	csrf := res.Header.Get("X-CSRF-Token")
	res, body = req("GET", "/api/v1/hosts/local", "", "")
	if res.StatusCode != 200 {
		t.Fatalf("host %d %s", res.StatusCode, body)
	}
	var h struct {
		Name     string
		Observed struct {
			CPUCount  int               `json:"cpu_count"`
			MemoryMiB int               `json:"memory_mib"`
			Virt      map[string]string `json:"virtualization"`
		}
	}
	if err := json.Unmarshal(body, &h); err != nil || h.Name != "lab" || h.Observed.CPUCount < 1 || h.Observed.MemoryMiB < 1 || len(h.Observed.Virt) != 4 {
		t.Fatalf("%v %s", err, body)
	}
	if res, _ := req("DELETE", "/api/v1/auth/session", "", csrf); res.StatusCode != 200 {
		t.Fatalf("sign-out %d", res.StatusCode)
	}
	if res, _ := req("GET", "/api/v1/hosts", "", ""); res.StatusCode != 401 {
		t.Fatalf("after sign-out: %d", res.StatusCode)
	}
	if code := stop(); code != 0 {
		t.Fatalf("shutdown code %d", code)
	}
}

func TestServeRefusesPublicListenerWithoutTLS(t *testing.T) {
	db := filepath.Join(t.TempDir(), "svavyom.db")
	for _, addr := range []string{"0.0.0.0:8443", ":8443", "192.0.2.1:8443", "[::]:8443", "localhost.example:8443"} {
		var errb bytes.Buffer
		if code := run(context.Background(), []string{"serve", "--db", db, "--listen", addr}, nil, io.Discard, &errb); code != 2 || !strings.Contains(errb.String(), "non-loopback") {
			t.Errorf("%s: %d %q", addr, code, errb.String())
		}
	}
	var errb bytes.Buffer
	if code := run(context.Background(), []string{"serve", "--db", db, "--tls-cert", "x"}, nil, io.Discard, &errb); code != 2 {
		t.Errorf("cert without key accepted: %d", code)
	}
}

// --behind-tls-proxy must never be a way to put a plaintext listener on a network (CT-PRODUCT-DELIVERY-003 section 1).
func TestBehindTLSProxyDoesNotAllowANonLoopbackPlaintextListener(t *testing.T) {
	db := filepath.Join(t.TempDir(), "svavyom.db")
	for _, addr := range []string{"0.0.0.0:8443", ":8443", "192.0.2.1:8443", "[::]:8443", "10.0.0.5:80"} {
		var errb bytes.Buffer
		code := run(context.Background(), []string{"serve", "--db", db, "--listen", addr, "--behind-tls-proxy"}, nil, io.Discard, &errb)
		if code != 2 || !strings.Contains(errb.String(), "loopback listener") {
			t.Errorf("%s: %d %q", addr, code, errb.String())
		}
	}
	// Proxy mode together with native TLS is a contradiction and is refused too.
	var errb bytes.Buffer
	if code := run(context.Background(), []string{"serve", "--db", db, "--listen", "127.0.0.1:8443", "--behind-tls-proxy", "--tls-cert", "c", "--tls-key", "k"}, nil, io.Discard, &errb); code != 2 {
		t.Errorf("proxy + native TLS accepted: %d", code)
	}
	// The permitted shape: loopback + proxy header trusted.
	base, stop := startServer(t, "--behind-tls-proxy")
	defer stop()
	req, _ := http.NewRequest("GET", base+"/api/v1/auth/session", nil)
	req.Header.Set("X-Forwarded-Proto", "https")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	var secure bool
	for _, c := range res.Cookies() {
		secure = secure || (c.Name == "__Host-svavyom_login" && c.Secure)
	}
	if !secure {
		t.Fatal("loopback proxy mode must honour X-Forwarded-Proto for the Secure cookie")
	}
	// Without the flag the header is ignored.
	base2, stop2 := startServer(t)
	defer stop2()
	req, _ = http.NewRequest("GET", base2+"/api/v1/auth/session", nil)
	req.Header.Set("X-Forwarded-Proto", "https")
	res, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	for _, c := range res.Cookies() {
		if c.Secure {
			t.Fatal("X-Forwarded-Proto honoured without --behind-tls-proxy")
		}
	}
}

func TestServeSecondProcessOnSameDatabaseIsRefused(t *testing.T) {
	base, stop := startServer(t)
	_ = base
	defer stop()
	// The database path of the running server is unknown here, so build a second one that holds the lock itself.
	db := filepath.Join(t.TempDir(), "svavyom.db")
	var errb bytes.Buffer
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan int, 1)
	addr := freeAddr(t)
	go func() { done <- run(ctx, []string{"serve", "--db", db, "--listen", addr}, nil, io.Discard, &errb) }()
	time.Sleep(300 * time.Millisecond)
	var errb2 bytes.Buffer
	if code := run(context.Background(), []string{"serve", "--db", db, "--listen", freeAddr(t)}, nil, io.Discard, &errb2); code != 1 || !strings.Contains(errb2.String(), "already in use") {
		t.Fatalf("%d %q", code, errb2.String())
	}
	cancel()
	<-done
}

func TestStaticFrontendIsServedWithSecurityHeadersAndSPAFallback(t *testing.T) {
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "index.html"), []byte("<!doctype html><title>Svavyom</title>"), 0o644)
	_ = os.WriteFile(filepath.Join(dir, "app.js"), []byte("console.log(1)"), 0o644)
	_ = os.WriteFile(filepath.Join(dir, "secret.txt"), []byte("x"), 0o644)
	base, stop := startServer(t, "--static-dir", dir)
	defer stop()
	for path, want := range map[string]string{"/": "Svavyom", "/dashboard": "Svavyom", "/app.js": "console.log", "/../../etc/passwd": "Svavyom"} {
		res, err := http.Get(base + path)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(res.Body)
		res.Body.Close()
		if res.StatusCode != 200 || !strings.Contains(string(b), want) {
			t.Errorf("%s: %d %q", path, res.StatusCode, b)
		}
		if res.Header.Get("Content-Security-Policy") == "" || res.Header.Get("X-Frame-Options") != "DENY" || res.Header.Get("X-Content-Type-Options") != "nosniff" {
			t.Errorf("%s: missing security headers", path)
		}
	}
	if res, _ := http.Post(base+"/", "text/plain", strings.NewReader("x")); res.StatusCode != 405 {
		t.Errorf("POST /: %d", res.StatusCode)
	}
	if res, _ := http.Get(base + "/api/v1/nonexistent"); res.StatusCode != 404 {
		t.Errorf("api 404 through static wrapper: %d", res.StatusCode)
	}
}

// ADR-011: the unprivileged API must never link libvirt (privilege boundary). The agent is a separate binary.
func TestAPIBinaryDoesNotLinkLibvirt(t *testing.T) {
	out, err := exec.Command("go", "list", "-deps", ".").CombinedOutput() // #nosec G204 -- fixed arguments
	if err != nil {
		t.Skipf("go list unavailable: %v", err)
	}
	if strings.Contains(string(out), "libvirt") {
		t.Fatalf("cmd/api links libvirt:\n%s", out)
	}
}
