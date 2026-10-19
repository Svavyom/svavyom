//go:build libvirt && libvirt_test

package agent_test

// The whole production chain of the inventory slice, with libvirt's in-process TEST driver at the bottom:
//   HTTP client -> API handler (real sessions) -> agent client -> Unix socket -> agent server -> libvirt read-only adapter.
// Simulation, not a real hypervisor or KVM.

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	libvirt "libvirt.org/go/libvirt"

	"example.invalid/dedicatedcloud/backend/internal/agent"
	"example.invalid/dedicatedcloud/backend/internal/api"
	"example.invalid/dedicatedcloud/backend/internal/auth"
	"example.invalid/dedicatedcloud/backend/internal/hostinfo"
	"example.invalid/dedicatedcloud/backend/internal/hypervisor/libvirtro"
	"example.invalid/dedicatedcloud/backend/internal/sqlitedb"
)

type hostStub struct{}

func (hostStub) Host(context.Context) (hostinfo.Info, error) {
	return hostinfo.Info{ID: "local", Name: "h"}, nil
}

func TestInventoryThroughTheWholeChain(t *testing.T) {
	// libvirt side: a writer connection populates the test driver; the agent only ever has a read-only connection.
	w, err := libvirt.NewConnect(libvirtro.TestURI)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	def := func(n string) *libvirt.Domain {
		d, err := w.DomainDefineXML(`<domain type="test"><name>` + n + `</name><memory unit="MiB">64</memory><vcpu>1</vcpu><os><type>hvm</type></os></domain>`)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = d.Destroy(); _ = d.Undefine(); _ = d.Free() })
		return d
	}
	def("chain-stopped")
	if err := def("chain-running").Create(); err != nil {
		t.Fatal(err)
	}

	ro, err := libvirtro.Open(libvirtro.TestURI)
	if err != nil {
		t.Fatal(err)
	}
	defer ro.Close()
	dir, _ := os.MkdirTemp("", "ch")
	defer os.RemoveAll(dir)
	sock := filepath.Join(dir, "agent.sock")
	srv, err := agent.Listen(sock, ro, []uint32{uint32(os.Getuid())}) // #nosec G115
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- srv.Serve() }()
	defer func() { srv.Close(); <-done }()
	cl, err := agent.NewClient(sock, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}

	db, err := sqlitedb.Open(filepath.Join(dir, "s.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	svc, err := auth.New(context.Background(), db, auth.Config{Params: auth.Params{MemoryKiB: 19 * 1024, Time: 2, Threads: 1, SaltLen: 16, KeyLen: 32}})
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.Bootstrap(context.Background(), "admin", "correct horse battery"); err != nil {
		t.Fatal(err)
	}
	web := httptest.NewServer(api.NewHandlerWith(api.Deps{Auth: svc, Hosts: hostStub{}, VMs: cl}))
	defer web.Close()
	jar, _ := cookiejar.New(nil)
	c := &http.Client{Jar: jar}
	do := func(method, path, body, csrf string) (*http.Response, []byte) {
		r, _ := http.NewRequest(method, web.URL+path, strings.NewReader(body))
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
	if res, _ := do("GET", "/api/v1/vms", "", ""); res.StatusCode != 401 {
		t.Fatalf("anonymous: %d", res.StatusCode)
	}
	res, _ := do("GET", "/api/v1/auth/session", "", "")
	if res, b := do("POST", "/api/v1/auth/session", `{"username":"admin","password":"correct horse battery"}`, res.Header.Get("X-CSRF-Token")); res.StatusCode != 200 {
		t.Fatalf("%d %s", res.StatusCode, b)
	}
	res, body := do("GET", "/api/v1/vms", "", "")
	if res.StatusCode != 200 {
		t.Fatalf("%d %s", res.StatusCode, body)
	}
	var list struct {
		Items []struct {
			ID       string
			Observed struct{ Power string }
		}
	}
	_ = json.Unmarshal(body, &list)
	got := map[string]string{}
	for _, v := range list.Items {
		got[v.ID] = v.Observed.Power
	}
	if got["chain-running"] != "running" || got["chain-stopped"] != "stopped" {
		t.Fatalf("%v", got)
	}
	if res, body := do("GET", "/api/v1/vms/chain-running", "", ""); res.StatusCode != 200 || !strings.Contains(string(body), `"power":"running"`) {
		t.Fatalf("%d %s", res.StatusCode, body)
	}
	if res, _ := do("GET", "/api/v1/vms/chain-absent", "", ""); res.StatusCode != 404 {
		t.Fatalf("absent: %d", res.StatusCode)
	}
	// The libvirt side changes: the next read reflects it (nothing is cached across requests).
	d, _ := w.LookupDomainByName("chain-running")
	_ = d.Destroy()
	_ = d.Free()
	if _, body := do("GET", "/api/v1/vms/chain-running", "", ""); !strings.Contains(string(body), `"power":"stopped"`) {
		t.Fatalf("stale: %s", body)
	}
	// The agent goes away: typed unavailable, no leak of socket paths.
	srv.Close()
	<-done
	res, body = do("GET", "/api/v1/vms", "", "")
	if res.StatusCode != 503 || strings.Contains(string(body), sock) || strings.Contains(string(body), "agent") {
		t.Fatalf("agent down: %d %s", res.StatusCode, body)
	}
	done <- nil
}
