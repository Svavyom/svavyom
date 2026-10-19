package api

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"
	"time"

	"example.invalid/dedicatedcloud/backend/internal/hypervisor"
)

type fakeVMs struct {
	domains []hypervisor.Domain
	err     error
}

func (f *fakeVMs) List(context.Context) ([]hypervisor.Domain, error) { return f.domains, f.err }
func (f *fakeVMs) Lookup(_ context.Context, n string) (hypervisor.Domain, error) {
	if f.err != nil {
		return hypervisor.Domain{}, f.err
	}
	for _, d := range f.domains {
		if d.Name == n {
			return d, nil
		}
	}
	return hypervisor.Domain{}, hypervisor.NewError(hypervisor.NotFound, "lookup", n, "x")
}

func (e *env) withVMs(vms hypervisor.Reader) {
	e.srv.Close()
	e.h = NewHandlerWith(Deps{Auth: e.svc, Hosts: e.hosts, VMs: vms, Now: func() time.Time { return time.Date(2026, 10, 9, 9, 0, 0, 0, time.UTC) }})
	e.srv = httptest.NewServer(e.h)
	e.t.Cleanup(e.srv.Close)
}

func threeVMs() *fakeVMs {
	return &fakeVMs{domains: []hypervisor.Domain{
		{Name: "db-1", State: hypervisor.StateShutoff}, {Name: "web-1", State: hypervisor.StateRunning}, {Name: "wk-1", State: hypervisor.StatePaused},
		{Name: "x-crash", State: hypervisor.StateCrashed}, {Name: "y-odd", State: hypervisor.StateUnknown}}}
}

func TestVMRoutesRequireASession(t *testing.T) {
	e := newEnv(t, true)
	e.withVMs(threeVMs())
	anon := e.browser()
	for _, p := range []string{"/api/v1/vms", "/api/v1/vms/web-1", "/api/v1/vms?limit=bogus", "/api/v1/vms/%00"} {
		r := anon.do("GET", p, "", nil)
		if r.status != 401 || catOf(t, r) != "unauthenticated" {
			t.Errorf("%s: %d %s", p, r.status, r.body)
		}
	}
}

func TestListVMsExactFieldsAndPowerMapping(t *testing.T) {
	e := newEnv(t, true)
	e.withVMs(threeVMs())
	b := signedIn(t, e)
	r := b.do("GET", "/api/v1/vms", "", nil)
	if r.status != 200 || r.header.Get("Cache-Control") != "no-store" {
		t.Fatalf("%d %v", r.status, r.header)
	}
	if got := strings.Join(keys(t, r.body), ","); got != "allowed_actions,items,next_cursor" {
		t.Fatalf("%s", got)
	}
	var list struct {
		Items []json.RawMessage `json:"items"`
		Next  *string           `json:"next_cursor"`
		Allow []string          `json:"allowed_actions"`
	}
	_ = json.Unmarshal(r.body, &list)
	if len(list.Items) != 5 || list.Next != nil || len(list.Allow) != 0 {
		t.Fatalf("%s", r.body)
	}
	powers := map[string]string{}
	for _, raw := range list.Items {
		if got := strings.Join(keys(t, raw), ","); got != "allowed_actions,desired,generation,id,name,observed,project_id" {
			t.Fatalf("vm keys %s", got)
		}
		var v vmJSON
		if err := json.Unmarshal(raw, &v); err != nil {
			t.Fatal(err)
		}
		if v.ProjectID != "default" || len(v.Allowed) != 0 || v.Observed.LastSeenAt != "2026-10-09T09:00:00Z" || v.ID != v.Name {
			t.Fatalf("%+v", v)
		}
		powers[v.ID] = v.Observed.Power + "/" + v.Desired.Power
	}
	want := map[string]string{"db-1": "stopped/stopped", "web-1": "running/running", "wk-1": "paused/stopped", "x-crash": "crashed/stopped", "y-odd": "unknown/stopped"}
	for k, v := range want {
		if powers[k] != v {
			t.Errorf("%s: %s, want %s", k, powers[k], v)
		}
	}
	for _, leak := range []string{"<domain", "xml", "/etc", "/var", "uuid", "libvirt", "qemu"} {
		if strings.Contains(strings.ToLower(string(r.body)), leak) {
			t.Errorf("response contains %q", leak)
		}
	}
}

func TestListVMsEmptyAndPaged(t *testing.T) {
	e := newEnv(t, true)
	e.withVMs(&fakeVMs{})
	b := signedIn(t, e)
	if r := b.do("GET", "/api/v1/vms", "", nil); r.status != 200 || !strings.Contains(string(r.body), `"items":[]`) || !strings.Contains(string(r.body), `"next_cursor":null`) {
		t.Fatalf("%d %s", r.status, r.body)
	}
	many := &fakeVMs{}
	for i := 0; i < 7; i++ {
		many.domains = append(many.domains, hypervisor.Domain{Name: fmt.Sprintf("vm-%02d", i), State: hypervisor.StateRunning})
	}
	e.withVMs(many)
	b = signedIn(t, e)
	var seen []string
	cursor := ""
	for page := 0; page < 10; page++ {
		path := "/api/v1/vms?limit=3"
		if cursor != "" {
			path += "&cursor=" + cursor
		}
		r := b.do("GET", path, "", nil)
		var got struct {
			Items []struct{ ID string }
			Next  *string `json:"next_cursor"`
		}
		if r.status != 200 || json.Unmarshal(r.body, &got) != nil {
			t.Fatalf("%d %s", r.status, r.body)
		}
		for _, it := range got.Items {
			seen = append(seen, it.ID)
		}
		if got.Next == nil {
			break
		}
		cursor = *got.Next
	}
	if len(seen) != 7 || !sort.StringsAreSorted(seen) {
		t.Fatalf("paging lost or duplicated items: %v", seen)
	}
}

func TestReadVMAndTypedFailures(t *testing.T) {
	e := newEnv(t, true)
	vms := threeVMs()
	e.withVMs(vms)
	b := signedIn(t, e)
	if r := b.do("GET", "/api/v1/vms/web-1", "", nil); r.status != 200 || strings.Join(keys(t, r.body), ",") != "allowed_actions,desired,generation,id,name,observed,project_id" {
		t.Fatalf("%d %s", r.status, r.body)
	}
	for p, want := range map[string]int{
		"/api/v1/vms/absent": 404, "/api/v1/vms/-bad": 400, "/api/v1/vms/web-1?x=1": 400, "/api/v1/vms/a%20b": 400, "/api/v1/vms/" + strings.Repeat("a", 64): 400,
		"/api/v1/vms?limit=0": 400, "/api/v1/vms?limit=201": 400, "/api/v1/vms?cursor=!!": 400, "/api/v1/vms?cursor=" + base64.RawURLEncoding.EncodeToString([]byte("../x")): 400,
		"/api/v1/vms?other=1": 400, "/api/v1/vms?limit=1&limit=2": 400,
	} {
		if r := b.do("GET", p, "", nil); r.status != want {
			t.Errorf("%s: %d, want %d (%s)", p, r.status, want, r.body)
		}
	}
	for cat, want := range map[hypervisor.Category]struct {
		status int
		name   string
	}{hypervisor.Unavailable: {503, "unavailable"}, hypervisor.Timeout: {503, "unavailable"}, hypervisor.HostError: {500, "internal"}, hypervisor.Conflict: {500, "internal"}} {
		vms.err = hypervisor.NewError(cat, "x", "d", "libvirt: /etc/libvirt/secret password=hunter2")
		for _, p := range []string{"/api/v1/vms", "/api/v1/vms/web-1"} {
			r := b.do("GET", p, "", nil)
			if r.status != want.status || catOf(t, r) != want.name || strings.Contains(string(r.body), "hunter2") {
				t.Errorf("%s %s: %d %s", cat, p, r.status, r.body)
			}
		}
	}
	vms.err = errors.New("anything")
	if r := b.do("GET", "/api/v1/vms", "", nil); r.status != 500 {
		t.Errorf("untyped error: %d", r.status)
	}
}

func TestVMRoutesStayClosedWithoutAnAgent(t *testing.T) {
	e := newEnv(t, true) // newEnv wires no VM source
	b := signedIn(t, e)
	if r := b.do("GET", "/api/v1/vms", "", nil); r.status != 401 {
		t.Fatalf("%d", r.status)
	}
}

func TestNoMutationRouteExistsForVMs(t *testing.T) {
	e := newEnv(t, true)
	e.withVMs(threeVMs())
	b := signedIn(t, e)
	for _, m := range []string{"POST", "PUT", "PATCH", "DELETE"} {
		for _, p := range []string{"/api/v1/vms", "/api/v1/vms/web-1", "/api/v1/vms/web-1/start", "/api/v1/operations"} {
			r := b.do(m, p, `{"type":"start","kind":"VM","id":"web-1","idempotency_key":"k"}`, map[string]string{"X-CSRF-Token": b.csrf})
			if r.status == 200 || r.status == 202 {
				t.Errorf("%s %s succeeded (%d)", m, p, r.status)
			}
		}
	}
	if r := b.do("POST", "/api/v1/operations", `{"type":"start","kind":"VM","id":"web-1","idempotency_key":"k"}`, map[string]string{"X-CSRF-Token": b.csrf}); r.status != 401 {
		t.Errorf("operations stay rejected as unauthenticated (not implemented): %d", r.status)
	}
}
