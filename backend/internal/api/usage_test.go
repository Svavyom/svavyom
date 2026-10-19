package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"testing"
	"time"

	"example.invalid/dedicatedcloud/backend/internal/metrics"
)

// fakeUsage is the sampler as the API sees it.
type fakeUsage struct {
	host metrics.HostUsage
	vms  map[string]metrics.VMUsage
}

func (f fakeUsage) Host(context.Context) metrics.HostUsage         { return f.host }
func (f fakeUsage) VMs(context.Context) map[string]metrics.VMUsage { return f.vms }

func ip(n int) *int       { return &n }
func ip64(n int64) *int64 { return &n }

func TestHostAndVMUsageAreExposedWithBoundedClosedShapes(t *testing.T) {
	at := time.Date(2026, 10, 13, 9, 0, 0, 0, time.UTC)
	r := newCRig(t, true)
	r.usage = fakeUsage{
		host: metrics.HostUsage{Available: true, IntervalSeconds: 30, CPUPercent: ip(40), MemUsedMiB: ip64(2048),
			History: []metrics.HostPoint{{At: at, CPUPercent: 30, MemUsedMiB: 2000}, {At: at.Add(30 * time.Second), CPUPercent: 40, MemUsedMiB: 2048}}},
		vms: map[string]metrics.VMUsage{"web-1": {Available: true, CPUPercent: ip(12), History: []metrics.VMPoint{{At: at, CPUPercent: 12}}}},
	}
	r.wire()
	b := signedIn(t, r.env)
	id := opID(t, r.post(b, r.createBody("web-1", r.key, nil)))
	r.await(b, id, "succeeded")
	id = opID(t, r.post(b, `{"type":"start","kind":"VM","id":"web-1","idempotency_key":"start-web-1"}`))
	r.await(b, id, "succeeded")

	var host hostJSON
	if rep := b.do("GET", "/api/v1/hosts/local", "", nil); rep.status != 200 || json.Unmarshal(rep.body, &host) != nil {
		t.Fatalf("%d %s", rep.status, rep.body)
	}
	u := host.Observed.Usage
	if u.State != "available" || u.IntervalSeconds != 30 || u.CPUPercent == nil || *u.CPUPercent != 40 || *u.MemoryUsedMiB != 2048 || len(u.History) != 2 || u.History[0].At != "2026-10-13T09:00:00Z" {
		t.Fatalf("host usage %+v", u)
	}
	var v vmJSON
	if rep := b.do("GET", "/api/v1/vms/web-1", "", nil); rep.status != 200 || json.Unmarshal(rep.body, &v) != nil {
		t.Fatalf("%d %s", rep.status, rep.body)
	}
	if v.Observed.VCPUs == nil || *v.Observed.VCPUs != 2 || v.Observed.MemoryMiB == nil || *v.Observed.MemoryMiB != 1024 {
		t.Fatalf("size %+v", v.Observed)
	}
	if v.Observed.Usage.State != "available" || *v.Observed.Usage.CPUPercent != 12 || len(v.Observed.Usage.History) != 1 {
		t.Fatalf("vm usage %+v", v.Observed.Usage)
	}
	// the list carries the same fields; a VM without samples says so plainly
	var l struct{ Items []vmJSON }
	rep := b.do("GET", "/api/v1/vms", "", nil)
	if json.Unmarshal(rep.body, &l) != nil || len(l.Items) != 1 || l.Items[0].Observed.Usage.State != "available" {
		t.Fatalf("%s", rep.body)
	}
}

func TestWithoutASamplerUsageIsUnavailableNotInvented(t *testing.T) {
	r := newCRig(t, true)
	b := signedIn(t, r.env)
	id := opID(t, r.post(b, r.createBody("web-2", r.key, nil)))
	r.await(b, id, "succeeded")
	var host hostJSON
	_ = json.Unmarshal(b.do("GET", "/api/v1/hosts/local", "", nil).body, &host)
	if u := host.Observed.Usage; u.State != "unavailable" || u.CPUPercent != nil || u.MemoryUsedMiB != nil || u.History == nil || len(u.History) != 0 || u.IntervalSeconds < 1 {
		t.Fatalf("host usage %+v", u)
	}
	var v vmJSON
	_ = json.Unmarshal(b.do("GET", "/api/v1/vms/web-2", "", nil).body, &v)
	if u := v.Observed.Usage; u.State != "unavailable" || u.CPUPercent != nil || u.History == nil || len(u.History) != 0 {
		t.Fatalf("vm usage %+v", u)
	}
}

func TestOperationsListNewestFirstPagedAndClosed(t *testing.T) {
	r := newCRig(t, true)
	b := signedIn(t, r.env)
	var ids []string
	for i := 1; i <= 3; i++ {
		id := opID(t, r.post(b, r.createBody(fmt.Sprintf("list-%d", i), r.key, nil)))
		r.await(b, id, "succeeded")
		ids = append(ids, id)
	}
	type page struct {
		Items []struct {
			ID         string `json:"id"`
			ResourceID string `json:"resource_id"`
		} `json:"items"`
		Allowed []string `json:"allowed_actions"`
		Next    *string  `json:"next_cursor"`
	}
	get := func(q string) (page, reply) {
		rep := b.do("GET", "/api/v1/operations"+q, "", nil)
		var p page
		_ = json.Unmarshal(rep.body, &p)
		return p, rep
	}
	p, rep := get("?limit=2")
	if rep.status != 200 || len(p.Items) != 2 || p.Items[0].ID != ids[2] || p.Items[1].ID != ids[1] || p.Next == nil || p.Allowed == nil || len(p.Allowed) != 0 {
		t.Fatalf("first page %d %s", rep.status, rep.body)
	}
	p2, rep2 := get("?limit=2&cursor=" + url.QueryEscape(*p.Next))
	if rep2.status != 200 || len(p2.Items) != 1 || p2.Items[0].ID != ids[0] || p2.Next != nil {
		t.Fatalf("second page %d %s", rep2.status, rep2.body)
	}
	// an operation list shows exactly the fields of an operation read: nothing about the request body or the key
	var m struct{ Items []json.RawMessage }
	_ = json.Unmarshal(rep.body, &m)
	if got := strings.Join(keys(t, m.Items[0]), ","); got != "allowed_actions,attempts,created_at,error_category,generation,id,project_id,requested_by,resource_id,resource_kind,status,type,updated_at" {
		t.Fatalf("operation fields %s", got)
	}
	for _, bad := range []string{"?limit=0", "?limit=201", "?cursor=!!", "?extra=1", "?limit=1&limit=2"} {
		if _, rep := get(bad); rep.status != 422 && rep.status != 400 {
			t.Fatalf("%s -> %d %s", bad, rep.status, rep.body)
		}
	}
	// no session, no list
	anon := r.env.browser()
	if rep := anon.do("GET", "/api/v1/operations", "", nil); rep.status != 401 {
		t.Fatalf("anonymous list %d %s", rep.status, rep.body)
	}
}

func TestOperationsListIsEmptyWhereNoOperationsCanExist(t *testing.T) {
	e := newEnv(t, true)
	b := signedIn(t, e)
	rep := b.do("GET", "/api/v1/operations", "", nil)
	var p struct {
		Items []json.RawMessage `json:"items"`
		Next  *string           `json:"next_cursor"`
	}
	if rep.status != 200 || json.Unmarshal(rep.body, &p) != nil || p.Items == nil || len(p.Items) != 0 || p.Next != nil {
		t.Fatalf("%d %s", rep.status, rep.body)
	}
}
