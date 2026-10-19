package api

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"example.invalid/dedicatedcloud/backend/internal/alerts"
	"example.invalid/dedicatedcloud/backend/internal/auth"
)

func (r *crig) raiseAlert(vm string) string {
	r.t.Helper()
	ctx := context.Background()
	_, err := r.engine.Apply(ctx, []alerts.Obs{{Type: alerts.VMCrashed, Kind: "VM", ResourceID: vm, Severity: alerts.Critical, Active: true}}, nil)
	if err != nil {
		r.t.Fatal(err)
	}
	a, ok, _ := r.astore.ByKey(ctx, "vm_crashed|VM|"+vm)
	if !ok {
		r.t.Fatal("alert not stored")
	}
	return a.ID
}

type eventList struct {
	Items []struct {
		ID      string   `json:"id"`
		State   string   `json:"state"`
		Type    string   `json:"type"`
		Allowed []string `json:"allowed_actions"`
	} `json:"items"`
	Next *string `json:"next_cursor"`
}

func TestAlertsAreListedReadAndAcknowledged(t *testing.T) {
	r := newCRig(t, true)
	admin := signedIn(t, r.env)
	if rep := admin.do("GET", "/api/v1/events", "", nil); rep.status != 200 || !strings.Contains(string(rep.body), `"items":[]`) {
		t.Fatalf("no alerts yet: %d %s", rep.status, rep.body)
	}
	id := r.raiseAlert("web-1")
	var l eventList
	rep := admin.do("GET", "/api/v1/events", "", nil)
	if err := json.Unmarshal(rep.body, &l); err != nil || len(l.Items) != 1 || l.Items[0].ID != id || l.Items[0].State != "open" || l.Items[0].Type != "vm_crashed" ||
		len(l.Items[0].Allowed) != 1 || l.Items[0].Allowed[0] != "acknowledge" {
		t.Fatalf("%v %s", err, rep.body)
	}
	if one := admin.do("GET", "/api/v1/events/"+id, "", nil); one.status != 200 || !strings.Contains(string(one.body), `"severity":"critical"`) {
		t.Fatalf("%d %s", one.status, one.body)
	}
	if h := admin.do("GET", "/api/v1/hosts/local", "", nil); !strings.Contains(string(h.body), `"alerts":{"open":1,"webhook":"none"}`) {
		t.Fatalf("host summary: %s", h.body)
	}
	op := r.post(admin, `{"type":"alert_acknowledge","kind":"Event","id":"`+id+`","idempotency_key":"ack-1"}`)
	if op.status != 202 {
		t.Fatalf("%d %s", op.status, op.body)
	}
	r.await(admin, opID(t, op), "succeeded")
	a, _, _ := r.astore.ByID(context.Background(), id)
	if a.State != alerts.StateAcknowledged {
		t.Fatalf("state %s", a.State)
	}
	if h := admin.do("GET", "/api/v1/hosts/local", "", nil); !strings.Contains(string(h.body), `"alerts":{"open":0,`) {
		t.Fatalf("an acknowledged alert is no longer counted open: %s", h.body)
	}
	if one := admin.do("GET", "/api/v1/events/"+id, "", nil); !strings.Contains(string(one.body), `"allowed_actions":[]`) {
		t.Fatalf("nothing left to do: %s", one.body)
	}
	// Replaying the same request returns the same operation; a different key acknowledges again harmlessly.
	if again := r.post(admin, `{"type":"alert_acknowledge","kind":"Event","id":"`+id+`","idempotency_key":"ack-2"}`); again.status != 202 {
		t.Fatalf("%d %s", again.status, again.body)
	}
}

func TestAlertAcknowledgeIsGuarded(t *testing.T) {
	r := newCRig(t, true)
	id := r.raiseAlert("web-1")
	v := r.asRole("vera", auth.RoleViewer)
	if rep := r.submitAs(v, "alert_acknowledge", "Event", id); rep.status != 403 {
		t.Errorf("viewer: %d %s", rep.status, rep.body)
	}
	if rep := v.do("GET", "/api/v1/events/"+id, "", nil); rep.status != 200 || !strings.Contains(string(rep.body), `"allowed_actions":[]`) {
		t.Errorf("a viewer reads alerts and is offered no action: %d %s", rep.status, rep.body)
	}
	o := r.asRole("olly", auth.RoleOperator)
	for name, body := range map[string]string{
		"unknown":     `{"type":"alert_acknowledge","kind":"Event","id":"al-00000000000000aa","idempotency_key":"k1"}`,
		"bad id":      `{"type":"alert_acknowledge","kind":"Event","id":"web-1","idempotency_key":"k2"}`,
		"wrong kind":  `{"type":"alert_acknowledge","kind":"VM","id":"` + id + `","idempotency_key":"k3"}`,
		"wrong type":  `{"type":"start","kind":"Event","id":"` + id + `","idempotency_key":"k4"}`,
		"with params": `{"type":"alert_acknowledge","kind":"Event","id":"` + id + `","idempotency_key":"k5","params":{"disk_gib":5}}`,
	} {
		rep := r.post(o, body)
		if rep.status == 202 {
			t.Errorf("%s accepted: %s", name, rep.body)
		}
	}
	if rep := r.post(o, `{"type":"alert_acknowledge","kind":"Event","id":"al-00000000000000aa","idempotency_key":"k1"}`); rep.status != 404 {
		t.Errorf("unknown alert: %d %s", rep.status, rep.body)
	}
	// A resolved alert has nothing left to acknowledge.
	ctx := context.Background()
	for i := 0; i < alerts.ClearAfter; i++ {
		_, _ = r.engine.Apply(ctx, nil, []string{alerts.VMCrashed})
	}
	if rep := r.submitAs(o, "alert_acknowledge", "Event", id); rep.status != 409 {
		t.Errorf("resolved: %d %s", rep.status, rep.body)
	}
}

func TestEventsRouteNeedsASessionAndValidInput(t *testing.T) {
	r := newCRig(t, true)
	anon := r.browser()
	for _, p := range []string{"/api/v1/events", "/api/v1/events/al-0000000000000001"} {
		if rep := anon.do("GET", p, "", nil); rep.status != 401 {
			t.Errorf("%s: %d", p, rep.status)
		}
	}
	admin := signedIn(t, r.env)
	for _, p := range []string{"/api/v1/events?limit=0", "/api/v1/events?limit=1000", "/api/v1/events?cursor=%21", "/api/v1/events?state=open", "/api/v1/events?limit=1&limit=2",
		"/api/v1/events/al-0000000000000001?x=1"} {
		if rep := admin.do("GET", p, "", nil); rep.status != 400 {
			t.Errorf("%s: %d %s", p, rep.status, rep.body)
		}
	}
	for _, p := range []string{"/api/v1/events/al-0000000000000001", "/api/v1/events/nonsense"} {
		if rep := admin.do("GET", p, "", nil); rep.status != 404 {
			t.Errorf("%s: %d", p, rep.status)
		}
	}
}

func TestEventsPageThroughCursor(t *testing.T) {
	r := newCRig(t, true)
	admin := signedIn(t, r.env)
	for _, vm := range []string{"a1", "a2", "a3", "a4", "a5"} {
		r.raiseAlert(vm)
	}
	seen := map[string]bool{}
	path := "/api/v1/events?limit=2"
	for pages := 0; pages < 5; pages++ {
		var l eventList
		rep := admin.do("GET", path, "", nil)
		if err := json.Unmarshal(rep.body, &l); err != nil {
			t.Fatalf("%v %s", err, rep.body)
		}
		for _, it := range l.Items {
			if seen[it.ID] {
				t.Fatalf("duplicate %s", it.ID)
			}
			seen[it.ID] = true
		}
		if l.Next == nil {
			break
		}
		path = "/api/v1/events?limit=2&cursor=" + *l.Next
	}
	if len(seen) != 5 {
		t.Fatalf("paged through %d of 5", len(seen))
	}
}
