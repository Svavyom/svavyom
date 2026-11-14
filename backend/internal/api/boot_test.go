package api

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"time"

	"example.invalid/dedicatedcloud/backend/internal/auth"
)

func (r *crig) vmDesired(b *browser, name string) (power string, box bool, allowed []string) {
	r.t.Helper()
	rep := b.do("GET", "/api/v1/vms/"+name, "", nil)
	var v struct {
		Desired struct {
			Power       string `json:"power"`
			StartOnBoot bool   `json:"start_on_boot"`
		} `json:"desired"`
		Allowed []string `json:"allowed_actions"`
	}
	if rep.status != 200 || json.Unmarshal(rep.body, &v) != nil {
		r.t.Fatalf("GET vm %s: %d %s", name, rep.status, rep.body)
	}
	return v.Desired.Power, v.Desired.StartOnBoot, v.Allowed
}

func (r *crig) flag(name string) bool { return r.sim.Load().Domains[name].Autostart }

func (r *crig) eventually(what string, ok func() bool) {
	r.t.Helper()
	for i := 0; i < 300; i++ {
		if ok() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	r.t.Fatalf("timed out waiting for: %s", what)
}

func (r *crig) action(b *browser, typ, name, key string, params string) reply {
	body := `{"type":"` + typ + `","kind":"VM","id":"` + name + `","idempotency_key":"` + key + `"`
	if params != "" {
		body += `,"params":` + params
	}
	return r.post(b, body+`}`)
}

func TestTheOwnersIntentAndTheBootFlagFollowTheConsole(t *testing.T) {
	r := newCRig(t, true)
	admin := signedIn(t, r.env)
	id := opID(t, r.post(admin, r.createBody("web-1", r.key, nil)))
	r.await(admin, id, "succeeded")

	power, box, allowed := r.vmDesired(admin, "web-1")
	if power != "stopped" || !box {
		t.Fatalf("a new VM: the box is on by default and it is stopped: power=%s box=%v", power, box)
	}
	if !slices.Contains(allowed, "set_start_on_boot") {
		t.Fatalf("the box is offered: %v", allowed)
	}
	if r.flag("web-1") {
		t.Fatal("a stopped VM has no autostart flag")
	}

	r.await(admin, opID(t, r.action(admin, "start", "web-1", "k-start", "")), "succeeded")
	r.eventually("the flag is set after a start", func() bool { return r.flag("web-1") })
	if power, box, _ = r.vmDesired(admin, "web-1"); power != "running" || !box {
		t.Fatalf("after a start: %s %v", power, box)
	}

	// unticking the box clears the flag even though the VM stays running
	r.await(admin, opID(t, r.action(admin, "set_start_on_boot", "web-1", "k-off", `{"autostart":"off"}`)), "succeeded")
	r.eventually("the flag is cleared by unticking the box", func() bool { return !r.flag("web-1") })
	if power, box, _ = r.vmDesired(admin, "web-1"); power != "running" || box {
		t.Fatalf("box off, still running: %s %v", power, box)
	}
	r.await(admin, opID(t, r.action(admin, "set_start_on_boot", "web-1", "k-on", `{"autostart":"on"}`)), "succeeded")
	r.eventually("the flag is back with the box", func() bool { return r.flag("web-1") })

	// a stop through the console is what the owner meant: the flag goes, the box stays
	r.await(admin, opID(t, r.action(admin, "stop", "web-1", "k-stop", "")), "succeeded")
	r.eventually("the flag is cleared by a stop", func() bool { return !r.flag("web-1") })
	if power, box, _ = r.vmDesired(admin, "web-1"); power != "stopped" || !box {
		t.Fatalf("after a stop: %s %v", power, box)
	}
}

func TestACreateCanUntickTheBoxAndTheOperationIsRoleAndCsrfChecked(t *testing.T) {
	r := newCRig(t, true)
	admin := signedIn(t, r.env)
	viewer := r.asRole("vera", auth.RoleViewer)
	id := opID(t, r.post(admin, r.createBody("db-1", r.key, func(c map[string]any) { c["start_on_boot"] = false })))
	r.await(admin, id, "succeeded")
	if _, box, _ := r.vmDesired(admin, "db-1"); box {
		t.Fatal("the box was unticked at creation")
	}
	r.await(admin, opID(t, r.action(admin, "start", "db-1", "k1", "")), "succeeded")
	time.Sleep(300 * time.Millisecond)
	if r.flag("db-1") {
		t.Fatal("a running VM with the box unticked has no autostart flag")
	}
	if rep := r.action(viewer, "set_start_on_boot", "db-1", "v1", `{"autostart":"on"}`); rep.status != 403 {
		t.Errorf("a viewer: %d", rep.status)
	}
	for name, p := range map[string]string{"no params": "", "junk": `{"autostart":"maybe"}`, "extra": `{"autostart":"on","vcpus":2}`} {
		if rep := r.action(admin, "set_start_on_boot", "db-1", "bad-"+name, p); rep.status != 400 {
			t.Errorf("%s: %d %s", name, rep.status, rep.body)
		}
	}
	if rep := r.action(admin, "set_start_on_boot", "ghost-1", "g1", `{"autostart":"on"}`); rep.status != 404 {
		t.Errorf("an unknown VM: %d", rep.status)
	}
	if rep := admin.do("POST", "/api/v1/operations", `{"type":"set_start_on_boot","kind":"VM","id":"db-1","idempotency_key":"nocsrf","params":{"autostart":"on"}}`, nil); rep.status != 403 {
		t.Errorf("without the CSRF token: %d", rep.status)
	}
	if power, _, allowed := r.vmDesired(viewer, "db-1"); power == "" || strings.Contains(strings.Join(allowed, ","), "set_start_on_boot") {
		t.Errorf("a viewer is not offered the box: %v", allowed)
	}
}
