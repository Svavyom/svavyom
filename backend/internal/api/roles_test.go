package api

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"example.invalid/dedicatedcloud/backend/internal/auth"
)

const rolePass = "another long passphrase"

// asRole creates a user with the role and returns a browser signed in as that user.
func (r *crig) asRole(name string, role auth.Role) *browser {
	r.t.Helper()
	if err := r.svc.AddUser(context.Background(), name, rolePass, role); err != nil {
		r.t.Fatal(err)
	}
	b := r.browser()
	b.status()
	if rep := b.signIn(name, rolePass); rep.status != 200 {
		r.t.Fatalf("sign-in %s: %d %s", name, rep.status, rep.body)
	}
	return b
}

func (r *crig) submitAs(b *browser, typ, kind, id string) reply {
	return r.post(b, `{"type":"`+typ+`","kind":"`+kind+`","id":"`+id+`","idempotency_key":"role-`+typ+`-`+id+`"}`)
}

func TestTheSessionReportsTheRole(t *testing.T) {
	r := newCRig(t, true)
	for name, role := range map[string]auth.Role{"olly": auth.RoleOperator, "vera": auth.RoleViewer} {
		b := r.asRole(name, role)
		var s struct {
			Authenticated bool   `json:"authenticated"`
			Username      string `json:"username"`
			Role          string `json:"role"`
		}
		if err := json.Unmarshal(b.status().body, &s); err != nil || !s.Authenticated || s.Username != name || s.Role != string(role) {
			t.Errorf("%s: %+v %v", name, s, err)
		}
	}
	admin := signedIn(t, r.env)
	if !strings.Contains(string(admin.status().body), `"role":"admin"`) {
		t.Errorf("%s", admin.status().body)
	}
}

func TestAViewerReadsEverythingAndChangesNothing(t *testing.T) {
	r := newCRig(t, true)
	admin := signedIn(t, r.env)
	r.await(admin, opID(t, r.post(admin, r.createBody("web-1", r.key, nil))), "succeeded")
	v := r.asRole("vera", auth.RoleViewer)
	for _, p := range []string{"/api/v1/hosts", "/api/v1/vms", "/api/v1/vms/web-1", "/api/v1/images", "/api/v1/backups", "/api/v1/virtual-networks", "/api/v1/operations"} {
		if rep := v.do("GET", p, "", nil); rep.status != 200 {
			t.Errorf("a viewer must read %s: %d %s", p, rep.status, rep.body)
		}
	}
	vm := v.do("GET", "/api/v1/vms/web-1", "", nil)
	if !strings.Contains(string(vm.body), `"allowed_actions":[]`) {
		t.Errorf("a viewer is offered no action: %s", vm.body)
	}
	for _, typ := range []string{"start", "stop", "reboot", "force_off", "delete"} {
		if rep := r.submitAs(v, typ, "VM", "web-1"); rep.status != 403 || catOf(t, rep) != "forbidden" {
			t.Errorf("viewer %s: %d %s", typ, rep.status, rep.body)
		}
	}
	if rep := r.post(v, r.createBody("web-2", r.key, nil)); rep.status != 403 {
		t.Errorf("viewer create: %d %s", rep.status, rep.body)
	}
	if got := admin.do("GET", "/api/v1/vms/web-2", "", nil); got.status != 404 {
		t.Errorf("nothing may have been created: %d", got.status)
	}
}

func TestAnOperatorManagesVMsButNotNetworksOrBackupDeletion(t *testing.T) {
	r := newCRig(t, true)
	o := r.asRole("olly", auth.RoleOperator)
	id := opID(t, r.post(o, r.createBody("web-1", r.key, nil)))
	if op := r.await(o, id, "succeeded"); op["requested_by"] != "olly" {
		t.Fatalf("%v", op)
	}
	r.await(o, opID(t, r.submitAs(o, "start", "VM", "web-1")), "succeeded")
	vm := o.do("GET", "/api/v1/vms/web-1", "", nil)
	if !strings.Contains(string(vm.body), `"stop"`) {
		t.Errorf("an operator keeps the lifecycle actions: %s", vm.body)
	}
	for _, typ := range []string{"network_create", "network_stop", "network_start", "network_delete", "network_autostart"} {
		body := `{"type":"` + typ + `","kind":"VirtualNetwork","id":"lab-net","idempotency_key":"role-` + typ + `"}`
		if rep := r.post(o, body); rep.status == 202 {
			t.Errorf("an operator must not submit %s: %d %s", typ, rep.status, rep.body)
		}
	}
	if rep := r.submitAs(o, "delete", "Backup", "does-not-matter"); rep.status != 403 {
		t.Errorf("an operator must not delete a backup: %d %s", rep.status, rep.body)
	}
}

func TestADisabledOrDemotedUserLosesAccessAtOnce(t *testing.T) {
	r := newCRig(t, true)
	o := r.asRole("olly", auth.RoleOperator)
	if err := r.svc.SetRole(context.Background(), "olly", auth.RoleViewer); err != nil {
		t.Fatal(err)
	}
	if rep := o.do("GET", "/api/v1/vms", "", nil); rep.status != 401 {
		t.Fatalf("the demotion ends the session: %d", rep.status)
	}
	again := r.browser()
	again.status()
	if rep := again.signIn("olly", rolePass); rep.status != 200 || !strings.Contains(string(rep.body), `"viewer"`) {
		t.Fatalf("%d %s", rep.status, rep.body)
	}
	if rep := r.submitAs(again, "start", "VM", "web-1"); rep.status != 403 {
		t.Fatalf("%d %s", rep.status, rep.body)
	}
}

func TestSnapshotActionFollowsTheHostsCapability(t *testing.T) {
	r := newCRig(t, true)
	b := signedIn(t, r.env)
	r.await(b, opID(t, r.post(b, r.createBody("web-1", r.key, nil))), "succeeded")
	host := b.do("GET", "/api/v1/hosts/local", "", nil)
	if !strings.Contains(string(host.body), `"snapshots":"available"`) {
		t.Fatalf("%s", host.body)
	}
	if vm := b.do("GET", "/api/v1/vms/web-1", "", nil); !strings.Contains(string(vm.body), `"snapshot"`) {
		t.Fatalf("a pool of files offers the snapshot action: %s", vm.body)
	}
	// a block-backed pool cannot hold internal snapshots: the host says so, the action disappears and a submit is refused
	r.poolType = "logical"
	r.h.snapAt = r.h.snapAt.AddDate(-1, 0, 0) // the cached answer is stale
	host = b.do("GET", "/api/v1/hosts/local", "", nil)
	if !strings.Contains(string(host.body), `"snapshots":"unavailable"`) {
		t.Fatalf("%s", host.body)
	}
	if vm := b.do("GET", "/api/v1/vms/web-1", "", nil); strings.Contains(string(vm.body), `"snapshot"`) || !strings.Contains(string(vm.body), `"start"`) {
		t.Fatalf("no snapshot action, the others stay: %s", vm.body)
	}
	if rep := r.submitAs(b, "snapshot", "VM", "web-1"); rep.status != 409 {
		t.Fatalf("%d %s", rep.status, rep.body)
	}
}
