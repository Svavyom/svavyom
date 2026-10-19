package api

import (
	"encoding/json"
	"strings"
	"testing"

	"example.invalid/dedicatedcloud/backend/internal/auth"
)

type volReply struct {
	ID      string `json:"id"`
	Desired struct {
		SizeGiB    int     `json:"size_gib"`
		AttachedTo *string `json:"attached_to"`
	} `json:"desired"`
	Observed struct {
		State string `json:"state"`
	} `json:"observed"`
	Allowed []string `json:"allowed_actions"`
}

func (r *crig) volume(b *browser, id string) (volReply, int) {
	r.t.Helper()
	rep := b.do("GET", "/api/v1/volumes/"+id, "", nil)
	var v volReply
	_ = json.Unmarshal(rep.body, &v)
	return v, rep.status
}

func (r *crig) volOp(b *browser, typ, id, params string) reply {
	body := `{"type":"` + typ + `","kind":"Volume","id":"` + id + `","idempotency_key":"vol-` + typ + `-` + id + `"`
	if params != "" {
		body += `,"params":` + params
	}
	return r.post(b, body+"}")
}

func TestDataVolumeJourneyThroughTheAPI(t *testing.T) {
	r := newCRig(t, true)
	b := signedIn(t, r.env)
	r.await(b, opID(t, r.post(b, r.createBody("web-1", r.key, nil))), "succeeded")

	list := b.do("GET", "/api/v1/volumes", "", nil)
	if list.status != 200 || !strings.Contains(string(list.body), `"web-1-root"`) || !strings.Contains(string(list.body), `"allowed_actions":["create"]`) {
		t.Fatalf("%d %s", list.status, list.body)
	}

	// create
	r.await(b, opID(t, r.volOp(b, "volume_create", "data-1", `{"disk_gib":10}`)), "succeeded")
	v, st := r.volume(b, "data-1")
	if st != 200 || v.Desired.SizeGiB != 10 || v.Desired.AttachedTo != nil || v.Observed.State != "available" || strings.Join(v.Allowed, ",") != "attach,delete" {
		t.Fatalf("%d %+v", st, v)
	}
	if rep := r.volOp(b, "volume_create", "data-1", `{"disk_gib":10}`); rep.status != 409 {
		t.Fatalf("a taken name: %d %s", rep.status, rep.body)
	}

	// attach to the stopped VM
	r.await(b, opID(t, r.volOp(b, "volume_attach", "data-1", `{"vm_id":"web-1"}`)), "succeeded")
	v, _ = r.volume(b, "data-1")
	if v.Desired.AttachedTo == nil || *v.Desired.AttachedTo != "web-1" || v.Observed.State != "attached" || strings.Join(v.Allowed, ",") != "detach" {
		t.Fatalf("%+v", v)
	}
	xml := r.sim.Load().Domains["web-1"].XML
	if !strings.Contains(xml, "svavyom-vol-data-1.qcow2") || !strings.Contains(xml, "ua-svavyom-vol-data-1") {
		t.Fatalf("the definition must carry the volume and its marker:\n%s", xml)
	}
	vm := b.do("GET", "/api/v1/vms/web-1", "", nil)
	if strings.Contains(string(vm.body), `"reinstall"`) || !strings.Contains(string(vm.body), `"resize"`) {
		t.Fatalf("reinstall is withheld while a volume is attached, resize stays: %s", vm.body)
	}
	for _, c := range []struct{ typ, id, params string }{
		{"volume_delete", "data-1", ""}, {"volume_attach", "data-1", `{"vm_id":"web-1"}`},
	} {
		if rep := r.volOp(b, c.typ, c.id, c.params); rep.status != 409 {
			t.Errorf("%s of an attached volume: %d %s", c.typ, rep.status, rep.body)
		}
	}
	if rep := r.post(b, `{"type":"reinstall","kind":"VM","id":"web-1","idempotency_key":"re-1","params":{"image_id":"debian-13","ssh_public_key":"`+r.key+`"}}`); rep.status != 409 {
		t.Errorf("reinstall with a volume attached: %d %s", rep.status, rep.body)
	}

	// the proofs of ownership still hold with a data disk in the definition: a resize works, and so does a second attach
	r.await(b, opID(t, r.post(b, `{"type":"resize","kind":"VM","id":"web-1","idempotency_key":"rs-1","params":{"disk_gib":30}}`)), "succeeded")
	r.await(b, opID(t, r.volOp(b, "volume_create", "data-2", `{"disk_gib":5}`)), "succeeded")
	r.await(b, opID(t, r.volOp(b, "volume_attach", "data-2", `{"vm_id":"web-1"}`)), "succeeded")
	if dom := r.sim.Load().Domains["web-1"].XML; !strings.Contains(dom, "name='vdc'") && !strings.Contains(dom, "dev='vdc'") {
		t.Fatalf("the second volume takes the next target:\n%s", dom)
	}

	// a running VM can neither take nor give up a volume
	r.await(b, opID(t, r.volOp(b, "volume_create", "data-3", `{"disk_gib":5}`)), "succeeded")
	r.await(b, opID(t, r.submitAs(b, "start", "VM", "web-1")), "succeeded")
	if rep := r.volOp(b, "volume_attach", "data-3", `{"vm_id":"web-1"}`); rep.status != 409 {
		t.Errorf("attach to a running VM: %d %s", rep.status, rep.body)
	}
	if rep := r.volOp(b, "volume_detach", "data-1", ""); rep.status != 409 {
		t.Errorf("detach from a running VM: %d %s", rep.status, rep.body)
	}
	list = b.do("GET", "/api/v1/volumes", "", nil)
	if strings.Contains(string(list.body), `"detach"`) {
		t.Errorf("a volume of a running VM offers no detach: %s", list.body)
	}
	r.await(b, opID(t, r.submitAs(b, "stop", "VM", "web-1")), "succeeded")

	// detach keeps the volume; delete is its own step
	r.await(b, opID(t, r.volOp(b, "volume_detach", "data-1", "")), "succeeded")
	v, _ = r.volume(b, "data-1")
	if v.Desired.AttachedTo != nil || v.Observed.State != "available" {
		t.Fatalf("%+v", v)
	}
	if !strings.Contains(r.sim.Load().Domains["web-1"].XML, "svavyom-vol-data-2.qcow2") || strings.Contains(r.sim.Load().Domains["web-1"].XML, "svavyom-vol-data-1.qcow2") {
		t.Fatal("only the detached volume leaves the definition")
	}
	r.await(b, opID(t, r.volOp(b, "volume_delete", "data-1", "")), "succeeded")
	if _, st := r.volume(b, "data-1"); st != 404 {
		t.Fatalf("a deleted volume is gone: %d", st)
	}

	// deleting the VM never deletes its volumes
	r.await(b, opID(t, r.submitAs(b, "delete", "VM", "web-1")), "succeeded")
	v, st = r.volume(b, "data-2")
	if st != 200 || v.Desired.AttachedTo != nil || v.Observed.State != "available" {
		t.Fatalf("the volume outlives its VM: %d %+v", st, v)
	}
}

func TestDataVolumeRequestValidationAndRoles(t *testing.T) {
	r := newCRig(t, true)
	b := signedIn(t, r.env)
	for name, c := range map[string]struct {
		typ, id, params string
		want            int
	}{
		"a name ending in -root":    {"volume_create", "web-1-root", `{"disk_gib":5}`, 400},
		"a name with capitals":      {"volume_create", "Data", `{"disk_gib":5}`, 400},
		"no size":                   {"volume_create", "data-9", ``, 400},
		"a size beyond the ceiling": {"volume_create", "data-9", `{"disk_gib":5000}`, 400},
		"a stray parameter":         {"volume_create", "data-9", `{"disk_gib":5,"vm_id":"web-1"}`, 400},
		"attach without a VM":       {"volume_attach", "data-9", ``, 400},
		"detach with parameters":    {"volume_detach", "data-9", `{"disk_gib":5}`, 400},
		"attach a missing volume":   {"volume_attach", "data-9", `{"vm_id":"web-1"}`, 404},
		"delete a missing volume":   {"volume_delete", "data-9", ``, 404},
	} {
		if rep := r.volOp(b, c.typ, c.id, c.params); rep.status != c.want {
			t.Errorf("%s: %d %s", name, rep.status, rep.body)
		}
	}
	if rep := r.post(b, `{"type":"volume_create","kind":"VM","id":"data-9","idempotency_key":"k1","params":{"disk_gib":5}}`); rep.status != 422 {
		t.Errorf("the wrong kind: %d %s", rep.status, rep.body)
	}
	// an operator manages volumes, a viewer only reads them
	op := r.asRole("olly", auth.RoleOperator)
	r.await(op, opID(t, r.volOp(op, "volume_create", "ops-vol", `{"disk_gib":5}`)), "succeeded")
	vw := r.asRole("vera", auth.RoleViewer)
	if rep := r.volOp(vw, "volume_delete", "ops-vol", ""); rep.status != 403 {
		t.Errorf("a viewer must not change volumes: %d %s", rep.status, rep.body)
	}
	if rep := vw.do("GET", "/api/v1/volumes", "", nil); rep.status != 200 || strings.Contains(string(rep.body), `"allowed_actions":["create"]`) || strings.Contains(string(rep.body), `"attach"`) {
		t.Errorf("a viewer reads volumes and is offered nothing: %d %s", rep.status, rep.body)
	}
}
