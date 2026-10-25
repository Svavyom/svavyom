package api

import (
	"encoding/json"
	"strings"
	"testing"

	"example.invalid/dedicatedcloud/backend/internal/auth"
	"example.invalid/dedicatedcloud/backend/internal/provision"
	"example.invalid/dedicatedcloud/backend/internal/simhost"
)

type vmMedia struct {
	Observed struct {
		GraphicalConsole string   `json:"graphical_console"`
		Rescue           bool     `json:"rescue"`
		ISO              *string  `json:"iso"`
		ISOs             []string `json:"isos"`
	} `json:"observed"`
	Allowed []string `json:"allowed_actions"`
}

func readVMMedia(t *testing.T, b *browser, vm string) vmMedia {
	t.Helper()
	var v vmMedia
	rep := b.do("GET", "/api/v1/vms/"+vm, "", nil)
	if err := json.Unmarshal(rep.body, &v); err != nil || rep.status != 200 {
		t.Fatalf("%d %v %s", rep.status, err, rep.body)
	}
	return v
}

func (r *crig) attach(b *browser, vm, image, boot, key string) reply {
	return r.post(b, `{"type":"iso_attach","kind":"VM","id":"`+vm+`","idempotency_key":"`+key+`","params":{"image_id":"`+image+`","boot":"`+boot+`"}}`)
}

func (r *crig) rescue(b *browser, vm, image, key string) reply {
	return r.post(b, `{"type":"rescue","kind":"VM","id":"`+vm+`","idempotency_key":"`+key+`","params":{"image_id":"`+image+`"}}`)
}

func (r *crig) domainXML(vm string) string { return r.sim.Load().Domains[vm].XML }

func TestGraphicalConsoleDeviceIsEnabledOnAnOldVMAndNewOnesHaveIt(t *testing.T) {
	r := newCRig(t, true)
	b := signedIn(t, r.env)
	r.await(b, opID(t, r.post(b, r.createBody("web-1", r.key, nil))), "succeeded")
	v := readVMMedia(t, b, "web-1")
	if v.Observed.GraphicalConsole != "present" || hasAction(v.Allowed, "graphics_enable") || !hasAction(v.Allowed, "rescue") {
		t.Fatalf("a new VM already has the console: %+v", v)
	}
	if rep := r.submitAs(b, "graphics_enable", "VM", "web-1"); rep.status != 409 {
		t.Errorf("nothing to enable: %d %s", rep.status, rep.body)
	}
	// a VM created before this release has no console device
	old := strings.NewReplacer("    "+"<graphics type='vnc'><listen type='none'/></graphics>\n", "", "    <video><model type='vga' vram='16384' heads='1'/></video>\n", "", "    <input type='tablet' bus='usb'/>\n", "").Replace(r.domainXML("web-1"))
	if err := r.sim.Update("web-1", func(d *simhost.Domain) { d.XML = old }); err != nil {
		t.Fatal(err)
	}
	v = readVMMedia(t, b, "web-1")
	if v.Observed.GraphicalConsole != "absent" || !hasAction(v.Allowed, "graphics_enable") || hasAction(v.Allowed, "rescue") {
		t.Fatalf("an old VM is offered the console, not the rescue: %+v", v)
	}
	if rep := r.rescue(b, "web-1", "rescue-iso", "k-r0"); rep.status == 202 {
		t.Errorf("rescue without a console: %s", rep.body)
	}
	r.await(b, opID(t, r.submitAs(b, "graphics_enable", "VM", "web-1")), "succeeded")
	if !provision.HasGraphics(r.domainXML("web-1")) || readVMMedia(t, b, "web-1").Observed.GraphicalConsole != "present" {
		t.Fatal("the devices are there")
	}
	// a running VM keeps its definition
	r.await(b, opID(t, r.submitAs(b, "start", "VM", "web-1")), "succeeded")
	if rep := r.submitAs(b, "graphics_enable", "VM", "web-1"); rep.status != 409 {
		t.Errorf("running: %d %s", rep.status, rep.body)
	}
}

func TestInstallationMediaCanBeAttachedToAnyStoppedVMAndEjected(t *testing.T) {
	r := newCRig(t, true)
	r.registerISO("tools-iso")
	b := signedIn(t, r.env)
	r.await(b, opID(t, r.post(b, r.createBody("web-1", r.key, nil))), "succeeded")
	v := readVMMedia(t, b, "web-1")
	if !hasAction(v.Allowed, "iso_attach") || hasAction(v.Allowed, "eject_iso") {
		t.Fatalf("%+v", v)
	}
	before := r.domainXML("web-1")
	r.await(b, opID(t, r.attach(b, "web-1", "tools-iso", "cdrom", "k-a1")), "succeeded")
	v = readVMMedia(t, b, "web-1")
	if v.Observed.ISO == nil || *v.Observed.ISO != "tools-iso" || !hasAction(v.Allowed, "eject_iso") || hasAction(v.Allowed, "iso_attach") {
		t.Fatalf("%+v", v)
	}
	if x := r.domainXML("web-1"); !strings.Contains(x, "<boot order='1'/>") || strings.Contains(x, "<boot dev=") {
		t.Fatalf("the media boots first:\n%s", x)
	}
	if rep := r.attach(b, "web-1", "tools-iso", "disk", "k-a2"); rep.status != 409 {
		t.Errorf("media already attached: %d %s", rep.status, rep.body)
	}
	r.await(b, opID(t, r.submitAs(b, "eject_iso", "VM", "web-1")), "succeeded")
	if r.domainXML("web-1") != before {
		t.Fatalf("eject must give back the definition exactly:\n%s", r.domainXML("web-1"))
	}
	// what is refused
	for name, body := range map[string]string{
		"not an ISO":    `{"type":"iso_attach","kind":"VM","id":"web-1","idempotency_key":"k-b1","params":{"image_id":"debian-13","boot":"disk"}}`,
		"unknown image": `{"type":"iso_attach","kind":"VM","id":"web-1","idempotency_key":"k-b2","params":{"image_id":"nope","boot":"disk"}}`,
		"bad boot":      `{"type":"iso_attach","kind":"VM","id":"web-1","idempotency_key":"k-b3","params":{"image_id":"tools-iso","boot":"network"}}`,
		"no boot":       `{"type":"iso_attach","kind":"VM","id":"web-1","idempotency_key":"k-b4","params":{"image_id":"tools-iso"}}`,
		"no params":     `{"type":"iso_attach","kind":"VM","id":"web-1","idempotency_key":"k-b5"}`,
		"a path":        `{"type":"iso_attach","kind":"VM","id":"web-1","idempotency_key":"k-b6","params":{"image_id":"tools-iso","boot":"disk","target_id":"x"}}`,
	} {
		if rep := r.post(b, body); rep.status == 202 {
			t.Errorf("%s accepted: %s", name, rep.body)
		}
	}
	r.await(b, opID(t, r.submitAs(b, "start", "VM", "web-1")), "succeeded")
	if rep := r.attach(b, "web-1", "tools-iso", "disk", "k-a3"); rep.status != 409 {
		t.Errorf("a running VM: %d %s", rep.status, rep.body)
	}
}

func TestRescueModeBootsRescueMediaAndLeavesExactlyWhatItFound(t *testing.T) {
	r := newCRig(t, true)
	r.registerISO("rescue-iso")
	b := signedIn(t, r.env)
	r.await(b, opID(t, r.post(b, r.createBody("web-1", r.key, nil))), "succeeded")
	before := r.domainXML("web-1")
	r.await(b, opID(t, r.rescue(b, "web-1", "rescue-iso", "k-r1")), "succeeded")
	v := readVMMedia(t, b, "web-1")
	if !v.Observed.Rescue || v.Observed.ISO == nil || *v.Observed.ISO != "rescue-iso" || !hasAction(v.Allowed, "unrescue") || hasAction(v.Allowed, "rescue") ||
		hasAction(v.Allowed, "iso_attach") || hasAction(v.Allowed, "eject_iso") || hasAction(v.Allowed, "backup") || hasAction(v.Allowed, "reinstall") {
		t.Fatalf("%+v", v)
	}
	for typ, body := range map[string]string{
		"attach":    `{"type":"iso_attach","kind":"VM","id":"web-1","idempotency_key":"k-r2","params":{"image_id":"rescue-iso","boot":"disk"}}`,
		"eject":     `{"type":"eject_iso","kind":"VM","id":"web-1","idempotency_key":"k-r3"}`,
		"backup":    `{"type":"backup","kind":"VM","id":"web-1","idempotency_key":"k-r4"}`,
		"reinstall": `{"type":"reinstall","kind":"VM","id":"web-1","idempotency_key":"k-r5","params":{"image_id":"debian-13","ssh_public_key":"` + r.key + `"}}`,
		"again":     `{"type":"rescue","kind":"VM","id":"web-1","idempotency_key":"k-r6","params":{"image_id":"rescue-iso"}}`,
	} {
		if rep := r.post(b, body); rep.status != 409 && rep.status != 422 {
			t.Errorf("%s in rescue mode: %d %s", typ, rep.status, rep.body)
		}
	}
	// the VM can be started into the rescue system and stopped again
	r.await(b, opID(t, r.submitAs(b, "start", "VM", "web-1")), "succeeded")
	if rep := r.submitAs(b, "unrescue", "VM", "web-1"); rep.status != 409 {
		t.Errorf("a running VM: %d %s", rep.status, rep.body)
	}
	r.await(b, opID(t, r.submitAs(b, "stop", "VM", "web-1")), "succeeded")
	r.await(b, opID(t, r.submitAs(b, "unrescue", "VM", "web-1")), "succeeded")
	if r.domainXML("web-1") != before {
		t.Fatalf("leaving rescue mode gives back exactly the definition we started with:\n%s", r.domainXML("web-1"))
	}
	if v = readVMMedia(t, b, "web-1"); v.Observed.Rescue || !hasAction(v.Allowed, "rescue") {
		t.Fatalf("%+v", v)
	}
	if rep := r.submitAs(b, "unrescue", "VM", "web-1"); rep.status != 409 {
		t.Errorf("not in rescue mode: %d %s", rep.status, rep.body)
	}
}

func TestRescueAndMediaAreForOperatorsAndOnlyForOurVMs(t *testing.T) {
	r := newCRig(t, true)
	r.registerISO("rescue-iso")
	admin := signedIn(t, r.env)
	r.await(admin, opID(t, r.post(admin, r.createBody("web-1", r.key, nil))), "succeeded")
	viewer := r.asRole("vera", auth.RoleViewer)
	for _, rep := range []reply{r.rescue(viewer, "web-1", "rescue-iso", "v-1"), r.attach(viewer, "web-1", "rescue-iso", "disk", "v-2"), r.submitAs(viewer, "graphics_enable", "VM", "web-1"), r.submitAs(viewer, "unrescue", "VM", "web-1")} {
		if rep.status != 403 {
			t.Errorf("viewer: %d %s", rep.status, rep.body)
		}
	}
	op := r.asRole("olly", auth.RoleOperator)
	if rep := r.rescue(op, "web-1", "rescue-iso", "o-1"); rep.status != 202 {
		t.Errorf("an operator may: %d %s", rep.status, rep.body)
	}
	_ = r.sim.Add("alien", simhost.Domain{UUID: "9a9a9a9a-2222-4333-8444-5555555555ab", VCPUs: 1, MemoryMiB: 64})
	for _, rep := range []reply{r.rescue(admin, "alien", "rescue-iso", "f-1"), r.attach(admin, "alien", "rescue-iso", "disk", "f-2"), r.submitAs(admin, "graphics_enable", "VM", "alien")} {
		if rep.status != 422 {
			t.Errorf("a VM Svavyom does not manage: %d %s", rep.status, rep.body)
		}
	}
	if rep := r.rescue(admin, "ghost", "rescue-iso", "f-3"); rep.status != 404 {
		t.Errorf("missing VM: %d", rep.status)
	}
}

// Found on the real host: a VM with a tools ISO or a rescue ISO attached could not be deleted, because the proof that the definition holds only the VM's
// own volumes counted the media as a foreign CD.
func TestAVMWithMediaOrInRescueModeCanBeDeleted(t *testing.T) {
	r := newCRig(t, true)
	r.registerISO("tools-iso")
	b := signedIn(t, r.env)
	for name, setup := range map[string]func(vm string){
		"attached media": func(vm string) { r.await(b, opID(t, r.attach(b, vm, "tools-iso", "cdrom", "d-a-"+vm)), "succeeded") },
		"rescue mode":    func(vm string) { r.await(b, opID(t, r.rescue(b, vm, "tools-iso", "d-r-"+vm)), "succeeded") },
	} {
		vm := strings.ReplaceAll(name, " ", "-")
		r.await(b, opID(t, r.post(b, r.createBody(vm, r.key, nil))), "succeeded")
		setup(vm)
		r.await(b, opID(t, r.submitAs(b, "delete", "VM", vm)), "succeeded")
		if _, ok := r.sim.Load().Domains[vm]; ok {
			t.Errorf("%s: the VM should be gone", name)
		}
		for k := range r.sim.Load().Volumes {
			if strings.Contains(k, vm) {
				t.Errorf("%s: volume %s should be gone", name, k)
			}
		}
	}
}
