package api

import (
	"strings"
	"testing"

	"example.invalid/dedicatedcloud/backend/internal/auth"
	"example.invalid/dedicatedcloud/backend/internal/provision"
	"example.invalid/dedicatedcloud/backend/internal/simhost"
)

// addMedium attaches a registered ISO to a stopped VM's definition the way a person with virsh would (a second CD on the next SATA target), so the
// observation and the eject of two media can be tested before the attach operation exists (DR-031, slice 1).
func (r *crig) addMedium(vm, image, dev string) {
	r.t.Helper()
	c, err := provision.LoadCatalog(r.catDir)
	if err != nil {
		r.t.Fatal(err)
	}
	im, ok := c.Get(image)
	if !ok {
		r.t.Fatalf("no image %s", image)
	}
	p, err := c.Path(im)
	if err != nil {
		r.t.Fatal(err)
	}
	dev2, err := provision.ISODiskXML(p, dev)
	if err != nil {
		r.t.Fatal(err)
	}
	if err := r.sim.Update(vm, func(d *simhost.Domain) {
		d.XML = strings.Replace(d.XML, "</devices>", "    "+dev2+"\n  </devices>", 1)
	}); err != nil {
		r.t.Fatal(err)
	}
}

func (r *crig) ejectBody(vm, key, params string) string {
	if params != "" {
		params = `,"params":` + params
	}
	return `{"type":"eject_iso","kind":"VM","id":"` + vm + `","idempotency_key":"` + key + `"` + params + `}`
}

func TestTwoMediaAreObservedAndEjectedByName(t *testing.T) {
	r := newCRig(t, true)
	for _, id := range []string{"tools-iso", "drivers-iso", "other-iso"} {
		r.registerISO(id)
	}
	b := signedIn(t, r.env)
	r.await(b, opID(t, r.post(b, r.createBody("web-1", r.key, nil))), "succeeded")
	if v := readVMMedia(t, b, "web-1"); v.Observed.ISOs == nil || len(v.Observed.ISOs) != 0 || v.Observed.ISO != nil {
		t.Fatalf("no medium: isos is an empty array, iso is null: %+v", v.Observed)
	}
	r.await(b, opID(t, r.attach(b, "web-1", "tools-iso", "cdrom", "k-t1")), "succeeded")
	if v := readVMMedia(t, b, "web-1"); len(v.Observed.ISOs) != 1 || v.Observed.ISOs[0] != "tools-iso" || v.Observed.ISO == nil || *v.Observed.ISO != "tools-iso" {
		t.Fatalf("one medium: %+v", v.Observed)
	}
	r.addMedium("web-1", "drivers-iso", "sdb")

	v := readVMMedia(t, b, "web-1")
	if len(v.Observed.ISOs) != 2 || v.Observed.ISOs[0] != "tools-iso" || v.Observed.ISOs[1] != "drivers-iso" || v.Observed.ISO == nil || *v.Observed.ISO != "tools-iso" {
		t.Fatalf("two media, in target order, iso is the one that boots: %+v", v.Observed)
	}
	if !hasAction(v.Allowed, "eject_iso") {
		t.Fatalf("eject is offered: %+v", v.Allowed)
	}

	// what is refused, and changes nothing
	before := r.domainXML("web-1")
	for name, c := range map[string]struct {
		body   string
		status int
	}{
		"two media, no name":          {r.ejectBody("web-1", "k-e1", ""), 400},
		"a name that is not an image": {r.ejectBody("web-1", "k-e2", `{"image_id":"nope"}`), 400},
		"a disk image":                {r.ejectBody("web-1", "k-e3", `{"image_id":"debian-13"}`), 400},
		"an ISO that is not attached": {r.ejectBody("web-1", "k-e4", `{"image_id":"other-iso"}`), 409},
		"a boot choice":               {r.ejectBody("web-1", "k-e5", `{"image_id":"tools-iso","boot":"disk"}`), 400},
		"a name with a path":          {r.ejectBody("web-1", "k-e6", `{"image_id":"../tools-iso"}`), 400},
		"a digest the caller made up": {r.ejectBody("web-1", "k-e7", `{"image_id":"tools-iso","image_sha256":"`+strings.Repeat("a", 64)+`"}`), 400},
	} {
		if rep := r.post(b, c.body); rep.status != c.status {
			t.Errorf("%s: %d, want %d: %s", name, rep.status, c.status, rep.body)
		}
	}
	if r.domainXML("web-1") != before {
		t.Fatal("a refused eject changed the definition")
	}
	if rep := r.post(r.asRole("vera", auth.RoleViewer), r.ejectBody("web-1", "k-e8", `{"image_id":"tools-iso"}`)); rep.status != 403 {
		t.Errorf("a viewer cannot eject: %d %s", rep.status, rep.body)
	}

	// eject the one that boots: the other stays and does not inherit the boot order
	r.await(b, opID(t, r.post(b, r.ejectBody("web-1", "k-e9", `{"image_id":"tools-iso"}`))), "succeeded")
	x := r.domainXML("web-1")
	if strings.Contains(x, "<boot order=") && !strings.Contains(x, "<boot dev='hd'/>") {
		t.Fatalf("no CD boots after the boot medium is gone:\n%s", x)
	}
	v = readVMMedia(t, b, "web-1")
	if len(v.Observed.ISOs) != 1 || v.Observed.ISOs[0] != "drivers-iso" || v.Observed.ISO == nil || *v.Observed.ISO != "drivers-iso" {
		t.Fatalf("the driver medium remains: %+v", v.Observed)
	}
	// the named medium is gone now: another eject of it is refused up front, the other can still be removed without a name (one medium left)
	if rep := r.post(b, r.ejectBody("web-1", "k-e10", `{"image_id":"tools-iso"}`)); rep.status != 409 {
		t.Errorf("already ejected: %d %s", rep.status, rep.body)
	}
	r.await(b, opID(t, r.submitAs(b, "eject_iso", "VM", "web-1")), "succeeded")
	if v = readVMMedia(t, b, "web-1"); len(v.Observed.ISOs) != 0 || v.Observed.ISO != nil || hasAction(v.Allowed, "eject_iso") {
		t.Fatalf("no medium left: %+v", v)
	}
	if strings.Count(r.domainXML("web-1"), "device='cdrom'") != 1 { // the cloud-init seed only
		t.Fatalf("only the seed CD remains:\n%s", r.domainXML("web-1"))
	}
}
