package api

import (
	"encoding/json"
	"strconv"
	"strings"
	"testing"

	"example.invalid/dedicatedcloud/backend/internal/auth"
)

// DR-032: the Windows profile through the API: what creates it, what refuses it, what is observed, and that the existing operations keep its shape.

func (r *crig) createProfile(b *browser, name, image string, profile any, key *string) reply {
	c := map[string]any{"vcpus": 2, "memory_mib": 1024, "image_id": image, "disk_gib": 20}
	if profile != nil {
		c["guest_profile"] = profile
	}
	if key != nil {
		c["ssh_public_key"] = *key
	}
	body, _ := json.Marshal(map[string]any{"type": "create", "kind": "VM", "id": name, "idempotency_key": "key-" + name, "create": c})
	return r.post(b, string(body))
}

// windowsShape lists what the Windows definition has and the Linux one does not (refinement 3.1; the simulated host is not a kvm domain, so the Hyper-V
// features and the clock timer are checked by the provision golden files).
var windowsShape = []string{"profile='windows'", "<clock offset='localtime'/>", "<target dev='sda' bus='sata'/>", "<target dev='sdb' bus='sata'/>", "<model type='e1000e'/>"}

// windowsCore is what stays true of a Windows VM whatever media come and go (the installer CD on sdb is only there while it is attached).
var windowsCore = []string{"profile='windows'", "<clock offset='localtime'/>", "<target dev='sda' bus='sata'/>", "<model type='e1000e'/>"}

func hasAll(x string, parts []string) bool {
	for _, p := range parts {
		if !strings.Contains(x, p) {
			return false
		}
	}
	return true
}

func TestCreatingAVMWithTheWindowsProfile(t *testing.T) {
	r := newCRig(t, true)
	r.registerISO("win-iso")
	b := signedIn(t, r.env)
	key := r.key

	// refusals: nothing is created
	for name, c := range map[string]reply{
		"windows with a cloud image":         r.createProfile(b, "w-0", "debian-13", "windows", &key),
		"windows with a cloud image, no key": r.createProfile(b, "w-1", "debian-13", "windows", nil),
		"windows with a key":                 r.createProfile(b, "w-2", "win-iso", "windows", &key),
		"an unknown profile":                 r.createProfile(b, "w-3", "win-iso", "mac", nil),
		"capitals":                           r.createProfile(b, "w-4", "win-iso", "Windows", nil),
		"an empty profile":                   r.createProfile(b, "w-5", "win-iso", "", nil),
		"a number":                           r.createProfile(b, "w-6", "win-iso", 1, nil),
		"markup":                             r.createProfile(b, "w-7", "win-iso", "windows'/><x", nil),
	} {
		if c.status != 400 {
			t.Errorf("%s: %d %s", name, c.status, c.body)
		}
	}
	if len(r.sim.Load().Domains) != 0 {
		t.Fatalf("a refused create made a VM: %v", r.sim.Load().Domains)
	}
	if rep := r.createProfile(r.asRole("vera", auth.RoleViewer), "w-8", "win-iso", "windows", nil); rep.status != 403 {
		t.Errorf("a viewer cannot create: %d", rep.status)
	}

	// linux, by default and by name, is the definition every VM had, and reads as linux
	r.await(b, opID(t, r.createProfile(b, "lin-1", "win-iso", nil, nil)), "succeeded")
	r.await(b, opID(t, r.createProfile(b, "lin-2", "win-iso", "linux", nil)), "succeeded")
	for _, n := range []string{"lin-1", "lin-2"} {
		x := r.domainXML(n)
		if strings.Contains(x, "profile=") || !strings.Contains(x, "<target dev='vda' bus='virtio'/>") || !strings.Contains(x, "<model type='virtio'/>") || !strings.Contains(x, "<clock offset='utc'/>") {
			t.Errorf("%s is not the Linux definition:\n%s", n, x)
		}
		if v := readVMMedia(t, b, n); v.Observed.GuestProfile != "linux" {
			t.Errorf("%s: %+v", n, v.Observed)
		}
	}

	// windows
	r.await(b, opID(t, r.createProfile(b, "win-1", "win-iso", "windows", nil)), "succeeded")
	x := r.domainXML("win-1")
	if !hasAll(x, windowsShape) || strings.Contains(x, "vda") || strings.Contains(x, "<model type='virtio'/>") {
		t.Fatalf("not the Windows definition:\n%s", x)
	}
	v := readVMMedia(t, b, "win-1")
	if v.Observed.GuestProfile != "windows" || len(v.Observed.ISOs) != 1 || v.Observed.ISOs[0] != "win-iso" || !hasAction(v.Allowed, "eject_iso") || !hasAction(v.Allowed, "start") {
		t.Fatalf("%+v %v", v.Observed, v.Allowed)
	}
	// the list endpoint reports it too, and an unmanaged or older VM reads as linux
	if l := b.do("GET", "/api/v1/vms", "", nil); !strings.Contains(string(l.body), `"guest_profile":"windows"`) || !strings.Contains(string(l.body), `"guest_profile":"linux"`) {
		t.Fatalf("%s", l.body)
	}
	// a replay of the same request, before the VM exists, is the same operation and makes one VM; the same key with another profile is a different request
	first := r.createProfile(b, "win-2", "win-iso", "windows", nil)
	second := r.createProfile(b, "win-2", "win-iso", "windows", nil)
	if first.status != 202 || second.status != 202 || opID(t, first) != opID(t, second) {
		t.Fatalf("a replay is the same operation: %d %s / %d %s", first.status, first.body, second.status, second.body)
	}
	if other := r.createProfile(b, "win-2", "win-iso", nil, nil); other.status != 409 {
		t.Errorf("same key, another profile: %d %s", other.status, other.body)
	}
	r.await(b, opID(t, first), "succeeded")
	if !hasAll(r.domainXML("win-2"), windowsShape) {
		t.Fatalf("the replayed create made a Windows VM:\n%s", r.domainXML("win-2"))
	}
}

// The existing operations keep the Windows shape: each one is run against a Windows VM and the definition is still the Windows one afterwards.
func TestExistingOperationsKeepTheWindowsShape(t *testing.T) {
	r := newCRig(t, true)
	for _, id := range []string{"win-iso", "drivers-iso", "rescue-iso"} {
		r.registerISO(id)
	}
	b := signedIn(t, r.env)
	r.await(b, opID(t, r.createProfile(b, "win-1", "win-iso", "windows", nil)), "succeeded")
	still := func(step string) {
		t.Helper()
		x := r.domainXML("win-1")
		if !hasAll(x, windowsCore) || readVMMedia(t, b, "win-1").Observed.GuestProfile != "windows" {
			t.Fatalf("after %s the VM is no longer the Windows definition:\n%s", step, x)
		}
	}
	op := func(step, body string) {
		t.Helper()
		r.await(b, opID(t, r.post(b, body)), "succeeded")
		still(step)
	}
	seq := 0
	vmOp := func(typ, params string) string {
		seq++
		s := `{"type":"` + typ + `","kind":"VM","id":"win-1","idempotency_key":"win-step-` + strconv.Itoa(seq) + `"`
		if params != "" {
			s += `,"params":` + params
		}
		return s + "}"
	}

	// media: the installer out, the driver disc in and out, rescue and back
	op("eject", vmOp("eject_iso", ""))
	op("attach", vmOp("iso_attach", `{"image_id":"drivers-iso","boot":"disk"}`))
	op("eject by name", vmOp("eject_iso", `{"image_id":"drivers-iso"}`))
	op("rescue", vmOp("rescue", `{"image_id":"rescue-iso"}`))
	op("unrescue", vmOp("unrescue", ""))
	// size
	op("resize", vmOp("resize", `{"disk_gib":40}`))
	op("compute", vmOp("compute", `{"vcpus":4,"memory_mib":2048}`))
	// a data volume attaches while stopped (virtio: Windows sees it once the person installs the driver) and detaches
	r.await(b, opID(t, r.volOp(b, "volume_create", "data-1", `{"disk_gib":5}`)), "succeeded")
	r.await(b, opID(t, r.volOp(b, "volume_attach", "data-1", `{"vm_id":"win-1"}`)), "succeeded")
	still("volume attach")
	r.await(b, opID(t, r.volOp(b, "volume_detach", "data-1", "")), "succeeded")
	still("volume detach")
	// run and power off
	op("start", vmOp("start", ""))
	op("force off", vmOp("force_off", ""))
	// delete
	r.await(b, opID(t, r.post(b, vmOp("delete", ""))), "succeeded")
	if _, ok := r.sim.Load().Domains["win-1"]; ok {
		t.Fatal("the Windows VM was not deleted")
	}
}
