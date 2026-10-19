package api

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"example.invalid/dedicatedcloud/backend/internal/provision"
	provtest "example.invalid/dedicatedcloud/backend/internal/provision/provtest"
)

func (r *crig) registerISO(id string) {
	r.t.Helper()
	src := filepath.Join(r.t.TempDir(), id+".iso")
	if err := os.WriteFile(src, provtest.ISO(id), 0o640); err != nil {
		r.t.Fatal(err)
	}
	if _, err := provision.Register(provision.DevPolicy(), r.catDir, provision.RegisterRequest{ID: id, DisplayName: "Installer " + id, Distribution: "Alpine", Version: "3.20", Source: src, MinDiskGiB: 2, Media: provision.MediaISO}); err != nil {
		r.t.Fatal(err)
	}
}

func (r *crig) createISO(b *browser, name, image string, key *string) reply {
	c := map[string]any{"vcpus": 2, "memory_mib": 1024, "image_id": image, "disk_gib": 20}
	if key != nil {
		c["ssh_public_key"] = *key
	}
	body, _ := json.Marshal(map[string]any{"type": "create", "kind": "VM", "id": name, "idempotency_key": "key-" + name, "create": c})
	return r.post(b, string(body))
}

func TestVMFromInstallationMediaThroughTheAPI(t *testing.T) {
	r := newCRig(t, true)
	r.registerISO("alpine-iso")
	b := signedIn(t, r.env)

	imgs := b.do("GET", "/api/v1/images", "", nil)
	if !strings.Contains(string(imgs.body), `"media":"iso"`) || !strings.Contains(string(imgs.body), `"media":"disk"`) {
		t.Fatalf("%s", imgs.body)
	}
	var list struct {
		Items []struct {
			ID       string `json:"id"`
			Observed struct {
				Media     string  `json:"media"`
				LoginUser *string `json:"login_user"`
			} `json:"observed"`
		} `json:"items"`
	}
	_ = json.Unmarshal(imgs.body, &list)
	for _, im := range list.Items {
		if (im.ID == "alpine-iso") != (im.Observed.LoginUser == nil) || (im.ID == "alpine-iso") != (im.Observed.Media == "iso") {
			t.Errorf("%s: %+v", im.ID, im.Observed)
		}
	}

	// the key rule follows the media
	key := r.key
	if rep := r.createISO(b, "inst-0", "alpine-iso", &key); rep.status != 400 {
		t.Errorf("an ISO install takes no key: %d %s", rep.status, rep.body)
	}
	if rep := r.createISO(b, "disk-0", "debian-13", nil); rep.status != 400 {
		t.Errorf("a cloud image needs its key: %d %s", rep.status, rep.body)
	}

	r.await(b, opID(t, r.createISO(b, "inst-1", "alpine-iso", nil)), "succeeded")
	st := r.sim.Load()
	xml := st.Domains["inst-1"].XML
	if !strings.Contains(xml, "media='iso'") || !strings.Contains(xml, ".iso'") || strings.Contains(xml, "-seed") {
		t.Fatalf("%s", xml)
	}
	for k := range st.Volumes {
		if strings.Contains(k, "seed") {
			t.Errorf("a VM installed from media has no seed volume: %s", k)
		}
	}

	var vm struct {
		Observed struct {
			ISO       *string `json:"iso"`
			LoginUser *string `json:"login_user"`
		} `json:"observed"`
		Allowed []string `json:"allowed_actions"`
	}
	rep := b.do("GET", "/api/v1/vms/inst-1", "", nil)
	_ = json.Unmarshal(rep.body, &vm)
	if vm.Observed.ISO == nil || *vm.Observed.ISO != "alpine-iso" || vm.Observed.LoginUser != nil {
		t.Fatalf("%s", rep.body)
	}
	joined := strings.Join(vm.Allowed, ",")
	if !strings.Contains(joined, "eject_iso") || strings.Contains(joined, "reinstall") || strings.Contains(joined, "backup") || !strings.Contains(joined, "resize") {
		t.Fatalf("a media VM can eject and resize, and has no image to reinstall or back up from: %s", joined)
	}
	for _, typ := range []string{"reinstall", "backup"} {
		body := `{"type":"` + typ + `","kind":"VM","id":"inst-1","idempotency_key":"x-` + typ + `"`
		if typ == "reinstall" {
			body += `,"params":{"image_id":"debian-13","ssh_public_key":"` + r.key + `"}`
		}
		if rep := r.post(b, body+"}"); rep.status != 409 && rep.status != 422 {
			t.Errorf("%s of a media VM: %d %s", typ, rep.status, rep.body)
		}
	}

	// the proofs of ownership tolerate the media: resize works; the VM starts and stops
	r.await(b, opID(t, r.post(b, `{"type":"resize","kind":"VM","id":"inst-1","idempotency_key":"rs-i","params":{"disk_gib":30}}`)), "succeeded")
	r.await(b, opID(t, r.submitAs(b, "start", "VM", "inst-1")), "succeeded")
	if rep := r.submitAs(b, "eject_iso", "VM", "inst-1"); rep.status != 409 {
		t.Errorf("a running VM keeps its media: %d %s", rep.status, rep.body)
	}
	r.await(b, opID(t, r.submitAs(b, "stop", "VM", "inst-1")), "succeeded")

	// eject, once
	r.await(b, opID(t, r.submitAs(b, "eject_iso", "VM", "inst-1")), "succeeded")
	rep = b.do("GET", "/api/v1/vms/inst-1", "", nil)
	vm.Observed.ISO = nil
	_ = json.Unmarshal(rep.body, &vm)
	if vm.Observed.ISO != nil || strings.Contains(strings.Join(vm.Allowed, ","), "eject_iso") || strings.Contains(r.sim.Load().Domains["inst-1"].XML, "cdrom") {
		t.Fatalf("%s\n%s", rep.body, r.sim.Load().Domains["inst-1"].XML)
	}
	if rep := r.submitAs(b, "eject_iso", "VM", "inst-1"); rep.status != 409 {
		t.Errorf("nothing left to eject: %d %s", rep.status, rep.body)
	}

	// delete removes the root disk and the definition, and finds no seed to expect
	r.await(b, opID(t, r.submitAs(b, "delete", "VM", "inst-1")), "succeeded")
	if st := r.sim.Load(); len(st.Domains) != 0 || len(st.Volumes) != 0 {
		t.Fatalf("%+v", st)
	}
	// the media itself stays in the catalog
	if _, err := os.Stat(filepath.Join(r.catDir, provision.StoreDir)); err != nil {
		t.Fatal(err)
	}
}
