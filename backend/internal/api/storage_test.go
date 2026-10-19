package api

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"example.invalid/dedicatedcloud/backend/internal/provision"
)

// storageRig is a create rig with one stopped VM "web-1" (20 GiB) and a helper to submit storage operations.
type storageRig struct {
	*crig
	b *browser
	n int
}

func newStorageRig(t *testing.T) *storageRig {
	t.Helper()
	r := newCRig(t, true)
	b := signedIn(t, r.env)
	r.await(b, opID(t, r.post(b, r.createBody("web-1", r.key, nil))), "succeeded")
	return &storageRig{crig: r, b: b}
}

func (s *storageRig) submit(typ, kind, id string, params map[string]any) reply {
	s.n++
	body := map[string]any{"type": typ, "kind": kind, "id": id, "idempotency_key": fmt.Sprintf("st-%d", s.n)}
	if params != nil {
		body["params"] = params
	}
	j, _ := json.Marshal(body)
	return s.post(s.b, string(j))
}

func (s *storageRig) do(typ, kind, id string, params map[string]any) {
	s.t.Helper()
	rep := s.submit(typ, kind, id, params)
	if rep.status != 202 {
		s.t.Fatalf("%s: %d %s", typ, rep.status, rep.body)
	}
	s.await(s.b, opID(s.t, rep), "succeeded")
}

func (s *storageRig) vm(id string) vmJSON {
	s.t.Helper()
	rep := s.b.do("GET", "/api/v1/vms/"+id, "", nil)
	var v vmJSON
	if rep.status != 200 || json.Unmarshal(rep.body, &v) != nil {
		s.t.Fatalf("%d %s", rep.status, rep.body)
	}
	return v
}

func TestStorageOperationsThroughTheAPI(t *testing.T) {
	s := newStorageRig(t)
	// resize: grow only, observed afterwards
	s.do("resize", "VM", "web-1", map[string]any{"disk_gib": 30})
	if v := s.vm("web-1"); v.Observed.DiskGiB == nil || *v.Observed.DiskGiB != 30 {
		t.Fatalf("disk %v", v.Observed.DiskGiB)
	}
	if rep := s.submit("resize", "VM", "web-1", map[string]any{"disk_gib": 10}); rep.status == 202 {
		t.Fatalf("a shrink was accepted: %s", rep.body)
	}
	// snapshots: taken, listed (id + time only), block resize, restored, deleted
	s.do("snapshot", "VM", "web-1", nil)
	v := s.vm("web-1")
	if len(v.Observed.Snapshots) != 1 || !snapshotRE.MatchString(v.Observed.Snapshots[0].ID) {
		t.Fatalf("snapshots %+v", v.Observed.Snapshots)
	}
	snap := v.Observed.Snapshots[0].ID
	if rep := s.submit("resize", "VM", "web-1", map[string]any{"disk_gib": 40}); rep.status != 409 {
		t.Fatalf("resize with a snapshot: %d %s", rep.status, rep.body)
	}
	s.do("restore_snapshot", "VM", "web-1", map[string]any{"snapshot_id": snap})
	s.do("delete_snapshot", "VM", "web-1", map[string]any{"snapshot_id": snap})
	if v := s.vm("web-1"); len(v.Observed.Snapshots) != 0 {
		t.Fatalf("snapshots %+v", v.Observed.Snapshots)
	}
	// backup: listed as a Backup resource that offers restore and delete; no key or path in any response
	s.do("backup", "VM", "web-1", nil)
	rep := s.b.do("GET", "/api/v1/backups", "", nil)
	var bl struct {
		Items []backupJSON `json:"items"`
	}
	if rep.status != 200 || json.Unmarshal(rep.body, &bl) != nil || len(bl.Items) != 1 {
		t.Fatalf("%d %s", rep.status, rep.body)
	}
	bk := bl.Items[0]
	if bk.Observed.State != "complete" || strings.Join(bk.Allowed, ",") != "restore,delete" || bk.Desired.SourceVolumeID != "web-1-root" {
		t.Fatalf("%+v", bk)
	}
	for _, leak := range []string{"/", "ssh-", ".qcow2", "sha256"} {
		if strings.Contains(string(rep.body), leak) {
			t.Fatalf("backup list leaks %q: %s", leak, rep.body)
		}
	}
	if one := s.b.do("GET", "/api/v1/backups/"+bk.ID, "", nil); one.status != 200 {
		t.Fatalf("%d", one.status)
	}
	// restore as a NEW VM; the name of an existing VM is refused
	if rep := s.submit("restore", "Backup", bk.ID, map[string]any{"new_name": "web-1", "ssh_public_key": s.key}); rep.status == 202 {
		sid := opID(t, rep)
		s.await(s.b, sid, "failed")
	}
	s.do("restore", "Backup", bk.ID, map[string]any{"new_name": "web-2", "ssh_public_key": s.key})
	if v := s.vm("web-2"); !v.Observed.Managed || v.Observed.DiskGiB == nil || *v.Observed.DiskGiB != 30 {
		t.Fatalf("restored %+v", v.Observed)
	}
	if st := s.sim.Load(); len(st.Domains) != 2 {
		t.Fatalf("expected two VMs, got %d", len(st.Domains))
	}
	// volumes are the VMs' root disks, read-only
	rep = s.b.do("GET", "/api/v1/volumes", "", nil)
	var vl struct {
		Items []volumeJSON `json:"items"`
	}
	if rep.status != 200 || json.Unmarshal(rep.body, &vl) != nil || len(vl.Items) != 2 {
		t.Fatalf("%d %s", rep.status, rep.body)
	}
	if vl.Items[0].Desired.SizeGiB != 30 || len(vl.Items[0].Allowed) != 0 {
		t.Fatalf("%+v", vl.Items[0])
	}
	// deleting the backup removes it
	s.do("delete", "Backup", bk.ID, nil)
	rep = s.b.do("GET", "/api/v1/backups", "", nil)
	if json.Unmarshal(rep.body, &bl) != nil || len(bl.Items) != 0 {
		t.Fatalf("%s", rep.body)
	}
	// the host summary carries the storage facts
	hr := s.b.do("GET", "/api/v1/hosts", "", nil)
	if hr.status != 200 || !strings.Contains(string(hr.body), `"storage":{"state":"available"`) {
		t.Fatalf("%d %s", hr.status, hr.body)
	}
}

func TestStorageParamsAreClosedAndTyped(t *testing.T) {
	s := newStorageRig(t)
	cases := map[string]struct {
		typ, kind, id string
		params        map[string]any
	}{
		"resize without params":   {"resize", "VM", "web-1", nil},
		"resize zero":             {"resize", "VM", "web-1", map[string]any{"disk_gib": 0}},
		"resize huge":             {"resize", "VM", "web-1", map[string]any{"disk_gib": 5000}},
		"resize string":           {"resize", "VM", "web-1", map[string]any{"disk_gib": "30"}},
		"resize with image":       {"resize", "VM", "web-1", map[string]any{"disk_gib": 30, "image_id": "debian-13"}},
		"params on start":         {"start", "VM", "web-1", map[string]any{"disk_gib": 30}},
		"snapshot with params":    {"snapshot", "VM", "web-1", map[string]any{"snapshot_id": "snap-000000000001"}},
		"restore_snapshot bad id": {"restore_snapshot", "VM", "web-1", map[string]any{"snapshot_id": "../etc"}},
		"restore_snapshot no id":  {"restore_snapshot", "VM", "web-1", nil},
		"delete_snapshot bad id":  {"delete_snapshot", "VM", "web-1", map[string]any{"snapshot_id": "snap-XYZ"}},
		"reinstall no key":        {"reinstall", "VM", "web-1", map[string]any{"image_id": "debian-13"}},
		"reinstall path image":    {"reinstall", "VM", "web-1", map[string]any{"image_id": "/var/lib/x.qcow2", "ssh_public_key": s.key}},
		"restore bad name":        {"restore", "Backup", "bk-0123456789abcdef", map[string]any{"new_name": "Web 2", "ssh_public_key": s.key}},
		"restore no key":          {"restore", "Backup", "bk-0123456789abcdef", map[string]any{"new_name": "web-2"}},
		"backup on a volume":      {"backup", "Volume", "web-1-root", nil},
		"unknown param":           {"resize", "VM", "web-1", map[string]any{"disk_gib": 30, "path": "/x"}},
		"snapshot of unknown VM":  {"snapshot", "VM", "nope", nil},
	}
	for name, c := range cases {
		rep := s.submit(c.typ, c.kind, c.id, c.params)
		if rep.status != 400 && rep.status != 404 && rep.status != 422 {
			t.Errorf("%s: %d %s", name, rep.status, rep.body)
		}
		if strings.Contains(string(rep.body), "BEGIN") || strings.Contains(string(rep.body), "ssh-") || strings.Contains(string(rep.body), "/var/lib") {
			t.Errorf("%s: input echoed", name)
		}
	}
	// a reinstall must name a real-host-qualified image: a merely registered one is refused before anything is stored
	if rep := s.submit("reinstall", "VM", "web-1", map[string]any{"image_id": "debian-13", "ssh_public_key": s.key}); rep.status == 202 {
		t.Fatalf("reinstall of an unqualified image was accepted: %s", rep.body)
	}
	if _, err := provision.SetState(provision.DevPolicy(), s.catDir, "debian-13", provision.StateQualified, "qr-test-0001"); err != nil {
		t.Fatal(err)
	}
	imgs := s.b.do("GET", "/api/v1/images", "", nil)
	var il struct {
		Items []imageJSON `json:"items"`
	}
	if imgs.status != 200 || json.Unmarshal(imgs.body, &il) != nil {
		t.Fatalf("%d %s", imgs.status, imgs.body)
	}
	for _, im := range il.Items {
		switch {
		case im.ID == "debian-13" && (im.Observed.Evidence == nil || *im.Observed.Evidence != "qr-test-0001"):
			t.Fatalf("a qualified image carries its evidence reference: %+v", im.Observed)
		case im.ID != "debian-13" && im.Observed.Evidence != nil:
			t.Fatalf("an image that is not qualified has no evidence: %s", im.ID)
		}
	}
	s.do("reinstall", "VM", "web-1", map[string]any{"image_id": "debian-13", "ssh_public_key": s.key})
	if st := s.sim.Load(); len(st.Domains) != 1 || len(st.Volumes) != 2 {
		t.Fatalf("reinstall must leave one VM and exactly its new pair of volumes: %d domains, %d volumes", len(st.Domains), len(st.Volumes))
	}
}

func TestStorageOperationsNeedAStoppedVMAndAreClosedWithoutTheSwitch(t *testing.T) {
	s := newStorageRig(t)
	s.do("start", "VM", "web-1", nil)
	for _, c := range []struct {
		typ    string
		params map[string]any
	}{{"resize", map[string]any{"disk_gib": 30}}, {"snapshot", nil}, {"backup", nil}, {"reinstall", map[string]any{"image_id": "debian-13", "ssh_public_key": s.key}}} {
		if rep := s.submit(c.typ, "VM", "web-1", c.params); rep.status != 409 && rep.status != 400 {
			t.Errorf("%s of a running VM: %d %s", c.typ, rep.status, rep.body)
		}
	}
	if v := s.vm("web-1"); strings.Contains(strings.Join(v.Allowed, ","), "resize") {
		t.Fatalf("a running VM offers storage actions: %v", v.Allowed)
	}
	off := newCRig(t, false)
	b := signedIn(t, off.env)
	rep := off.post(b, `{"type":"snapshot","kind":"VM","id":"web-1","idempotency_key":"k1"}`)
	if rep.status != 422 && rep.status != 403 {
		t.Fatalf("with the switch closed: %d %s", rep.status, rep.body)
	}
}
