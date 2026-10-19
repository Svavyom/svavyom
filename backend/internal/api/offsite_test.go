package api

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"example.invalid/dedicatedcloud/backend/internal/auth"
	"example.invalid/dedicatedcloud/backend/internal/offsite"
	"example.invalid/dedicatedcloud/backend/internal/provision"
)

// withOffsite declares one mounted-directory target and rewires the API so the backup views and the export operation use it.
func (r *crig) withOffsite() string {
	r.t.Helper()
	dir := filepath.Join(r.t.TempDir(), "mnt")
	if err := os.Mkdir(dir, 0o700); err != nil {
		r.t.Fatal(err)
	}
	state := filepath.Join(r.t.TempDir(), "offsite")
	if err := os.Mkdir(state, 0o700); err != nil {
		r.t.Fatal(err)
	}
	r.host.exp = &offsite.Exporter{Store: r.host.bak, Targets: []provision.BackupTarget{{ID: "usb", Kind: "path", Dir: dir}}, StateDir: state}
	r.wire()
	return dir
}

func TestBackupExportThroughTheAPI(t *testing.T) {
	r := newCRig(t, true)
	dir := r.withOffsite()
	b := signedIn(t, r.env)
	r.await(b, opID(t, r.post(b, r.createBody("web-1", r.key, nil))), "succeeded")
	r.await(b, opID(t, r.submitAs(b, "backup", "VM", "web-1")), "succeeded")

	var bl struct {
		Items []struct {
			ID       string `json:"id"`
			Observed struct {
				State  string   `json:"state"`
				Copies []string `json:"copies"`
			} `json:"observed"`
			Allowed []string `json:"allowed_actions"`
		} `json:"items"`
	}
	rep := b.do("GET", "/api/v1/backups", "", nil)
	_ = json.Unmarshal(rep.body, &bl)
	if len(bl.Items) != 1 || len(bl.Items[0].Observed.Copies) != 0 || !strings.Contains(strings.Join(bl.Items[0].Allowed, ","), "export") {
		t.Fatalf("%s", rep.body)
	}
	id := bl.Items[0].ID
	host := b.do("GET", "/api/v1/hosts/local", "", nil)
	if !strings.Contains(string(host.body), `"backup_targets":[{"id":"usb","kind":"path","state":"ready"}]`) || strings.Contains(string(host.body), dir) {
		t.Fatalf("the host lists the target without its path: %s", host.body)
	}

	export := func(target string) reply {
		return r.post(b, `{"type":"backup_export","kind":"Backup","id":"`+id+`","idempotency_key":"exp-`+target+`","params":{"target_id":"`+target+`"}}`)
	}
	if rep := export("nowhere"); rep.status != 404 {
		t.Errorf("an undeclared target: %d %s", rep.status, rep.body)
	}
	r.await(b, opID(t, export("usb")), "succeeded")
	if _, err := os.Stat(filepath.Join(dir, id, "root.qcow2")); err != nil {
		t.Fatalf("the copy is on the target: %v", err)
	}
	rep = b.do("GET", "/api/v1/backups/"+id, "", nil)
	var one struct {
		Observed struct {
			Copies []string `json:"copies"`
		} `json:"observed"`
	}
	_ = json.Unmarshal(rep.body, &one)
	if len(one.Observed.Copies) != 1 || one.Observed.Copies[0] != "usb" {
		t.Fatalf("%s", rep.body)
	}

	// a viewer cannot export; a VM id is not a backup id
	vw := r.asRole("vera", auth.RoleViewer)
	if rep := vw.do("GET", "/api/v1/backups", "", nil); rep.status != 200 || strings.Contains(string(rep.body), `"export"`) {
		t.Errorf("a viewer is offered no export: %d %s", rep.status, rep.body)
	}
	if rep := r.post(vw, `{"type":"backup_export","kind":"Backup","id":"`+id+`","idempotency_key":"vw","params":{"target_id":"usb"}}`); rep.status != 403 {
		t.Errorf("a viewer must not export: %d %s", rep.status, rep.body)
	}
	if rep := r.post(b, `{"type":"backup_export","kind":"VM","id":"web-1","idempotency_key":"bad","params":{"target_id":"usb"}}`); rep.status != 422 {
		t.Errorf("the wrong kind: %d %s", rep.status, rep.body)
	}
}

func TestNoTargetsMeansNoExportIsOffered(t *testing.T) {
	r := newCRig(t, true)
	b := signedIn(t, r.env)
	r.await(b, opID(t, r.post(b, r.createBody("web-1", r.key, nil))), "succeeded")
	r.await(b, opID(t, r.submitAs(b, "backup", "VM", "web-1")), "succeeded")
	rep := b.do("GET", "/api/v1/backups", "", nil)
	if strings.Contains(string(rep.body), `"export"`) {
		t.Fatalf("%s", rep.body)
	}
	host := b.do("GET", "/api/v1/hosts/local", "", nil)
	if !strings.Contains(string(host.body), `"backup_targets":[]`) {
		t.Fatalf("%s", host.body)
	}
}
