package api

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"example.invalid/dedicatedcloud/backend/internal/auth"
	"example.invalid/dedicatedcloud/backend/internal/sqlitedb"
	"example.invalid/dedicatedcloud/backend/internal/sshkeys"
)

func publicKeyLine(t *testing.T) string {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sp, _ := ssh.NewPublicKey(pub)
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sp)))
}

func keyRig(t *testing.T) *env {
	t.Helper()
	e := newEnv(t, true)
	db, err := sqlitedb.Open(filepath.Join(t.TempDir(), "keys.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	store, err := sshkeys.OpenSQLite(context.Background(), db)
	if err != nil {
		t.Fatal(err)
	}
	e.srv.Close()
	e.h = NewHandlerWith(Deps{Auth: e.svc, Hosts: e.hosts, SSHKeys: store})
	e.srv = httptest.NewServer(e.h)
	t.Cleanup(e.srv.Close)
	return e
}

func (e *env) asRole(name string, role auth.Role) *browser {
	e.t.Helper()
	if err := e.svc.AddUser(context.Background(), name, rolePass, role); err != nil {
		e.t.Fatal(err)
	}
	b := e.browser()
	b.status()
	if rep := b.signIn(name, rolePass); rep.status != 200 {
		e.t.Fatalf("sign-in %s: %d %s", name, rep.status, rep.body)
	}
	return b
}

func TestSSHKeyLibraryRolesCsrfValidationAndDeletion(t *testing.T) {
	e := keyRig(t)
	admin := signedIn(t, e)
	viewer := e.asRole("vera", auth.RoleViewer)
	op1 := e.asRole("olly", auth.RoleOperator)
	op2 := e.asRole("omar", auth.RoleOperator)
	hdr := func(b *browser) map[string]string { return map[string]string{"X-CSRF-Token": b.csrf} }
	body := func(name, key string) string {
		j, _ := json.Marshal(map[string]string{"name": name, "public_key": key})
		return string(j)
	}

	for name, rep := range map[string]reply{
		"list":   e.browser().do("GET", "/api/v1/ssh-keys", "", nil),
		"add":    e.browser().do("POST", "/api/v1/ssh-keys", body("x", publicKeyLine(t)), nil),
		"delete": e.browser().do("DELETE", "/api/v1/ssh-keys/k-0123456789abcdef", "", nil),
	} {
		if rep.status != 401 {
			t.Errorf("anonymous %s: %d, want 401", name, rep.status)
		}
	}
	if rep := viewer.do("POST", "/api/v1/ssh-keys", body("v", publicKeyLine(t)), hdr(viewer)); rep.status != 403 {
		t.Errorf("a viewer adds: %d, want 403", rep.status)
	}
	if rep := op1.do("POST", "/api/v1/ssh-keys", body("no csrf", publicKeyLine(t)), nil); rep.status != 403 {
		t.Errorf("without the CSRF token: %d, want 403", rep.status)
	}

	line := publicKeyLine(t)
	rep := op1.do("POST", "/api/v1/ssh-keys", body("Olly laptop", line+" laptop"), hdr(op1))
	var k map[string]any
	_ = json.Unmarshal(rep.body, &k)
	if rep.status != 201 || k["added_by"] != "olly" || !strings.HasPrefix(k["fingerprint"].(string), "SHA256:") || strings.Contains(k["public_key"].(string), "laptop") || k["type"] != "ed25519" {
		t.Fatalf("add: %d %s", rep.status, rep.body)
	}
	id := k["id"].(string)

	// the client cannot supply a fingerprint; a private key is refused without being echoed; a duplicate is a conflict
	if rep := op1.do("POST", "/api/v1/ssh-keys", `{"name":"f","public_key":"`+line+`","fingerprint":"SHA256:x"}`, hdr(op1)); rep.status != 400 {
		t.Errorf("a client-supplied fingerprint: %d, want 400", rep.status)
	}
	rep = op1.do("POST", "/api/v1/ssh-keys", body("secret", "-----BEGIN OPENSSH PRIVATE KEY-----\\nAAAA\\n-----END OPENSSH PRIVATE KEY-----"), hdr(op1))
	if rep.status != 400 || strings.Contains(string(rep.body), "PRIVATE") {
		t.Errorf("a private key: %d %s", rep.status, rep.body)
	}
	if rep := op2.do("POST", "/api/v1/ssh-keys", body("again", line), hdr(op2)); rep.status != 409 {
		t.Errorf("the same key again: %d, want 409", rep.status)
	}

	// every role lists; allowed_actions say who may do what
	for who, c := range map[string]struct {
		b           *browser
		add, delete bool
	}{"viewer": {viewer, false, false}, "other operator": {op2, true, false}, "adder": {op1, true, true}, "admin": {admin, true, true}} {
		rep := c.b.do("GET", "/api/v1/ssh-keys", "", nil)
		var l struct {
			Items   []map[string]any `json:"items"`
			Allowed []string         `json:"allowed_actions"`
		}
		_ = json.Unmarshal(rep.body, &l)
		if rep.status != 200 || len(l.Items) != 1 || (len(l.Allowed) == 1) != c.add || (len(l.Items[0]["allowed_actions"].([]any)) == 1) != c.delete {
			t.Errorf("%s lists: %d %s", who, rep.status, rep.body)
		}
	}
	if rep := admin.do("GET", "/api/v1/ssh-keys?x=1", "", nil); rep.status != 400 {
		t.Errorf("a query on the list: %d, want 400", rep.status)
	}

	// delete: not by another operator or a viewer, not an unknown or malformed id, by the adder, and by an admin
	if rep := op2.do("DELETE", "/api/v1/ssh-keys/"+id, "", hdr(op2)); rep.status != 403 {
		t.Errorf("another operator deletes: %d, want 403", rep.status)
	}
	if rep := viewer.do("DELETE", "/api/v1/ssh-keys/"+id, "", hdr(viewer)); rep.status != 403 {
		t.Errorf("a viewer deletes: %d, want 403", rep.status)
	}
	if rep := admin.do("DELETE", "/api/v1/ssh-keys/k-0000000000000000", "", hdr(admin)); rep.status != 404 {
		t.Errorf("an unknown id: %d, want 404", rep.status)
	}
	if rep := admin.do("DELETE", "/api/v1/ssh-keys/not-a-key", "", hdr(admin)); rep.status != 400 {
		t.Errorf("a malformed id: %d, want 400", rep.status)
	}
	if rep := op1.do("DELETE", "/api/v1/ssh-keys/"+id, "", nil); rep.status != 403 {
		t.Errorf("the adder without the CSRF token: %d, want 403", rep.status)
	}
	if rep := op1.do("DELETE", "/api/v1/ssh-keys/"+id, "", hdr(op1)); rep.status != 200 || !strings.Contains(string(rep.body), id) {
		t.Errorf("the adder deletes: %d %s", rep.status, rep.body)
	}
	k2 := op2.do("POST", "/api/v1/ssh-keys", body("Omar", publicKeyLine(t)), hdr(op2))
	var m map[string]any
	_ = json.Unmarshal(k2.body, &m)
	if rep := admin.do("DELETE", "/api/v1/ssh-keys/"+m["id"].(string), "", hdr(admin)); rep.status != 200 {
		t.Errorf("an admin deletes another's key: %d %s", rep.status, rep.body)
	}
}

func TestSSHKeyRoutesAreClosedWithoutALibrary(t *testing.T) {
	e := newEnv(t, true)
	b := signedIn(t, e)
	if rep := b.do("GET", "/api/v1/ssh-keys", "", nil); rep.status == 200 {
		t.Errorf("no library configured: %d %s", rep.status, rep.body)
	}
}
