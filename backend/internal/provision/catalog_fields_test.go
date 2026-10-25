package provision

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"example.invalid/dedicatedcloud/backend/internal/provision/provtest"
)

// A refused registration says which field failed and the rule, never repeats the value, and changes nothing (M6-E03-S07).
func TestRegisterRefusalNamesTheFieldAndRule(t *testing.T) {
	const secret = "Zz-Secret-Value"
	cases := []struct {
		name  string
		mut   func(*RegisterRequest)
		field string
		rule  string
	}{
		{"id with capitals", func(r *RegisterRequest) { r.ID = "Win-" + secret }, "image id", ruleID},
		{"id with a path", func(r *RegisterRequest) { r.ID = "../x" }, "image id", ruleID},
		{"id empty", func(r *RegisterRequest) { r.ID = "" }, "image id", ruleID},
		{"display name markup", func(r *RegisterRequest) { r.DisplayName = "<b>" + secret + "</b>" }, "display name", ruleText},
		{"distribution", func(r *RegisterRequest) { r.Distribution = "_" + secret }, "distribution", ruleText},
		{"version", func(r *RegisterRequest) { r.Version = secret + "!" }, "version", ruleText},
		{"minimum disk zero", func(r *RegisterRequest) { r.MinDiskGiB = 0 }, "minimum disk", ruleDisk},
		{"minimum disk too large", func(r *RegisterRequest) { r.MinDiskGiB = 4097 }, "minimum disk", ruleDisk},
		{"login user", func(r *RegisterRequest) { r.LoginUser = "Root!" + secret }, "login user", ruleLogin},
		{"login user empty", func(r *RegisterRequest) { r.LoginUser = "" }, "login user", ruleLogin},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := catalogDir(t)
			r := reg(source(t, "debian-13.qcow2", qcow2Bytes("payload")))
			c.mut(&r)
			_, err := Register(DevPolicy(), dir, r)
			if !errors.Is(err, ErrCatalog) {
				t.Fatalf("want ErrCatalog, got %v", err)
			}
			msg := err.Error()
			if !strings.Contains(msg, c.field+": "+c.rule) {
				t.Fatalf("message %q does not name %q and its rule", msg, c.field)
			}
			if strings.Contains(msg, secret) || (r.ID != "" && strings.Contains(msg, r.ID)) {
				t.Fatalf("message %q repeats what the operator typed", msg)
			}
			if _, statErr := os.Stat(filepath.Join(dir, CatalogFile)); !errors.Is(statErr, os.ErrNotExist) {
				t.Fatal("a refused registration wrote a catalog")
			}
			if ents, _ := os.ReadDir(filepath.Join(dir, StoreDir)); len(ents) != 0 {
				t.Fatalf("a refused registration left %d files in the store", len(ents))
			}
		})
	}
}

// The same rules apply to installation media, with no login user to check.
func TestRegisterISORefusalNamesTheField(t *testing.T) {
	dir := catalogDir(t)
	r := isoReq(source(t, "alpine.iso", provtest.ISO("a")))
	r.ID = "WindowServer2019-iso"
	_, err := Register(DevPolicy(), dir, r)
	if !errors.Is(err, ErrCatalog) || !strings.Contains(err.Error(), "image id: "+ruleID) {
		t.Fatalf("got %v", err)
	}
	if ents, _ := os.ReadDir(filepath.Join(dir, StoreDir)); len(ents) != 0 {
		t.Fatal("a refused ISO registration left files in the store")
	}
}

// image-state refusals name their field too.
func TestSetStateRefusalNamesTheField(t *testing.T) {
	dir := catalogDir(t)
	r := reg(source(t, "d.qcow2", qcow2Bytes("x")))
	r.CloudInit = false
	if _, err := Register(DevPolicy(), dir, r); err != nil {
		t.Fatal(err)
	}
	_, err := SetState(DevPolicy(), dir, r.ID, StateVerified, "")
	if !errors.Is(err, ErrCatalog) || !strings.Contains(err.Error(), "state: verified and qualified images must support cloud-init") {
		t.Fatalf("got %v", err)
	}
	r2 := reg(source(t, "e.qcow2", qcow2Bytes("y")))
	r2.ID = "debian-14"
	if _, err := Register(DevPolicy(), dir, r2); err != nil {
		t.Fatal(err)
	}
	_, err = SetState(DevPolicy(), dir, "debian-14", StateQualified, "")
	if !errors.Is(err, ErrCatalog) || !strings.Contains(err.Error(), "evidence: ") {
		t.Fatalf("got %v", err)
	}
}

// What is accepted does not change: ids and names that were valid stay valid.
func TestRegisterStillAcceptsTheValidSet(t *testing.T) {
	for _, id := range []string{"a", "ubuntu-24.04", "windowsserver2019-iso", strings.Repeat("a", 63)} {
		dir := catalogDir(t)
		r := reg(source(t, "d.qcow2", qcow2Bytes(id)))
		r.ID = id
		if _, err := Register(DevPolicy(), dir, r); err != nil {
			t.Errorf("%q refused: %v", id, err)
		}
	}
	for _, id := range []string{strings.Repeat("a", 64), "-a", "a b", "Ünï"} {
		if _, err := Register(DevPolicy(), catalogDir(t), func() RegisterRequest { r := reg(source(t, "d.qcow2", qcow2Bytes("z"))); r.ID = id; return r }()); err == nil {
			t.Errorf("%q accepted", id)
		}
	}
}

// USING.md states the rules the code enforces, word for word.
func TestUsingDocumentStatesTheRules(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "..", "..", "USING.md"))
	if err != nil {
		t.Fatal(err)
	}
	for _, rule := range []string{ruleID, ruleText, ruleLogin, ruleDisk} {
		if !strings.Contains(string(b), rule) {
			t.Errorf("USING.md does not state the rule: %s", rule)
		}
	}
}
