package hypervisor

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"testing"
)

// The interface implements the M0-E01-S01 boundary host-agent-libvirt; its
// operations and error categories must be allowed by the pinned contracts.

func readJSON(t *testing.T, name string, v any) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "contracts", "interfaces", name))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, v); err != nil {
		t.Fatal(err)
	}
}

func TestOperationsAllowedByTypedLibvirtCall(t *testing.T) {
	var schemas struct {
		Categories map[string]map[string]any `json:"categories"`
		ValueTypes map[string]string         `json:"value_types"`
	}
	readJSON(t, "request-schemas.json", &schemas)
	raw, ok := schemas.Categories["typed_libvirt_call"]["call"].([]any)
	if !ok {
		t.Fatal("typed_libvirt_call.call is not an enumeration")
	}
	allowed := map[string]bool{}
	for _, c := range raw {
		allowed[c.(string)] = true
	}
	ops := map[string]string{"Define": "domain_define_typed", "Start": "domain_create", "Stop": "domain_shutdown",
		"Destroy": "domain_destroy", "Undefine": "domain_undefine", "Lookup": "domain_lookup", "List": "domain_list"}
	for op, call := range ops {
		if !allowed[call] {
			t.Errorf("%s maps to %s, which typed_libvirt_call does not allow", op, call)
		}
	}
	// Domain names must satisfy value_types.id as well as the stricter grammar.
	id := regexp.MustCompile(schemas.ValueTypes["id"])
	for _, name := range []string{"a", "vm-1", "a2-b3"} {
		if ValidateName("t", name) == nil && !id.MatchString(name) {
			t.Errorf("%q accepted by ValidateName but not by value_types.id", name)
		}
	}
}

func TestErrorCategoriesListedOnBoundary(t *testing.T) {
	var inv struct {
		Boundaries map[string]struct {
			ErrorCategories []string `json:"error_categories"`
		} `json:"boundaries"`
	}
	readJSON(t, "inventory.json", &inv)
	listed := map[string]bool{}
	for _, c := range inv.Boundaries["host-agent-libvirt"].ErrorCategories {
		listed[c] = true
	}
	for _, c := range []Category{Validation, NotFound, Conflict, Prohibited, Timeout, Unavailable, HostError} {
		if !listed[string(c)] {
			t.Errorf("category %s is not listed on host-agent-libvirt", c)
		}
	}
}
