// Package contracttest is the shared Hypervisor contract suite (story
// M0-E02-S03 AC01/AC02). It runs unchanged against every implementation.
package contracttest

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"example.invalid/dedicatedcloud/backend/internal/hypervisor"
)

// Factory returns a fresh, empty implementation and a snapshot function
// listing every domain the implementation knows (including pre-existing ones).
type Factory func(t *testing.T) (hypervisor.Hypervisor, func() map[string]hypervisor.State)

var spec = hypervisor.DomainSpec{Name: "contract-vm", VCPUs: 1, MemoryMiB: 128}

func expect(t *testing.T, err error, want hypervisor.Category) {
	t.Helper()
	if got := hypervisor.CategoryOf(err); got != want {
		t.Fatalf("error category = %q (%v), want %q", got, err, want)
	}
}

func state(t *testing.T, h hypervisor.Hypervisor, name string, want hypervisor.State) {
	t.Helper()
	d, err := h.Lookup(context.Background(), name)
	if err != nil {
		t.Fatalf("lookup %s: %v", name, err)
	}
	if d.State != want {
		t.Fatalf("state of %s = %s, want %s", name, d.State, want)
	}
}

// Run executes the full contract suite.
func Run(t *testing.T, newHV Factory) {
	t.Logf("environment_class=%s", hypervisor.EnvironmentClass)
	if hypervisor.EnvironmentClass != "simulated" {
		t.Fatal("fake and test-driver evidence must be tagged simulated")
	}
	ctx := context.Background()

	t.Run("lifecycle_and_idempotency", func(t *testing.T) {
		h, _ := newHV(t)
		d, err := h.Define(ctx, spec)
		if err != nil || d.State != hypervisor.StateShutoff {
			t.Fatalf("define: %v %v", d, err)
		}
		steps := []struct {
			op   func(context.Context, string) error
			want hypervisor.State
		}{
			{h.Start, hypervisor.StateRunning}, {h.Start, hypervisor.StateRunning},
			{h.Stop, hypervisor.StateShutoff}, {h.Stop, hypervisor.StateShutoff},
			{h.Start, hypervisor.StateRunning},
			{h.Destroy, hypervisor.StateShutoff}, {h.Destroy, hypervisor.StateShutoff},
		}
		for i, s := range steps {
			if err := s.op(ctx, spec.Name); err != nil {
				t.Fatalf("step %d: %v", i, err)
			}
			state(t, h, spec.Name, s.want)
		}
		list, err := h.List(ctx)
		if err != nil || !contains(list, spec.Name) {
			t.Fatalf("list: %v %v", list, err)
		}
		if err := h.Undefine(ctx, spec.Name); err != nil {
			t.Fatal(err)
		}
		if err := h.Undefine(ctx, spec.Name); err != nil {
			t.Fatalf("undefine is idempotent: %v", err)
		}
		_, err = h.Lookup(ctx, spec.Name)
		expect(t, err, hypervisor.NotFound)
	})

	t.Run("negative_cases_leave_state_unchanged", func(t *testing.T) {
		h, snapshot := newHV(t)
		other := hypervisor.DomainSpec{Name: "bystander", VCPUs: 1, MemoryMiB: 128}
		if _, err := h.Define(ctx, other); err != nil {
			t.Fatal(err)
		}
		if err := h.Start(ctx, other.Name); err != nil {
			t.Fatal(err)
		}
		before := snapshot()
		bad := []string{"", "A", "../etc/passwd", "a/b", "a;rm -rf /", "$(id)", "<domain/>", "a b",
			strings.Repeat("a", 64), "a\nb", "-x"}
		for _, name := range bad {
			_, err := h.Define(ctx, hypervisor.DomainSpec{Name: name, VCPUs: 1, MemoryMiB: 128})
			expect(t, err, hypervisor.Validation)
			for _, op := range []func(context.Context, string) error{h.Start, h.Stop, h.Destroy, h.Undefine} {
				expect(t, op(ctx, name), hypervisor.Validation)
			}
		}
		for _, s := range []hypervisor.DomainSpec{
			{Name: "x", VCPUs: 0, MemoryMiB: 128}, {Name: "x", VCPUs: 65, MemoryMiB: 128},
			{Name: "x", VCPUs: 1, MemoryMiB: 63}, {Name: "x", VCPUs: 1, MemoryMiB: 1048577},
		} {
			_, err := h.Define(ctx, s)
			expect(t, err, hypervisor.Validation)
		}
		_, err := h.Define(ctx, other)
		expect(t, err, hypervisor.Conflict)
		for _, op := range []func(context.Context, string) error{h.Start, h.Stop, h.Destroy} {
			expect(t, op(ctx, "ghost"), hypervisor.NotFound)
		}
		expect(t, h.Undefine(ctx, other.Name), hypervisor.Conflict)
		if after := snapshot(); !reflect.DeepEqual(before, after) {
			t.Fatalf("state changed by rejected calls:\nbefore %v\nafter  %v", before, after)
		}
	})

	t.Run("audit_log_has_no_secret_fields", func(t *testing.T) {
		h, _ := newHV(t)
		_, _ = h.Define(ctx, spec)
		_ = h.Start(ctx, spec.Name)
		_ = h.Start(ctx, "Bad;Name")
		calls := h.Calls()
		if len(calls) == 0 {
			t.Fatal("no calls recorded")
		}
		subs := redactionSubstrings(t)
		typ := reflect.TypeOf(hypervisor.CallRecord{})
		for i := 0; i < typ.NumField(); i++ {
			name := strings.ToLower(typ.Field(i).Name)
			for _, s := range subs {
				if strings.Contains(name, s) {
					t.Fatalf("audit field %s matches redaction substring %q", typ.Field(i).Name, s)
				}
			}
		}
		if got := typ.NumField(); got != 3 {
			t.Fatalf("CallRecord has %d fields, want 3 (Op, Domain, Outcome)", got)
		}
	})
}

// DomainXMLContract checks XML generation (independent of implementation).
func DomainXMLContract(t *testing.T) {
	out, err := hypervisor.DomainXML(spec)
	if err != nil {
		t.Fatal(err)
	}
	var parsed struct {
		Name string `xml:"name"`
		VCPU int    `xml:"vcpu"`
	}
	if err := xml.Unmarshal([]byte(out), &parsed); err != nil || parsed.Name != spec.Name || parsed.VCPU != 1 {
		t.Fatalf("generated XML %q parsed as %+v (%v)", out, parsed, err)
	}
	for _, s := range []string{"<qemu:commandline", "<disk", "<interface", "<devices"} {
		if strings.Contains(out, s) {
			t.Fatalf("generated XML contains %s", s)
		}
	}
	if _, err := hypervisor.DomainXML(hypervisor.DomainSpec{Name: "<x/>", VCPUs: 1, MemoryMiB: 128}); err == nil {
		t.Fatal("invalid spec rendered")
	}
}

func contains(list []hypervisor.Domain, name string) bool {
	for _, d := range list {
		if d.Name == name {
			return true
		}
	}
	return false
}

func redactionSubstrings(t *testing.T) []string {
	_, file, _, _ := runtime.Caller(0)
	dir := filepath.Join(filepath.Dir(file), "..", "..", "..", "..", "contracts", "interfaces")
	raw, err := fs.ReadFile(os.DirFS(dir), "prohibited.json")
	if err != nil {
		t.Fatalf("read redaction contract: %v", err)
	}
	var doc struct {
		Redaction struct {
			KeySubstrings []string `json:"key_substrings"`
		} `json:"redaction"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil || len(doc.Redaction.KeySubstrings) == 0 {
		t.Fatalf("parse redaction contract: %v", err)
	}
	return doc.Redaction.KeySubstrings
}
