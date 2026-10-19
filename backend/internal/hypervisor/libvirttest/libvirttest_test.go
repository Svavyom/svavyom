//go:build libvirt_test

package libvirttest

import (
	"context"
	"testing"

	libvirt "libvirt.org/go/libvirt"

	"example.invalid/dedicatedcloud/backend/internal/hypervisor"
	"example.invalid/dedicatedcloud/backend/internal/hypervisor/contracttest"
)

func factory(t *testing.T) (hypervisor.Hypervisor, func() map[string]hypervisor.State) {
	h, err := Open(URI)
	if err != nil {
		t.Fatalf("open %s: %v", URI, err)
	}
	t.Cleanup(h.Close)
	snapshot := func() map[string]hypervisor.State {
		list, err := h.List(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		out := map[string]hypervisor.State{}
		for _, d := range list {
			out[d.Name] = d.State
		}
		return out
	}
	return h, snapshot
}

func TestContractSuiteOnTestDriver(t *testing.T) { contracttest.Run(t, factory) }

func TestRefusesEveryNonTestURI(t *testing.T) {
	for _, uri := range []string{"qemu:///system", "qemu:///session", "qemu+ssh://h/system",
		"test+tcp://127.0.0.1/default", "test:///default ", "TEST:///default", ""} {
		h, err := Open(uri)
		if h != nil || hypervisor.CategoryOf(err) != hypervisor.Prohibited {
			t.Fatalf("Open(%q) = %v, %v; want Prohibited", uri, h, err)
		}
	}
}

func TestConnectionIsTheTestDriver(t *testing.T) {
	h, err := Open(URI)
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	uri, err := h.conn.GetURI()
	if err != nil || uri != URI {
		t.Fatalf("connected URI %q (%v), want %s", uri, err, URI)
	}
}

func TestErrorMapping(t *testing.T) {
	cases := map[libvirt.ErrorNumber]hypervisor.Category{
		libvirt.ERR_NO_DOMAIN:          hypervisor.NotFound,
		libvirt.ERR_DOM_EXIST:          hypervisor.Conflict,
		libvirt.ERR_OPERATION_INVALID:  hypervisor.Conflict,
		libvirt.ERR_OPERATION_TIMEOUT:  hypervisor.Timeout,
		libvirt.ERR_NO_CONNECT:         hypervisor.Unavailable,
		libvirt.ERR_SYSTEM_ERROR:       hypervisor.Unavailable,
		libvirt.ERR_RPC:                hypervisor.Unavailable,
		libvirt.ERR_AGENT_UNRESPONSIVE: hypervisor.Unavailable,
		libvirt.ERR_XML_ERROR:          hypervisor.Validation,
		libvirt.ERR_INVALID_ARG:        hypervisor.Validation,
		libvirt.ERR_INTERNAL_ERROR:     hypervisor.HostError,
	}
	for code, want := range cases {
		got := mapErr("op", "vm", libvirt.Error{Code: code})
		if hypervisor.CategoryOf(got) != want {
			t.Errorf("code %d -> %v, want %s", code, got, want)
		}
		he := got.(*hypervisor.Error)
		if he.Retryable() != (want == hypervisor.Timeout || want == hypervisor.Unavailable) {
			t.Errorf("code %d retryable=%v", code, he.Retryable())
		}
	}
	if hypervisor.CategoryOf(mapErr("op", "vm", context.Canceled)) != hypervisor.HostError {
		t.Error("non-libvirt error must map to host_error")
	}
}

// The observed definition is what create reconciliation compares (CT-PRODUCT-DELIVERY-003 s5).
func TestObservedDefinitionIsReportedByLookupAndList(t *testing.T) {
	h, _ := factory(t)
	ctx := context.Background()
	if _, err := h.Define(ctx, hypervisor.DomainSpec{Name: "def-readback", VCPUs: 2, MemoryMiB: 1024}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = h.Undefine(ctx, "def-readback") })
	d, err := h.Lookup(ctx, "def-readback")
	if err != nil || d.VCPUs != 2 || d.MemoryMiB != 1024 {
		t.Fatalf("lookup: %+v %v", d, err)
	}
	list, _ := h.List(ctx)
	for _, x := range list {
		if x.Name == "def-readback" && (x.VCPUs != 2 || x.MemoryMiB != 1024) {
			t.Fatalf("list: %+v", x)
		}
	}
}
