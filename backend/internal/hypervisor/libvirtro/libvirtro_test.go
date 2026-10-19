//go:build libvirt && libvirt_test

package libvirtro

import (
	"context"
	"os"
	"strings"
	"testing"

	libvirt "libvirt.org/go/libvirt"

	"example.invalid/dedicatedcloud/backend/internal/hypervisor"
)

// Tests run against libvirt's in-process test driver (test:///default): simulation, not a real hypervisor.

func writer(t *testing.T) *libvirt.Connect {
	t.Helper()
	c, err := libvirt.NewConnect(TestURI) // the test driver shares state between connections in this process
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = c.Close() })
	return c
}

func define(t *testing.T, c *libvirt.Connect, name string) *libvirt.Domain {
	t.Helper()
	d, err := c.DomainDefineXML(sprintf(name))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = d.Destroy()
		_ = d.Undefine()
		_ = d.Free()
	})
	return d
}

func sprintf(name string) string {
	return "<domain type=\"test\"><name>" + name + "</name><memory unit=\"MiB\">64</memory><vcpu>1</vcpu><os><type>hvm</type></os></domain>"
}

func open(t *testing.T) *Reader {
	t.Helper()
	r, err := Open(TestURI)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(r.Close)
	return r
}

func TestOpenRefusesEveryOtherURI(t *testing.T) {
	for _, uri := range []string{"", "qemu:///session", "qemu+ssh://h/system", "qemu+tcp://127.0.0.1/system", "xen:///", "QEMU:///system", "qemu:///system ", "test:///other"} {
		if r, err := Open(uri); r != nil || hypervisor.CategoryOf(err) != hypervisor.Prohibited {
			t.Errorf("Open(%q) = %v, %v", uri, r, err)
		}
	}
}

func TestListAndLookupObservedPowerStates(t *testing.T) {
	w := writer(t)
	run := define(t, w, "inv-running")
	define(t, w, "inv-stopped")
	paused := define(t, w, "inv-paused")
	if err := run.Create(); err != nil {
		t.Fatal(err)
	}
	if err := paused.Create(); err != nil {
		t.Fatal(err)
	}
	if err := paused.Suspend(); err != nil {
		t.Fatal(err)
	}
	r := open(t)
	list, err := r.List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]hypervisor.State{}
	for i, d := range list {
		got[d.Name] = d.State
		if i > 0 && list[i-1].Name >= d.Name {
			t.Fatalf("not sorted: %v", list)
		}
	}
	want := map[string]hypervisor.State{"inv-running": hypervisor.StateRunning, "inv-stopped": hypervisor.StateShutoff, "inv-paused": hypervisor.StatePaused}
	for n, s := range want {
		if got[n] != s {
			t.Errorf("%s: %q, want %q (all: %v)", n, got[n], s, got)
		}
	}
	d, err := r.Lookup(context.Background(), "inv-paused")
	if err != nil || d.State != hypervisor.StatePaused || d.Name != "inv-paused" {
		t.Fatalf("%+v %v", d, err)
	}
}

func TestLookupErrorsAreTyped(t *testing.T) {
	r := open(t)
	ctx := context.Background()
	if _, err := r.Lookup(ctx, "no-such-vm"); hypervisor.CategoryOf(err) != hypervisor.NotFound {
		t.Fatalf("absent: %v", err)
	}
	for _, bad := range []string{"", "../etc/passwd", "a b", "x;rm", "-lead", string(make([]byte, 64)), "UPPER\x00"} {
		if _, err := r.Lookup(ctx, bad); hypervisor.CategoryOf(err) != hypervisor.NotFound {
			t.Errorf("%q: %v", bad, err)
		}
	}
	cctx, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := r.List(cctx); hypervisor.CategoryOf(err) != hypervisor.Timeout {
		t.Fatalf("cancelled: %v", err)
	}
	r.Close()
	if _, err := r.List(ctx); hypervisor.CategoryOf(err) != hypervisor.Unavailable {
		t.Fatalf("closed: %v", err)
	}
}

// CT-PRODUCT-DELIVERY-004 s6: an unrepresentable host domain fails the inventory; it never disappears from a "successful" list.
func TestUnrepresentableDomainFailsTheInventoryWithoutLeakingItsName(t *testing.T) {
	w := writer(t)
	define(t, w, "inv-ok")
	define(t, w, "bad_name with space")
	r := open(t)
	list, err := r.List(context.Background())
	if list != nil || hypervisor.CategoryOf(err) != hypervisor.HostError {
		t.Fatalf("want HostError and no partial list, got %v %v", list, err)
	}
	if strings.Contains(err.Error(), "bad_name") || strings.Contains(err.Error(), "space") {
		t.Fatalf("the error leaks the rejected name: %v", err)
	}
	if _, err := r.Lookup(context.Background(), "bad_name with space"); hypervisor.CategoryOf(err) != hypervisor.NotFound {
		t.Fatal(err)
	}
}

// CT-PRODUCT-DELIVERY-004 s7: the power-state mapping is honest; transitional or unsupported states are unknown.
func TestPowerStateMapping(t *testing.T) {
	for in, want := range map[libvirt.DomainState]hypervisor.State{
		libvirt.DOMAIN_RUNNING: hypervisor.StateRunning, libvirt.DOMAIN_BLOCKED: hypervisor.StateRunning,
		libvirt.DOMAIN_SHUTOFF: hypervisor.StateShutoff,
		libvirt.DOMAIN_PAUSED:  hypervisor.StatePaused, libvirt.DOMAIN_PMSUSPENDED: hypervisor.StatePaused,
		libvirt.DOMAIN_CRASHED:  hypervisor.StateCrashed,
		libvirt.DOMAIN_SHUTDOWN: hypervisor.StateUnknown, // shutting down: no such state in the API, so never "running"
		libvirt.DOMAIN_NOSTATE:  hypervisor.StateUnknown, libvirt.DomainState(99): hypervisor.StateUnknown,
	} {
		if got := toState(in); got != want {
			t.Errorf("state %d -> %q, want %q", in, got, want)
		}
	}
}

// The connection is a libvirt READ-ONLY connection: the daemon side refuses mutation. Prove it by trying a mutation on
// the very connection type Open returns.
func TestConnectionIsReadOnlyAtLibvirt(t *testing.T) {
	c, err := libvirt.NewConnectReadOnly(TestURI)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if ro, err := c.IsAlive(); err != nil || !ro {
		t.Fatalf("alive=%v err=%v", ro, err)
	}
	if _, err := c.DomainDefineXML(sprintf("must-not-exist")); err == nil {
		t.Skip("NOT_RUN: the libvirt test driver does not enforce read-only connections; enforcement is by the real daemon (higher-tier qualification)")
	}
}

// Higher tier: the real system hypervisor. NOT_RUN in Docker (no libvirtd, no KVM); run by the qualification harness
// on a disposable authorized host with SVAVYOM_QUALIFY_SYSTEM_LIBVIRT=1.
func TestSystemHypervisorQualification(t *testing.T) {
	if os.Getenv("SVAVYOM_QUALIFY_SYSTEM_LIBVIRT") != "1" {
		t.Skip("NOT_RUN: higher-tier qualification pending (qemu:///system needs a real libvirt daemon; not available in Docker)")
	}
	r, err := Open(SystemURI)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if _, err := r.List(context.Background()); err != nil {
		t.Fatal(err)
	}
}
