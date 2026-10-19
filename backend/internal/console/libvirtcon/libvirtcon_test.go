//go:build libvirt && libvirt_test

package libvirtcon

import (
	"context"
	"strings"
	"testing"

	libvirt "libvirt.org/go/libvirt"

	"example.invalid/dedicatedcloud/backend/internal/console"
	"example.invalid/dedicatedcloud/backend/internal/provision"
)

// Against libvirt's in-process TEST driver: the facts, the listing and the refusals. The test driver has no console device
// implementation, so actually opening a console stream is exercised only by the real-host qualification.

func def(t *testing.T, c *libvirt.Connect, name, uuid string, managed, serial bool) {
	t.Helper()
	marker := ""
	if managed {
		marker = "<metadata><svavyom:managed xmlns:svavyom='" + provision.MetadataNamespace + "' version='" + provision.MetadataVersion + "' uuid='" + uuid +
			"' fingerprint='" + strings.Repeat("ab", 32) + "' image='x'/></metadata>"
	}
	dev := ""
	if serial {
		dev = "<serial type='pty'><target port='0'/></serial><console type='pty'><target type='serial' port='0'/></console>"
	}
	x := "<domain type='test'><name>" + name + "</name><uuid>" + uuid + "</uuid>" + marker + "<memory unit='MiB'>64</memory><vcpu>1</vcpu><os><type>hvm</type></os><devices>" + dev + "</devices></domain>"
	d, err := c.DomainDefineXML(x)
	if err != nil {
		t.Fatal(err)
	}
	if err := d.Create(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Destroy(); _ = d.Undefine(); _ = d.Free() })
}

func TestFactsListingAndRefusalsOnTheTestDriver(t *testing.T) {
	s, err := Open(TestURI)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	c, err := s.connect()
	if err != nil {
		t.Fatal(err)
	}
	def(t, c, "lc-ours", "6a6a6a6a-2222-4333-8444-5555555555ab", true, true)
	def(t, c, "lc-noserial", "7a7a7a7a-2222-4333-8444-5555555555ab", true, false)
	def(t, c, "lc-foreign", "8a8a8a8a-2222-4333-8444-5555555555ab", false, true)
	ctx := context.Background()
	names, err := s.Running(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var ours, others int
	for _, n := range names {
		if n == "lc-ours" {
			ours++
		} else if strings.HasPrefix(n, "lc-") {
			others++
		}
	}
	if ours != 1 || others != 0 {
		t.Fatalf("only a running managed VM with a serial device is followed: %v", names)
	}
	for vm, want := range map[string]console.Info{
		"lc-ours": {Managed: true, Configured: true, Running: true}, "lc-noserial": {Managed: true, Configured: false, Running: true},
		"lc-foreign": {Managed: false, Configured: true, Running: true},
	} {
		if got, err := s.Check(ctx, vm); err != nil || got != want {
			t.Errorf("%s: %+v %v, want %+v", vm, got, err, want)
		}
	}
	if _, err := s.Check(ctx, "lc-ghost"); !console.IsNotFound(err) {
		t.Errorf("missing VM: %v", err)
	}
	for _, vm := range []string{"lc-noserial", "lc-foreign"} {
		if st, err := s.Open(ctx, vm); err == nil {
			_ = st.Close()
			t.Errorf("a console was opened for %s", vm)
		}
	}
	if _, err := Open("qemu+ssh://elsewhere/system"); err == nil {
		t.Error("a remote URI was accepted")
	}
}
