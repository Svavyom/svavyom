package provision

import (
	"strings"
	"testing"
)

func TestParseDomainReadsIdentityAndOwnershipMarker(t *testing.T) {
	s := specForTest(t)
	cfg := Config{CatalogDir: "/c", Pool: "svavyom", Network: "svavyom-nat", DomainType: "test", LibvirtURI: "test:///default", StateDir: "/s"}
	x, err := DomainXML(cfg, s, backingForTest(cfg, s), rootForTest(s))
	if err != nil {
		t.Fatal(err)
	}
	d, err := ParseDomain(x)
	if err != nil || d.Name != "web-1" || d.UUID != s.UUID || d.VCPUs != 2 || d.MemoryMiB != 1024 || !d.Managed || d.Fingerprint != s.Fingerprint ||
		d.ImageID != "debian-13" || d.Root != RootVolumeName(s.UUID) || d.Seed != SeedVolumeName(s.UUID) {
		t.Fatalf("%+v %v", d, err)
	}
}

func TestOnlyAWellFormedMarkerInOurNamespaceMakesADomainManaged(t *testing.T) {
	uuid := "1a1a1a1a-2222-4333-8444-5555555555ab"
	fp := strings.Repeat("ab", 32)
	dom := func(meta string) string {
		return `<domain type='kvm'><name>x</name><uuid>` + uuid + `</uuid><memory unit='KiB'>1048576</memory><vcpu>2</vcpu><metadata>` + meta + `</metadata></domain>`
	}
	ns := "xmlns:s='https://svavyom.invalid/xml/1'"
	cases := map[string]struct {
		meta    string
		managed bool
	}{
		"valid":              {`<s:managed ` + ns + ` version='1' uuid='` + uuid + `' fingerprint='` + fp + `' image='debian-13'/>`, true},
		"other namespace":    {`<s:managed xmlns:s='https://evil.invalid/xml/1' version='1' uuid='` + uuid + `' fingerprint='` + fp + `'/>`, false},
		"other element":      {`<s:owned ` + ns + ` version='1' uuid='` + uuid + `' fingerprint='` + fp + `'/>`, false},
		"wrong version":      {`<s:managed ` + ns + ` version='2' uuid='` + uuid + `' fingerprint='` + fp + `'/>`, false},
		"uuid of another vm": {`<s:managed ` + ns + ` version='1' uuid='2a1a1a1a-2222-4333-8444-5555555555ab' fingerprint='` + fp + `'/>`, false},
		"short fingerprint":  {`<s:managed ` + ns + ` version='1' uuid='` + uuid + `' fingerprint='abc'/>`, false},
		"bad image":          {`<s:managed ` + ns + ` version='1' uuid='` + uuid + `' fingerprint='` + fp + `' image='../x'/>`, false},
		"no metadata":        {``, false},
	}
	for name, c := range cases {
		d, err := ParseDomain(dom(c.meta))
		if err != nil || d.Managed != c.managed || d.MemoryMiB != 1024 {
			t.Errorf("%s: %+v %v", name, d, err)
		}
	}
	if _, err := ParseDomain("<domain"); err == nil {
		t.Error("broken XML accepted")
	}
	if _, err := ParseDomain(strings.Repeat("a", 2<<20)); err == nil {
		t.Error("oversized XML accepted")
	}
}

func TestIsIPv4(t *testing.T) {
	for in, want := range map[string]bool{"192.168.122.23": true, "10.0.0.1": true, "0.0.0.0": true, "256.1.1.1": false, "1.2.3": false, "1.2.3.4.5": false, "01.2.3.4": false,
		"a.b.c.d": false, "": false, "1.2.3.4 ": false, "::1": false, "1..2.3": false} {
		if IsIPv4(in) != want {
			t.Errorf("%q", in)
		}
	}
}

// libvirt reports a running domain on a bridge-mode network as type='bridge' with the network still named in <source network=...>; the VM must still be
// seen as attached to that network (otherwise a running VM would not stop its network from being stopped or deleted).
func TestParseDomainSeesARunningVMOnABridgeModeNetwork(t *testing.T) {
	s := specForTest(t)
	cfg := Config{CatalogDir: "/c", Pool: "svavyom", Network: "svavyom-nat", DomainType: "test", LibvirtURI: "test:///default", StateDir: "/s"}
	x, err := DomainXML(cfg, s, backingForTest(cfg, s), rootForTest(s))
	if err != nil {
		t.Fatal(err)
	}
	live := strings.Replace(x, "<interface type='network'>", "<interface type='bridge'>", 1)
	live = strings.Replace(live, "<source network='svavyom-nat'/>", "<source network='svavyom-nat' portid='0f0f0f0f' bridge='svbr0'/>", 1)
	if live == x {
		t.Fatal("the test did not change the interface")
	}
	d, err := ParseDomain(live)
	if err != nil || d.Network != "svavyom-nat" || d.MAC == "" {
		t.Fatalf("%+v %v", d, err)
	}
	// a foreign bridge-type interface that names no libvirt network is not an attachment to one
	foreign := strings.Replace(live, " network='svavyom-nat'", "", 1)
	if d, err := ParseDomain(foreign); err != nil || d.Network != "" {
		t.Fatalf("%+v %v", d, err)
	}
}
