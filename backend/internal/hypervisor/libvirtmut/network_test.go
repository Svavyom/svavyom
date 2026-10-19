//go:build libvirt && libvirt_test

package libvirtmut

// Managed networks against libvirt's in-process TEST driver: the generated network XML, define/start/stop/autostart/undefine, the parsed read-back and the
// ownership marker, and the persistent compute change of a stopped domain. SIMULATION: the test driver has no bridge, DHCP server or lease table, so
// reservations and leases are exercised only by the real-host qualification (docs/QUALIFICATION-NETWORKS.md).

import (
	"context"
	"testing"

	libvirt "libvirt.org/go/libvirt"

	"example.invalid/dedicatedcloud/backend/internal/hypervisor"
	"example.invalid/dedicatedcloud/backend/internal/provision"
)

func cleanupNet(name string) {
	c, err := libvirt.NewConnect(TestURI)
	if err != nil {
		return
	}
	defer c.Close()
	if n, err := c.LookupNetworkByName(name); err == nil {
		_ = n.Destroy()
		_ = n.Undefine()
		_ = n.Free()
	}
}

func TestManagedNetworkOnTheTestDriver(t *testing.T) {
	e := newEnv(t, "lm-net", "4a4a4a4a-2222-4333-8444-5555555555ab")
	t.Cleanup(e.cleanup)
	t.Cleanup(func() { cleanupNet("lmnet") })
	ctx := context.Background()
	spec := provision.NetworkSpec{Name: "lmnet", UUID: "5a5a5a5a-2222-4333-8444-5555555555ab", Subnet: "10.88.0.0/24", DHCPStart: "10.88.0.10", DHCPEnd: "10.88.0.100"}
	if err := provision.NetworkCreate(ctx, e.ops, e.cfg, spec, nil, nil); err != nil {
		t.Fatal(err)
	}
	if err := provision.NetworkCreate(ctx, e.ops, e.cfg, spec, nil, nil); err != nil {
		t.Fatalf("a repeat: %v", err)
	}
	n, err := e.ops.LookupNetwork(ctx, "lmnet")
	if err != nil || !n.Managed || !n.Active || !n.Autostart || n.Subnet.String() != "10.88.0.0/24" || n.Gateway != "10.88.0.1" || n.DHCPStart != "10.88.0.10" || n.Bridge != "svbr5a5a5a5a" || n.Mode != "nat" {
		t.Fatalf("%+v %v", n, err)
	}
	// the default network of the driver is listed and foreign; a second managed network may not overlap the first
	all, err := e.ops.ListNetworks(ctx)
	if err != nil {
		t.Fatal(err)
	}
	foundDefault := false
	for _, x := range all {
		if x.Name == "default" {
			foundDefault = true
			if x.Managed {
				t.Fatal("the driver's default network must not look managed")
			}
		}
	}
	if !foundDefault {
		t.Fatalf("%+v", all)
	}
	overlap := provision.NetworkSpec{Name: "lmnet2", UUID: "6a6a6a6a-2222-4333-8444-5555555555ab", Subnet: "10.88.0.0/25", DHCPStart: "10.88.0.10", DHCPEnd: "10.88.0.50"}
	if err := provision.NetworkCreate(ctx, e.ops, e.cfg, overlap, nil, nil); hypervisor.CategoryOf(err) != hypervisor.Conflict {
		t.Fatalf("%v", err)
	}
	// foreign networks are never touched
	if err := provision.NetworkDelete(ctx, e.ops, "default", nil); hypervisor.CategoryOf(err) != hypervisor.Prohibited {
		t.Fatalf("%v", err)
	}
	if err := provision.NetworkStop(ctx, e.ops, "lmnet", nil); err != nil {
		t.Fatal(err)
	}
	if err := provision.NetworkStart(ctx, e.ops, "lmnet", nil); err != nil {
		t.Fatal(err)
	}
	if err := provision.NetworkAutostart(ctx, e.ops, "lmnet", false); err != nil {
		t.Fatal(err)
	}
	if n, _ = e.ops.LookupNetwork(ctx, "lmnet"); n.Autostart || !n.Active {
		t.Fatalf("%+v", n)
	}
	if err := provision.NetworkDelete(ctx, e.ops, "lmnet", nil); err != nil {
		t.Fatal(err)
	}
	if _, err := e.ops.LookupNetwork(ctx, "lmnet"); hypervisor.CategoryOf(err) != hypervisor.NotFound {
		t.Fatalf("%v", err)
	}
}

func TestComputeOnTheTestDriver(t *testing.T) {
	e := newEnv(t, "lm-cpu", "7b7b7b7b-2222-4333-8444-5555555555ab")
	t.Cleanup(e.cleanup)
	ctx := context.Background()
	if err := provision.Provision(ctx, e.ops, e.cfg, e.cat, e.spec, e.cfg.StateDir, nil); err != nil {
		t.Fatal(err)
	}
	if err := provision.Compute(ctx, e.ops, "lm-cpu", 4, 2048, nil); err != nil {
		t.Fatal(err)
	}
	d, err := e.ops.LookupDomain(ctx, "lm-cpu")
	if err != nil || d.VCPUs != 4 || d.MemoryMiB != 2048 {
		t.Fatalf("%+v %v", d, err)
	}
	pd, _ := provision.ParseDomain(d.XML)
	if pd.Network != "default" || pd.MAC != provision.MAC(e.spec.UUID) {
		t.Fatalf("%+v", pd)
	}
	all, err := e.ops.ListDomains(ctx)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, x := range all {
		found = found || (x.UUID == e.spec.UUID && x.Managed)
	}
	if !found {
		t.Fatal("the domain is missing from the listing")
	}
}
