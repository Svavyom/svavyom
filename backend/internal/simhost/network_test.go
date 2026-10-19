package simhost_test

import (
	"context"
	"net/netip"
	"strings"
	"testing"

	"example.invalid/dedicatedcloud/backend/internal/hypervisor"
	"example.invalid/dedicatedcloud/backend/internal/provision"
	"example.invalid/dedicatedcloud/backend/internal/simhost"
)

const netUUID = "7a7a7a7a-2222-4333-8444-5555555555ab"

func netSpec(mut func(*provision.NetworkSpec)) provision.NetworkSpec {
	s := provision.NetworkSpec{Name: "lab-net", UUID: netUUID, Subnet: "10.77.0.0/24", DHCPStart: "10.77.0.10", DHCPEnd: "10.77.0.200"}
	if mut != nil {
		mut(&s)
	}
	return s
}

func (r *rig) createNet(t *testing.T, s provision.NetworkSpec) {
	t.Helper()
	if err := provision.NetworkCreate(context.Background(), r.counter, r.cfg, s, nil, nil); err != nil {
		t.Fatal(err)
	}
}

// attachedRig provisions the rig's VM on the managed network "lab-net".
func (r *rig) attached(t *testing.T) {
	t.Helper()
	r.createNet(t, netSpec(nil))
	r.spec.Network = "lab-net"
	if err := r.provision(nil); err != nil {
		t.Fatal(err)
	}
}

func TestCreateManagedNetworkIsDefinedStartedAndOwned(t *testing.T) {
	ctx := context.Background()
	r := newRig(t)
	r.createNet(t, netSpec(nil))
	n, err := r.host.LookupNetwork(ctx, "lab-net")
	if err != nil || !n.Managed || !n.Active || !n.Autostart || n.Mode != "nat" || n.Subnet.String() != "10.77.0.0/24" || n.Gateway != "10.77.0.1" ||
		n.Bridge != "svbr7a7a7a7a" || n.DHCPStart != "10.77.0.10" || n.DHCPEnd != "10.77.0.200" {
		t.Fatalf("%+v %v", n, err)
	}
	// the same specification again is a no-op; a different one under the same name is a conflict
	r.createNet(t, netSpec(nil))
	if err := provision.NetworkCreate(ctx, r.counter, r.cfg, netSpec(func(s *provision.NetworkSpec) { s.DHCPEnd = "10.77.0.100" }), nil, nil); cat(err) != hypervisor.Conflict {
		t.Fatalf("%v", err)
	}
	if nets, _ := r.host.ListNetworks(ctx); len(nets) != 2 {
		t.Fatalf("the default network plus one: %d", len(nets))
	}
}

func TestCreateManagedNetworkRefusals(t *testing.T) {
	ctx := context.Background()
	r := newRig(t)
	if err := r.host.AddForeignNetwork("office", "10.78.0.1", "255.255.255.0", true); err != nil {
		t.Fatal(err)
	}
	r.createNet(t, netSpec(nil))
	hostNets := []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24")} // what the caller found on the host
	cases := map[string]struct {
		mut  func(*provision.NetworkSpec)
		want hypervisor.Category
	}{
		"overlaps a managed network": {func(s *provision.NetworkSpec) {
			s.Name, s.UUID = "other", "8a8a8a8a-2222-4333-8444-5555555555ab"
			s.Subnet = "10.77.0.0/25"
			s.DHCPStart, s.DHCPEnd = "10.77.0.10", "10.77.0.100"
		}, hypervisor.Conflict},
		"overlaps a foreign network": {func(s *provision.NetworkSpec) {
			s.Name, s.UUID = "other", "8a8a8a8a-2222-4333-8444-5555555555ab"
			s.Subnet = "10.78.0.0/16"
			s.DHCPStart, s.DHCPEnd = "10.78.0.10", "10.78.0.100"
		}, hypervisor.Conflict},
		"overlaps the default network": {func(s *provision.NetworkSpec) {
			s.Name, s.UUID = "other", "8a8a8a8a-2222-4333-8444-5555555555ab"
			s.Subnet = "192.168.122.0/24"
			s.DHCPStart, s.DHCPEnd = "192.168.122.10", "192.168.122.100"
		}, hypervisor.Conflict},
		"overlaps a host subnet": {func(s *provision.NetworkSpec) {
			s.Name, s.UUID = "other", "8a8a8a8a-2222-4333-8444-5555555555ab"
			s.Subnet = "192.168.1.0/24"
			s.DHCPStart, s.DHCPEnd = "192.168.1.10", "192.168.1.100"
		}, hypervisor.Conflict},
		"name of the configured network": {func(s *provision.NetworkSpec) { s.Name = "svavyom-nat" }, hypervisor.Validation},
		"public subnet": {func(s *provision.NetworkSpec) {
			s.Name, s.UUID = "other", "8a8a8a8a-2222-4333-8444-5555555555ab"
			s.Subnet = "8.8.8.0/24"
			s.DHCPStart, s.DHCPEnd = "8.8.8.10", "8.8.8.100"
		}, hypervisor.Validation},
		"too large a subnet": {func(s *provision.NetworkSpec) {
			s.Name, s.UUID = "other", "8a8a8a8a-2222-4333-8444-5555555555ab"
			s.Subnet = "10.0.0.0/8"
			s.DHCPStart, s.DHCPEnd = "10.0.0.10", "10.0.0.100"
		}, hypervisor.Validation},
		"non-canonical subnet": {func(s *provision.NetworkSpec) {
			s.Name, s.UUID = "other", "8a8a8a8a-2222-4333-8444-5555555555ab"
			s.Subnet = "10.79.0.5/24"
		}, hypervisor.Validation},
		"range outside": {func(s *provision.NetworkSpec) {
			s.Name, s.UUID = "other", "8a8a8a8a-2222-4333-8444-5555555555ab"
			s.Subnet = "10.79.0.0/24"
			s.DHCPStart, s.DHCPEnd = "10.79.1.10", "10.79.1.20"
		}, hypervisor.Validation},
		"range starts at the gateway": {func(s *provision.NetworkSpec) {
			s.Name, s.UUID = "other", "8a8a8a8a-2222-4333-8444-5555555555ab"
			s.Subnet = "10.79.0.0/24"
			s.DHCPStart, s.DHCPEnd = "10.79.0.1", "10.79.0.20"
		}, hypervisor.Validation},
		"range ends at the broadcast": {func(s *provision.NetworkSpec) {
			s.Name, s.UUID = "other", "8a8a8a8a-2222-4333-8444-5555555555ab"
			s.Subnet = "10.79.0.0/24"
			s.DHCPStart, s.DHCPEnd = "10.79.0.10", "10.79.0.255"
		}, hypervisor.Validation},
		"range reversed": {func(s *provision.NetworkSpec) {
			s.Name, s.UUID = "other", "8a8a8a8a-2222-4333-8444-5555555555ab"
			s.Subnet = "10.79.0.0/24"
			s.DHCPStart, s.DHCPEnd = "10.79.0.50", "10.79.0.20"
		}, hypervisor.Validation},
		"bad name": {func(s *provision.NetworkSpec) {
			s.Name, s.UUID = "Bad_Name", "8a8a8a8a-2222-4333-8444-5555555555ab"
			s.Subnet = "10.79.0.0/24"
			s.DHCPStart, s.DHCPEnd = "10.79.0.10", "10.79.0.20"
		}, hypervisor.Validation},
		"same uuid under another name": {func(s *provision.NetworkSpec) {
			s.Name = "second"
			s.Subnet = "10.79.0.0/24"
			s.DHCPStart, s.DHCPEnd = "10.79.0.10", "10.79.0.20"
		}, hypervisor.Conflict},
		"the name of a foreign network": {func(s *provision.NetworkSpec) {
			s.Name, s.UUID = "office", "8a8a8a8a-2222-4333-8444-5555555555ab"
			s.Subnet = "10.79.0.0/24"
			s.DHCPStart, s.DHCPEnd = "10.79.0.10", "10.79.0.20"
		}, hypervisor.Conflict},
	}
	for name, c := range cases {
		if err := provision.NetworkCreate(ctx, r.counter, r.cfg, netSpec(c.mut), hostNets, nil); cat(err) != c.want {
			t.Errorf("%s: %v", name, err)
		}
	}
	if nets, _ := r.host.ListNetworks(ctx); len(nets) != 3 {
		t.Fatalf("a refused create changed the host: %d networks", len(nets))
	}
}

func TestInterruptedNetworkCreateIsFinishedWithoutDuplicates(t *testing.T) {
	ctx := context.Background()
	r := newRig(t)
	stop := make(chan struct{})
	func() {
		defer func() { _ = recover() }()
		_ = provision.NetworkCreate(ctx, r.counter, r.cfg, netSpec(nil), nil, func(step string) {
			if step == provision.StepNetworkDefined {
				close(stop)
				panic("killed after the define")
			}
		})
	}()
	<-stop
	n, err := r.host.LookupNetwork(ctx, "lab-net")
	if err != nil || n.Active {
		t.Fatalf("defined but not started: %+v %v", n, err)
	}
	r.createNet(t, netSpec(nil))
	r.createNet(t, netSpec(nil))
	n, _ = r.host.LookupNetwork(ctx, "lab-net")
	if !n.Active || !n.Autostart {
		t.Fatalf("%+v", n)
	}
	if nets, _ := r.host.ListNetworks(ctx); len(nets) != 2 {
		t.Fatalf("a duplicate was created: %d", len(nets))
	}
}

func TestManagedNetworkLifecycleRules(t *testing.T) {
	ctx := context.Background()
	r := newRig(t)
	r.attached(t) // VM web-1 stopped on lab-net
	if err := provision.NetworkDelete(ctx, r.counter, "lab-net", nil); cat(err) != hypervisor.Conflict {
		t.Fatalf("delete with an attached VM: %v", err)
	}
	if err := provision.Start(ctx, r.counter, "web-1", nil); err != nil {
		t.Fatal(err)
	}
	if err := provision.NetworkStop(ctx, r.counter, "lab-net", nil); cat(err) != hypervisor.Conflict {
		t.Fatalf("stop with a running VM: %v", err)
	}
	if err := provision.Stop(ctx, r.counter, "web-1", nil); err != nil {
		t.Fatal(err)
	}
	if err := provision.NetworkStop(ctx, r.counter, "lab-net", nil); err != nil {
		t.Fatal(err)
	}
	if err := provision.NetworkStop(ctx, r.counter, "lab-net", nil); err != nil {
		t.Fatalf("a repeat: %v", err)
	}
	// a VM cannot start on an inactive network; start the network and autostart toggle
	if n, _ := r.host.LookupNetwork(ctx, "lab-net"); n.Active {
		t.Fatal("still active")
	}
	if err := provision.NetworkStart(ctx, r.counter, "lab-net", nil); err != nil {
		t.Fatal(err)
	}
	if err := provision.NetworkAutostart(ctx, r.counter, "lab-net", false); err != nil {
		t.Fatal(err)
	}
	if n, _ := r.host.LookupNetwork(ctx, "lab-net"); !n.Active || n.Autostart {
		t.Fatalf("%+v", n)
	}
	// delete the VM, then the network goes; a repeat is success
	if err := provision.Delete(ctx, r.counter, r.cfg, "web-1", nil); err != nil {
		t.Fatal(err)
	}
	if err := provision.NetworkDelete(ctx, r.counter, "lab-net", nil); err != nil {
		t.Fatal(err)
	}
	if err := provision.NetworkDelete(ctx, r.counter, "lab-net", nil); err != nil {
		t.Fatalf("a repeat: %v", err)
	}
	if _, err := r.host.LookupNetwork(ctx, "lab-net"); cat(err) != hypervisor.NotFound {
		t.Fatalf("%v", err)
	}
}

func TestForeignAndDefaultNetworksAreNeverMutated(t *testing.T) {
	ctx := context.Background()
	r := newRig(t)
	if err := r.host.AddForeignNetwork("office", "10.78.0.1", "255.255.255.0", true); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"office", simhost.DefaultNetwork} {
		if err := provision.NetworkDelete(ctx, r.counter, name, nil); cat(err) != hypervisor.Prohibited {
			t.Errorf("delete %s: %v", name, err)
		}
		if err := provision.NetworkStop(ctx, r.counter, name, nil); cat(err) != hypervisor.Prohibited {
			t.Errorf("stop %s: %v", name, err)
		}
		if err := provision.NetworkStart(ctx, r.counter, name, nil); cat(err) != hypervisor.Prohibited {
			t.Errorf("start %s: %v", name, err)
		}
		if err := provision.NetworkAutostart(ctx, r.counter, name, false); cat(err) != hypervisor.Prohibited {
			t.Errorf("autostart %s: %v", name, err)
		}
	}
	if nets, _ := r.host.ListNetworks(ctx); len(nets) != 2 {
		t.Fatal("a foreign network was changed")
	}
	// a VM cannot attach to a foreign or nonexistent network
	for _, n := range []string{"office", "nope"} {
		r.spec.Network = n
		if err := r.provision(nil); cat(err) != hypervisor.Validation {
			t.Errorf("attach to %s: %v", n, err)
		}
	}
	if st := r.host.Load(); len(st.Domains) != 0 || len(st.Volumes) != 0 {
		t.Fatal("a refused attach created something")
	}
	// an inactive managed network is not ready
	r.createNet(t, netSpec(nil))
	if err := provision.NetworkStop(ctx, r.counter, "lab-net", nil); err != nil {
		t.Fatal(err)
	}
	r.spec.Network = "lab-net"
	if err := r.provision(nil); cat(err) != hypervisor.Unavailable {
		t.Fatalf("attach to an inactive network: %v", err)
	}
}

func TestAttachedVMGetsAnAddressOfItsNetworkAndReports(t *testing.T) {
	ctx := context.Background()
	r := newRig(t)
	r.attached(t)
	if err := provision.Start(ctx, r.counter, "web-1", nil); err != nil {
		t.Fatal(err)
	}
	d, err := (simhost.Reader{H: r.host}).Lookup(ctx, "web-1")
	if err != nil || d.Network != "lab-net" || d.MAC != provision.MAC(r.spec.UUID) || !strings.HasPrefix(d.IPv4, "10.77.0.") {
		t.Fatalf("%+v %v", d, err)
	}
	nets, _ := (simhost.Reader{H: r.host}).Networks(ctx)
	for _, n := range nets {
		if n.Name == "lab-net" && n.AttachedVMs != 1 {
			t.Fatalf("%+v", n)
		}
	}
}

func TestReserveAndReleaseIP(t *testing.T) {
	ctx := context.Background()
	r := newRig(t)
	r.attached(t)
	vm := "web-1"
	for name, ip := range map[string]string{"network address": "10.77.0.0", "gateway": "10.77.0.1", "broadcast": "10.77.0.255", "outside": "10.99.0.5", "garbage": "10.77.0.x", "leading zero": "10.77.0.010", "ipv6": "fd00::5"} {
		if err := provision.ReserveIP(ctx, r.counter, vm, ip, nil); cat(err) != hypervisor.Validation {
			t.Errorf("%s: %v", name, err)
		}
	}
	if err := provision.ReserveIP(ctx, r.counter, vm, "10.77.0.50", nil); err != nil {
		t.Fatal(err)
	}
	if err := provision.ReserveIP(ctx, r.counter, vm, "10.77.0.50", nil); err != nil {
		t.Fatalf("a repeat: %v", err)
	}
	if err := provision.ReserveIP(ctx, r.counter, vm, "10.77.0.51", nil); cat(err) != hypervisor.Conflict {
		t.Fatalf("a second reservation for the same VM: %v", err)
	}
	// another VM cannot take the same address
	r2 := *r
	r2.spec.Name, r2.spec.UUID = "web-2", "2b2b2b2b-2222-4333-8444-5555555555ab"
	if err := provision.Provision(ctx, r.counter, r.cfg, r.cat, r2.spec, r.scratch, nil); err != nil {
		t.Fatal(err)
	}
	if err := provision.ReserveIP(ctx, r.counter, "web-2", "10.77.0.50", nil); cat(err) != hypervisor.Conflict {
		t.Fatalf("a duplicate reservation: %v", err)
	}
	// an address leased to some other machine
	st := r.host.Load()
	st.ExtraLeases = append(st.ExtraLeases, simhost.ExtraLease{Network: "lab-net", MAC: "52:54:00:99:99:99", IP: "10.77.0.60"})
	_ = r.host.Save(st)
	if err := provision.ReserveIP(ctx, r.counter, "web-2", "10.77.0.60", nil); cat(err) != hypervisor.Conflict {
		t.Fatalf("an address leased elsewhere: %v", err)
	}
	// the reservation binds the exact VM: it shows up on the network and the VM boots into it
	if err := provision.Start(ctx, r.counter, vm, nil); err != nil {
		t.Fatal(err)
	}
	if d, _ := (simhost.Reader{H: r.host}).Lookup(ctx, vm); d.IPv4 != "10.77.0.50" {
		t.Fatalf("%+v", d)
	}
	// wrong VM, foreign VM, default network
	if err := provision.ReserveIP(ctx, r.counter, "nope", "10.77.0.70", nil); cat(err) != hypervisor.NotFound {
		t.Fatalf("%v", err)
	}
	_ = r.host.Add("foreign", simhost.Domain{UUID: "9a9a9a9a-2222-4333-8444-5555555555ac", VCPUs: 1, MemoryMiB: 64})
	if err := provision.ReserveIP(ctx, r.counter, "foreign", "10.77.0.70", nil); cat(err) != hypervisor.Prohibited {
		t.Fatalf("%v", err)
	}
	// release (twice) and re-reserve
	if err := provision.ReleaseIP(ctx, r.counter, vm, nil); err != nil {
		t.Fatal(err)
	}
	if err := provision.ReleaseIP(ctx, r.counter, vm, nil); err != nil {
		t.Fatalf("a repeat: %v", err)
	}
	// web-1 still holds its lease until it expires, so the address stays taken; another address is fine
	if err := provision.ReserveIP(ctx, r.counter, "web-2", "10.77.0.50", nil); cat(err) != hypervisor.Conflict {
		t.Fatalf("an address that is still leased: %v", err)
	}
	if err := provision.ReserveIP(ctx, r.counter, "web-2", "10.77.0.52", nil); err != nil {
		t.Fatalf("a free address: %v", err)
	}
}

func TestReservationNeedsAManagedNetwork(t *testing.T) {
	ctx := context.Background()
	r := newRig(t)
	if err := r.provision(nil); err != nil { // on the default (foreign) network
		t.Fatal(err)
	}
	if err := provision.ReserveIP(ctx, r.counter, "web-1", "192.168.122.50", nil); cat(err) != hypervisor.Prohibited {
		t.Fatalf("%v", err)
	}
}

func TestComputeChangeRules(t *testing.T) {
	ctx := context.Background()
	r := newRig(t)
	r.stopped(t)
	if err := provision.Compute(ctx, r.counter, "web-1", 4, 2048, nil); err != nil {
		t.Fatal(err)
	}
	d, _ := r.host.LookupDomain(ctx, "web-1")
	pd, _ := provision.ParseDomain(d.XML)
	if d.VCPUs != 4 || d.MemoryMiB != 2048 || pd.VCPUs != 4 || pd.MemoryMiB != 2048 {
		t.Fatalf("%+v %+v", d, pd)
	}
	if err := provision.Compute(ctx, r.counter, "web-1", 4, 2048, nil); err != nil {
		t.Fatalf("a repeat: %v", err)
	}
	for name, c := range map[string][2]int{"zero cpus": {0, 1024}, "too many cpus": {provision.MaxVCPUs + 1, 1024}, "tiny memory": {2, 32}, "odd memory": {2, 1000}, "huge memory": {2, provision.MaxMemoryMiB + 64}} {
		if err := provision.Compute(ctx, r.counter, "web-1", c[0], c[1], nil); cat(err) != hypervisor.Validation {
			t.Errorf("%s: %v", name, err)
		}
	}
	if err := provision.Start(ctx, r.counter, "web-1", nil); err != nil {
		t.Fatal(err)
	}
	if err := provision.Compute(ctx, r.counter, "web-1", 2, 1024, nil); cat(err) != hypervisor.Conflict {
		t.Fatalf("a running VM: %v", err)
	}
	_ = r.host.Add("foreign", simhost.Domain{UUID: "9a9a9a9a-2222-4333-8444-5555555555ad", VCPUs: 1, MemoryMiB: 64})
	if err := provision.Compute(ctx, r.counter, "foreign", 2, 1024, nil); cat(err) != hypervisor.Prohibited {
		t.Fatalf("%v", err)
	}
}

func TestNoNetworkXMLCanBeInjected(t *testing.T) {
	for _, bad := range []string{"x'/><evil/>", "a b", "a<b", "", "ab\"", "A"} {
		if _, err := provision.NetworkXML(netSpec(func(s *provision.NetworkSpec) { s.Name = bad })); err == nil {
			t.Errorf("name %q was accepted", bad)
		}
	}
	for _, bad := range []string{"10.77.0.0/24'/><evil/>", "10.77.0.0/24\n", " 10.77.0.0/24"} {
		if _, err := provision.NetworkXML(netSpec(func(s *provision.NetworkSpec) { s.Subnet = bad })); err == nil {
			t.Errorf("subnet %q was accepted", bad)
		}
	}
	x, err := provision.NetworkXML(netSpec(nil))
	if err != nil || strings.Count(x, "<") != strings.Count(x, ">") || strings.Contains(x, "evil") {
		t.Fatalf("%q %v", x, err)
	}
	if _, err := provision.HostEntryXML("52:54:00:00:00:01'/><x", "10.0.0.1"); err == nil {
		t.Fatal("a MAC with markup was accepted")
	}
}

func bridgeSpec(mut func(*provision.NetworkSpec)) provision.NetworkSpec {
	s := provision.NetworkSpec{Name: "lan", UUID: "9b9b9b9b-2222-4333-8444-5555555555ab", HostBridge: "svbr0"}
	if mut != nil {
		mut(&s)
	}
	return s
}

func TestABridgeModeNetworkIsOwnedStartedAndUsesTheHostBridgeAsIs(t *testing.T) {
	ctx := context.Background()
	r := newRig(t)
	r.createNet(t, bridgeSpec(nil))
	n, err := r.host.LookupNetwork(ctx, "lan")
	if err != nil || !n.Managed || !n.Active || !n.Autostart || n.Mode != "bridge" || n.Bridge != "svbr0" || n.Subnet.IsValid() || n.DHCPStart != "" {
		t.Fatalf("%+v %v", n, err)
	}
	r.createNet(t, bridgeSpec(nil)) // the same specification again is a no-op
	if nets, _ := r.host.ListNetworks(ctx); len(nets) != 2 {
		t.Fatalf("the default network plus one: %d", len(nets))
	}
	for name, mut := range map[string]func(*provision.NetworkSpec){
		"another bridge under the same name":   func(s *provision.NetworkSpec) { s.HostBridge = "br9" },
		"another network on the same bridge":   func(s *provision.NetworkSpec) { s.Name, s.UUID = "lan2", "8c8c8c8c-2222-4333-8444-5555555555ab" },
		"the same identity under another name": func(s *provision.NetworkSpec) { s.Name = "lan3" },
	} {
		if err := provision.NetworkCreate(ctx, r.counter, r.cfg, bridgeSpec(mut), nil, nil); cat(err) != hypervisor.Conflict {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestABridgeModeNetworkRefusesBridgesThatAreNotTheHostsToUse(t *testing.T) {
	ctx := context.Background()
	r := newRig(t)
	for name, mut := range map[string]func(*provision.NetworkSpec){
		"libvirt's own bridge":     func(s *provision.NetworkSpec) { s.HostBridge = "virbr0" },
		"docker's bridge":          func(s *provision.NetworkSpec) { s.HostBridge = "docker0" },
		"a docker network bridge":  func(s *provision.NetworkSpec) { s.HostBridge = "br-0a1b2c3d4e5f" },
		"a bridge Svavyom derives": func(s *provision.NetworkSpec) { s.HostBridge = "svbr7a7a7a7a" },
		"a name with a space":      func(s *provision.NetworkSpec) { s.HostBridge = "a b" },
		"a name that is too long":  func(s *provision.NetworkSpec) { s.HostBridge = "abcdefghijklmnop" },
		"a subnet as well":         func(s *provision.NetworkSpec) { s.Subnet = "10.77.0.0/24" },
		"a DHCP range as well":     func(s *provision.NetworkSpec) { s.DHCPStart, s.DHCPEnd = "10.77.0.10", "10.77.0.20" },
	} {
		if err := provision.NetworkCreate(ctx, r.counter, r.cfg, bridgeSpec(mut), nil, nil); cat(err) != hypervisor.Validation {
			t.Errorf("%s: %v", name, err)
		}
	}
	if nets, _ := r.host.ListNetworks(ctx); len(nets) != 1 {
		t.Fatalf("a refused create left a network behind: %d", len(nets))
	}
}

func TestAVMOnABridgeModeNetworkRunsAndTheNetworkCannotBeStoppedUnderIt(t *testing.T) {
	ctx := context.Background()
	r := newRig(t)
	r.createNet(t, bridgeSpec(nil))
	r.spec.Network = "lan"
	if err := r.provision(nil); err != nil {
		t.Fatal(err)
	}
	if err := r.host.StartDomain(ctx, r.spec.Name); err != nil {
		t.Fatal(err)
	}
	if err := provision.NetworkStop(ctx, r.counter, "lan", nil); cat(err) != hypervisor.Conflict {
		t.Fatalf("stopping under a running VM: %v", err)
	}
	if err := provision.NetworkDelete(ctx, r.counter, "lan", nil); cat(err) != hypervisor.Conflict {
		t.Fatalf("deleting with a VM attached: %v", err)
	}
}
