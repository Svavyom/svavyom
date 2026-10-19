package api

import (
	"encoding/json"
	"net/netip"
	"strings"
	"testing"
)

func (s *storageRig) networks() map[string]networkJSON {
	s.t.Helper()
	rep := s.b.do("GET", "/api/v1/virtual-networks", "", nil)
	var l struct {
		Items []networkJSON `json:"items"`
	}
	if rep.status != 200 || json.Unmarshal(rep.body, &l) != nil {
		s.t.Fatalf("%d %s", rep.status, rep.body)
	}
	out := map[string]networkJSON{}
	for _, n := range l.Items {
		out[n.ID] = n
	}
	return out
}

func (s *storageRig) createVMOn(name, network string) {
	s.t.Helper()
	body := s.createBody(name, s.key, func(c map[string]any) {
		if network != "" {
			c["network"] = network
		}
	})
	s.await(s.b, opID(s.t, s.post(s.b, body)), "succeeded")
}

var lab = map[string]any{"subnet": "10.77.0.0/24", "dhcp_start": "10.77.0.10", "dhcp_end": "10.77.0.200"}

func TestManagedNetworkJourneyThroughTheAPI(t *testing.T) {
	s := newStorageRig(t)
	nets := s.networks()
	def, ok := nets["svavyom-nat"]
	if !ok || def.Observed.Managed || len(def.Allowed) != 0 || def.Observed.Subnet == nil || *def.Observed.Subnet != "192.168.122.0/24" {
		t.Fatalf("the pre-existing network is listed, foreign and offers no action: %+v", def)
	}
	s.do("network_create", "VirtualNetwork", "lab-net", lab)
	lab1 := s.networks()["lab-net"]
	if !lab1.Observed.Managed || lab1.Observed.State != "active" || !lab1.Desired.Autostart || lab1.Observed.AttachedVMs != 0 || lab1.Desired.Mode != "nat" ||
		lab1.Observed.Gateway == nil || *lab1.Observed.Gateway != "10.77.0.1" || strings.Join(lab1.Allowed, ",") != "stop,delete,disable_autostart" {
		t.Fatalf("%+v", lab1)
	}
	if one := s.b.do("GET", "/api/v1/virtual-networks/lab-net", "", nil); one.status != 200 {
		t.Fatalf("%d %s", one.status, one.body)
	}
	if nf := s.b.do("GET", "/api/v1/virtual-networks/nope", "", nil); nf.status != 404 {
		t.Fatalf("%d", nf.status)
	}
	// a VM on the managed network reports it, offers a reservation and a compute change
	s.createVMOn("db-1", "lab-net")
	v := s.vm("db-1")
	if v.Observed.Network == nil || v.Observed.Network.Name != "lab-net" || v.Observed.Network.State != "active" || v.Observed.Network.ReservedIP != nil ||
		!strings.Contains(strings.Join(v.Allowed, ","), "reserve_ip") || !strings.Contains(strings.Join(v.Allowed, ","), "compute") {
		t.Fatalf("%+v %v", v.Observed.Network, v.Allowed)
	}
	if w := s.vm("web-1"); w.Observed.Network == nil || w.Observed.Network.Name != "svavyom-nat" || strings.Contains(strings.Join(w.Allowed, ","), "reserve_ip") {
		t.Fatalf("a VM on the foreign network offers no reservation: %+v %v", w.Observed.Network, w.Allowed)
	}
	if got := s.networks()["lab-net"]; got.Observed.AttachedVMs != 1 || strings.Contains(strings.Join(got.Allowed, ","), "delete") {
		t.Fatalf("%+v", got)
	}
	// reserve, see it on both resources, release
	s.do("reserve_ip", "VM", "db-1", map[string]any{"ip_address": "10.77.0.50"})
	if v = s.vm("db-1"); v.Observed.Network.ReservedIP == nil || *v.Observed.Network.ReservedIP != "10.77.0.50" || !strings.Contains(strings.Join(v.Allowed, ","), "release_ip") ||
		strings.Contains(strings.Join(v.Allowed, ","), "reserve_ip") {
		t.Fatalf("%+v %v", v.Observed.Network, v.Allowed)
	}
	if r := s.networks()["lab-net"].Observed.Reservations; len(r) != 1 || r[0].IP != "10.77.0.50" {
		t.Fatalf("%+v", r)
	}
	// start: the guest boots into its reserved address; the running VM pins the network up
	s.do("start", "VM", "db-1", nil)
	if v = s.vm("db-1"); v.Observed.IPAddress == nil || *v.Observed.IPAddress != "10.77.0.50" {
		t.Fatalf("%v", v.Observed.IPAddress)
	}
	if rep := s.submit("network_stop", "VirtualNetwork", "lab-net", nil); rep.status != 409 {
		t.Fatalf("stop with a running VM: %d %s", rep.status, rep.body)
	}
	if got := s.networks()["lab-net"]; strings.Contains(strings.Join(got.Allowed, ","), "stop") {
		t.Fatalf("a network with a running VM does not offer stop: %v", got.Allowed)
	}
	s.do("stop", "VM", "db-1", nil)
	// compute on the stopped VM, then autostart, stop, start
	s.do("compute", "VM", "db-1", map[string]any{"vcpus": 1, "memory_mib": 512})
	if v = s.vm("db-1"); v.Observed.Network == nil {
		t.Fatal("lost the network")
	}
	s.do("network_autostart", "VirtualNetwork", "lab-net", map[string]any{"autostart": "off"})
	if n := s.networks()["lab-net"]; n.Desired.Autostart || !strings.Contains(strings.Join(n.Allowed, ","), "enable_autostart") {
		t.Fatalf("%+v", n)
	}
	s.do("network_stop", "VirtualNetwork", "lab-net", nil)
	if n := s.networks()["lab-net"]; n.Observed.State != "inactive" || !strings.Contains(strings.Join(n.Allowed, ","), "start") {
		t.Fatalf("%+v", n)
	}
	if rep := s.submit("start", "VM", "db-1", nil); rep.status != 409 {
		t.Fatalf("a VM does not start on an inactive network: %d %s", rep.status, rep.body)
	}
	s.do("network_start", "VirtualNetwork", "lab-net", nil)
	// release, delete is refused while the VM exists, then goes after it
	s.do("release_ip", "VM", "db-1", nil)
	if rep := s.submit("network_delete", "VirtualNetwork", "lab-net", nil); rep.status != 409 {
		t.Fatalf("delete with an attached VM: %d %s", rep.status, rep.body)
	}
	s.do("delete", "VM", "db-1", nil)
	s.do("network_delete", "VirtualNetwork", "lab-net", nil)
	if _, there := s.networks()["lab-net"]; there {
		t.Fatal("the network is still listed")
	}
}

func TestNetworkCreateRefusals(t *testing.T) {
	s := newStorageRig(t)
	s.host.avoid = []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24"), netip.MustParsePrefix("10.99.0.0/16")}
	s.do("network_create", "VirtualNetwork", "lab-net", lab)
	with := func(m map[string]any) map[string]any {
		out := map[string]any{}
		for k, v := range lab {
			out[k] = v
		}
		for k, v := range m {
			out[k] = v
		}
		return out
	}
	cases := map[string]struct {
		id     string
		params map[string]any
		status int
	}{
		"name taken":               {"lab-net", with(map[string]any{"subnet": "10.78.0.0/24", "dhcp_start": "10.78.0.10", "dhcp_end": "10.78.0.20"}), 409},
		"name of the default":      {"svavyom-nat", with(map[string]any{"subnet": "10.78.0.0/24", "dhcp_start": "10.78.0.10", "dhcp_end": "10.78.0.20"}), 400},
		"overlaps a managed one":   {"other", with(map[string]any{"subnet": "10.77.0.0/25", "dhcp_start": "10.77.0.10", "dhcp_end": "10.77.0.20"}), 409},
		"overlaps the default":     {"other", with(map[string]any{"subnet": "192.168.122.0/24", "dhcp_start": "192.168.122.10", "dhcp_end": "192.168.122.20"}), 409},
		"overlaps the host":        {"other", with(map[string]any{"subnet": "192.168.1.0/24", "dhcp_start": "192.168.1.10", "dhcp_end": "192.168.1.20"}), 409},
		"inside a host route":      {"other", with(map[string]any{"subnet": "10.99.4.0/24", "dhcp_start": "10.99.4.10", "dhcp_end": "10.99.4.20"}), 409},
		"public subnet":            {"other", with(map[string]any{"subnet": "8.8.8.0/24", "dhcp_start": "8.8.8.10", "dhcp_end": "8.8.8.20"}), 400},
		"huge subnet":              {"other", with(map[string]any{"subnet": "10.0.0.0/8", "dhcp_start": "10.0.0.10", "dhcp_end": "10.0.0.20"}), 400},
		"range outside the subnet": {"other", with(map[string]any{"subnet": "10.78.0.0/24", "dhcp_start": "10.79.0.10", "dhcp_end": "10.79.0.20"}), 400},
		"range at the gateway":     {"other", with(map[string]any{"subnet": "10.78.0.0/24", "dhcp_start": "10.78.0.1", "dhcp_end": "10.78.0.20"}), 400},
		"reversed range":           {"other", with(map[string]any{"subnet": "10.78.0.0/24", "dhcp_start": "10.78.0.50", "dhcp_end": "10.78.0.20"}), 400},
		"uppercase name":           {"Other", with(map[string]any{"subnet": "10.78.0.0/24", "dhcp_start": "10.78.0.10", "dhcp_end": "10.78.0.20"}), 400},
		"missing params":           {"other", nil, 400},
		"xml in the subnet":        {"other", with(map[string]any{"subnet": "10.78.0.0/24'/><evil/>"}), 400},
		"unknown param":            {"other", with(map[string]any{"bridge": "br0"}), 400},
	}
	for name, c := range cases {
		rep := s.submit("network_create", "VirtualNetwork", c.id, c.params)
		if rep.status != c.status {
			t.Errorf("%s: %d %s", name, rep.status, rep.body)
		}
		if strings.Contains(string(rep.body), "evil") || strings.Contains(string(rep.body), "10.78") {
			t.Errorf("%s: input echoed", name)
		}
	}
	// unreadable host networks: fail closed
	s.host.avoid = nil
	if len(s.networks()) != 2 {
		t.Fatalf("a refused create changed the host: %v", s.networks())
	}
}

func TestNetworkOperationsNeverTouchForeignNetworksOrOtherKinds(t *testing.T) {
	s := newStorageRig(t)
	for _, typ := range []string{"network_start", "network_stop", "network_delete"} {
		if rep := s.submit(typ, "VirtualNetwork", "svavyom-nat", nil); rep.status != 409 && rep.status != 422 {
			t.Errorf("%s of the default network: %d %s", typ, rep.status, rep.body)
		}
	}
	if rep := s.submit("network_delete", "VirtualNetwork", "svavyom-nat", nil); rep.status != 422 {
		t.Fatalf("deleting the default network must be prohibited: %d %s", rep.status, rep.body)
	}
	if rep := s.submit("network_autostart", "VirtualNetwork", "svavyom-nat", map[string]any{"autostart": "off"}); rep.status != 422 {
		t.Fatalf("%d", rep.status)
	}
	if rep := s.submit("network_start", "VirtualNetwork", "ghost", nil); rep.status != 404 {
		t.Fatalf("%d", rep.status)
	}
	for name, c := range map[string]struct{ typ, kind, id string }{
		"network type on a VM":     {"network_stop", "VM", "web-1"},
		"VM type on a network":     {"start", "VirtualNetwork", "svavyom-nat"},
		"network kind with delete": {"delete", "VirtualNetwork", "svavyom-nat"},
		"a Volume":                 {"network_stop", "Volume", "web-1-root"},
	} {
		if rep := s.submit(c.typ, c.kind, c.id, nil); rep.status != 422 {
			t.Errorf("%s: %d %s", name, rep.status, rep.body)
		}
	}
	if !s.sim.Load().Domains["web-1"].Managed || len(s.networks()) != 1 {
		t.Fatal("something changed")
	}
}

func TestAttachingAVMToTheWrongNetworkIsRefused(t *testing.T) {
	s := newStorageRig(t)
	if err := s.sim.AddForeignNetwork("office", "10.78.0.1", "255.255.255.0", true); err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{"office", "ghost-net", "svavyom-nat-2"} {
		body := s.createBody("bad-"+strings.ReplaceAll(n, "_", "-"), s.key, func(c map[string]any) { c["network"] = n })
		if rep := s.post(s.b, body); rep.status != 400 {
			t.Errorf("attach to %s: %d %s", n, rep.status, rep.body)
		}
	}
	// an inactive managed network is not ready
	s.do("network_create", "VirtualNetwork", "lab-net", lab)
	s.do("network_stop", "VirtualNetwork", "lab-net", nil)
	body := s.createBody("late-1", s.key, func(c map[string]any) { c["network"] = "lab-net" })
	if rep := s.post(s.b, body); rep.status != 503 {
		t.Fatalf("%d %s", rep.status, rep.body)
	}
	if st := s.sim.Load(); len(st.Domains) != 1 {
		t.Fatalf("a refused create made a VM: %d", len(st.Domains))
	}
	// naming the configured network explicitly is the same as not naming one
	same := s.createBody("same-1", s.key, func(c map[string]any) { c["network"] = "svavyom-nat" })
	s.await(s.b, opID(t, s.post(s.b, same)), "succeeded")
}

func TestReservationAndComputeRules(t *testing.T) {
	s := newStorageRig(t)
	s.do("network_create", "VirtualNetwork", "lab-net", lab)
	s.createVMOn("db-1", "lab-net")
	s.createVMOn("db-2", "lab-net")
	ip := func(v string) map[string]any { return map[string]any{"ip_address": v} }
	for name, v := range map[string]string{"gateway": "10.77.0.1", "network address": "10.77.0.0", "broadcast": "10.77.0.255", "outside": "10.99.0.5", "ipv6": "fd00::5", "garbage": "10.77.0.x"} {
		if rep := s.submit("reserve_ip", "VM", "db-1", ip(v)); rep.status != 400 {
			t.Errorf("%s: %d %s", name, rep.status, rep.body)
		}
	}
	s.do("reserve_ip", "VM", "db-1", ip("10.77.0.50"))
	if rep := s.submit("reserve_ip", "VM", "db-2", ip("10.77.0.50")); rep.status != 409 {
		t.Fatalf("a duplicate reservation: %d %s", rep.status, rep.body)
	}
	if rep := s.submit("reserve_ip", "VM", "db-1", ip("10.77.0.51")); rep.status != 409 {
		t.Fatalf("a second reservation for the same VM: %d %s", rep.status, rep.body)
	}
	if rep := s.submit("release_ip", "VM", "db-2", nil); rep.status != 409 {
		t.Fatalf("nothing to release: %d %s", rep.status, rep.body)
	}
	// the default (foreign) network offers no reservation, an unknown VM is not found
	if rep := s.submit("reserve_ip", "VM", "web-1", ip("192.168.122.50")); rep.status != 422 {
		t.Fatalf("%d %s", rep.status, rep.body)
	}
	if rep := s.submit("reserve_ip", "VM", "ghost", ip("10.77.0.60")); rep.status != 404 {
		t.Fatalf("%d", rep.status)
	}
	// compute: only on a Stopped VM, only within the sizes the host offers
	for name, p := range map[string]map[string]any{"zero cpus": {"vcpus": 0, "memory_mib": 1024}, "not offered": {"vcpus": 3, "memory_mib": 1024}, "odd memory": {"vcpus": 2, "memory_mib": 1000},
		"huge": {"vcpus": 64, "memory_mib": 1 << 30}, "missing": {"vcpus": 2}} {
		if rep := s.submit("compute", "VM", "db-1", p); rep.status != 400 {
			t.Errorf("%s: %d %s", name, rep.status, rep.body)
		}
	}
	s.do("compute", "VM", "db-1", map[string]any{"vcpus": 2, "memory_mib": 2048})
	s.do("start", "VM", "db-1", nil)
	if rep := s.submit("compute", "VM", "db-1", map[string]any{"vcpus": 1, "memory_mib": 1024}); rep.status != 409 {
		t.Fatalf("compute of a running VM: %d %s", rep.status, rep.body)
	}
	if v := s.vm("db-1"); strings.Contains(strings.Join(v.Allowed, ","), "compute") {
		t.Fatalf("a running VM offers compute: %v", v.Allowed)
	}
	if d := s.sim.Load().Domains["db-1"]; d.VCPUs != 2 || d.MemoryMiB != 2048 {
		t.Fatalf("%+v", d)
	}
}

func TestABridgeModeNetworkNeedsTheHostBridgeSvavyomCtlRecordedAsActive(t *testing.T) {
	s := newStorageRig(t)
	bridge := &BridgeObserved{State: "active", Bridge: "svbr0", Interface: "eno1"}
	device := true
	s.env.h.deps.Bridge = func() *BridgeObserved { return bridge }
	s.env.h.deps.BridgeDevice = func(string) bool { return device }
	on := func(b string) map[string]any { return map[string]any{"bridge": b} }

	bridge = nil
	if rep := s.submit("network_create", "VirtualNetwork", "lan", on("svbr0")); rep.status != 422 {
		t.Fatalf("no recorded bridge: %d %s", rep.status, rep.body)
	}
	bridge = &BridgeObserved{State: "planned", Bridge: "svbr0", Interface: "eno1"}
	if rep := s.submit("network_create", "VirtualNetwork", "lan", on("svbr0")); rep.status != 422 {
		t.Fatalf("a planned bridge is not in place: %d %s", rep.status, rep.body)
	}
	ten := 10
	bridge = &BridgeObserved{State: "pending_confirmation", Bridge: "svbr0", Interface: "eno1", SecondsLeft: &ten}
	if rep := s.submit("network_create", "VirtualNetwork", "lan", on("svbr0")); rep.status != 422 {
		t.Fatalf("an unconfirmed bridge may still be rolled back: %d %s", rep.status, rep.body)
	}
	bridge = &BridgeObserved{State: "active", Bridge: "svbr0", Interface: "eno1"}
	if rep := s.submit("network_create", "VirtualNetwork", "lan", on("br9")); rep.status != 422 {
		t.Fatalf("another bridge name: %d %s", rep.status, rep.body)
	}
	device = false
	if rep := s.submit("network_create", "VirtualNetwork", "lan", on("svbr0")); rep.status != 503 {
		t.Fatalf("the device is missing: %d %s", rep.status, rep.body)
	}
	device = true
	for name, c := range map[string]struct {
		id     string
		params map[string]any
	}{
		"libvirt's bridge":         {"lan", on("virbr0")},
		"a subnet as well":         {"lan", map[string]any{"bridge": "svbr0", "subnet": "10.77.0.0/24"}},
		"a DHCP range as well":     {"lan", map[string]any{"bridge": "svbr0", "dhcp_start": "10.77.0.10", "dhcp_end": "10.77.0.20"}},
		"a name with a space":      {"lan", on("a b")},
		"the default network name": {"svavyom-nat", on("svbr0")},
	} {
		if rep := s.submit("network_create", "VirtualNetwork", c.id, c.params); rep.status != 400 {
			t.Errorf("%s: %d %s", name, rep.status, rep.body)
		}
	}
	s.do("network_create", "VirtualNetwork", "lan", on("svbr0"))
	n := s.networks()["lan"]
	if !n.Observed.Managed || n.Desired.Mode != "bridge" || n.Observed.State != "active" || n.Observed.Subnet != nil || n.Observed.Bridge == nil || *n.Observed.Bridge != "svbr0" || n.Observed.DHCPStart != nil {
		t.Fatalf("%+v", n)
	}
	if rep := s.submit("network_create", "VirtualNetwork", "lan", on("svbr0")); rep.status != 409 {
		t.Fatalf("same name: %d %s", rep.status, rep.body)
	}
	if rep := s.submit("network_create", "VirtualNetwork", "lan2", on("svbr0")); rep.status != 409 {
		t.Fatalf("a second network on the same bridge: %d %s", rep.status, rep.body)
	}
	// A VM may be created on it, and the network then cannot be deleted from under it.
	s.createVMOn("edge-1", "lan")
	if got := s.networks()["lan"]; got.Observed.AttachedVMs != 1 || strings.Contains(strings.Join(got.Allowed, ","), "delete") {
		t.Fatalf("%+v", got)
	}
}
