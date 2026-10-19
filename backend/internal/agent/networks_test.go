package agent

import (
	"context"
	"testing"
	"time"

	"example.invalid/dedicatedcloud/backend/internal/hypervisor"
)

type netReader struct {
	*memReader
	nets []hypervisor.Network
	err  error
}

func (n netReader) Networks(context.Context) ([]hypervisor.Network, error) { return n.nets, n.err }

func goodNet() hypervisor.Network {
	return hypervisor.Network{Name: "lab-net", UUID: "7a7a7a7a-2222-4333-8444-5555555555ab", Managed: true, Active: true, Autostart: true, Mode: "nat", Bridge: "svbr7a7a7a7a",
		Subnet: "10.77.0.0/24", Gateway: "10.77.0.1", DHCPStart: "10.77.0.10", DHCPEnd: "10.77.0.200", AttachedVMs: 2,
		Reservations: []hypervisor.Reservation{{MAC: "52:54:00:aa:bb:cc", IP: "10.77.0.50"}}}
}

func TestNetworksAreReadOverTheClosedProtocol(t *testing.T) {
	foreign := hypervisor.Network{Name: "default", UUID: "00000000-0000-4000-8000-000000000001", Active: true, Mode: "nat", Bridge: "virbr0", Subnet: "192.168.122.0/24", Gateway: "192.168.122.1"}
	g := start(t, netReader{memReader: seeded(), nets: []hypervisor.Network{goodNet(), foreign}})
	c, err := NewClient(g.path, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	got, err := c.Networks(context.Background())
	if err != nil || len(got) != 2 || got[0].Name != "default" || got[0].Managed || got[1].Name != "lab-net" || !got[1].Managed || got[1].AttachedVMs != 2 ||
		len(got[1].Reservations) != 1 || got[1].Reservations[0].IP != "10.77.0.50" {
		t.Fatalf("%+v %v", got, err)
	}
}

func TestMalformedNetworkInventoryIsAnErrorNeverASilentGap(t *testing.T) {
	bad := map[string]func(*hypervisor.Network){
		"name with a space":    func(n *hypervisor.Network) { n.Name = "my net" },
		"managed without uuid": func(n *hypervisor.Network) { n.UUID = "" },
		"bad subnet":           func(n *hypervisor.Network) { n.Subnet = "10.77.0.5/24" },
		"ipv6 gateway":         func(n *hypervisor.Network) { n.Gateway = "fd00::1" },
		"bad bridge":           func(n *hypervisor.Network) { n.Bridge = "a b" },
		"bad reservation mac":  func(n *hypervisor.Network) { n.Reservations[0].MAC = "XX" },
		"negative attached":    func(n *hypervisor.Network) { n.AttachedVMs = -1 },
	}
	for name, mut := range bad {
		n := goodNet()
		n.Reservations = append([]hypervisor.Reservation(nil), n.Reservations...)
		mut(&n)
		g := start(t, netReader{memReader: seeded(), nets: []hypervisor.Network{n}})
		c, _ := NewClient(g.path, 2*time.Second)
		if _, err := c.Networks(context.Background()); hypervisor.CategoryOf(err) != hypervisor.HostError {
			t.Errorf("%s: %v", name, err)
		}
	}
	// a reader that cannot describe networks, and one that fails
	g := start(t, seeded())
	c, _ := NewClient(g.path, 2*time.Second)
	if _, err := c.Networks(context.Background()); hypervisor.CategoryOf(err) != hypervisor.Unavailable {
		t.Fatalf("%v", err)
	}
	g2 := start(t, netReader{memReader: seeded(), err: hypervisor.NewError(hypervisor.Unavailable, "x", "", "down")})
	c2, _ := NewClient(g2.path, 2*time.Second)
	if _, err := c2.Networks(context.Background()); hypervisor.CategoryOf(err) != hypervisor.Unavailable {
		t.Fatalf("%v", err)
	}
	// an unknown libvirt forward mode is reported as "other", not dropped
	n := goodNet()
	n.Mode = "weird"
	g3 := start(t, netReader{memReader: seeded(), nets: []hypervisor.Network{n}})
	c3, _ := NewClient(g3.path, 2*time.Second)
	if got, err := c3.Networks(context.Background()); err != nil || got[0].Mode != "other" {
		t.Fatalf("%+v %v", got, err)
	}
}
