package mutagent

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"example.invalid/dedicatedcloud/backend/internal/hypervisor"
)

const mnUUID = "7a7a7a7a-2222-4333-8444-5555555555ab"

func lab() Net {
	return Net{UUID: mnUUID, Subnet: "10.77.0.0/24", DHCPStart: "10.77.0.10", DHCPEnd: "10.77.0.200", Avoid: []string{"192.168.1.0/24"}}
}

func TestNetworkOperationsThroughTheSupervisor(t *testing.T) {
	r := newRig(t, 30*time.Second, "")
	ctx := context.Background()
	if err := r.client.NetworkCreate(ctx, "lab-net", lab()); err != nil {
		t.Fatal(err)
	}
	if err := r.client.NetworkCreate(ctx, "lab-net", lab()); err != nil {
		t.Fatalf("a repeat: %v", err)
	}
	// the host prefixes the API passed are extra reasons to refuse
	clash := Net{UUID: "8a8a8a8a-2222-4333-8444-5555555555ab", Subnet: "192.168.1.0/24", DHCPStart: "192.168.1.10", DHCPEnd: "192.168.1.20", Avoid: []string{"192.168.1.0/24"}}
	if err := r.client.NetworkCreate(ctx, "clash-net", clash); cat(err) != hypervisor.Conflict {
		t.Fatalf("%v", err)
	}
	// a VM on the managed network, a reservation, a compute change
	r.spec.Network = "lab-net"
	if err := r.client.Provision(ctx, r.spec); err != nil {
		t.Fatal(err)
	}
	if err := r.client.ReserveIP(ctx, "web-1", "10.77.0.50"); err != nil {
		t.Fatal(err)
	}
	if err := r.client.ReserveIP(ctx, "web-1", "10.77.0.1"); cat(err) != hypervisor.Validation {
		t.Fatalf("the gateway: %v", err)
	}
	if err := r.client.Compute(ctx, "web-1", 4, 2048); err != nil {
		t.Fatal(err)
	}
	if d := r.sim.Load().Domains["web-1"]; d.VCPUs != 4 || d.MemoryMiB != 2048 {
		t.Fatalf("%+v", d)
	}
	if err := r.client.NetworkDelete(ctx, "lab-net"); cat(err) != hypervisor.Conflict {
		t.Fatalf("an attached VM: %v", err)
	}
	if err := r.client.ReleaseIP(ctx, "web-1"); err != nil {
		t.Fatal(err)
	}
	if err := r.client.NetworkStop(ctx, "lab-net"); err != nil {
		t.Fatal(err)
	}
	if err := r.client.NetworkStart(ctx, "lab-net"); err != nil {
		t.Fatal(err)
	}
	if err := r.client.NetworkAutostart(ctx, "lab-net", "off"); err != nil {
		t.Fatal(err)
	}
	if err := r.client.Delete(ctx, "web-1"); err != nil {
		t.Fatal(err)
	}
	if err := r.client.NetworkDelete(ctx, "lab-net"); err != nil {
		t.Fatal(err)
	}
	if err := r.client.NetworkDelete(ctx, "lab-net"); err != nil {
		t.Fatalf("a repeat: %v", err)
	}
	// the default network is foreign
	if err := r.client.NetworkDelete(ctx, "svavyom-nat"); cat(err) != hypervisor.Prohibited {
		t.Fatalf("%v", err)
	}
}

func TestNetworkRequestsAreClosed(t *testing.T) {
	long := make([]string, MaxAvoid+1)
	for i := range long {
		long[i] = "192.168.1.0/24"
	}
	bad := map[string]Request{
		"net_create without a body":       {V: Version, Op: OpNetCreate, Name: "lab-net"},
		"net_create bad name":             {V: Version, Op: OpNetCreate, Name: "Lab Net", Net: ptr(lab())},
		"net_create name too short":       {V: Version, Op: OpNetCreate, Name: "a", Net: ptr(lab())},
		"net_create public subnet":        {V: Version, Op: OpNetCreate, Name: "lab-net", Net: &Net{UUID: mnUUID, Subnet: "8.8.8.0/24", DHCPStart: "8.8.8.10", DHCPEnd: "8.8.8.20"}},
		"net_create dhcp outside":         {V: Version, Op: OpNetCreate, Name: "lab-net", Net: &Net{UUID: mnUUID, Subnet: "10.77.0.0/24", DHCPStart: "10.78.0.10", DHCPEnd: "10.78.0.20"}},
		"net_create bad uuid":             {V: Version, Op: OpNetCreate, Name: "lab-net", Net: &Net{UUID: "nope", Subnet: "10.77.0.0/24", DHCPStart: "10.77.0.10", DHCPEnd: "10.77.0.20"}},
		"net_create junk avoid":           {V: Version, Op: OpNetCreate, Name: "lab-net", Net: &Net{UUID: mnUUID, Subnet: "10.77.0.0/24", DHCPStart: "10.77.0.10", DHCPEnd: "10.77.0.20", Avoid: []string{"10.0.0.5/8"}}},
		"net_create too many avoid":       {V: Version, Op: OpNetCreate, Name: "lab-net", Net: &Net{UUID: mnUUID, Subnet: "10.77.0.0/24", DHCPStart: "10.77.0.10", DHCPEnd: "10.77.0.20", Avoid: long}},
		"net_create with reservation":     {V: Version, Op: OpNetCreate, Name: "lab-net", Net: &Net{UUID: mnUUID, Subnet: "10.77.0.0/24", DHCPStart: "10.77.0.10", DHCPEnd: "10.77.0.20", IP: "10.77.0.5"}},
		"net_create bridge with a subnet": {V: Version, Op: OpNetCreate, Name: "lan", Net: &Net{UUID: mnUUID, HostBridge: "svbr0", Subnet: "10.77.0.0/24"}},
		"net_create bridge virbr0":        {V: Version, Op: OpNetCreate, Name: "lan", Net: &Net{UUID: mnUUID, HostBridge: "virbr0"}},
		"net_create bridge with an avoid": {V: Version, Op: OpNetCreate, Name: "lan", Net: &Net{UUID: mnUUID, HostBridge: "svbr0", Avoid: []string{"192.168.1.0/24"}}},
		"host bridge on an autostart":     {V: Version, Op: OpNetAutostart, Name: "lan", Net: &Net{Autostart: "on", HostBridge: "svbr0"}},
		"net_start with a body":           {V: Version, Op: OpNetStart, Name: "lab-net", Net: &Net{IP: "10.0.0.1"}},
		"net_start of a VM-style name":    {V: Version, Op: OpNetStart, Name: "../etc"},
		"net_autostart junk":              {V: Version, Op: OpNetAutostart, Name: "lab-net", Net: &Net{Autostart: "maybe"}},
		"net_autostart extra":             {V: Version, Op: OpNetAutostart, Name: "lab-net", Net: &Net{Autostart: "on", IP: "10.0.0.1"}},
		"compute zero cpus":               {V: Version, Op: OpCompute, Name: "web-1", Net: &Net{VCPUs: 0, MemoryMiB: 1024}},
		"compute too many cpus":           {V: Version, Op: OpCompute, Name: "web-1", Net: &Net{VCPUs: 65, MemoryMiB: 1024}},
		"compute odd memory":              {V: Version, Op: OpCompute, Name: "web-1", Net: &Net{VCPUs: 2, MemoryMiB: 1000}},
		"compute huge memory":             {V: Version, Op: OpCompute, Name: "web-1", Net: &Net{VCPUs: 2, MemoryMiB: 1 << 30}},
		"compute with an ip":              {V: Version, Op: OpCompute, Name: "web-1", Net: &Net{VCPUs: 2, MemoryMiB: 1024, IP: "10.0.0.1"}},
		"reserve_ip ipv6":                 {V: Version, Op: OpReserveIP, Name: "web-1", Net: &Net{IP: "fd00::1"}},
		"reserve_ip with markup":          {V: Version, Op: OpReserveIP, Name: "web-1", Net: &Net{IP: "10.0.0.1'/><x"}},
		"reserve_ip without a body":       {V: Version, Op: OpReserveIP, Name: "web-1"},
		"release_ip with a body":          {V: Version, Op: OpReleaseIP, Name: "web-1", Net: &Net{IP: "10.0.0.1"}},
		"net body on an old operation":    {V: Version, Op: OpStart, Name: "web-1", Net: &Net{IP: "10.0.0.1"}},
	}
	for name, q := range bad {
		if q.Valid() {
			t.Errorf("%s was accepted", name)
		}
	}
	good := []Request{
		{V: Version, Op: OpNetCreate, Name: "lab-net", Net: ptr(lab())}, {V: Version, Op: OpNetCreate, Name: "lan", Net: &Net{UUID: mnUUID, HostBridge: "svbr0"}}, {V: Version, Op: OpNetStart, Name: "lab-net"}, {V: Version, Op: OpNetStop, Name: "lab-net"},
		{V: Version, Op: OpNetDelete, Name: "lab-net"}, {V: Version, Op: OpNetAutostart, Name: "lab-net", Net: &Net{Autostart: "on"}},
		{V: Version, Op: OpCompute, Name: "web-1", Net: &Net{VCPUs: 4, MemoryMiB: 2048}}, {V: Version, Op: OpReserveIP, Name: "web-1", Net: &Net{IP: "10.77.0.50"}},
		{V: Version, Op: OpReleaseIP, Name: "web-1"},
	}
	for _, q := range good {
		if !q.Valid() {
			t.Errorf("%s was refused", q.Op)
		}
	}
	if b, _ := json.Marshal(Request{V: Version, Op: OpNetCreate, Name: "lab-net", Net: ptr(lab())}); strings.Contains(strings.ToLower(string(b)), "xml") {
		t.Fatal("no XML field exists in the protocol")
	}
}

func ptr(n Net) *Net { return &n }
