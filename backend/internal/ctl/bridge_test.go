package ctl

import (
	"context"
	"errors"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"example.invalid/dedicatedcloud/backend/internal/bridgestatus"
)

// The lab host's own netplan file, with its "routes:" list at the same indent as its key.
const labNetplan = `network:
 version: 2
 ethernets:
  eno1:
   dhcp4: false
   addresses:
    - 203.0.113.25/24
   routes: 
   - to: default
     via: 203.0.113.1
   nameservers:
    addresses:
     - 8.8.8.8
     - 1.1.1.1
`

func TestYAMLReadsTheLabNetplanFileAndWritesItBack(t *testing.T) {
	n, err := parseYAML(labNetplan)
	if err != nil {
		t.Fatal(err)
	}
	eth := n.get("network").get("ethernets").get("eno1")
	if a, _ := eth.get("addresses").strs(); len(a) != 1 || a[0] != "203.0.113.25/24" {
		t.Fatalf("addresses %v", a)
	}
	r := eth.get("routes").l
	if len(r) != 1 || r[0].get("to").s != "default" || r[0].get("via").s != "203.0.113.1" {
		t.Fatalf("routes %+v", r)
	}
	again, err := parseYAML(marshalYAML(n))
	if err != nil || marshalYAML(again) != marshalYAML(n) {
		t.Fatalf("round trip differs: %v\n%s", err, marshalYAML(n))
	}
}

func TestYAMLRefusesWhatItDoesNotUnderstand(t *testing.T) {
	for name, src := range map[string]string{
		"tab":         "network:\n\tversion: 2\n",
		"anchor":      "network: &a\n  version: 2\n",
		"flow map":    "network: {version: 2}\n",
		"block text":  "network:\n  version: |\n    2\n",
		"two docs":    "---\nnetwork:\n  version: 2\n",
		"duplicate":   "network:\n  version: 2\n  version: 2\n",
		"nested flow": "network:\n  x: [[a], b]\n",
	} {
		if _, err := parseYAML(src); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
	n, err := parseYAML("network:\n  x: [a, \"b c\", 'd']  # comment\n  y: \"has # hash\"\n")
	if err != nil {
		t.Fatal(err)
	}
	if x, _ := n.get("network").get("x").strs(); len(x) != 3 || x[1] != "b c" || n.get("network").get("y").s != "has # hash" {
		t.Fatalf("%v", x)
	}
}

// bridgeHost is a test host that looks like the lab host: static address on eno1, one default route, netplan with the networkd renderer.
func bridgeHost(t *testing.T) *testHost {
	t.Helper()
	h := newHost(t)
	h.write("/etc/netplan/01-static.yaml", labNetplan)
	h.write("/sys/class/net/eno1/address", "00:25:90:a8:14:8e\n")
	h.run.reply["systemctl is-active NetworkManager"] = "inactive\n"
	h.run.reply["ip -o -4 route show default"] = "default via 203.0.113.1 dev eno1 proto static\n"
	h.run.reply["ip -o -4 addr show dev eno1"] = "2: eno1    inet 203.0.113.25/24 brd 203.0.113.255 scope global eno1\\       valid_lft forever preferred_lft forever\n"
	h.run.fail["ip -o link show dev svbr0"] = true
	return h
}

func wantRefusal(t *testing.T, err error, code string) {
	t.Helper()
	var r *BridgeRefusal
	if !errors.As(err, &r) || r.Code != code {
		t.Fatalf("want refusal %s, got %v", code, err)
	}
}

func TestPlanProposesTheBridgeAndShowsTheExactChange(t *testing.T) {
	h := bridgeHost(t)
	p, err := h.env.BridgePlanFor(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if p.Interface != "eno1" || p.Bridge != "svbr0" || p.Gateway != "203.0.113.1" || p.File != "/etc/netplan/01-static.yaml" || p.MAC != "00:25:90:a8:14:8e" {
		t.Fatalf("%+v", p)
	}
	n, err := parseYAML(p.After)
	if err != nil {
		t.Fatal(err)
	}
	net := n.get("network")
	eth := net.get("ethernets").get("eno1")
	if eth.get("addresses") != nil || eth.get("routes") != nil || eth.get("nameservers") != nil || eth.get("dhcp4").s != "false" {
		t.Fatalf("the device must keep no addressing:\n%s", p.After)
	}
	br := net.get("bridges").get("svbr0")
	if a, _ := br.get("interfaces").strs(); len(a) != 1 || a[0] != "eno1" {
		t.Fatal(p.After)
	}
	if a, _ := br.get("addresses").strs(); len(a) != 1 || a[0] != "203.0.113.25/24" {
		t.Fatal(p.After)
	}
	if br.get("macaddress").s != "00:25:90:a8:14:8e" || br.get("routes").l[0].get("via").s != "203.0.113.1" || br.get("parameters").get("stp").s != "false" {
		t.Fatal(p.After)
	}
	if ns, _ := br.get("nameservers").get("addresses").strs(); len(ns) != 2 {
		t.Fatal(p.After)
	}
	for _, want := range []string{"- ", "+ ", "bridges:", "svbr0"} {
		if !strings.Contains(p.Diff, want) {
			t.Fatalf("diff lacks %q:\n%s", want, p.Diff)
		}
	}
	// Planning reads only: no command other than the listing ones ran, and nothing was written.
	for _, c := range h.run.calls {
		if !strings.HasPrefix(c, "ip ") && !strings.HasPrefix(c, "systemctl is-active") {
			t.Fatalf("plan ran %q", c)
		}
	}
	if h.exists(BridgeDir) {
		t.Fatal("plan wrote state")
	}
	if p2, _ := h.env.BridgePlanFor(context.Background()); p2.ID != p.ID {
		t.Fatal("the plan id must be stable for the same host")
	}
}

func TestPlanRefusesWhatItCannotReverse(t *testing.T) {
	cases := []struct {
		name string
		code string
		mut  func(h *testHost)
	}{
		{"no default route", BRNoDefaultRoute, func(h *testHost) { h.run.reply["ip -o -4 route show default"] = "" }},
		{"two default routes", BRManyDefault, func(h *testHost) {
			h.run.reply["ip -o -4 route show default"] = "default via 1.1.1.1 dev eno1\ndefault via 2.2.2.2 dev wlan0\n"
		}},
		{"wireless", BRWireless, func(h *testHost) { h.write("/sys/class/net/eno1/wireless/x", "") }},
		{"bond master", BRBond, func(h *testHost) { h.write("/sys/class/net/eno1/bonding/x", "") }},
		{"bond slave", BRBond, func(h *testHost) { h.write("/sys/class/net/eno1/master", "") }},
		{"vlan device", BRVlan, func(h *testHost) { h.write("/proc/net/vlan/eno1", "") }},
		{"already in a bridge", BRAlreadyBridged, func(h *testHost) { h.write("/sys/class/net/eno1/brport/x", "") }},
		{"name in use", BRNameInUse, func(h *testHost) { delete(h.run.fail, "ip -o link show dev svbr0") }},
		{"networkmanager active", BRBackendNM, func(h *testHost) { h.run.reply["systemctl is-active NetworkManager"] = "active\n" }},
		{"networkmanager renderer", BRBackendNM, func(h *testHost) {
			h.write("/etc/netplan/01-static.yaml", strings.Replace(labNetplan, "network:\n", "network:\n renderer: NetworkManager\n", 1))
		}},
		{"dhcp nic", BRDHCP, func(h *testHost) {
			h.write("/etc/netplan/01-static.yaml", strings.Replace(labNetplan, "dhcp4: false", "dhcp4: true", 1))
		}},
		{"unsupported key", BRUnsupportedKey, func(h *testHost) {
			h.write("/etc/netplan/01-static.yaml", strings.Replace(labNetplan, "   dhcp4: false\n", "   dhcp4: false\n   wakeonlan: true\n", 1))
		}},
		{"match block", BRUnsupportedKey, func(h *testHost) {
			h.write("/etc/netplan/01-static.yaml", strings.Replace(labNetplan, "  eno1:\n", "  eno1:\n   match:\n    name: eno1\n", 1))
		}},
		{"config differs from the live address", BRConfigMismatch, func(h *testHost) {
			h.run.reply["ip -o -4 addr show dev eno1"] = "2: eno1    inet 10.9.9.9/24 scope global eno1\n"
		}},
		{"not in netplan", BRNotInNetplan, func(h *testHost) {
			h.write("/etc/netplan/01-static.yaml", strings.ReplaceAll(labNetplan, "eno1", "eno2"))
		}},
		{"in a bond in netplan", BRBond, func(h *testHost) {
			h.write("/etc/netplan/01-static.yaml", labNetplan+" bonds:\n  bond0:\n   interfaces: [eno1]\n")
		}},
		{"under a vlan in netplan", BRVlan, func(h *testHost) {
			h.write("/etc/netplan/01-static.yaml", labNetplan+" vlans:\n  v10:\n   id: 10\n   link: eno1\n")
		}},
		{"defined twice", BRMultiDefinition, func(h *testHost) {
			h.write("/etc/netplan/02-more.yaml", "network:\n version: 2\n ethernets:\n  eno1:\n   mtu: 9000\n")
		}},
		{"a file in another netplan directory", BRNetplanDirs, func(h *testHost) { h.write("/run/netplan/x.yaml", "network:\n") }},
		{"unparsable file", BRUnparsable, func(h *testHost) { h.write("/etc/netplan/02-bad.yaml", "network: {a: b}\n") }},
		{"no netplan", BRNoNetplan, func(h *testHost) { _ = os.Remove(h.root + "/etc/netplan/01-static.yaml") }},
		{"no default gateway in the file", BRConfigMismatch, func(h *testHost) {
			h.write("/etc/netplan/01-static.yaml", strings.Replace(labNetplan, "   routes: \n   - to: default\n     via: 203.0.113.1\n", "", 1))
		}},
		{"unmovable route key", BRUnsupportedKey, func(h *testHost) {
			h.write("/etc/netplan/01-static.yaml", strings.Replace(labNetplan, "     via: 203.0.113.1\n", "     via: 203.0.113.1\n     table: 100\n", 1))
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := bridgeHost(t)
			c.mut(h)
			_, err := h.env.BridgePlanFor(context.Background())
			wantRefusal(t, err, c.code)
		})
	}
}

// applied runs plan and apply and returns the host with a change waiting for confirmation.
func applied(t *testing.T) (*testHost, *BridgePlan) {
	t.Helper()
	h := bridgeHost(t)
	p, err := h.env.BridgePlanAndRecord(context.Background(), io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if err := h.env.BridgeApply(context.Background(), io.Discard, p.ID, "svbr0", 0); err != nil {
		t.Fatal(err)
	}
	return h, p
}

func TestApplyNeedsARecordedPlanAndATypedConfirmation(t *testing.T) {
	h := bridgeHost(t)
	ctx := context.Background()
	wantRefusal(t, h.env.BridgeApply(ctx, io.Discard, "abc", "svbr0", 0), BRNoPlan)
	p, err := h.env.BridgePlanAndRecord(ctx, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	wantRefusal(t, h.env.BridgeApply(ctx, io.Discard, "deadbeef", "svbr0", 0), BRNoPlan)
	wantRefusal(t, h.env.BridgeApply(ctx, io.Discard, p.ID, "", 0), BRNeedsConfirm)
	wantRefusal(t, h.env.BridgeApply(ctx, io.Discard, p.ID, "svbr1", 0), BRNeedsConfirm)
	wantRefusal(t, h.env.BridgeApply(ctx, io.Discard, p.ID, "svbr0", 5), BRNeedsConfirm)
	if h.run.called("netplan") != 0 || h.run.called("systemd-run") != 0 {
		t.Fatalf("a refused apply ran commands: %v", h.run.calls)
	}
	if s, _ := h.read("/etc/netplan/01-static.yaml"); s != labNetplan {
		t.Fatal("a refused apply changed the configuration")
	}
	// A plan is only good for a short while and only for the host it was made on.
	h.now = h.now.Add(planTTL + time.Second)
	wantRefusal(t, h.env.BridgeApply(ctx, io.Discard, p.ID, "svbr0", 0), BRPlanStale)
	h.now = h.now.Add(-planTTL)
	h.write("/etc/netplan/01-static.yaml", labNetplan+"# touched\n")
	wantRefusal(t, h.env.BridgeApply(ctx, io.Discard, p.ID, "svbr0", 0), BRPlanStale)
	e := *h.env
	e.Euid = func() int { return 1000 }
	wantRefusal(t, e.BridgeApply(ctx, io.Discard, p.ID, "svbr0", 0), BRNeedsRoot)
	wantRefusal(t, e.BridgeConfirm(ctx, io.Discard), BRNeedsRoot)
	wantRefusal(t, e.BridgeRollback(ctx, io.Discard, false, false, ""), BRNeedsRoot)
}

func TestApplyArmsTheSafetyNetBeforeItChangesTheNetwork(t *testing.T) {
	h, p := applied(t)
	// Order matters: recovery unit enabled and timer armed before generate and apply.
	idx := func(prefix string) int {
		for i, c := range h.run.calls {
			if strings.HasPrefix(c, prefix) {
				return i
			}
		}
		return -1
	}
	en, tm, gen, app := idx("systemctl enable -- "+BridgeRecoverUnit), idx("systemd-run --unit=svavyom-bridge-rollback --on-active=120s"), idx("netplan generate"), idx("netplan apply")
	if en < 0 || tm < 0 || gen < 0 || app < 0 || !(en < gen && tm < gen && gen < app) {
		t.Fatalf("order wrong (enable %d, timer %d, generate %d, apply %d): %v", en, tm, gen, app, h.run.calls)
	}
	if !strings.Contains(h.run.calls[tm], "svavyom-ctl bridge rollback --auto") {
		t.Fatal(h.run.calls[tm])
	}
	if s, _ := h.read("/etc/netplan/01-static.yaml"); s != p.After {
		t.Fatal("the new configuration was not written")
	}
	if snap, _ := h.read(bridgeSnapDir + "/01-static.yaml"); snap != labNetplan {
		t.Fatal("the original was not saved")
	}
	if u, _ := h.read(UnitDir + "/" + BridgeRecoverUnit); !strings.Contains(u, "bridge recover") || !strings.Contains(u, "Before=sysinit.target network-pre.target") {
		t.Fatalf("recovery unit: %s", u)
	}
	raw, _ := h.read(BridgeStatusFile)
	got, ok := bridgestatus.Read(func(string) ([]byte, error) { return []byte(raw), nil }, "", h.now)
	if !ok || got.State != "pending_confirmation" || got.Bridge != "svbr0" || got.Interface != "eno1" || got.SecondsLeft == nil || *got.SecondsLeft != 120 {
		t.Fatalf("%+v %s", got, raw)
	}
	// A second apply, or a new plan, during the countdown is refused.
	wantRefusal(t, h.env.BridgeApply(context.Background(), io.Discard, p.ID, "svbr0", 0), BRBusy)
	_, err := h.env.BridgePlanAndRecord(context.Background(), io.Discard)
	wantRefusal(t, err, BRBusy)
}

func TestConfirmKeepsTheChangeOnlyWhenTheBridgeIsHealthyAndInTime(t *testing.T) {
	h, _ := applied(t)
	ctx := context.Background()
	// The bridge has no address yet (a broken gateway or address): confirming is refused and the countdown goes on.
	wantRefusal(t, h.env.BridgeConfirm(ctx, io.Discard), BRNotHealthy)
	h.run.reply["ip -o -4 addr show dev svbr0"] = "5: svbr0    inet 203.0.113.25/24 scope global svbr0\n"
	h.run.reply["ip -o -4 route show default"] = "default via 203.0.113.1 dev svbr0 proto static\n"
	h.now = h.now.Add(121 * time.Second)
	wantRefusal(t, h.env.BridgeConfirm(ctx, io.Discard), BRExpired)
	h.now = h.now.Add(-60 * time.Second)
	if err := h.env.BridgeConfirm(ctx, io.Discard); err != nil {
		t.Fatal(err)
	}
	if h.run.called("systemctl stop svavyom-bridge-rollback.timer") == 0 {
		t.Fatal("the rollback timer was not stopped")
	}
	if h.exists(UnitDir + "/" + BridgeRecoverUnit) {
		t.Fatal("the recovery unit stayed after a confirmation")
	}
	if st, _ := h.env.readBridgeState(); st.State != bridgestatus.StateActive || st.Deadline != "" {
		t.Fatalf("%+v", st)
	}
	wantRefusal(t, h.env.BridgeConfirm(ctx, io.Discard), BRNotPending)
	wantRefusal(t, h.env.BridgeApply(ctx, io.Discard, "x", "svbr0", 0), BRAlreadyActive)
	if !strings.Contains(h.env.BridgeStatusText(), "active: svbr0") {
		t.Fatal(h.env.BridgeStatusText())
	}
}

func TestForgettingARecordedPlanChangesNothingOnTheHost(t *testing.T) {
	h := bridgeHost(t)
	ctx := context.Background()
	if _, err := h.env.BridgePlanAndRecord(ctx, io.Discard); err != nil {
		t.Fatal(err)
	}
	if err := h.env.BridgeRollback(ctx, io.Discard, false, false, ""); err != nil {
		t.Fatalf("forgetting a plan is not an error: %v", err)
	}
	if h.exists(bridgeStateFile) || h.exists(BridgeStatusFile) || h.exists(bridgePlanFile) {
		t.Fatal("the plan was not forgotten")
	}
	if h.run.called("netplan") != 0 || h.run.called("ip link del") != 0 {
		t.Fatalf("forgetting a plan touched the host: %v", h.run.calls)
	}
	wantRefusal(t, h.env.BridgeRollback(ctx, io.Discard, false, false, ""), BRNothingToDo)
}

func TestRollbackGivesBackTheOriginalFileExactly(t *testing.T) {
	h, _ := applied(t)
	ctx := context.Background()
	// The timer fires (a broken apply, lost connection): no confirmation is needed and the old configuration returns.
	if err := h.env.BridgeRollback(ctx, io.Discard, true, false, ""); err != nil {
		t.Fatal(err)
	}
	if s, _ := h.read("/etc/netplan/01-static.yaml"); s != labNetplan {
		t.Fatalf("not restored exactly:\n%s", s)
	}
	if h.exists(BridgeStatusFile) || h.exists(bridgeStateFile) || h.exists(UnitDir+"/"+BridgeRecoverUnit) || h.exists(bridgeSnapDir+"/01-static.yaml") {
		t.Fatal("leftovers after a rollback")
	}
	if n := h.run.called("netplan apply"); n != 2 {
		t.Fatalf("netplan apply ran %d times; want the change and the restore", n)
	}
	// Idempotent for the timer, an error for a person with nothing to undo.
	if err := h.env.BridgeRollback(ctx, io.Discard, true, false, ""); err != nil {
		t.Fatal(err)
	}
	wantRefusal(t, h.env.BridgeRollback(ctx, io.Discard, false, false, ""), BRNothingToDo)
}

func TestRollbackRemovesTheBridgeDeviceNetworkdLeavesBehind(t *testing.T) {
	h, _ := applied(t)
	delete(h.run.fail, "ip -o link show dev svbr0") // the device exists now
	if err := h.env.BridgeRollback(context.Background(), io.Discard, true, false, ""); err != nil {
		t.Fatal(err)
	}
	if h.run.called("ip link del dev svbr0") != 1 {
		t.Fatalf("the bridge device was not removed: %v", h.run.calls)
	}
	if n := h.run.called("netplan apply"); n != 3 {
		t.Fatalf("netplan apply ran %d times; want change, restore, and again after removing the device", n)
	}
	// At boot the device does not exist and recovery must not apply.
	h2, _ := applied(t)
	h2.run.calls = nil
	delete(h2.run.fail, "ip -o link show dev svbr0")
	if err := h2.env.BridgeRecover(context.Background(), io.Discard); err != nil {
		t.Fatal(err)
	}
	if h2.run.called("ip link del") != 0 || h2.run.called("netplan apply") != 0 {
		t.Fatalf("boot recovery must only regenerate: %v", h2.run.calls)
	}
}

func TestRollbackOfAConfirmedBridgeIsRefusedWhileLibvirtNetworksUseIt(t *testing.T) {
	h, _ := applied(t)
	h.run.reply["ip -o -4 addr show dev svbr0"] = "5: svbr0    inet 203.0.113.25/24 scope global svbr0\n"
	h.run.reply["ip -o -4 route show default"] = "default via 203.0.113.1 dev svbr0\n"
	if err := h.env.BridgeConfirm(context.Background(), io.Discard); err != nil {
		t.Fatal(err)
	}
	h.paths["virsh"] = "/usr/bin/virsh"
	h.run.reply["virsh -r -c qemu:///system net-list --all --name"] = "default\nlan\n"
	h.run.reply["virsh -r -c qemu:///system net-dumpxml -- default"] = "<network><name>default</name><bridge name='virbr0' stp='on'/></network>"
	h.run.reply["virsh -r -c qemu:///system net-dumpxml -- lan"] = "<network><name>lan</name><forward mode='bridge'/><bridge name='svbr0'/></network>"
	wantRefusal(t, h.env.BridgeRollback(context.Background(), io.Discard, false, false, "svbr0"), BRInUse)
	if s, _ := h.read("/etc/netplan/01-static.yaml"); s == labNetplan {
		t.Fatal("a refused rollback changed the configuration")
	}
	h.run.reply["virsh -r -c qemu:///system net-list --all --name"] = "default\n"
	if err := h.env.BridgeRollback(context.Background(), io.Discard, false, false, "svbr0"); err != nil {
		t.Fatal(err)
	}
}

func TestRollbackOfAConfirmedBridgeNeedsTheTypedName(t *testing.T) {
	h, _ := applied(t)
	h.run.reply["ip -o -4 addr show dev svbr0"] = "5: svbr0    inet 203.0.113.25/24 scope global svbr0\n"
	h.run.reply["ip -o -4 route show default"] = "default via 203.0.113.1 dev svbr0\n"
	if err := h.env.BridgeConfirm(context.Background(), io.Discard); err != nil {
		t.Fatal(err)
	}
	wantRefusal(t, h.env.BridgeRollback(context.Background(), io.Discard, false, false, ""), BRNeedsConfirm)
	if err := h.env.BridgeRollback(context.Background(), io.Discard, false, false, "svbr0"); err != nil {
		t.Fatal(err)
	}
	if s, _ := h.read("/etc/netplan/01-static.yaml"); s != labNetplan {
		t.Fatal("not restored")
	}
}

func TestARebootDuringTheCountdownRestoresTheOldConfiguration(t *testing.T) {
	h, _ := applied(t)
	// The machine restarts: the transient timer is gone, the recovery unit runs before the network and only regenerates the netplan output.
	h.run.calls = nil
	if err := h.env.BridgeRecover(context.Background(), io.Discard); err != nil {
		t.Fatal(err)
	}
	if s, _ := h.read("/etc/netplan/01-static.yaml"); s != labNetplan {
		t.Fatalf("not restored:\n%s", s)
	}
	if h.run.called("netplan generate") != 1 || h.run.called("netplan apply") != 0 {
		t.Fatalf("boot recovery must generate, not apply: %v", h.run.calls)
	}
	if h.exists(bridgeStateFile) || h.exists(UnitDir+"/"+BridgeRecoverUnit) {
		t.Fatal("leftovers")
	}
	// A confirmed bridge is not touched by the boot unit, which only removes itself.
	h2, _ := applied(t)
	h2.run.reply["ip -o -4 addr show dev svbr0"] = "5: svbr0    inet 203.0.113.25/24 scope global svbr0\n"
	h2.run.reply["ip -o -4 route show default"] = "default via 203.0.113.1 dev svbr0\n"
	if err := h2.env.BridgeConfirm(context.Background(), io.Discard); err != nil {
		t.Fatal(err)
	}
	if err := h2.env.BridgeRecover(context.Background(), io.Discard); err != nil {
		t.Fatal(err)
	}
	if s, _ := h2.read("/etc/netplan/01-static.yaml"); s == labNetplan {
		t.Fatal("a confirmed bridge was undone at boot")
	}
}

func TestApplyFailuresLeaveTheOriginalConfigurationInPlace(t *testing.T) {
	ctx := context.Background()
	for name, mut := range map[string]func(h *testHost){
		"netplan rejects the file":   func(h *testHost) { h.run.fail["netplan generate"] = true },
		"the timer cannot be armed":  func(h *testHost) { h.run.fail["systemd-run"] = true },
		"the unit cannot be enabled": func(h *testHost) { h.run.fail["systemctl enable"] = true },
	} {
		t.Run(name, func(t *testing.T) {
			h := bridgeHost(t)
			p, err := h.env.BridgePlanAndRecord(ctx, io.Discard)
			if err != nil {
				t.Fatal(err)
			}
			mut(h)
			if err := h.env.BridgeApply(ctx, io.Discard, p.ID, "svbr0", 0); err == nil {
				t.Fatal("apply succeeded")
			}
			if s, _ := h.read("/etc/netplan/01-static.yaml"); s != labNetplan {
				t.Fatalf("the original is not back:\n%s", s)
			}
			if h.run.called("netplan apply") != 0 {
				t.Fatal("netplan apply ran although the safety net or the file was not ready")
			}
			if h.exists(UnitDir + "/" + BridgeRecoverUnit) {
				t.Fatal("recovery unit left behind")
			}
			if st, ok := h.env.readBridgeState(); ok && st.State != bridgestatus.StatePlanned && st.State != "" {
				t.Fatalf("state %+v", st)
			}
		})
	}
	t.Run("netplan apply fails", func(t *testing.T) {
		h := bridgeHost(t)
		p, _ := h.env.BridgePlanAndRecord(ctx, io.Discard)
		h.run.failN["netplan apply"] = 1
		if err := h.env.BridgeApply(ctx, io.Discard, p.ID, "svbr0", 0); err == nil {
			t.Fatal("apply succeeded")
		}
		if s, _ := h.read("/etc/netplan/01-static.yaml"); s != labNetplan {
			t.Fatal("not restored after a failed apply")
		}
		if h.exists(bridgeStateFile) {
			t.Fatal("state left behind")
		}
	})
}

func TestAdoptRecordsAnExistingBridgeWithoutTouchingTheHost(t *testing.T) {
	h := bridgeHost(t)
	ctx := context.Background()
	wantRefusal(t, h.env.BridgeAdopt(ctx, io.Discard, "virbr0", "virbr0"), BRNotForeign)
	wantRefusal(t, h.env.BridgeAdopt(ctx, io.Discard, "br9", "br9"), BRNotForeign)
	h.write("/sys/class/net/br9/bridge/x", "")
	h.write("/sys/class/net/br9/brif/eno7/x", "")
	wantRefusal(t, h.env.BridgeAdopt(ctx, io.Discard, "br9", ""), BRNeedsConfirm)
	if err := h.env.BridgeAdopt(ctx, io.Discard, "br9", "br9"); err != nil {
		t.Fatal(err)
	}
	if h.run.called("netplan") != 0 || h.run.called("systemd-run") != 0 {
		t.Fatalf("adoption changed the host: %v", h.run.calls)
	}
	st, _ := h.env.readBridgeState()
	if st.State != "active" || st.Bridge != "br9" || !st.Adopted {
		t.Fatalf("%+v", st)
	}
	if err := h.env.BridgeRollback(ctx, io.Discard, false, false, "br9"); err != nil {
		t.Fatal(err)
	}
	if h.run.called("netplan") != 0 || h.exists(bridgeStateFile) {
		t.Fatal("forgetting an adopted bridge must not touch the network")
	}
}

func TestStatusFileIsRefusedOutsideTheClosedVocabulary(t *testing.T) {
	now := time.Date(2026, 10, 18, 0, 0, 0, 0, time.UTC)
	rd := func(s string) func(string) ([]byte, error) {
		return func(string) ([]byte, error) { return []byte(s), nil }
	}
	for _, bad := range []string{`{"state":"bogus","bridge":"svbr0","interface":"eno1"}`, `{"state":"active","bridge":"a b","interface":"eno1"}`, `not json`,
		`{"state":"pending_confirmation","bridge":"svbr0","interface":"eno1","deadline":"x"}`} {
		if _, ok := bridgestatus.Read(rd(bad), "", now); ok {
			t.Errorf("accepted %s", bad)
		}
	}
	o, ok := bridgestatus.Read(rd(`{"state":"pending_confirmation","bridge":"svbr0","interface":"eno1","deadline":"2025-01-01T00:00:00Z"}`), "", now)
	if !ok || *o.SecondsLeft != 0 {
		t.Fatalf("%+v", o)
	}
}
