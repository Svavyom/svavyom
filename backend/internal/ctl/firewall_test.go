package ctl

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"example.invalid/dedicatedcloud/backend/internal/fwstatus"
)

// The structure of this host's real output (ufw active, default-deny routed, FORWARD policy DROP, libvirt's own chains inserted): VMs reach the network,
// so there must be no finding.
const (
	realFilter = "-P INPUT DROP\n-P FORWARD DROP\n-P OUTPUT ACCEPT\n-N LIBVIRT_FWI\n-N LIBVIRT_FWO\n-N LIBVIRT_FWX\n-N LIBVIRT_INP\n-A INPUT -j ts-input\n-A INPUT -j LIBVIRT_INP\n" +
		"-A FORWARD -j ts-forward\n-A FORWARD -j LIBVIRT_FWX\n-A FORWARD -j LIBVIRT_FWI\n-A FORWARD -j LIBVIRT_FWO\n-A FORWARD -j ufw-before-forward\n"
	realNat   = "-P POSTROUTING ACCEPT\n-A POSTROUTING -s 172.17.0.0/16 ! -o docker0 -j MASQUERADE\n-A POSTROUTING -j LIBVIRT_PRT\n"
	ufwRouted = "Status: active\nLogging: on (low)\nDefault: deny (incoming), allow (outgoing), deny (routed)\nNew profiles: skip\n\nTo Action From\n-- ------ ----\n22/tcp ALLOW IN Anywhere\n"
)

func fwHost(t *testing.T, tools []string, replies map[string]string) *testHost {
	t.Helper()
	h := newHost(t)
	for _, tool := range tools {
		h.paths[tool] = "/usr/sbin/" + tool
	}
	for k, v := range replies {
		h.run.reply[k] = v
	}
	return h
}

func codes(r FirewallResult) string {
	var c []string
	for _, f := range r.Findings {
		c = append(c, f.Code)
	}
	return strings.Join(c, ",")
}

func TestFirewallCheckFindsNothingWhenLibvirtsRulesCarryTheTraffic(t *testing.T) {
	h := fwHost(t, []string{"ufw", "iptables"}, map[string]string{"ufw status verbose": ufwRouted, "iptables -S": realFilter, "iptables -t nat -S": realNat})
	if r := FirewallCheck(context.Background(), h.env, "default"); len(r.Findings) != 0 {
		t.Fatalf("the VMs on this kind of host have a network: %+v", r.Findings)
	}
}

func TestFirewallCheckTypedFindings(t *testing.T) {
	noLibvirt := "-P INPUT DROP\n-P FORWARD DROP\n-P OUTPUT ACCEPT\n-A INPUT -j LIBVIRT_INP\n"
	cases := map[string]struct {
		tools   []string
		replies map[string]string
		fail    []string
		want    string
	}{
		"ufw routed deny and nothing forwards": {[]string{"ufw", "iptables"}, map[string]string{"ufw status verbose": ufwRouted, "iptables -S": noLibvirt, "iptables -t nat -S": realNat}, nil, FWUfwActiveNoRoute},
		"forward drop without ufw":             {[]string{"iptables"}, map[string]string{"iptables -S": noLibvirt, "iptables -t nat -S": realNat}, nil, FWForwardDrop},
		"forward accept is no conflict":        {[]string{"iptables"}, map[string]string{"iptables -S": "-P INPUT ACCEPT\n-P FORWARD ACCEPT\n-P OUTPUT ACCEPT\n", "iptables -t nat -S": realNat}, nil, ""},
		"no masquerade":                        {[]string{"iptables"}, map[string]string{"iptables -S": realFilter, "iptables -t nat -S": "-P POSTROUTING ACCEPT\n"}, nil, FWNoMasquerade},
		"a drop rule for the bridge":           {[]string{"iptables"}, map[string]string{"iptables -S": realFilter + "-A INPUT -i virbr0 -p udp -m udp --dport 67 -j DROP\n", "iptables -t nat -S": realNat}, nil, FWBridgeReject},
		"input drop without libvirt's chain":   {[]string{"iptables"}, map[string]string{"iptables -S": "-P INPUT DROP\n-P FORWARD ACCEPT\n", "iptables -t nat -S": realNat}, nil, FWBridgeReject},
		"firewalld without a libvirt zone":     {[]string{"firewall-cmd"}, map[string]string{"firewall-cmd --state": "running\n", "firewall-cmd --get-zones": "block dmz drop public work\n"}, nil, FWFirewalldZone},
		"firewalld with the zone":              {[]string{"firewall-cmd"}, map[string]string{"firewall-cmd --state": "running\n", "firewall-cmd --get-zones": "block dmz libvirt public\n"}, nil, ""},
		"firewalld not running":                {[]string{"firewall-cmd"}, map[string]string{"firewall-cmd --state": "not running\n"}, nil, ""},
		"iptables unreadable is unknown":       {[]string{"iptables"}, nil, []string{"iptables -S"}, FWUnknown},
		"ufw unreadable is unknown":            {[]string{"ufw"}, nil, []string{"ufw status"}, FWUnknown},
		"nftables with libvirt's table":        {[]string{"nft"}, map[string]string{"nft list ruleset": "table inet libvirt_network {\n chain forward {\n type filter hook forward priority 0; policy accept;\n }\n}\ntable inet filter {\n chain forward {\n type filter hook forward priority 0; policy drop;\n }\n}\n"}, nil, ""},
		"nftables drop without libvirt":        {[]string{"nft"}, map[string]string{"nft list ruleset": "table inet filter {\n chain forward {\n type filter hook forward priority 0; policy drop;\n }\n}\n"}, nil, FWForwardDrop},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			h := fwHost(t, c.tools, c.replies)
			for _, f := range c.fail {
				h.run.fail[f] = true
			}
			got := codes(FirewallCheck(context.Background(), h.env, "default"))
			if c.want == FWUnknown {
				if !strings.Contains(got, FWUnknown) {
					t.Fatalf("an unreadable firewall must not be reported clean: %q", got)
				}
				return
			}
			if got != c.want {
				t.Fatalf("got %q, want %q", got, c.want)
			}
		})
	}
}

func TestFirewallCheckSaysNothingWhileTheNetworkIsDown(t *testing.T) {
	h := fwHost(t, []string{"iptables"}, map[string]string{"iptables -S": "-P FORWARD DROP\n", "iptables -t nat -S": ""})
	h.run.reply["virsh -r -c qemu:///system net-info"] = "Name: default\nActive: no\n"
	if r := FirewallCheck(context.Background(), h.env, "default"); len(r.Findings) != 0 {
		t.Fatalf("libvirt has installed no rules yet, so there is nothing to conflict with: %+v", r.Findings)
	}
}

func TestFirewallStatusIsRecordedReadBackAndExpires(t *testing.T) {
	h, listen := serverHost(t)
	if out, err := install(t, h, listen, makeArtifact(t, "0.1.0", curSchema, nil), nil); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	h.paths["iptables"] = "/usr/sbin/iptables"
	h.run.reply["iptables -S"], h.run.reply["iptables -t nat -S"] = "-P FORWARD DROP\n-P INPUT ACCEPT\n", realNat
	if err := h.env.recordFirewall(context.Background()); err != nil {
		t.Fatal(err)
	}
	read := func(p string) ([]byte, error) { return h.env.ReadFile(p) }
	r, ok := fwstatus.Read(read, h.root+FirewallStatusFile, h.now, 7*24*time.Hour)
	if !ok || len(r.Findings) != 1 || r.Findings[0].Code != FWForwardDrop || len(r.Findings[0].Remediation) > 200 {
		t.Fatalf("%+v %v", r, ok)
	}
	if _, ok := fwstatus.Read(read, h.root+FirewallStatusFile, h.now.Add(8*24*time.Hour), 7*24*time.Hour); ok {
		t.Fatal("an old result must not be shown as current")
	}
	if _, ok := fwstatus.Read(read, h.root+"/nowhere", h.now, time.Hour); ok {
		t.Fatal("a missing file shows nothing")
	}
	// validate-config shows it, as advice that never changes the verdict
	rep := ValidateConfig(context.Background(), h.env, ValidateOptions{})
	found := false
	for _, f := range rep.Findings {
		if f.ID == "firewall" {
			found = true
			if f.Required || f.Code != FWForwardDrop {
				t.Fatalf("%+v", f)
			}
		}
	}
	if !found {
		t.Fatal("validate-config must show the recorded firewall finding")
	}
	b, _ := json.Marshal(r)
	if strings.Contains(string(b), "password") {
		t.Fatal("no secret can be in the file")
	}
}
