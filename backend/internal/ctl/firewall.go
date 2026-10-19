package ctl

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"

	"example.invalid/dedicatedcloud/backend/internal/fwstatus"
	"example.invalid/dedicatedcloud/backend/internal/provision"
)

// Firewall conflict detection (M1-E03-S03, DR-024 D1). It is READ-ONLY: it runs the firewall tools' listing commands, parses their output, and reports
// typed findings with the commands the administrator would run. Svavyom never edits a firewall rule. It runs in svavyom-ctl (root) and writes one
// status file that the API reads; the API itself gains no firewall access. An unreadable or unparsable firewall is reported as FW_UNKNOWN, never as clean.

// FirewallStatusFile is the last result, root-owned and world-readable.
const FirewallStatusFile = LibDir + "/firewall-status.json"

// Closed finding codes (they join Host.observed.capability_findings).
const (
	FWForwardDrop      = "FW_FORWARD_DROP"
	FWNoMasquerade     = "FW_NO_MASQUERADE"
	FWBridgeReject     = "FW_BRIDGE_REJECT"
	FWUfwActiveNoRoute = "FW_UFW_ACTIVE_NO_ROUTE"
	FWFirewalldZone    = "FW_FIREWALLD_ZONE"
	FWUnknown          = "FW_UNKNOWN"
)

// FirewallFinding and FirewallResult are the status file's content (package fwstatus, shared with the API).
type (
	FirewallFinding = fwstatus.Finding
	FirewallResult  = fwstatus.Result
)

var (
	ufwActiveRE   = regexp.MustCompile(`(?m)^Status:\s+active\b`)
	ufwRoutedRE   = regexp.MustCompile(`(?m)^Default:.*\b(deny|reject) \(routed\)`)
	chainJumpRE   = regexp.MustCompile(`(?m)^-A FORWARD .*-j (LIBVIRT_FW[A-Z]|LIBVIRT_FORWARD)\b`)
	inputJumpRE   = regexp.MustCompile(`(?m)^-A INPUT .*-j LIBVIRT_INP\b`)
	postJumpRE    = regexp.MustCompile(`(?m)^-A POSTROUTING .*-j LIBVIRT_PRT\b`)
	forwardPolRE  = regexp.MustCompile(`(?m)^-P FORWARD (DROP|REJECT)\b`)
	inputPolRE    = regexp.MustCompile(`(?m)^-P INPUT (DROP|REJECT)\b`)
	nftForwardRE  = regexp.MustCompile(`(?s)chain forward \{[^}]*policy (drop|reject)`)
	bridgeRuleRE  = regexp.MustCompile(`(?m)^-A INPUT .*-i (virbr[0-9A-Za-z_.-]*) .*-j (DROP|REJECT)\b`)
	masqRE        = regexp.MustCompile(`(?m)^-A POSTROUTING .*-j MASQUERADE\b`)
	netActiveRE   = regexp.MustCompile(`(?m)^Active:\s+yes\b`)
	libvirtNftTbl = "table inet libvirt_network"
)

// FirewallCheck inspects the host. network is the libvirt network name from the provisioning configuration.
func FirewallCheck(ctx context.Context, e *Env, network string) FirewallResult {
	res := FirewallResult{GeneratedAt: e.Now().UTC().Format(time.RFC3339), Network: network, Findings: []FirewallFinding{}}
	add := func(code, rem string) {
		if len(rem) > 200 {
			rem = rem[:200]
		}
		for _, f := range res.Findings {
			if f.Code == code {
				return
			}
		}
		res.Findings = append(res.Findings, FirewallFinding{Code: code, Remediation: rem})
	}
	run := func(name string, args ...string) (string, bool) {
		out, err := e.Run.Run(ctx, name, args...)
		return out, err == nil
	}
	have := func(name string) bool { _, err := e.LookPath(name); return err == nil }

	// Is the libvirt network up? Without it libvirt has installed no rules, so there is nothing to conflict with yet.
	netUp := false
	if have("virsh") {
		if out, ok := run("virsh", "-r", "-c", "qemu:///system", "net-info", "--", network); ok {
			netUp = netActiveRE.MatchString(out)
		} else {
			add(FWUnknown, "The libvirt network could not be queried, so firewall conflicts could not be checked. Run: sudo svavyom-ctl firewall-check")
		}
	}

	inspected := false // some firewall front end was read successfully
	ufwActive, ufwRouted := false, false
	if have("ufw") {
		if out, ok := run("ufw", "status", "verbose"); ok {
			inspected = true
			ufwActive, ufwRouted = ufwActiveRE.MatchString(out), ufwRoutedRE.MatchString(out)
		} else {
			add(FWUnknown, "ufw is installed but its state could not be read. Run: sudo ufw status verbose")
		}
	}
	if have("firewall-cmd") {
		out, ok := run("firewall-cmd", "--state")
		switch {
		case strings.Contains(out, "not running"): // firewall-cmd exits non-zero when firewalld is stopped; that is an answer, not a failure
			inspected = true
		case ok && strings.TrimSpace(out) == "running":
			inspected = true
			if zones, zok := run("firewall-cmd", "--get-zones"); !zok {
				add(FWUnknown, "firewalld is running but its zones could not be read. Run: sudo firewall-cmd --get-zones")
			} else if netUp && !strings.Contains(" "+zones+" ", " libvirt ") {
				add(FWFirewalldZone, "firewalld is running but has no libvirt zone, so traffic from VMs may be blocked. Run: sudo firewall-cmd --permanent --new-zone=libvirt (see the libvirt documentation) and reload.")
			}
		default:
			add(FWUnknown, "firewalld's state could not be read. Run: sudo firewall-cmd --state")
		}
	}

	if netUp {
		var filter, nat, nft string
		var haveIpt, haveNft bool
		if have("iptables") {
			var ok1, ok2 bool
			filter, ok1 = run("iptables", "-S")
			nat, ok2 = run("iptables", "-t", "nat", "-S")
			haveIpt = ok1 && ok2
			if !haveIpt {
				add(FWUnknown, "iptables could not be read. Run: sudo iptables -S")
			}
		}
		if have("nft") {
			var ok bool
			nft, ok = run("nft", "list", "ruleset")
			haveNft = ok
			if !ok && !haveIpt {
				add(FWUnknown, "nftables could not be read. Run: sudo nft list ruleset")
			}
		}
		if !haveIpt && !haveNft && !inspected && len(res.Findings) == 0 {
			add(FWUnknown, "No firewall tool could be read (iptables, nft). Firewall conflicts were not checked.")
		}
		libvirtNft := strings.Contains(nft, libvirtNftTbl)
		// The forwarding path: libvirt inserts its own FORWARD jumps (iptables backend) or its own nftables table; either means VM traffic is let through
		// ahead of a default-deny policy. A default-deny forward policy WITHOUT them is the conflict.
		fwdDrop := (haveIpt && forwardPolRE.MatchString(filter)) || nftForwardRE.MatchString(nft)
		libvirtFwd := chainJumpRE.MatchString(filter) || libvirtNft
		if fwdDrop && !libvirtFwd {
			if ufwActive && ufwRouted {
				add(FWUfwActiveNoRoute, "ufw denies routed traffic and nothing lets the VM network through. Run: sudo ufw route allow in on virbr0 && sudo ufw route allow out on virbr0 (use your bridge name)")
			} else {
				add(FWForwardDrop, "The firewall drops forwarded traffic and nothing lets the VM network through, so VMs will have no network. Allow forwarding for the libvirt bridge (virbr0) in your firewall.")
			}
		}
		if haveIpt && !postJumpRE.MatchString(nat) && !masqRE.MatchString(nat) && !libvirtNft {
			add(FWNoMasquerade, "No masquerade rule exists for the libvirt NAT network, so VMs cannot reach outside networks. Restart the libvirt network (virsh net-destroy/net-start) so it installs its rules.")
		}
		if haveIpt {
			if m := bridgeRuleRE.FindStringSubmatch(filter); m != nil {
				add(FWBridgeReject, fmt.Sprintf("A firewall rule drops or rejects traffic arriving on %s, so VMs cannot get DHCP or DNS from the host. Remove or reorder that INPUT rule.", m[1]))
			} else if inputPolRE.MatchString(filter) && !inputJumpRE.MatchString(filter) && !libvirtNft {
				add(FWBridgeReject, "The INPUT policy drops traffic and libvirt's own INPUT rules are missing, so VMs cannot get DHCP or DNS from the host. Restart the libvirt network.")
			}
		}
	}
	return res
}

// WriteFirewallStatus writes the result atomically (root:root 0644).
func (e *Env) WriteFirewallStatus(r FirewallResult) error {
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	_, err = e.writeAtomic(e.P(FirewallStatusFile), append(b, '\n'), 0o644, 0, 0)
	return err
}

// networkOf returns the libvirt network name of the installed provisioning configuration ("default" when it cannot be read).
func (e *Env) networkOf() string { return e.NetworkOfConfig("") }

// NetworkOfConfig is networkOf for a named configuration file ("" means the installed one).
func (e *Env) NetworkOfConfig(path string) string {
	if path == "" {
		path = e.P(ConfigFile)
	}
	if pc, err := provision.LoadConfig(path); err == nil && pc.Network != "" {
		return pc.Network
	}
	return "default"
}

// firewallFinding turns the result into a preflight finding.
func firewallFinding(r FirewallResult) Finding {
	if len(r.Findings) == 0 {
		return Finding{ID: "firewall", Status: Pass, Detail: "no firewall rule found that blocks the VM network"}
	}
	f := r.Findings[0]
	detail := f.Code
	if len(r.Findings) > 1 {
		detail = fmt.Sprintf("%s and %d more", f.Code, len(r.Findings)-1)
	}
	return Finding{ID: "firewall", Status: NotReady, Code: f.Code, Detail: detail, Remediation: f.Remediation}
}

// recordFirewall runs the check and writes the status file. It never fails an install or an upgrade: a firewall that cannot be read is a finding, not an error.
func (e *Env) recordFirewall(ctx context.Context) error {
	res := FirewallCheck(ctx, e, e.networkOf())
	_ = e.ensureDir(e.P(LibDir), 0o755, 0, 0)
	_ = e.WriteFirewallStatus(res)
	return nil
}
