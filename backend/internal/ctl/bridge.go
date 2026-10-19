package ctl

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"example.invalid/dedicatedcloud/backend/internal/bridgestatus"
)

// Host bridge safe-adoption (M1-E03-S02, DR-024 D5). `svavyom-ctl bridge plan|apply|confirm|rollback|recover|adopt|status` runs as root; the API only reads
// the status file and gains no network privilege. The safety design is a countdown: `apply` writes the new netplan configuration, arms a transient systemd
// timer and a boot-time recovery unit that both restore the previous configuration, applies, and then waits for `confirm`. Whatever goes wrong (a lost
// connection, a broken gateway, a reboot) ends in the old configuration, not in a host nobody can reach.
//
// Scope of this backend: netplan with the networkd renderer on one Ethernet uplink with static IPv4 addresses. Everything else is refused with a typed reason.

// Paths and fixed names (relative to Env.Root).
const (
	BridgeName        = "svbr0"
	BridgeDir         = LibDir + "/bridge"
	BridgeStatusFile  = LibDir + "/bridge-status.json"
	NetplanDir        = "/etc/netplan"
	BridgeRecoverUnit = "svavyom-bridge-recover.service"
	bridgeStateFile   = BridgeDir + "/state.json"
	bridgePlanFile    = BridgeDir + "/plan.json"
	bridgeSnapDir     = BridgeDir + "/snapshot"
	bridgeRollbackRun = "svavyom-bridge-rollback"

	// DefaultCountdown is the default seconds the person has to confirm; the bounds keep a typo from making it useless or endless.
	DefaultCountdown = 120
	MinCountdown     = 30
	MaxCountdown     = 900
	planTTL          = 15 * time.Minute
)

// Closed refusal codes.
const (
	BRNoNetplan       = "BR_NO_NETPLAN"
	BRNetplanDirs     = "BR_NETPLAN_OTHER_DIRS"
	BRUnparsable      = "BR_NETPLAN_UNPARSABLE"
	BRBackendNM       = "BR_BACKEND_NETWORKMANAGER"
	BRNoDefaultRoute  = "BR_NO_DEFAULT_ROUTE"
	BRManyDefault     = "BR_MULTIPLE_DEFAULT_ROUTES"
	BRWireless        = "BR_WIRELESS"
	BRBond            = "BR_BOND"
	BRVlan            = "BR_VLAN"
	BRAlreadyBridged  = "BR_ALREADY_BRIDGED"
	BRNotInNetplan    = "BR_NOT_IN_NETPLAN"
	BRMultiDefinition = "BR_MULTIPLE_DEFINITIONS"
	BRDHCP            = "BR_DHCP_NIC"
	BRUnsupportedKey  = "BR_UNSUPPORTED_KEY"
	BRConfigMismatch  = "BR_CONFIG_MISMATCH"
	BRNoMAC           = "BR_NO_MAC"
	BRNameInUse       = "BR_NAME_IN_USE"
	BRNoPlan          = "BR_NO_PLAN"
	BRPlanStale       = "BR_PLAN_STALE"
	BRBusy            = "BR_BUSY"
	BRAlreadyActive   = "BR_ALREADY_ACTIVE"
	BRNotPending      = "BR_NOT_PENDING"
	BRExpired         = "BR_EXPIRED"
	BRNotHealthy      = "BR_NOT_HEALTHY"
	BRNeedsConfirm    = "BR_NEEDS_CONFIRMATION"
	BRNeedsRoot       = "BR_NEEDS_ROOT"
	BRNothingToDo     = "BR_NOTHING_TO_DO"
	BRNotForeign      = "BR_NOT_A_BRIDGE"
	BRSafetyNet       = "BR_NO_SAFETY_NET"
	BRInUse           = "BR_IN_USE"
)

// BridgeRefusal is a typed refusal: a closed code and a sentence for the person.
type BridgeRefusal struct{ Code, Detail string }

func (r *BridgeRefusal) Error() string { return r.Code + ": " + r.Detail }

func refuse(code, format string, a ...any) error {
	return &BridgeRefusal{Code: code, Detail: fmt.Sprintf(format, a...)}
}

// BridgePlan is what `plan` proposes and `apply` executes. It never contains anything the browser sent.
type BridgePlan struct {
	ID        string   `json:"id"`
	CreatedAt string   `json:"created_at"`
	ExpiresAt string   `json:"expires_at"`
	Interface string   `json:"interface"`
	Bridge    string   `json:"bridge"`
	MAC       string   `json:"mac"`
	Addresses []string `json:"addresses"`
	Gateway   string   `json:"gateway"`
	File      string   `json:"file"`
	Digest    string   `json:"digest"`
	Before    string   `json:"before"`
	After     string   `json:"after"`
	Diff      string   `json:"diff"`
}

type bridgeState struct {
	State     string `json:"state"`
	Bridge    string `json:"bridge"`
	Interface string `json:"interface"`
	PlanID    string `json:"plan_id,omitempty"`
	File      string `json:"file,omitempty"`
	Deadline  string `json:"deadline,omitempty"`
	Adopted   bool   `json:"adopted,omitempty"`
	UpdatedAt string `json:"updated_at"`
}

var (
	routeDevRE = regexp.MustCompile(`\bdev (\S+)`)
	inetRE     = regexp.MustCompile(`\binet (\d+\.\d+\.\d+\.\d+/\d+)`)
	macRE      = regexp.MustCompile(`^[0-9a-f]{2}(:[0-9a-f]{2}){5}$`)
)

// movedKeys are the settings of an Ethernet device that move to the bridge; keptKeys stay on the device. Anything else is refused.
var (
	movedKeys = map[string]bool{"addresses": true, "routes": true, "nameservers": true, "gateway4": true}
	keptKeys  = map[string]bool{"dhcp4": true, "dhcp6": true, "optional": true, "mtu": true, "renderer": true, "link-local": true, "accept-ra": true}
	routeKeys = map[string]bool{"to": true, "via": true, "metric": true, "on-link": true}
	nsKeys    = map[string]bool{"addresses": true, "search": true}
)

type nfile struct {
	path string // standard path (without the Env root)
	raw  string
	root *ynode
}

func (e *Env) readNetplan() ([]nfile, error) {
	for _, d := range []string{"/run/netplan", "/lib/netplan", "/usr/lib/netplan"} {
		if ents, err := os.ReadDir(e.P(d)); err == nil {
			for _, en := range ents {
				if strings.HasSuffix(en.Name(), ".yaml") {
					return nil, refuse(BRNetplanDirs, "netplan files exist in %s as well as %s; adoption only handles %s", d, NetplanDir, NetplanDir)
				}
			}
		}
	}
	ents, err := os.ReadDir(e.P(NetplanDir))
	if err != nil {
		return nil, refuse(BRNoNetplan, "%s cannot be read; this host does not use netplan (the NetworkManager backend arrives with the Alma/Rocky work)", NetplanDir)
	}
	var out []nfile
	for _, en := range ents {
		if en.IsDir() || !strings.HasSuffix(en.Name(), ".yaml") {
			continue
		}
		p := NetplanDir + "/" + en.Name()
		b, err := e.ReadFile(e.P(p))
		if err != nil {
			return nil, refuse(BRUnparsable, "%s cannot be read", p)
		}
		root, perr := parseYAML(string(b))
		if perr != nil {
			return nil, refuse(BRUnparsable, "%s: %v", p, perr)
		}
		out = append(out, nfile{path: p, raw: string(b), root: root})
	}
	if len(out) == 0 {
		return nil, refuse(BRNoNetplan, "no netplan file in %s", NetplanDir)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].path < out[j].path })
	return out, nil
}

func (e *Env) ipLines(ctx context.Context, args ...string) ([]string, bool) {
	out, err := e.Run.Run(ctx, "ip", args...)
	if err != nil {
		return nil, false
	}
	var ls []string
	for _, l := range strings.Split(out, "\n") {
		if l = strings.TrimSpace(l); l != "" {
			ls = append(ls, l)
		}
	}
	return ls, true
}

func (e *Env) exists(p string) bool {
	_, err := e.Lstat(e.P(p))
	return err == nil
}

// BridgePlanFor reads the host and proposes the change. It writes nothing. A refusal is a *BridgeRefusal.
func (e *Env) BridgePlanFor(ctx context.Context) (*BridgePlan, error) {
	if out, err := e.Run.Run(ctx, "systemctl", "is-active", "NetworkManager"); err == nil && strings.TrimSpace(out) == "active" {
		return nil, refuse(BRBackendNM, "NetworkManager is active; this release adopts a bridge only through netplan with networkd")
	}
	routes, ok := e.ipLines(ctx, "-o", "-4", "route", "show", "default")
	if !ok {
		return nil, refuse(BRNoDefaultRoute, "the default route could not be read")
	}
	switch len(routes) {
	case 0:
		return nil, refuse(BRNoDefaultRoute, "the host has no IPv4 default route, so there is no uplink to adopt")
	case 1:
	default:
		return nil, refuse(BRManyDefault, "the host has %d default routes; adoption needs exactly one uplink", len(routes))
	}
	m := routeDevRE.FindStringSubmatch(routes[0])
	if m == nil || !bridgestatus.NameOK(m[1]) {
		return nil, refuse(BRNoDefaultRoute, "the default route names no usable device")
	}
	nic := m[1]
	switch {
	case e.exists("/sys/class/net/" + nic + "/wireless"):
		return nil, refuse(BRWireless, "%s is a wireless interface; a wireless link cannot be bridged", nic)
	case e.exists("/sys/class/net/" + nic + "/bonding"), e.exists("/sys/class/net/" + nic + "/master"):
		return nil, refuse(BRBond, "%s is a bond or part of one; bonds are not adopted", nic)
	case e.exists("/proc/net/vlan/" + nic):
		return nil, refuse(BRVlan, "%s is a VLAN device; VLANs are not adopted", nic)
	case e.exists("/sys/class/net/" + nic + "/brport"):
		return nil, refuse(BRAlreadyBridged, "%s is already part of a bridge", nic)
	}
	if _, err := e.Run.Run(ctx, "ip", "-o", "link", "show", "dev", BridgeName); err == nil {
		return nil, refuse(BRNameInUse, "a device called %s already exists", BridgeName)
	}

	files, err := e.readNetplan()
	if err != nil {
		return nil, err
	}
	var home *nfile
	var eth *ynode
	for i := range files {
		f := &files[i]
		net := f.root.get("network")
		if net == nil || !net.isMap() {
			return nil, refuse(BRUnparsable, "%s has no network section", f.path)
		}
		if v := net.get("version"); v != nil && v.s != "2" {
			return nil, refuse(BRUnparsable, "%s: only netplan version 2 is supported", f.path)
		}
		if r := net.get("renderer"); r != nil && r.s != "networkd" {
			return nil, refuse(BRBackendNM, "%s sets the renderer to %s; only networkd is supported", f.path, r.s)
		}
		for _, sect := range []string{"bonds", "vlans", "wifis", "bridges", "ethernets"} {
			s := net.get(sect)
			if s == nil || !s.isMap() {
				continue
			}
			for _, name := range s.keys {
				dev := s.m[name]
				if !dev.isMap() {
					continue
				}
				if _, bad := dev.m["match"]; bad {
					return nil, refuse(BRUnsupportedKey, "%s: device %s uses match:, which adoption cannot reason about", f.path, name)
				}
				if r := dev.get("renderer"); r != nil && r.s != "networkd" {
					return nil, refuse(BRBackendNM, "%s: device %s uses the %s renderer", f.path, name, r.s)
				}
				members, _ := dev.get("interfaces").strs()
				involved := name == nic || (sect != "ethernets" && containsStr(members, nic)) || dev.get("link") != nil && dev.get("link").s == nic
				if !involved {
					continue
				}
				switch sect {
				case "bonds":
					return nil, refuse(BRBond, "%s puts %s in a bond", f.path, nic)
				case "vlans":
					return nil, refuse(BRVlan, "%s puts %s under a VLAN", f.path, nic)
				case "wifis":
					return nil, refuse(BRWireless, "%s defines %s as wireless", f.path, nic)
				case "bridges":
					return nil, refuse(BRAlreadyBridged, "%s already bridges %s", f.path, nic)
				}
				if home != nil {
					return nil, refuse(BRMultiDefinition, "%s is defined in both %s and %s", nic, home.path, f.path)
				}
				home, eth = f, dev
			}
			if sect == "bridges" && s.get(BridgeName) != nil {
				return nil, refuse(BRNameInUse, "%s already defines %s", f.path, BridgeName)
			}
		}
	}
	if home == nil {
		return nil, refuse(BRNotInNetplan, "%s carries the default route but no netplan file configures it", nic)
	}
	for _, k := range eth.keys {
		if !movedKeys[k] && !keptKeys[k] {
			return nil, refuse(BRUnsupportedKey, "%s: device %s uses the key %q, which adoption does not move", home.path, nic, k)
		}
	}
	if d := eth.get("dhcp4"); d != nil && d.s != "false" && d.s != "no" {
		return nil, refuse(BRDHCP, "%s gets its address by DHCP; adoption only handles static addresses (a bridge would need the same lease)", nic)
	}
	if d := eth.get("dhcp6"); d != nil && d.s != "false" && d.s != "no" {
		return nil, refuse(BRDHCP, "%s uses DHCPv6; only static addressing is adopted", nic)
	}
	if a := eth.get("accept-ra"); a != nil && a.s != "false" && a.s != "no" {
		return nil, refuse(BRUnsupportedKey, "%s accepts router advertisements; IPv6 adoption is not supported", nic)
	}
	cfgAddrs, okA := eth.get("addresses").strs()
	if !okA || len(cfgAddrs) == 0 {
		return nil, refuse(BRConfigMismatch, "%s has no static addresses in %s", nic, home.path)
	}
	live, ok := e.ipLines(ctx, "-o", "-4", "addr", "show", "dev", nic, "scope", "global")
	if !ok {
		return nil, refuse(BRConfigMismatch, "the addresses of %s could not be read", nic)
	}
	liveSet := map[string]bool{}
	for _, l := range live {
		if mm := inetRE.FindStringSubmatch(l); mm != nil {
			liveSet[mm[1]] = true
		}
	}
	cfg4 := map[string]bool{}
	for _, a := range cfgAddrs {
		if !strings.Contains(a, ":") {
			cfg4[a] = true
		}
	}
	if len(cfg4) == 0 || !sameSet(cfg4, liveSet) {
		return nil, refuse(BRConfigMismatch, "the IPv4 addresses on %s (%s) differ from netplan (%s); fix or apply the configuration first", nic, setText(liveSet), setText(cfg4))
	}
	macRaw, err := e.ReadFile(e.P("/sys/class/net/" + nic + "/address"))
	mac := strings.ToLower(strings.TrimSpace(string(macRaw)))
	if err != nil || !macRE.MatchString(mac) {
		return nil, refuse(BRNoMAC, "the hardware address of %s could not be read", nic)
	}

	// Build the new file: the device keeps only its link settings; the bridge takes over the addressing and the hardware address.
	root := home.root.clone()
	net := root.get("network")
	if net.get("version") == nil {
		net.set("version", scalar("2"))
	}
	e2 := net.get("ethernets").get(nic)
	br := newMap()
	br.set("interfaces", strList([]string{nic}))
	br.set("macaddress", quotedScalar(mac))
	br.set("dhcp4", scalar("false"))
	gateway := ""
	var brRoutes []*ynode
	if r := e2.get("routes"); r != nil {
		if !r.isList() {
			return nil, refuse(BRUnsupportedKey, "%s: routes is not a list", home.path)
		}
		for _, item := range r.l {
			if !item.isMap() {
				return nil, refuse(BRUnsupportedKey, "%s: a route is not a map", home.path)
			}
			for _, k := range item.keys {
				if !routeKeys[k] {
					return nil, refuse(BRUnsupportedKey, "%s: a route uses the key %q, which adoption does not move", home.path, k)
				}
			}
			if t := item.get("to"); t != nil && (t.s == "default" || t.s == "0.0.0.0/0") {
				if gateway != "" {
					return nil, refuse(BRManyDefault, "%s configures two default routes", home.path)
				}
				if v := item.get("via"); v != nil {
					gateway = v.s
				}
			}
			brRoutes = append(brRoutes, item.clone())
		}
	}
	if g := e2.get("gateway4"); g != nil {
		if gateway != "" {
			return nil, refuse(BRManyDefault, "%s sets gateway4 and a default route", home.path)
		}
		gateway = g.s
		rt := newMap()
		rt.set("to", scalar("default"))
		rt.set("via", scalar(g.s))
		brRoutes = append(brRoutes, rt)
	}
	if gateway == "" {
		return nil, refuse(BRConfigMismatch, "%s configures no default gateway for %s, but the host's default route uses it", home.path, nic)
	}
	br.set("addresses", e2.get("addresses").clone())
	if len(brRoutes) > 0 {
		l := newList()
		l.l = brRoutes
		br.set("routes", l)
	}
	if ns := e2.get("nameservers"); ns != nil {
		if !ns.isMap() {
			return nil, refuse(BRUnsupportedKey, "%s: nameservers is not a map", home.path)
		}
		for _, k := range ns.keys {
			if !nsKeys[k] {
				return nil, refuse(BRUnsupportedKey, "%s: nameservers uses the key %q", home.path, k)
			}
		}
		br.set("nameservers", ns.clone())
	}
	if mtu := e2.get("mtu"); mtu != nil {
		br.set("mtu", mtu.clone())
	}
	par := newMap()
	par.set("stp", scalar("false"))
	par.set("forward-delay", scalar("0"))
	br.set("parameters", par)
	for k := range movedKeys {
		e2.del(k)
	}
	e2.set("dhcp4", scalar("false"))
	bridges := net.get("bridges")
	if bridges == nil || !bridges.isMap() {
		bridges = newMap()
		net.set("bridges", bridges)
	}
	bridges.set(BridgeName, br)
	after := marshalYAMLUnit(root, indentUnit(home.raw))
	if chk, perr := parseYAML(after); perr != nil || chk.get("network").get("bridges").get(BridgeName) == nil {
		return nil, refuse(BRUnparsable, "the proposed configuration could not be rendered safely")
	}

	h := sha256.New()
	for _, f := range files {
		_, _ = h.Write([]byte(f.path + "\x00" + f.raw + "\x00"))
	}
	var addrs []string
	for a := range liveSet {
		addrs = append(addrs, a)
	}
	sort.Strings(addrs)
	_, _ = h.Write([]byte(nic + "\x00" + mac + "\x00" + strings.Join(addrs, ",") + "\x00" + routes[0]))
	digest := hex.EncodeToString(h.Sum(nil))
	now := e.Now().UTC()
	return &BridgePlan{ID: digest[:12], CreatedAt: now.Format(time.RFC3339), ExpiresAt: now.Add(planTTL).Format(time.RFC3339), Interface: nic, Bridge: BridgeName, MAC: mac,
		Addresses: addrs, Gateway: gateway, File: home.path, Digest: digest, Before: home.raw, After: after, Diff: lineDiff(home.raw, after)}, nil
}

func containsStr(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}

func sameSet(a, b map[string]bool) bool {
	if len(a) != len(b) {
		return false
	}
	for k := range a {
		if !b[k] {
			return false
		}
	}
	return true
}

func setText(m map[string]bool) string {
	var s []string
	for k := range m {
		s = append(s, k)
	}
	sort.Strings(s)
	if len(s) == 0 {
		return "none"
	}
	return strings.Join(s, ", ")
}

// lineDiff is a plain line diff (longest common subsequence) with "  ", "- " and "+ " prefixes; files here are a few dozen lines.
func lineDiff(a, b string) string {
	x, y := strings.Split(strings.TrimRight(a, "\n"), "\n"), strings.Split(strings.TrimRight(b, "\n"), "\n")
	if len(x) > 400 || len(y) > 400 {
		return "(the file is too long to show a line diff)"
	}
	l := make([][]int, len(x)+1)
	for i := range l {
		l[i] = make([]int, len(y)+1)
	}
	for i := len(x) - 1; i >= 0; i-- {
		for j := len(y) - 1; j >= 0; j-- {
			if x[i] == y[j] {
				l[i][j] = l[i+1][j+1] + 1
			} else if l[i+1][j] >= l[i][j+1] {
				l[i][j] = l[i+1][j]
			} else {
				l[i][j] = l[i][j+1]
			}
		}
	}
	var out []string
	i, j := 0, 0
	for i < len(x) && j < len(y) {
		switch {
		case x[i] == y[j]:
			out = append(out, "  "+x[i])
			i++
			j++
		case l[i+1][j] >= l[i][j+1]:
			out = append(out, "- "+x[i])
			i++
		default:
			out = append(out, "+ "+y[j])
			j++
		}
	}
	for ; i < len(x); i++ {
		out = append(out, "- "+x[i])
	}
	for ; j < len(y); j++ {
		out = append(out, "+ "+y[j])
	}
	return strings.Join(out, "\n") + "\n"
}

// ---- state --------------------------------------------------------------------------------------------------------------------------------

func (e *Env) readBridgeState() (bridgeState, bool) {
	b, err := e.ReadFile(e.P(bridgeStateFile))
	if err != nil {
		return bridgeState{}, false
	}
	var s bridgeState
	if json.Unmarshal(b, &s) != nil || s.State == "" {
		return bridgeState{}, false
	}
	return s, true
}

// writeBridgeState records the private state and the public status together; a state of "" removes both.
func (e *Env) writeBridgeState(s bridgeState) error {
	if err := e.ensureDir(e.P(BridgeDir), 0o700, 0, 0); err != nil {
		return err
	}
	if s.State == "" {
		if err := removeIfExists(e.P(bridgeStateFile)); err != nil {
			return err
		}
		return removeIfExists(e.P(BridgeStatusFile))
	}
	s.UpdatedAt = e.Now().UTC().Format(time.RFC3339)
	b, _ := json.MarshalIndent(s, "", "  ")
	if _, err := e.writeAtomic(e.P(bridgeStateFile), append(b, '\n'), 0o600, 0, 0); err != nil {
		return err
	}
	pub := bridgestatus.File{State: s.State, Bridge: s.Bridge, Interface: s.Interface, Deadline: s.Deadline, GeneratedAt: s.UpdatedAt}
	pb, _ := json.MarshalIndent(pub, "", "  ")
	_, err := e.writeAtomic(e.P(BridgeStatusFile), append(pb, '\n'), 0o644, 0, 0)
	return err
}

func (e *Env) needRoot() error {
	if e.Euid() != 0 {
		return refuse(BRNeedsRoot, "this command changes the host network and needs root (run with sudo)")
	}
	return nil
}

// BridgePlanAndRecord is `bridge plan`: it proposes the change and, as root, records the plan so that `apply` can execute exactly it.
func (e *Env) BridgePlanAndRecord(ctx context.Context, w io.Writer) (*BridgePlan, error) {
	st, have := e.readBridgeState()
	if have && (st.State == bridgestatus.StatePendingConfirmation || st.State == bridgestatus.StateActive) {
		return nil, refuse(BRBusy, "a bridge change is already %s", strings.ReplaceAll(st.State, "_", " "))
	}
	p, err := e.BridgePlanFor(ctx)
	if err != nil {
		return nil, err
	}
	_, _ = fmt.Fprintf(w, "Plan %s: move the addressing of %s (%s, gateway %s) to a new bridge %s that enslaves %s.\n", p.ID, p.Interface, strings.Join(p.Addresses, ", "), p.Gateway, p.Bridge, p.Interface)
	_, _ = fmt.Fprintf(w, "File changed: %s\n\n%s\n", p.File, p.Diff)
	if e.Euid() != 0 {
		_, _ = fmt.Fprintln(w, "Not recorded: run as root to record this plan before applying it.")
		return p, nil
	}
	if err := e.ensureDir(e.P(BridgeDir), 0o700, 0, 0); err != nil {
		return nil, err
	}
	b, _ := json.MarshalIndent(p, "", "  ")
	if _, err := e.writeAtomic(e.P(bridgePlanFile), append(b, '\n'), 0o600, 0, 0); err != nil {
		return nil, err
	}
	if err := e.writeBridgeState(bridgeState{State: bridgestatus.StatePlanned, Bridge: p.Bridge, Interface: p.Interface, PlanID: p.ID, File: p.File}); err != nil {
		return nil, err
	}
	_, _ = fmt.Fprintf(w, "Recorded. To apply it (the plan is good for %d minutes):\n  sudo svavyom-ctl bridge apply --plan %s --confirm-bridge %s [--countdown %d]\n", int(planTTL.Minutes()), p.ID, p.Bridge, DefaultCountdown)
	return p, nil
}

// ---- apply, confirm, rollback -------------------------------------------------------------------------------------------------------------

func recoverUnit() string {
	return `[Unit]
Description=Svavyom: undo a host bridge change that was never confirmed
DefaultDependencies=no
After=local-fs.target
Before=sysinit.target network-pre.target systemd-networkd.service NetworkManager.service
ConditionPathExists=` + bridgeStateFile + `

[Service]
Type=oneshot
ExecStart=` + LibexecDir + `/svavyom-ctl bridge recover

[Install]
WantedBy=sysinit.target
`
}

func (e *Env) removeRecoverUnit(ctx context.Context) {
	if e.exists(UnitDir + "/" + BridgeRecoverUnit) {
		_, _ = e.Run.Run(ctx, "systemctl", "disable", "--", BridgeRecoverUnit)
	}
	_ = removeIfExists(e.P(UnitDir + "/" + BridgeRecoverUnit))
	_, _ = e.Run.Run(ctx, "systemctl", "daemon-reload")
}

// BridgeApply executes a recorded plan with a countdown. It returns once the new configuration is in effect (or restored, on failure).
func (e *Env) BridgeApply(ctx context.Context, w io.Writer, planID, typed string, countdown int) error {
	if err := e.needRoot(); err != nil {
		return err
	}
	if countdown == 0 {
		countdown = DefaultCountdown
	}
	if countdown < MinCountdown || countdown > MaxCountdown {
		return refuse(BRNeedsConfirm, "the countdown must be between %d and %d seconds", MinCountdown, MaxCountdown)
	}
	st, have := e.readBridgeState()
	if have {
		switch st.State {
		case bridgestatus.StatePendingConfirmation:
			return refuse(BRBusy, "a bridge change is waiting for confirmation; confirm or roll it back first")
		case bridgestatus.StateActive:
			return refuse(BRAlreadyActive, "a bridge is already in place (%s on %s)", st.Bridge, st.Interface)
		}
	}
	raw, err := e.ReadFile(e.P(bridgePlanFile))
	var plan BridgePlan
	if err != nil || json.Unmarshal(raw, &plan) != nil || plan.ID == "" || plan.ID != planID {
		return refuse(BRNoPlan, "there is no recorded plan with id %q; run `svavyom-ctl bridge plan` first", planID)
	}
	if typed != plan.Bridge {
		return refuse(BRNeedsConfirm, "type the bridge name to confirm: --confirm-bridge %s", plan.Bridge)
	}
	if exp, perr := time.Parse(time.RFC3339, plan.ExpiresAt); perr != nil || e.Now().After(exp) {
		return refuse(BRPlanStale, "the plan has expired; run `svavyom-ctl bridge plan` again")
	}
	cur, err := e.BridgePlanFor(ctx)
	if err != nil {
		return err
	}
	if cur.Digest != plan.Digest || cur.After != plan.After {
		return refuse(BRPlanStale, "the network configuration changed since the plan was made; run `svavyom-ctl bridge plan` again")
	}

	// Safety net first: snapshot, recovery unit, timer. Nothing is applied until all three exist.
	if err := e.ensureDir(e.P(bridgeSnapDir), 0o700, 0, 0); err != nil {
		return err
	}
	snap := e.P(bridgeSnapDir + "/" + filepath.Base(plan.File))
	if _, err := e.writeAtomic(snap, []byte(plan.Before), 0o600, 0, 0); err != nil {
		return err
	}
	mode := os.FileMode(0o600)
	if fi, err := os.Lstat(e.P(plan.File)); err == nil {
		mode = fi.Mode().Perm()
	}
	restore := func() {
		_, _ = e.writeAtomic(e.P(plan.File), []byte(plan.Before), mode, 0, 0)
	}
	deadline := e.Now().Add(time.Duration(countdown) * time.Second).UTC()
	if err := e.ensureDir(e.P(UnitDir), 0o755, 0, 0); err != nil {
		return err
	}
	if _, err := e.writeAtomic(e.P(UnitDir+"/"+BridgeRecoverUnit), []byte(recoverUnit()), 0o644, 0, 0); err != nil {
		return err
	}
	if out, err := e.Run.Run(ctx, "systemctl", "daemon-reload"); err != nil {
		e.removeRecoverUnit(ctx)
		return refuse(BRSafetyNet, "systemctl daemon-reload failed (%s); nothing was changed", clean(out))
	}
	if out, err := e.Run.Run(ctx, "systemctl", "enable", "--", BridgeRecoverUnit); err != nil {
		e.removeRecoverUnit(ctx)
		return refuse(BRSafetyNet, "the boot-time recovery unit could not be enabled (%s); nothing was changed", clean(out))
	}
	state := bridgeState{State: bridgestatus.StatePendingConfirmation, Bridge: plan.Bridge, Interface: plan.Interface, PlanID: plan.ID, File: plan.File, Deadline: deadline.Format(time.RFC3339)}
	if err := e.writeBridgeState(state); err != nil {
		e.removeRecoverUnit(ctx)
		return err
	}
	abort := func(why error) error {
		_, _ = e.Run.Run(ctx, "systemctl", "stop", bridgeRollbackRun+".timer")
		e.removeRecoverUnit(ctx)
		restore()
		_ = e.writeBridgeState(bridgeState{})
		return why
	}
	if out, err := e.Run.Run(ctx, "systemd-run", "--unit="+bridgeRollbackRun, fmt.Sprintf("--on-active=%ds", countdown), "--timer-property=AccuracySec=1s", "--",
		LibexecDir+"/svavyom-ctl", "bridge", "rollback", "--auto"); err != nil {
		return abort(refuse(BRSafetyNet, "the rollback timer could not be armed (%s); nothing was changed", clean(out)))
	}
	if _, err := e.writeAtomic(e.P(plan.File), []byte(plan.After), mode, 0, 0); err != nil {
		return abort(err)
	}
	if out, err := e.Run.Run(ctx, "netplan", "generate"); err != nil {
		return abort(fmt.Errorf("netplan rejected the new configuration, nothing was applied: %s", clean(out)))
	}
	_, _ = fmt.Fprintf(w, "Applying plan %s. If this session drops, that is expected while the bridge comes up.\n", plan.ID)
	if out, err := e.Run.Run(ctx, "netplan", "apply"); err != nil {
		_, _ = fmt.Fprintf(w, "netplan apply failed (%s); restoring the previous configuration.\n", clean(out))
		if rerr := e.BridgeRollback(ctx, w, true, false, ""); rerr != nil {
			return fmt.Errorf("netplan apply failed and the rollback also failed: %w", rerr)
		}
		return errors.New("netplan apply failed; the previous configuration was restored")
	}
	_, _ = fmt.Fprintf(w, "Applied. You have %d seconds. From a session that reaches this host on the new setup (a second browser tab or SSH to %s), run:\n  sudo svavyom-ctl bridge confirm\nOtherwise the previous configuration is restored automatically.\n", countdown, strings.Split(plan.Addresses[0], "/")[0])
	return nil
}

// BridgeConfirm keeps the new configuration. It refuses unless the bridge really is carrying the address and the default route, so a configuration
// that merely applied cleanly but cut the host off cannot be confirmed from a stale session.
func (e *Env) BridgeConfirm(ctx context.Context, w io.Writer) error {
	if err := e.needRoot(); err != nil {
		return err
	}
	st, ok := e.readBridgeState()
	if !ok || st.State != bridgestatus.StatePendingConfirmation {
		return refuse(BRNotPending, "no bridge change is waiting for confirmation")
	}
	if d, err := time.Parse(time.RFC3339, st.Deadline); err != nil || e.Now().After(d) {
		return refuse(BRExpired, "the countdown has run out; the previous configuration is being restored")
	}
	addrs, _ := e.ipLines(ctx, "-o", "-4", "addr", "show", "dev", st.Bridge, "scope", "global")
	routes, _ := e.ipLines(ctx, "-o", "-4", "route", "show", "default")
	if len(addrs) == 0 || len(routes) != 1 || !strings.Contains(routes[0]+" ", "dev "+st.Bridge+" ") {
		return refuse(BRNotHealthy, "%s does not carry an address and the default route yet; not confirming (the countdown continues)", st.Bridge)
	}
	_, _ = e.Run.Run(ctx, "systemctl", "stop", bridgeRollbackRun+".timer")
	e.removeRecoverUnit(ctx)
	st.State, st.Deadline = bridgestatus.StateActive, ""
	if err := e.writeBridgeState(st); err != nil {
		return err
	}
	_, _ = fmt.Fprintf(w, "Confirmed: %s now carries the host's network. `svavyom-ctl bridge rollback --confirm-bridge %s` undoes it.\n", st.Bridge, st.Bridge)
	return nil
}

// BridgeRollback restores the configuration saved by apply. auto is the timer and the boot unit (no typed confirmation, no error when there is nothing to
// do); noApply only regenerates the netplan output, for the boot-time recovery that runs before the network starts.
func (e *Env) BridgeRollback(ctx context.Context, w io.Writer, auto, noApply bool, typed string) error {
	if err := e.needRoot(); err != nil {
		return err
	}
	st, ok := e.readBridgeState()
	if !ok || st.State == bridgestatus.StatePlanned {
		if ok { // only a recorded plan: forgetting it changes nothing on the host
			_ = removeIfExists(e.P(bridgePlanFile))
			_, _ = fmt.Fprintf(w, "Forgot the recorded plan; the host network was not touched.\n")
			return e.writeBridgeState(bridgeState{})
		}
		e.removeRecoverUnit(ctx)
		if auto {
			return nil
		}
		return refuse(BRNothingToDo, "no bridge change to undo")
	}
	if !auto && st.State == bridgestatus.StateActive {
		if users := e.networksOnBridge(ctx, st.Bridge); len(users) > 0 {
			return refuse(BRInUse, "libvirt networks still use %s (%s); delete them in the console first, otherwise their VMs lose their network", st.Bridge, strings.Join(users, ", "))
		}
	}
	if st.Adopted {
		if !auto && typed != st.Bridge {
			return refuse(BRNeedsConfirm, "type the bridge name to confirm: --confirm-bridge %s", st.Bridge)
		}
		e.removeRecoverUnit(ctx)
		_, _ = fmt.Fprintf(w, "Forgot the adopted bridge %s; the host network was not touched.\n", st.Bridge)
		return e.writeBridgeState(bridgeState{})
	}
	if !auto && st.State == bridgestatus.StateActive && typed != st.Bridge {
		return refuse(BRNeedsConfirm, "this undoes a confirmed bridge; type the bridge name to confirm: --confirm-bridge %s", st.Bridge)
	}
	snap := e.P(bridgeSnapDir + "/" + filepath.Base(st.File))
	before, err := e.ReadFile(snap)
	if err != nil || st.File == "" || !strings.HasPrefix(st.File, NetplanDir+"/") {
		return fmt.Errorf("the saved configuration %s cannot be read: restore %s by hand", snap, st.File)
	}
	mode := os.FileMode(0o600)
	if fi, err := os.Lstat(e.P(st.File)); err == nil {
		mode = fi.Mode().Perm()
	}
	if _, err := e.writeAtomic(e.P(st.File), before, mode, 0, 0); err != nil {
		return err
	}
	verb := "apply"
	if noApply {
		verb = "generate"
	}
	if out, err := e.Run.Run(ctx, "netplan", verb); err != nil {
		return fmt.Errorf("the previous configuration is back in %s but netplan %s failed: %s", st.File, verb, clean(out))
	}
	// networkd does not delete a virtual device when its configuration disappears, and the uplink would stay enslaved to it: remove the bridge we created
	// and apply again so the uplink gets its own addressing back. (At boot there is nothing to remove: the device does not exist yet.)
	if !noApply {
		if _, err := e.Run.Run(ctx, "ip", "-o", "link", "show", "dev", st.Bridge); err == nil {
			if out, derr := e.Run.Run(ctx, "ip", "link", "del", "dev", st.Bridge); derr != nil {
				return fmt.Errorf("the previous configuration is back in %s but %s could not be removed: %s", st.File, st.Bridge, clean(out))
			}
			if out, aerr := e.Run.Run(ctx, "netplan", "apply"); aerr != nil {
				return fmt.Errorf("the previous configuration is back in %s but netplan apply failed after removing %s: %s", st.File, st.Bridge, clean(out))
			}
		}
	}
	_, _ = e.Run.Run(ctx, "systemctl", "stop", bridgeRollbackRun+".timer")
	e.removeRecoverUnit(ctx)
	_ = removeIfExists(snap)
	_ = removeIfExists(e.P(bridgePlanFile))
	_, _ = fmt.Fprintf(w, "Restored the previous network configuration (%s).\n", st.File)
	return e.writeBridgeState(bridgeState{})
}

var bridgeNameAttrRE = regexp.MustCompile(`<bridge\s+name=['"]([^'"]+)['"]`)

// networksOnBridge lists the libvirt networks whose definition names the host bridge. Without virsh there is nothing to ask, and nothing is claimed.
func (e *Env) networksOnBridge(ctx context.Context, bridge string) []string {
	if _, err := e.LookPath("virsh"); err != nil {
		return nil
	}
	list, err := e.Run.Run(ctx, "virsh", "-r", "-c", "qemu:///system", "net-list", "--all", "--name")
	if err != nil {
		return nil
	}
	var out []string
	for _, n := range strings.Fields(list) {
		x, err := e.Run.Run(ctx, "virsh", "-r", "-c", "qemu:///system", "net-dumpxml", "--", n)
		if err != nil {
			continue
		}
		if m := bridgeNameAttrRE.FindStringSubmatch(x); m != nil && m[1] == bridge {
			out = append(out, n)
		}
	}
	return out
}

// BridgeRecover is run by the boot-time unit: a change that was never confirmed does not survive a reboot.
func (e *Env) BridgeRecover(ctx context.Context, w io.Writer) error {
	st, ok := e.readBridgeState()
	if ok && st.State == bridgestatus.StatePendingConfirmation {
		return e.BridgeRollback(ctx, w, true, true, "")
	}
	e.removeRecoverUnit(ctx)
	return nil
}

// BridgeAdopt records an existing bridge that someone else created, so VMs may attach to it. Nothing on the host is changed, now or at rollback.
func (e *Env) BridgeAdopt(ctx context.Context, w io.Writer, name, typed string) error {
	if err := e.needRoot(); err != nil {
		return err
	}
	if !bridgestatus.NameOK(name) || strings.HasPrefix(name, "virbr") || strings.HasPrefix(name, "docker") {
		return refuse(BRNotForeign, "%q is not a bridge that can be adopted (libvirt's and Docker's own bridges are managed by them)", name)
	}
	if typed != name {
		return refuse(BRNeedsConfirm, "type the bridge name to confirm: --confirm-bridge %s", name)
	}
	if st, ok := e.readBridgeState(); ok && st.State != bridgestatus.StatePlanned {
		return refuse(BRBusy, "a bridge is already %s", strings.ReplaceAll(st.State, "_", " "))
	}
	if !e.exists("/sys/class/net/" + name + "/bridge") {
		return refuse(BRNotForeign, "%s is not a bridge on this host", name)
	}
	nic := ""
	if ents, err := os.ReadDir(e.P("/sys/class/net/" + name + "/brif")); err == nil && len(ents) > 0 {
		nic = ents[0].Name()
	}
	if nic == "" {
		nic = "none"
	}
	_, _ = fmt.Fprintf(w, "Adopted the existing bridge %s as it is; Svavyom will never modify it.\n", name)
	return e.writeBridgeState(bridgeState{State: bridgestatus.StateActive, Bridge: name, Interface: nic, Adopted: true})
}

// BridgeStatusText describes the current state.
func (e *Env) BridgeStatusText() string {
	st, ok := e.readBridgeState()
	if !ok {
		return "no bridge: the host network is as it was installed"
	}
	switch st.State {
	case bridgestatus.StatePendingConfirmation:
		left := 0
		if d, err := time.Parse(time.RFC3339, st.Deadline); err == nil && d.After(e.Now()) {
			left = int(d.Sub(e.Now()).Seconds())
		}
		return fmt.Sprintf("pending confirmation: %s on %s, %d seconds left (sudo svavyom-ctl bridge confirm)", st.Bridge, st.Interface, left)
	case bridgestatus.StateActive:
		if st.Adopted {
			return fmt.Sprintf("active: adopted existing bridge %s", st.Bridge)
		}
		return fmt.Sprintf("active: %s carries the host network (uplink %s)", st.Bridge, st.Interface)
	}
	return fmt.Sprintf("planned: %s on %s (plan %s)", st.Bridge, st.Interface, st.PlanID)
}
