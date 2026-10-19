package api

import (
	"context"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"time"

	"example.invalid/dedicatedcloud/backend/internal/hypervisor"
	"example.invalid/dedicatedcloud/backend/internal/operation"
	"example.invalid/dedicatedcloud/backend/internal/provision"
)

// networkType is the subset of lifecycleType added by M3 that acts on a Svavyom-managed network (kind VirtualNetwork).
func networkType(t operation.Type) bool {
	switch t {
	case operation.NetworkCreate, operation.NetworkStart, operation.NetworkStop, operation.NetworkAutostart, operation.NetworkDelete:
		return true
	}
	return false
}

// vmNetType is the subset added by M3 that acts on a Svavyom-managed VM's configuration.
func vmNetType(t operation.Type) bool {
	return t == operation.Compute || t == operation.ReserveIP || t == operation.ReleaseIP
}

// paramType is the set of types that carry a `params` object.
func paramType(t operation.Type) bool {
	switch t {
	case operation.Resize, operation.Reinstall, operation.RestoreSnapshot, operation.DeleteSnapshot, operation.Restore,
		operation.NetworkCreate, operation.NetworkAutostart, operation.Compute, operation.ReserveIP, operation.VolumeCreate, operation.VolumeAttach, operation.BackupExport, operation.ScheduleSet, operation.ISOAttach, operation.Rescue:
		return true
	}
	return false
}

// ---- the networks as resources -------------------------------------------------------------------------------------------------

type networkJSON struct {
	ID         string      `json:"id"`
	ProjectID  string      `json:"project_id"`
	Generation int         `json:"generation"`
	Name       string      `json:"name"`
	Desired    netDesired  `json:"desired"`
	Observed   netObserved `json:"observed"`
	Allowed    []string    `json:"allowed_actions"`
}

type netDesired struct {
	Mode      string `json:"mode"`
	Autostart bool   `json:"autostart"`
}

type netObserved struct {
	State        string        `json:"state"`
	Managed      bool          `json:"managed"`
	Bridge       *string       `json:"bridge"`
	Subnet       *string       `json:"subnet"`
	Gateway      *string       `json:"gateway"`
	DHCPStart    *string       `json:"dhcp_start"`
	DHCPEnd      *string       `json:"dhcp_end"`
	AttachedVMs  int           `json:"attached_vms"`
	Reservations []reservation `json:"reservations"`
}

type reservation struct {
	MAC string `json:"mac"`
	IP  string `json:"ip"`
}

func strp(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// networkReader is the read-only network view of the host (the agent client), or nil when the reader cannot describe networks.
func (h *Handler) networkReader() hypervisor.NetworkReader {
	if h.deps.VMs == nil {
		return nil
	}
	nr, _ := h.deps.VMs.(hypervisor.NetworkReader)
	return nr
}

// networkIndex returns the networks by name, or ok=false when they cannot be read.
func (h *Handler) networkIndex(ctx context.Context) (map[string]hypervisor.Network, bool) {
	nr := h.networkReader()
	if nr == nil {
		return nil, false
	}
	cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	list, err := nr.Networks(cctx)
	if err != nil {
		return nil, false
	}
	m := make(map[string]hypervisor.Network, len(list))
	for _, n := range list {
		m[n.Name] = n
	}
	return m, true
}

func toNetwork(n hypervisor.Network, running int, actions bool) networkJSON {
	mode := n.Mode
	switch mode {
	case "nat", "route", "bridge", "open", "isolated":
	default:
		mode = "other"
	}
	state := "inactive"
	if n.Active {
		state = "active"
	}
	res := []reservation{}
	for _, r := range n.Reservations {
		res = append(res, reservation{MAC: r.MAC, IP: r.IP})
	}
	allowed := []string{}
	if actions && n.Managed {
		if !n.Active {
			allowed = append(allowed, "start")
		} else if running == 0 {
			allowed = append(allowed, "stop")
		}
		if n.AttachedVMs == 0 {
			allowed = append(allowed, "delete")
		}
		if n.Autostart {
			allowed = append(allowed, "disable_autostart")
		} else {
			allowed = append(allowed, "enable_autostart")
		}
	}
	return networkJSON{ID: n.Name, ProjectID: defaultProject, Generation: 1, Name: n.Name, Allowed: allowed,
		Desired: netDesired{Mode: mode, Autostart: n.Autostart},
		Observed: netObserved{State: state, Managed: n.Managed, Bridge: strp(n.Bridge), Subnet: strp(n.Subnet), Gateway: strp(n.Gateway), DHCPStart: strp(n.DHCPStart),
			DHCPEnd: strp(n.DHCPEnd), AttachedVMs: n.AttachedVMs, Reservations: res}}
}

// runningByNetwork counts the running VMs per network from the VM inventory.
func (h *Handler) runningByNetwork(ctx context.Context) map[string]int {
	out := map[string]int{}
	if h.deps.VMs == nil {
		return out
	}
	if list, err := h.deps.VMs.List(ctx); err == nil {
		for _, d := range list {
			if d.State == hypervisor.StateRunning && d.Network != "" {
				out[d.Network]++
			}
		}
	}
	return out
}

func (h *Handler) requireNetworkSession(w http.ResponseWriter, r *http.Request) bool {
	if h.deps.Auth == nil || h.networkReader() == nil {
		h.reject(w, categoryUnauthenticated)
		return false
	}
	_, _, ok, failed := h.session(r)
	switch {
	case failed:
		h.reject(w, categoryUnavailable)
	case !ok:
		h.reject(w, categoryUnauthenticated)
	}
	return ok
}

func (h *Handler) listNetworks(w http.ResponseWriter, r *http.Request) {
	if !h.requireNetworkSession(w, r) {
		return
	}
	for k, v := range r.URL.Query() {
		if len(v) != 1 || (k != "limit" && k != "cursor") || (k == "limit" && !limitRE.MatchString(v[0])) || k == "cursor" {
			h.reject(w, categoryValidation) // one page: no cursor can be valid
			return
		}
	}
	idx, ok := h.networkIndex(r.Context())
	if !ok {
		h.reject(w, categoryUnavailable)
		return
	}
	running := h.runningByNetwork(r.Context())
	enabled := h.deps.Creation != nil && h.deps.Creation.Enabled
	names := make([]string, 0, len(idx))
	for n := range idx {
		names = append(names, n)
	}
	sortStrings(names)
	items := []networkJSON{}
	role := h.roleOf(r)
	for _, n := range names {
		nj := toNetwork(idx[n], running[n], enabled)
		nj.Allowed = restrict(role, "VirtualNetwork", nj.Allowed)
		items = append(items, nj)
	}
	allowed := []string{}
	if enabled {
		allowed = append(allowed, "create")
	}
	allowed = restrict(role, "NetworkCollection", allowed)
	writeJSON(w, http.StatusOK, struct {
		Items   []networkJSON `json:"items"`
		Allowed []string      `json:"allowed_actions"`
		Next    *string       `json:"next_cursor"`
	}{Items: items, Allowed: allowed})
}

func (h *Handler) readNetwork(w http.ResponseWriter, r *http.Request) {
	if !h.requireNetworkSession(w, r) {
		return
	}
	if len(r.URL.Query()) != 0 {
		h.reject(w, categoryValidation)
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/api/v1/virtual-networks/")
	if !vmIDRE.MatchString(id) {
		h.reject(w, categoryValidation)
		return
	}
	idx, ok := h.networkIndex(r.Context())
	if !ok {
		h.reject(w, categoryUnavailable)
		return
	}
	n, found := idx[id]
	if !found {
		h.reject(w, categoryNotFound)
		return
	}
	running := h.runningByNetwork(r.Context())
	nj := toNetwork(n, running[id], h.deps.Creation != nil && h.deps.Creation.Enabled)
	nj.Allowed = restrict(h.roleOf(r), "VirtualNetwork", nj.Allowed)
	writeJSON(w, http.StatusOK, nj)
}

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}

// ---- prechecks -------------------------------------------------------------------------------------------------------------------

// placeholderNetUUID stands in for the UUID the manager generates, so the specification can be validated before it is accepted.
const placeholderNetUUID = "00000000-0000-4000-8000-000000000000"

// bridgeDevice reports whether the host has a bridge device of that name (the sysfs entry exists only for bridges).
func (h *Handler) bridgeDevice(name string) bool {
	if h.deps.BridgeDevice != nil {
		return h.deps.BridgeDevice(name)
	}
	fi, err := os.Stat("/sys/class/net/" + name + "/bridge")
	return err == nil && fi.IsDir()
}

// networkPrechecks gives early, friendly answers for the network operations before anything is stored. The mutation helper re-proves ownership
// and every rule on the host; these are not the safety net.
func (h *Handler) networkPrechecks(w http.ResponseWriter, r *http.Request, req operation.Request) bool {
	cr := h.deps.Creation
	idx, ok := h.networkIndex(r.Context())
	if !ok {
		h.reject(w, categoryUnavailable)
		return false
	}
	name := req.ResourceID
	if req.Type == operation.NetworkCreate && req.Params.Bridge != "" {
		// A bridge-mode network (DR-024 D5): only on the host bridge svavyom-ctl recorded as active, which must really exist on this host. There is no
		// subnet to keep apart from anything; the host's own network addresses the guests.
		p := req.Params
		spec := provision.NetworkSpec{Name: name, UUID: placeholderNetUUID, HostBridge: p.Bridge}
		if spec.Validate() != nil || name == cr.Network {
			h.reject(w, categoryValidation)
			return false
		}
		if _, taken := idx[name]; taken {
			h.reject(w, categoryConflict)
			return false
		}
		if b := h.hostBridge(); b == nil || b.State != "active" || b.Bridge != p.Bridge {
			h.reject(w, categoryProhibited) // no confirmed or adopted host bridge of that name
			return false
		}
		if !h.bridgeDevice(p.Bridge) {
			h.reject(w, categoryUnavailable)
			return false
		}
		for _, n := range idx {
			if n.Bridge == p.Bridge {
				h.reject(w, categoryConflict) // another libvirt network already uses it
				return false
			}
		}
		return true
	}
	if req.Type == operation.NetworkCreate {
		p := req.Params
		spec := provision.NetworkSpec{Name: name, UUID: placeholderNetUUID, Subnet: p.Subnet, DHCPStart: p.DHCPStart, DHCPEnd: p.DHCPEnd}
		if spec.Validate() != nil || name == cr.Network {
			h.reject(w, categoryValidation)
			return false
		}
		if _, taken := idx[name]; taken {
			h.reject(w, categoryConflict)
			return false
		}
		pfx, _ := provision.ParseManagedSubnet(p.Subnet)
		for _, n := range idx {
			if sp, err := netip.ParsePrefix(n.Subnet); err == nil && provision.Overlaps(sp, pfx) {
				h.reject(w, categoryConflict) // overlaps another libvirt network
				return false
			}
		}
		avoid, err := h.hostPrefixes()
		if err != nil {
			h.reject(w, categoryUnavailable) // fail closed: the host's own networks cannot be read
			return false
		}
		for _, a := range avoid {
			if provision.Overlaps(a, pfx) {
				h.reject(w, categoryConflict)
				return false
			}
		}
		return true
	}
	n, found := idx[name]
	switch {
	case !found:
		h.reject(w, categoryNotFound)
		return false
	case !n.Managed:
		h.reject(w, categoryProhibited) // foreign networks are never changed
		return false
	}
	switch req.Type {
	case operation.NetworkStart:
		if n.Active {
			h.reject(w, categoryConflict)
			return false
		}
	case operation.NetworkStop:
		if !n.Active || h.runningByNetwork(r.Context())[name] > 0 {
			h.reject(w, categoryConflict)
			return false
		}
	case operation.NetworkAutostart:
		if n.Autostart == (req.Params.Autostart == "on") {
			h.reject(w, categoryConflict)
			return false
		}
	case operation.NetworkDelete:
		if n.AttachedVMs > 0 {
			h.reject(w, categoryConflict)
			return false
		}
	}
	return true
}

// hostPrefixes returns the host's own subnets, or an error when they cannot be read (the create is then refused).
func (h *Handler) hostPrefixes() ([]netip.Prefix, error) {
	cr := h.deps.Creation
	if cr == nil || cr.HostPrefixes == nil {
		return nil, errNoHostPrefixes
	}
	return cr.HostPrefixes()
}

type apiErr string

func (e apiErr) Error() string { return string(e) }

const errNoHostPrefixes = apiErr("host prefixes unavailable")

// vmNetPrechecks gives early answers for compute, reserve_ip and release_ip on a Svavyom-managed VM.
func (h *Handler) vmNetPrechecks(w http.ResponseWriter, r *http.Request, req operation.Request) bool {
	if h.deps.VMs == nil {
		h.reject(w, categoryUnavailable)
		return false
	}
	d, err := h.deps.VMs.Lookup(r.Context(), req.ResourceID)
	switch hypervisor.CategoryOf(err) {
	case "":
	case hypervisor.NotFound:
		h.reject(w, categoryNotFound)
		return false
	default:
		h.reject(w, categoryUnavailable)
		return false
	}
	if !d.Managed {
		h.reject(w, categoryProhibited)
		return false
	}
	switch req.Type {
	case operation.Compute:
		if d.State != hypervisor.StateShutoff {
			h.reject(w, categoryConflict) // compute changes apply to a Stopped VM only
			return false
		}
		if h.deps.Hosts != nil {
			info, herr := h.deps.Hosts.Host(r.Context())
			if herr != nil {
				h.reject(w, categoryUnavailable)
				return false
			}
			o := provision.Choices(info.CPUCount, int(info.MemoryMiB))
			if !contains(o.VCPUs, req.Params.VCPUs) || !contains(o.MemoryMiB, req.Params.MemoryMiB) {
				h.reject(w, categoryValidation) // outside the sizes this host offers
				return false
			}
		}
		return true
	}
	idx, ok := h.networkIndex(r.Context())
	if !ok {
		h.reject(w, categoryUnavailable)
		return false
	}
	n, found := idx[d.Network]
	if !found || !n.Managed {
		h.reject(w, categoryProhibited) // reservations exist only on a Svavyom-managed network
		return false
	}
	var mine *hypervisor.Reservation
	for i, x := range n.Reservations {
		if x.MAC == d.MAC {
			mine = &n.Reservations[i]
		}
	}
	if req.Type == operation.ReleaseIP {
		if mine == nil {
			h.reject(w, categoryConflict) // nothing to release
			return false
		}
		return true
	}
	ip, perr := netip.ParseAddr(req.Params.IPAddress)
	sp, serr := netip.ParsePrefix(n.Subnet)
	if perr != nil || serr != nil || !provision.UsableHost(sp, ip) {
		h.reject(w, categoryValidation)
		return false
	}
	for _, x := range n.Reservations {
		if x.IP == req.Params.IPAddress && x.MAC != d.MAC {
			h.reject(w, categoryConflict) // reserved for another VM
			return false
		}
	}
	if mine != nil && mine.IP != req.Params.IPAddress {
		h.reject(w, categoryConflict) // release the current reservation first
		return false
	}
	return true
}

// ---- what a VM reports about its network -------------------------------------------------------------------------------------------

type vmNetworkJSON struct {
	Name       string  `json:"name"`
	MAC        string  `json:"mac"`
	ReservedIP *string `json:"reserved_ip"`
	State      string  `json:"state"`
}

// vmNetwork describes the network of a managed VM: its name, MAC, static reservation (if any) and whether the network is active.
func vmNetwork(d hypervisor.Domain, nets map[string]hypervisor.Network, known bool) *vmNetworkJSON {
	if !d.Managed || d.Network == "" || d.MAC == "" {
		return nil
	}
	out := &vmNetworkJSON{Name: d.Network, MAC: d.MAC, State: "unknown"}
	if !known {
		return out
	}
	if n, ok := nets[d.Network]; ok {
		out.State = "inactive"
		if n.Active {
			out.State = "active"
		}
		for _, x := range n.Reservations {
			if x.MAC == d.MAC {
				ip := x.IP
				out.ReservedIP = &ip
			}
		}
	}
	return out
}

// netActions lists the M3 actions that apply to a managed VM.
func netActions(d hypervisor.Domain, nets map[string]hypervisor.Network, known bool) []string {
	out := []string{}
	if d.State == hypervisor.StateShutoff {
		out = append(out, string(operation.Compute))
	}
	if !known {
		return out
	}
	n, ok := nets[d.Network]
	if !ok || !n.Managed {
		return out
	}
	reserved := false
	for _, x := range n.Reservations {
		reserved = reserved || x.MAC == d.MAC
	}
	if reserved {
		out = append(out, string(operation.ReleaseIP))
	} else {
		out = append(out, string(operation.ReserveIP))
	}
	return out
}
