package api

import (
	"context"
	"encoding/base64"
	"net/http"
	"regexp"
	"strconv"
	"time"

	"example.invalid/dedicatedcloud/backend/internal/auth"
	"example.invalid/dedicatedcloud/backend/internal/hypervisor"
	"example.invalid/dedicatedcloud/backend/internal/metrics"
	"example.invalid/dedicatedcloud/backend/internal/schedule"
)

// defaultProject is the single approved project of this phase (the VM schema requires a project id).
const defaultProject = "default"

// vmJSON is the VM schema. It is built only from the agent's approved fields (name, observed power), so nothing else
// can leave the process: no XML, no paths, no host details.
type vmJSON struct {
	ID         string     `json:"id"`
	ProjectID  string     `json:"project_id"`
	Generation int        `json:"generation"`
	Name       string     `json:"name"`
	Desired    vmDesired  `json:"desired"`
	Observed   vmObserved `json:"observed"`
	Allowed    []string   `json:"allowed_actions"`
}

type vmDesired struct {
	Power string `json:"power"`
	// BackupSchedule is the maintenance-window backup schedule of the VM, or null (DR-024 D3).
	BackupSchedule *backupScheduleJSON `json:"backup_schedule"`
}

type backupScheduleJSON struct {
	EveryHours           *int    `json:"every_hours"`
	At                   *string `json:"at"`
	KeepLocal            int     `json:"keep_local"`
	KeepOffsite          int     `json:"keep_offsite"`
	TargetID             *string `json:"target_id"`
	DowntimeAcknowledged bool    `json:"downtime_acknowledged"`
}

type vmBackupJSON struct {
	NextRunAt *string         `json:"next_run_at"`
	LastRun   *lastBackupJSON `json:"last_run"`
}

type lastBackupJSON struct {
	At     string `json:"at"`
	Result string `json:"result"`
}

type vmObserved struct {
	Power      string  `json:"power"`
	LastSeenAt string  `json:"last_seen_at"`
	Managed    bool    `json:"managed"`
	IPAddress  *string `json:"ip_address"`
	LoginUser  *string `json:"login_user"`
	// ISO is the id of the installation medium that boots next, else the first attached (DR-031); null when none, or when the catalog no longer names it.
	ISO *string `json:"iso"`
	// GuestProfile is "windows" for a VM created with the Windows profile, else "linux" (DR-032).
	GuestProfile string `json:"guest_profile"`
	// ISOs is the id of every installation medium attached, in guest target order, at most two (DR-031); a medium the catalog no longer names is left out. Never null.
	ISOs []string `json:"isos"`
	// DiskGiB is the root disk's virtual size (null for a VM Svavyom does not manage); Snapshots are the VM's own (M2).
	DiskGiB   *int           `json:"disk_gib"`
	Snapshots []snapshotJSON `json:"snapshots"`
	// Network is the VM's network, MAC, static reservation and the network's state (null for a VM Svavyom does not manage).
	Network *vmNetworkJSON `json:"network"`
	// VCPUs and MemoryMiB are the configured size from the stored definition; Usage is the sampled CPU use (DR-022).
	VCPUs     *int        `json:"vcpus"`
	MemoryMiB *int        `json:"memory_mib"`
	Usage     vmUsageJSON `json:"usage"`
	// Backup is the scheduled backup: when the next window is and how the last one ended.
	Backup vmBackupJSON `json:"backup"`
	// GraphicalConsole is "present" when the VM has the VNC console device and "absent" when it does not (DR-026); Rescue is true while it is in rescue mode.
	GraphicalConsole string `json:"graphical_console"`
	Rescue           bool   `json:"rescue"`
}

type vmUsageJSON struct {
	State         string        `json:"state"`
	CPUPercent    *int          `json:"cpu_percent"`
	MemoryUsedMiB *int64        `json:"memory_used_mib"`
	DiskKiBs      *int64        `json:"disk_kib_s"`
	NetKiBs       *int64        `json:"net_kib_s"`
	History       []vmPointJSON `json:"history"`
}

type vmPointJSON struct {
	At            string `json:"at"`
	CPUPercent    int    `json:"cpu_percent"`
	MemoryUsedMiB int64  `json:"memory_used_mib"`
	DiskKiBs      int64  `json:"disk_kib_s"`
	NetKiBs       int64  `json:"net_kib_s"`
}

func toVMUsage(u metrics.VMUsage, ok bool) vmUsageJSON {
	out := vmUsageJSON{State: "unavailable", History: []vmPointJSON{}}
	if !ok {
		return out
	}
	if u.Available {
		out.State, out.CPUPercent, out.MemoryUsedMiB, out.DiskKiBs, out.NetKiBs = "available", u.CPUPercent, u.MemUsedMiB, u.DiskKiBs, u.NetKiBs
	}
	for _, p := range u.History {
		out.History = append(out.History, vmPointJSON{At: p.At.UTC().Format(time.RFC3339), CPUPercent: p.CPUPercent, MemoryUsedMiB: p.MemUsedMiB, DiskKiBs: p.DiskKiBs, NetKiBs: p.NetKiBs})
	}
	return out
}

type snapshotJSON struct {
	ID        string `json:"id"`
	CreatedAt string `json:"created_at"`
}

// toVMJSON maps an observed domain. There is no desired-state store yet, so the desired power mirrors the observation
// (running -> running, anything else -> stopped); allowed_actions is empty unless the VM is managed and the mutation switch is on.
func (h *Handler) toVM(d hypervisor.Domain, seen time.Time, logins map[string]string, nets map[string]hypervisor.Network, netsKnown bool, usage map[string]metrics.VMUsage, vc viewCtx) vmJSON {
	v := toVMJSON(d, seen)
	if d.VCPUs > 0 {
		c := d.VCPUs
		v.Observed.VCPUs = &c
	}
	if d.MemoryMiB > 0 {
		m := d.MemoryMiB
		v.Observed.MemoryMiB = &m
	}
	u, ok := usage[d.Name]
	v.Observed.Usage = toVMUsage(u, ok)
	v.Observed.Managed = d.Managed
	v.Observed.GraphicalConsole = "absent"
	if d.Managed && d.Graphics {
		v.Observed.GraphicalConsole = "present"
	}
	v.Observed.Rescue = d.Managed && d.RescueSHA256 != ""
	if d.IPv4 != "" && d.State == hypervisor.StateRunning {
		ip := d.IPv4
		v.Observed.IPAddress = &ip
	}
	if u, ok := logins[d.ImageID]; ok && d.Managed && u != "" {
		v.Observed.LoginUser = &u
	}
	if id, ok := vc.isos[d.ISOSHA256]; ok && d.ISOSHA256 != "" {
		v.Observed.ISO = &id
	}
	if d.Managed && d.Profile == "windows" {
		v.Observed.GuestProfile = "windows"
	}
	if d.Managed {
		for _, sha := range d.ISOSHA256s {
			if id, ok := vc.isos[sha]; ok {
				v.Observed.ISOs = append(v.Observed.ISOs, id)
			}
		}
	}
	if d.Managed && d.DiskBytes > 0 {
		g := int(d.DiskBytes >> 30)
		v.Observed.DiskGiB = &g
	}
	v.Observed.Snapshots = []snapshotJSON{}
	for _, sn := range d.Snapshots {
		v.Observed.Snapshots = append(v.Observed.Snapshots, snapshotJSON{ID: sn.ID, CreatedAt: time.Unix(sn.Created, 0).UTC().Format(time.RFC3339)})
	}
	// Lifecycle actions are offered for a Svavyom-managed VM while the Development Preview mutation switch is on.
	if h.deps.Creation != nil && h.deps.Creation.Enabled && d.Managed {
		v.Allowed = restrict(vc.role, "VM", withoutSnapshot(allowedActions(d, nets, netsKnown), vc.snapshots))
	}
	v.Observed.Network = vmNetwork(d, nets, netsKnown)
	if sc, ok := vc.scheds[d.Name]; ok && d.Managed {
		v.Desired.BackupSchedule, v.Observed.Backup = toScheduleJSON(sc)
	}
	if h.scheduleActionsOn() && d.Managed && vc.role.AtLeast(auth.RoleOperator) {
		v.Allowed = append(v.Allowed, "set_schedule")
		if _, ok := vc.scheds[d.Name]; ok {
			v.Allowed = append(v.Allowed, "clear_schedule")
		}
	}
	return v
}

func (h *Handler) vmUsage(ctx context.Context) map[string]metrics.VMUsage {
	if h.deps.Usage == nil {
		return nil
	}
	return h.deps.Usage.VMs(ctx)
}

// logins maps catalog image ids to their default login user (empty when no catalog is configured).
func (h *Handler) logins() map[string]string {
	m := map[string]string{}
	if h.deps.Creation != nil && h.deps.Creation.Catalog != nil {
		if c, err := h.deps.Creation.Catalog(); err == nil {
			for _, im := range c.Images {
				m[im.ID] = im.LoginUser
			}
		}
	}
	return m
}

func toVMJSON(d hypervisor.Domain, seen time.Time) vmJSON {
	desired := "stopped"
	if d.State == hypervisor.StateRunning {
		desired = "running"
	}
	power := string(d.State)
	switch d.State {
	case hypervisor.StateShutoff:
		power = "stopped"
	case hypervisor.StateRunning, hypervisor.StatePaused, hypervisor.StateCrashed:
	default:
		power = "unknown"
	}
	return vmJSON{ID: d.Name, ProjectID: defaultProject, Generation: 1, Name: d.Name,
		Desired: vmDesired{Power: desired}, Observed: vmObserved{Power: power, LastSeenAt: seen.UTC().Format(time.RFC3339), Snapshots: []snapshotJSON{}, ISOs: []string{}, GuestProfile: "linux"},
		Allowed: []string{}}
}

var cursorRE = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)
var vmIDRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$`)

const defaultPageSize = 50

func (h *Handler) now() time.Time {
	if h.deps.Now != nil {
		return h.deps.Now()
	}
	return time.Now()
}

// vmError maps a hypervisor error category to the typed API error. Nothing from the error text is used.
func (h *Handler) vmError(w http.ResponseWriter, err error) {
	switch hypervisor.CategoryOf(err) {
	case hypervisor.NotFound:
		h.reject(w, categoryNotFound)
	case hypervisor.Unavailable, hypervisor.Timeout:
		h.reject(w, categoryUnavailable)
	default:
		h.reject(w, categoryInternal)
	}
}

func (h *Handler) requireVMSession(w http.ResponseWriter, r *http.Request) bool {
	if h.deps.Auth == nil || h.deps.VMs == nil {
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

func (h *Handler) listVMs(w http.ResponseWriter, r *http.Request) {
	if !h.requireVMSession(w, r) {
		return
	}
	limit, after := defaultPageSize, ""
	for k, v := range r.URL.Query() {
		if len(v) != 1 {
			h.reject(w, categoryValidation)
			return
		}
		switch k {
		case "limit":
			if !limitRE.MatchString(v[0]) {
				h.reject(w, categoryValidation)
				return
			}
			limit, _ = strconv.Atoi(v[0])
		case "cursor":
			raw, err := base64.RawURLEncoding.DecodeString(v[0])
			if !cursorRE.MatchString(v[0]) || err != nil || !vmIDRE.MatchString(string(raw)) {
				h.reject(w, categoryValidation)
				return
			}
			after = string(raw)
		default:
			h.reject(w, categoryValidation)
			return
		}
	}
	list, err := h.deps.VMs.List(r.Context())
	if err != nil {
		h.vmError(w, err)
		return
	}
	seen := h.now()
	logins := h.logins()
	nets, netsKnown := h.networkIndex(r.Context())
	usage := h.vmUsage(r.Context())
	vc := h.viewCtx(r)
	items := make([]vmJSON, 0, limit)
	var next *string
	for _, d := range list { // the agent returns names sorted ascending
		if after != "" && d.Name <= after {
			continue
		}
		if len(items) == limit {
			c := base64.RawURLEncoding.EncodeToString([]byte(items[len(items)-1].ID))
			next = &c
			break
		}
		items = append(items, h.toVM(d, seen, logins, nets, netsKnown, usage, vc))
	}
	writeJSON(w, http.StatusOK, struct {
		Items   []vmJSON `json:"items"`
		Allowed []string `json:"allowed_actions"`
		Next    *string  `json:"next_cursor"`
	}{Items: items, Allowed: []string{}, Next: next})
}

func (h *Handler) readVM(w http.ResponseWriter, r *http.Request) {
	if !h.requireVMSession(w, r) {
		return
	}
	if len(r.URL.Query()) != 0 {
		h.reject(w, categoryValidation)
		return
	}
	id := r.URL.Path[len("/api/v1/vms/"):]
	if !vmIDRE.MatchString(id) {
		h.reject(w, categoryValidation)
		return
	}
	d, err := h.deps.VMs.Lookup(r.Context(), id)
	if err != nil {
		h.vmError(w, err)
		return
	}
	nets, netsKnown := h.networkIndex(r.Context())
	writeJSON(w, http.StatusOK, h.toVM(d, h.now(), h.logins(), nets, netsKnown, h.vmUsage(r.Context()), h.viewCtx(r)))
}

// viewCtx is what differs per caller when a VM is rendered: the caller's role, and whether the host can hold snapshots at all.
type viewCtx struct {
	role      auth.Role
	snapshots bool
	isos      map[string]string // installation media digest -> catalog image id
	scheds    map[string]schedule.Schedule
}

func (h *Handler) viewCtx(r *http.Request) viewCtx {
	return viewCtx{role: h.roleOf(r), snapshots: h.snapshotsAvailable(r.Context()), isos: h.isoImages(), scheds: h.schedules(r.Context())}
}

// ScheduleSource is the schedule store as the API sees it (read only; changes are the operations schedule_set and schedule_clear).
type ScheduleSource interface {
	All(ctx context.Context) ([]schedule.Schedule, error)
}

func (h *Handler) schedules(ctx context.Context) map[string]schedule.Schedule {
	m := map[string]schedule.Schedule{}
	if h.deps.Schedules == nil {
		return m
	}
	if all, err := h.deps.Schedules.All(ctx); err == nil {
		for _, sc := range all {
			m[sc.VM] = sc
		}
	}
	return m
}

// scheduleActionsOn is true when a person may be offered the schedule actions: the mutation switch is on and a scheduler exists.
func (h *Handler) scheduleActionsOn() bool {
	return h.deps.Schedules != nil && h.deps.Creation != nil && h.deps.Creation.Enabled
}

func toScheduleJSON(sc schedule.Schedule) (*backupScheduleJSON, vmBackupJSON) {
	d := &backupScheduleJSON{KeepLocal: sc.Spec.KeepLocal, KeepOffsite: sc.Spec.KeepOffsite, DowntimeAcknowledged: true}
	if sc.Spec.EveryHours > 0 {
		h := sc.Spec.EveryHours
		d.EveryHours = &h
	}
	if sc.Spec.At != "" {
		a := sc.Spec.At
		d.At = &a
	}
	if sc.Spec.TargetID != "" {
		t := sc.Spec.TargetID
		d.TargetID = &t
	}
	var o vmBackupJSON
	if !sc.NextRun.IsZero() {
		n := sc.NextRun.UTC().Format(time.RFC3339)
		o.NextRunAt = &n
	}
	if sc.LastResult != "" && !sc.LastAt.IsZero() {
		o.LastRun = &lastBackupJSON{At: sc.LastAt.UTC().Format(time.RFC3339), Result: sc.LastResult}
	}
	return d, o
}

// isoImages maps the digest of each registered installation media to its image id.
func (h *Handler) isoImages() map[string]string {
	m := map[string]string{}
	if h.deps.Creation != nil && h.deps.Creation.Catalog != nil {
		if c, err := h.deps.Creation.Catalog(); err == nil {
			for _, im := range c.Images {
				if im.IsISO() {
					m[im.SHA256] = im.ID
				}
			}
		}
	}
	return m
}

// withoutSnapshot drops the snapshot action when the host has not shown that its pool can hold internal snapshots (DR-023 D6).
func withoutSnapshot(allowed []string, snapshots bool) []string {
	if snapshots {
		return allowed
	}
	out := make([]string, 0, len(allowed))
	for _, a := range allowed {
		if a != "snapshot" {
			out = append(out, a)
		}
	}
	return out
}
