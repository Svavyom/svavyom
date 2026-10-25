package api

import (
	"context"
	"errors"
	"net/http"
	"regexp"
	"strings"
	"time"

	"example.invalid/dedicatedcloud/backend/internal/hypervisor"
	"example.invalid/dedicatedcloud/backend/internal/operation"
	"example.invalid/dedicatedcloud/backend/internal/provision"
)

// ---- what the storage operations need from the host side, as functions (the API links neither libvirt nor the mutation client) ------------------

// BackupInfo is one backup of the backup store as the API sees it.
type BackupInfo struct {
	ID        string
	VM        string
	CreatedAt string
	SizeBytes int64
	DiskGiB   int
	ImageID   string
	Valid     bool
}

// StorageStats are the pool and backup-store facts of the host summary.
type StorageStats struct {
	PoolCapacity, PoolAvailable, PoolAllocation int64
	BackupsKnown                                bool
	BackupBytes, BackupFree, BackupTotal        int64
	// Snapshots is available | unavailable | unknown (empty counts as unknown).
	Snapshots string
}

// ---- parameters of the storage and recovery operations (request side) ---------------------------------------------------------

type paramsBody struct {
	DiskGiB      *int    `json:"disk_gib"`
	ImageID      *string `json:"image_id"`
	SSHPublicKey *string `json:"ssh_public_key"`
	SnapshotID   *string `json:"snapshot_id"`
	NewName      *string `json:"new_name"`
	Subnet       *string `json:"subnet"`
	DHCPStart    *string `json:"dhcp_start"`
	DHCPEnd      *string `json:"dhcp_end"`
	Bridge       *string `json:"bridge"` // network_create: bridge mode on the host bridge (DR-024 D5)
	Autostart    *string `json:"autostart"`
	VCPUs        *int    `json:"vcpus"`
	MemoryMiB    *int    `json:"memory_mib"`
	IPAddress    *string `json:"ip_address"`
	VMID         *string `json:"vm_id"`
	TargetID     *string `json:"target_id"`
	Boot         *string `json:"boot"` // iso_attach (DR-026)
	// DR-024 D3: schedule_set.
	EveryHours           *int    `json:"every_hours"`
	At                   *string `json:"at"`
	KeepLocal            *int    `json:"keep_local"`
	KeepOffsite          *int    `json:"keep_offsite"`
	DowntimeAcknowledged *bool   `json:"downtime_acknowledged"`
}

// toParams maps the browser's typed object to the operation parameters. The type decides which fields are acceptable; operation.Request
// validation refuses any other combination.
func (b *paramsBody) toParams() operation.Params {
	var p operation.Params
	if b == nil {
		return p
	}
	if b.DiskGiB != nil {
		p.DiskGiB = *b.DiskGiB
	}
	if b.ImageID != nil {
		p.ImageID = *b.ImageID
	}
	if b.SSHPublicKey != nil {
		p.SSHPublicKey = *b.SSHPublicKey
	}
	if b.SnapshotID != nil {
		p.SnapshotID = *b.SnapshotID
	}
	if b.NewName != nil {
		p.NewName = *b.NewName
	}
	if b.Subnet != nil {
		p.Subnet = *b.Subnet
	}
	if b.DHCPStart != nil {
		p.DHCPStart = *b.DHCPStart
	}
	if b.DHCPEnd != nil {
		p.DHCPEnd = *b.DHCPEnd
	}
	if b.Bridge != nil {
		p.Bridge = *b.Bridge
	}
	if b.Autostart != nil {
		p.Autostart = *b.Autostart
	}
	if b.VCPUs != nil {
		p.VCPUs = *b.VCPUs
	}
	if b.MemoryMiB != nil {
		p.MemoryMiB = *b.MemoryMiB
	}
	if b.IPAddress != nil {
		p.IPAddress = *b.IPAddress
	}
	if b.VMID != nil {
		p.VMID = *b.VMID
	}
	if b.TargetID != nil {
		p.TargetID = *b.TargetID
	}
	if b.Boot != nil {
		p.Boot = *b.Boot
	}
	if b.EveryHours != nil {
		p.EveryHours = *b.EveryHours
	}
	if b.At != nil {
		p.At = *b.At
	}
	if b.KeepLocal != nil {
		p.KeepLocal = *b.KeepLocal
	}
	if b.KeepOffsite != nil {
		p.KeepOffsite = *b.KeepOffsite
	}
	if b.DowntimeAcknowledged != nil {
		p.DowntimeAck = *b.DowntimeAcknowledged
	}
	return p
}

// NewParamsPreparer returns the operation.Config.PrepareParams hook: a reinstall must name a REAL-HOST-QUALIFIED image (its digest is resolved from
// the catalog here), and any SSH key is normalised to the one-line form with no options and no comment. An error stores nothing.
func NewParamsPreparer(cat func() (*provision.Catalog, error)) func(operation.Type, string, *operation.Params) error {
	return func(t operation.Type, _ string, p *operation.Params) error {
		if p.SSHPublicKey != "" {
			k, err := provision.NormalizeSSHKey(p.SSHPublicKey)
			if err != nil {
				return err
			}
			p.SSHPublicKey = k.Authorized
		}
		if t == operation.EjectISO && p.ImageID != "" {
			c, err := cat()
			if err != nil {
				return err
			}
			im, ok := c.Get(p.ImageID) // any state: a medium whose image was disabled must still be removable
			if !ok || !im.IsISO() {
				return errors.New("image")
			}
			p.ImageSHA256 = im.SHA256
		}
		if t == operation.ISOAttach || t == operation.Rescue {
			c, err := cat()
			if err != nil {
				return err
			}
			im, err := c.Usable(p.ImageID)
			if err != nil || !im.IsISO() {
				return errors.New("image") // only installation media from the catalog
			}
			p.ImageSHA256 = im.SHA256
		}
		if t == operation.Reinstall {
			c, err := cat()
			if err != nil {
				return err
			}
			im, err := c.Usable(p.ImageID)
			if err != nil || im.State != provision.StateQualified {
				return errors.New("image")
			}
			p.ImageSHA256 = im.SHA256
		}
		return nil
	}
}

var snapshotRE = regexp.MustCompile(`^snap-[0-9a-f]{12}$`)

// storagePrechecks gives early, friendly answers for the M2 operations before anything is stored. The mutation helper re-proves ownership,
// state and every limit on the host; these are not the safety net.
func (h *Handler) storagePrechecks(w http.ResponseWriter, r *http.Request, b submitBody, req operation.Request) bool {
	cr := h.deps.Creation
	if b.Kind == operation.KindBackup {
		return h.backupPrechecks(w, r, req)
	}
	if h.deps.VMs == nil {
		h.reject(w, categoryUnavailable)
		return false
	}
	d, err := h.deps.VMs.Lookup(r.Context(), b.ID)
	switch hypervisor.CategoryOf(err) {
	case "":
	case hypervisor.NotFound:
		h.reject(w, categoryNotFound)
		return false
	default:
		h.reject(w, categoryUnavailable)
		return false
	}
	switch {
	case !d.Managed:
		h.reject(w, categoryProhibited)
		return false
	case d.State != hypervisor.StateShutoff:
		h.reject(w, categoryConflict) // every storage operation needs a Stopped VM
		return false
	}
	owned := 0
	for _, s := range d.Snapshots {
		if snapshotRE.MatchString(s.ID) {
			owned++
		}
	}
	switch req.Type {
	case operation.Resize:
		cur := int(d.DiskBytes >> 30)
		switch {
		case owned > 0:
			h.reject(w, categoryConflict)
			return false
		case d.DiskBytes <= 0 || req.Params.DiskGiB <= cur:
			h.reject(w, categoryValidation) // grow only; also refuses "no change"
			return false
		case cr.Stats != nil:
			ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
			defer cancel()
			if st, err := cr.Stats(ctx); err == nil && st.PoolAvailable > 0 && int64(req.Params.DiskGiB-cur)<<30+(256<<20) > st.PoolAvailable {
				h.reject(w, categoryConflict) // the pool cannot take the growth
				return false
			}
		}
	case operation.EjectISO:
		if (d.ISOSHA256 == "" && len(d.ISOSHA256s) == 0) || d.RescueSHA256 != "" {
			h.reject(w, categoryConflict) // there is no installation media to eject, or the VM is in rescue mode (leave it with unrescue)
			return false
		}
		if id := req.Params.ImageID; id != "" {
			attached, isISO := false, false
			ids := h.isoImages()
			for _, name := range ids {
				isISO = isISO || name == id
			}
			for _, sha := range d.ISOSHA256s {
				attached = attached || ids[sha] == id
			}
			if !isISO {
				h.reject(w, categoryValidation) // not an installation medium of this catalog
				return false
			}
			if !attached {
				h.reject(w, categoryConflict) // the named medium is not attached (a repeated eject that already worked is the operation manager's, not this check's)
				return false
			}
		} else if len(d.ISOSHA256s) > 1 {
			h.reject(w, categoryValidation) // two media are attached: say which one to remove (DR-031)
			return false
		}
	case operation.GraphicsEnable:
		if d.Graphics {
			h.reject(w, categoryConflict) // already has the console
			return false
		}
	case operation.ISOAttach:
		if d.ISOSHA256 != "" || d.RescueSHA256 != "" {
			h.reject(w, categoryConflict) // media is attached already (eject it first), or the VM is in rescue mode
			return false
		}
	case operation.Rescue:
		if d.ISOSHA256 != "" || d.RescueSHA256 != "" || !d.Graphics {
			h.reject(w, categoryConflict) // needs the graphical console, no media attached and no rescue in progress
			return false
		}
	case operation.Unrescue:
		if d.RescueSHA256 == "" {
			h.reject(w, categoryConflict)
			return false
		}
	case operation.Reinstall, operation.Backup:
		if owned > 0 || d.RescueSHA256 != "" || (req.Type == operation.Reinstall && len(d.DataVolumes) > 0) || d.Media == "iso" {
			h.reject(w, categoryConflict)
			return false
		}
		if req.Type == operation.Backup && !h.backupsConfigured(r.Context()) {
			h.reject(w, categoryProhibited)
			return false
		}
	case operation.Snapshot:
		if owned >= provision.MaxSnapshots {
			h.reject(w, categoryConflict)
			return false
		}
	case operation.RestoreSnapshot, operation.DeleteSnapshot:
		found := false
		for _, s := range d.Snapshots {
			found = found || s.ID == req.Params.SnapshotID
		}
		if !found {
			h.reject(w, categoryNotFound)
			return false
		}
	}
	return true
}

func (h *Handler) backupsConfigured(ctx context.Context) bool {
	cr := h.deps.Creation
	if cr == nil || cr.Stats == nil {
		return false
	}
	cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	st, err := cr.Stats(cctx)
	return err == nil && st.BackupsKnown
}

// backupPrechecks covers the operations whose resource is a backup: restore (creates a new VM) and delete.
func (h *Handler) backupPrechecks(w http.ResponseWriter, r *http.Request, req operation.Request) bool {
	cr := h.deps.Creation
	if cr.ListBackups == nil || h.deps.VMs == nil {
		h.reject(w, categoryUnavailable)
		return false
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	list, err := cr.ListBackups(ctx)
	if err != nil {
		h.reject(w, categoryUnavailable)
		return false
	}
	var found *BackupInfo
	for i := range list {
		if list[i].ID == req.ResourceID {
			found = &list[i]
		}
	}
	if found == nil {
		h.reject(w, categoryNotFound)
		return false
	}
	if req.Type == operation.BackupExport {
		if !found.Valid {
			h.reject(w, categoryConflict) // a damaged backup is never exported
			return false
		}
		ts, err := h.targetsOrNil(ctx)
		if err != nil {
			h.reject(w, categoryUnavailable)
			return false
		}
		for _, t := range ts {
			if t.ID == req.Params.TargetID {
				if t.State != "ready" {
					h.reject(w, categoryUnavailable)
					return false
				}
				return true
			}
		}
		h.reject(w, categoryNotFound) // not one of the targets the operator declared
		return false
	}
	if req.Type == operation.Restore {
		if !found.Valid {
			h.reject(w, categoryConflict) // a damaged backup is never restored
			return false
		}
		_, err := h.deps.VMs.Lookup(r.Context(), req.Params.NewName)
		switch hypervisor.CategoryOf(err) {
		case hypervisor.NotFound:
		case "":
			h.reject(w, categoryConflict) // the name is taken
			return false
		default:
			h.reject(w, categoryUnavailable)
			return false
		}
	}
	return true
}

// ---- storage facts of the host summary -------------------------------------------------------------------------------------------

type storageJSON struct {
	State             string `json:"state"` // available | unavailable | unknown
	PoolTotalGiB      *int   `json:"pool_total_gib"`
	PoolFreeGiB       *int   `json:"pool_free_gib"`
	ImagesGiB         *int   `json:"images_gib"`
	BackupsConfigured bool   `json:"backups_configured"`
	BackupsGiB        *int   `json:"backups_gib"`
	BackupsFreeGiB    *int   `json:"backups_free_gib"`
	AllocationNote    string `json:"allocation_note"`
	// BackupTargets are the off-host targets the operator declared and whether each can be used now (DR-023 D4): never a host, a path or a key.
	BackupTargets []backupTargetJSON `json:"backup_targets"`
	Snapshots     string             `json:"snapshots"` // available | unavailable | unknown: whether the pool can hold Svavyom's internal snapshots (DR-023 D6)
}

type backupTargetJSON struct {
	ID    string `json:"id"`
	Kind  string `json:"kind"`  // ssh | path
	State string `json:"state"` // ready | unavailable
}

// offsiteView reads the off-host service: whether an export can be offered now (some target is ready) and which targets hold a copy of which backup.
// A service that does not answer offers nothing and shows no copies; it never fails the page.
func (h *Handler) offsiteView(ctx context.Context) (canExport bool, copies map[string][]string) {
	cr := h.deps.Creation
	if cr == nil || cr.Targets == nil {
		return false, map[string][]string{}
	}
	cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	ts, err := cr.Targets(cctx)
	if err != nil {
		return false, map[string][]string{}
	}
	for _, t := range ts {
		canExport = canExport || t.State == "ready"
	}
	copies = map[string][]string{}
	if cr.Copies != nil {
		if m, err := cr.Copies(cctx); err == nil {
			copies = m
		}
	}
	return canExport, copies
}

func (h *Handler) targetsOrNil(ctx context.Context) ([]TargetInfo, error) {
	if h.deps.Creation == nil || h.deps.Creation.Targets == nil {
		return nil, nil
	}
	return h.deps.Creation.Targets(ctx)
}

func gib(n int64) *int {
	v := int((n + (1 << 30) - 1) >> 30) // round up: never show less than is used
	return &v
}

func gibFloor(n int64) *int {
	v := int(n >> 30) // round down: never show more than is free
	return &v
}

// storageFor describes the pool and the backup store. Thin allocation means a volume's virtual size is not the space it occupies, so the summary
// says exactly what is measured: the pool's own capacity/free figures, the catalog's image sizes and the backup copies' sizes.
func (h *Handler) storageFor(ctx context.Context) storageJSON {
	s := storageJSON{State: "unknown", Snapshots: "unknown", BackupTargets: []backupTargetJSON{}, AllocationNote: "Disk sizes shown for a VM are virtual sizes. Real usage is lower while the disk is thinly allocated; the pool free figure is what counts."}
	cr := h.deps.Creation
	if cr == nil || !cr.Enabled || cr.Stats == nil {
		return s
	}
	cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	st, err := cr.Stats(cctx)
	if err != nil {
		s.State = "unavailable"
		return s
	}
	s.State = "available"
	s.Snapshots = snapshotState(st.Snapshots)
	s.PoolTotalGiB, s.PoolFreeGiB = gib(st.PoolCapacity), gibFloor(st.PoolAvailable)
	if ims, err := h.usableImages(); err == nil {
		var total int64
		for _, im := range ims {
			total += im.SizeBytes
		}
		s.ImagesGiB = gib(total)
	}
	if st.BackupsKnown {
		s.BackupsConfigured = true
		s.BackupsGiB, s.BackupsFreeGiB = gib(st.BackupBytes), gibFloor(st.BackupFree)
	}
	if cr.Targets != nil {
		if ts, err := cr.Targets(cctx); err == nil {
			for _, t := range ts {
				s.BackupTargets = append(s.BackupTargets, backupTargetJSON(t))
			}
		}
	}
	return s
}

// ---- volumes and backups as resources ----------------------------------------------------------------------------------------------

type volumeJSON struct {
	ID         string        `json:"id"`
	ProjectID  string        `json:"project_id"`
	Generation int           `json:"generation"`
	Name       string        `json:"name"`
	Desired    volumeDesired `json:"desired"`
	Observed   volumeState   `json:"observed"`
	Allowed    []string      `json:"allowed_actions"`
}

type volumeDesired struct {
	SizeGiB    int     `json:"size_gib"`
	AttachedTo *string `json:"attached_to"`
}

type volumeState struct {
	State string `json:"state"`
}

// volumeID is the id of a VM's root volume: the volume of a Svavyom VM has no life of its own, so it is named for the VM.
func volumeID(vm string) string { return vm + "-root" }

func toVolume(d hypervisor.Domain) (volumeJSON, bool) {
	if !d.Managed || d.DiskBytes <= 0 {
		return volumeJSON{}, false
	}
	vm := d.Name
	return volumeJSON{ID: volumeID(vm), ProjectID: defaultProject, Generation: 1, Name: vm + " root disk", Allowed: []string{},
		Desired: volumeDesired{SizeGiB: int(d.DiskBytes >> 30), AttachedTo: &vm}, Observed: volumeState{State: "attached"}}, true
}

func (h *Handler) requireStorageSession(w http.ResponseWriter, r *http.Request) bool {
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

type backupJSON struct {
	ID         string        `json:"id"`
	ProjectID  string        `json:"project_id"`
	Generation int           `json:"generation"`
	Name       string        `json:"name"`
	Desired    backupDesired `json:"desired"`
	Observed   backupState   `json:"observed"`
	Allowed    []string      `json:"allowed_actions"`
}

type backupDesired struct {
	SourceVolumeID string `json:"source_volume_id"`
}

type backupState struct {
	State string `json:"state"` // complete | failed (damaged); a backup that is still being written is not visible
	// Copies are the ids of the off-host targets that hold a verified copy (DR-023 D4).
	Copies []string `json:"copies"`
}

func toBackup(b BackupInfo, actions, canExport bool, copies []string) backupJSON {
	st, allowed := "failed", []string{}
	if b.Valid {
		st = "complete"
	}
	if actions {
		allowed = []string{"restore", "delete"}
		if canExport && b.Valid {
			allowed = append(allowed, "export")
		}
	}
	if copies == nil {
		copies = []string{}
	}
	name := b.VM + " " + b.CreatedAt
	if !b.Valid {
		name = b.ID
	}
	if len(name) > 63 {
		name = name[:63]
	}
	src := volumeID(b.VM)
	if !vmIDRE.MatchString(src) {
		src = "unknown-root"
	}
	return backupJSON{ID: b.ID, ProjectID: defaultProject, Generation: 1, Name: name, Allowed: allowed,
		Desired: backupDesired{SourceVolumeID: src}, Observed: backupState{State: st, Copies: copies}}
}

func (h *Handler) requireBackupSession(w http.ResponseWriter, r *http.Request) bool {
	if h.deps.Auth == nil || h.deps.Creation == nil || h.deps.Creation.ListBackups == nil {
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

func (h *Handler) listBackups(w http.ResponseWriter, r *http.Request) {
	if !h.requireBackupSession(w, r) {
		return
	}
	for k, v := range r.URL.Query() {
		if len(v) != 1 || (k != "limit" && k != "cursor") || (k == "limit" && !limitRE.MatchString(v[0])) || k == "cursor" {
			h.reject(w, categoryValidation)
			return
		}
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	list, err := h.deps.Creation.ListBackups(ctx)
	if err != nil {
		h.reject(w, categoryUnavailable)
		return
	}
	items := []backupJSON{}
	role := h.roleOf(r)
	canExport, copies := h.offsiteView(ctx)
	for _, b := range list {
		bj := toBackup(b, h.deps.Creation.Enabled, canExport, copies[b.ID])
		bj.Allowed = restrict(role, "Backup", bj.Allowed)
		items = append(items, bj)
	}
	writeJSON(w, http.StatusOK, struct {
		Items   []backupJSON `json:"items"`
		Allowed []string     `json:"allowed_actions"`
		Next    *string      `json:"next_cursor"`
	}{Items: items, Allowed: []string{}})
}

func (h *Handler) readBackup(w http.ResponseWriter, r *http.Request) {
	if !h.requireBackupSession(w, r) {
		return
	}
	if len(r.URL.Query()) != 0 {
		h.reject(w, categoryValidation)
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/api/v1/backups/")
	if !vmIDRE.MatchString(id) {
		h.reject(w, categoryValidation)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	list, err := h.deps.Creation.ListBackups(ctx)
	if err != nil {
		h.reject(w, categoryUnavailable)
		return
	}
	for _, b := range list {
		if b.ID == id {
			canExport, copies := h.offsiteView(ctx)
			bj := toBackup(b, h.deps.Creation.Enabled, canExport, copies[b.ID])
			bj.Allowed = restrict(h.roleOf(r), "Backup", bj.Allowed)
			writeJSON(w, http.StatusOK, bj)
			return
		}
	}
	h.reject(w, categoryNotFound)
}

func snapshotState(v string) string {
	switch v {
	case "available", "unavailable":
		return v
	}
	return "unknown"
}

// snapshotsAvailable reports whether the snapshot actions may be offered: only when the host proved the pool can hold internal snapshots.
// The answer is cached for a short time so a list of VMs does not ask the helper once per request.
func (h *Handler) snapshotsAvailable(ctx context.Context) bool {
	cr := h.deps.Creation
	if cr == nil || !cr.Enabled || cr.Stats == nil {
		return false
	}
	h.snapMu.Lock()
	defer h.snapMu.Unlock()
	if !h.snapAt.IsZero() && h.now().Sub(h.snapAt) < 30*time.Second {
		return h.snapOK
	}
	cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	st, err := cr.Stats(cctx)
	h.snapOK = err == nil && snapshotState(st.Snapshots) == "available"
	h.snapAt = h.now()
	return h.snapOK
}
