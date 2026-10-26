package api

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"time"

	"example.invalid/dedicatedcloud/backend/internal/auth"
	"example.invalid/dedicatedcloud/backend/internal/hostinfo"
	"example.invalid/dedicatedcloud/backend/internal/hypervisor"
	"example.invalid/dedicatedcloud/backend/internal/operation"
	"example.invalid/dedicatedcloud/backend/internal/provision"
)

// Creation is the server-owned wiring of VM creation (DR-016). Everything in it comes from the operator's configuration; nothing
// is chosen by a browser.
type Creation struct {
	// Enabled is the Development Preview mutation switch. False (the default of an unqualified installation) refuses every
	// create and start with a typed `prohibited`.
	Enabled bool
	// Ops is the reviewed operation manager; Notify wakes its worker after a submission.
	Ops    *operation.Manager
	Notify func()
	// Catalog loads the operator-registered images. Preflight asks the mutation agent whether the network and pool are ready.
	Catalog   func() (*provision.Catalog, error)
	Preflight func(ctx context.Context) (provision.Readiness, error)
	// Network is the configured default network new VMs attach to unless the create names a Svavyom-managed one.
	Network string
	// HostPrefixes returns the host's own IPv4 subnets and routes (read in the API's network namespace, which is the host's). A network create is
	// refused when it is nil or fails: the confined mutation helper cannot see them, so the API is the one that must.
	HostPrefixes func() ([]netip.Prefix, error)
	// RequireKVM is true for a production (kvm) provisioning profile: a host that reports no virtualization then cannot create.
	RequireKVM bool
	// ListBackups and Stats read the backup store and the pool through the mutation supervisor (M2). Nil leaves the storage views empty/closed.
	ListBackups func(ctx context.Context) ([]BackupInfo, error)
	Stats       func(ctx context.Context) (StorageStats, error)
	// Targets and Copies read the off-host backup service (DR-023 D4): the declared targets with their state, and which targets hold a verified copy
	// of which backup. Nil means no off-host target is configured.
	Targets func(ctx context.Context) ([]TargetInfo, error)
	Copies  func(ctx context.Context) (map[string][]string, error)
}

// TargetInfo is a declared off-host backup target as the API may show it: an id, a kind and whether it can be used now.
type TargetInfo struct{ ID, Kind, State string }

// adminAuthorizer is the real single-administrator authorizer of this phase: deny by default, one project, the VM lifecycle types.
// The identity it sees is the signed-in administrator's name, put there by the session layer, never by the request body.
type adminAuthorizer struct{}

func (adminAuthorizer) Authorize(a operation.Actor, project string, t operation.Type) error {
	if a.ID != "" && project == defaultProject && lifecycleType(t) {
		return nil
	}
	return &operation.Error{Category: operation.CatForbidden}
}

// lifecycleType is the closed set of VM operation types the browser may submit.
func lifecycleType(t operation.Type) bool {
	switch t {
	case operation.Create, operation.Start, operation.Stop, operation.Reboot, operation.ForceOff, operation.Delete,
		operation.Resize, operation.Reinstall, operation.Snapshot, operation.RestoreSnapshot, operation.DeleteSnapshot, operation.Backup, operation.Restore, operation.BackupExport,
		operation.NetworkCreate, operation.NetworkStart, operation.NetworkStop, operation.NetworkAutostart, operation.NetworkDelete,
		operation.Compute, operation.ReserveIP, operation.ReleaseIP, operation.EjectISO, operation.VolumeCreate, operation.VolumeAttach, operation.VolumeDetach, operation.VolumeDelete,
		operation.AlertAcknowledge, operation.ScheduleSet, operation.ScheduleClear, operation.GraphicsEnable, operation.ISOAttach, operation.Rescue, operation.Unrescue:
		return true
	}
	return false
}

// storageType is the subset of lifecycleType added by M2.
func storageType(t operation.Type) bool {
	switch t {
	case operation.Resize, operation.Reinstall, operation.Snapshot, operation.RestoreSnapshot, operation.DeleteSnapshot, operation.Backup, operation.Restore, operation.EjectISO, operation.GraphicsEnable, operation.ISOAttach, operation.Rescue, operation.Unrescue:
		return true
	}
	return false
}

// Authorizer returns the authorizer to build the operation manager with.
func Authorizer() operation.Authorizer { return adminAuthorizer{} }

// NewCreatePreparer returns the operation.Config.PrepareCreate hook: it validates a create against the catalog and the host's
// capacity choices, normalises the SSH key, and fills the server-resolved fields. A returned error stores nothing.
func NewCreatePreparer(cat func() (*provision.Catalog, error), network string, capacity func() (cpus, memMiB int)) func(string, *operation.CreateSpec) error {
	return func(name string, s *operation.CreateSpec) error {
		if !provision.VMNameRE.MatchString(name) {
			return errors.New("name")
		}
		c, err := cat()
		if err != nil {
			return err
		}
		im, err := c.Usable(s.ImageID)
		if err != nil {
			return err
		}
		cpus, mem := capacity()
		o := provision.Choices(cpus, mem)
		if !contains(o.VCPUs, s.VCPUs) || !contains(o.MemoryMiB, s.MemoryMiB) || !contains(provision.DiskChoicesFor(im.MinDiskGiB, o.DiskGiB), s.DiskGiB) {
			return errors.New("size")
		}
		if s.Profile != "" && !im.IsISO() {
			return errors.New("profile for a cloud image") // the Windows profile is for installation media (DR-032)
		}
		if im.IsISO() { // installation media: no cloud-init, so there is no key to inject and none may be given (DR-023 D3)
			if s.SSHPublicKey != "" {
				return errors.New("ssh key for an ISO")
			}
			s.ImageSHA256 = im.SHA256
		} else {
			k, err := provision.NormalizeSSHKey(s.SSHPublicKey)
			if err != nil {
				return err
			}
			s.ImageSHA256, s.SSHPublicKey, s.SSHFingerprint = im.SHA256, k.Authorized, k.Fingerprint
		}
		if s.Network == "" {
			s.Network = network // the configured default; a chosen network was checked against the host by the API and is re-proven by the helper
		}
		return nil
	}
}

func contains(l []int, v int) bool {
	for _, x := range l {
		if x == v {
			return true
		}
	}
	return false
}

// ---- images ------------------------------------------------------------------------------------------------------------

type imageJSON struct {
	ID         string        `json:"id"`
	ProjectID  string        `json:"project_id"`
	Generation int           `json:"generation"`
	Name       string        `json:"name"`
	Desired    imageDesired  `json:"desired"`
	Observed   imageObserved `json:"observed"`
	Allowed    []string      `json:"allowed_actions"`
}

type imageDesired struct {
	SourceDigest string `json:"source_digest"`
}

type imageObserved struct {
	State        string  `json:"state"`
	Distribution string  `json:"distribution"`
	Version      string  `json:"version"`
	Architecture string  `json:"architecture"`
	LoginUser    *string `json:"login_user"` // null for installation media
	// Media is "disk" for a bootable cloud image and "iso" for installation media (DR-023 D3).
	Media         string `json:"media"`
	MinDiskGiB    int    `json:"min_disk_gib"`
	Qualification string `json:"qualification"` // registered | verified | qualified (never simulated)
	// Evidence is the operator-recorded reference to the real-host qualification record; null unless qualified.
	Evidence *string `json:"qualification_evidence"`
}

func loginOf(im provision.Image) *string {
	if im.LoginUser == "" {
		return nil
	}
	u := im.LoginUser
	return &u
}

func toImageJSON(im provision.Image) imageJSON {
	var ev *string
	if im.Evidence != "" {
		ev = &im.Evidence
	}
	media := provision.MediaDisk
	if im.IsISO() {
		media = provision.MediaISO
	}
	return imageJSON{ID: im.ID, ProjectID: defaultProject, Generation: 1, Name: im.DisplayName, Allowed: []string{},
		Desired:  imageDesired{SourceDigest: "sha256:" + im.SHA256},
		Observed: imageObserved{Media: media, State: "available", Distribution: im.Distribution, Version: im.Version, Architecture: im.Architecture, LoginUser: loginOf(im), MinDiskGiB: im.MinDiskGiB, Qualification: im.State, Evidence: ev}}
}

// usableImages lists the images shown to the administrator: everything not disabled, in catalog order, each with its
// qualification so that the UI can offer only what can be chosen and label what is not yet qualified.
func (h *Handler) usableImages() ([]provision.Image, error) {
	if h.deps.Creation == nil || h.deps.Creation.Catalog == nil {
		return nil, errors.New("no catalog")
	}
	c, err := h.deps.Creation.Catalog()
	if err != nil {
		return nil, err
	}
	var out []provision.Image
	for _, im := range c.Images {
		if im.State != provision.StateDisabled {
			out = append(out, im)
		}
	}
	return out, nil
}

func (h *Handler) requireCreationSession(w http.ResponseWriter, r *http.Request) bool {
	if h.deps.Auth == nil || h.deps.Creation == nil || h.deps.Creation.Catalog == nil {
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

func (h *Handler) listImages(w http.ResponseWriter, r *http.Request) {
	if !h.requireCreationSession(w, r) {
		return
	}
	for k, v := range r.URL.Query() {
		if len(v) != 1 || (k != "limit" && k != "cursor") || (k == "limit" && !limitRE.MatchString(v[0])) || k == "cursor" {
			h.reject(w, categoryValidation) // the catalog is small: one page, so no cursor can be valid
			return
		}
	}
	ims, err := h.usableImages()
	if err != nil {
		h.reject(w, categoryUnavailable)
		return
	}
	items := make([]imageJSON, 0, len(ims))
	for _, im := range ims {
		items = append(items, toImageJSON(im))
	}
	writeJSON(w, http.StatusOK, struct {
		Items   []imageJSON `json:"items"`
		Allowed []string    `json:"allowed_actions"`
		Next    *string     `json:"next_cursor"`
	}{Items: items, Allowed: []string{}})
}

func (h *Handler) readImage(w http.ResponseWriter, r *http.Request) {
	if !h.requireCreationSession(w, r) {
		return
	}
	if len(r.URL.Query()) != 0 {
		h.reject(w, categoryValidation)
		return
	}
	id := r.URL.Path[len("/api/v1/images/"):]
	if !vmIDRE.MatchString(id) {
		h.reject(w, categoryValidation)
		return
	}
	ims, err := h.usableImages()
	if err != nil {
		h.reject(w, categoryUnavailable)
		return
	}
	for _, im := range ims {
		if im.ID == id {
			writeJSON(w, http.StatusOK, toImageJSON(im))
			return
		}
	}
	h.reject(w, categoryNotFound)
}

// ---- creation readiness for the host summary ----------------------------------------------------------------------------------

type creationJSON struct {
	Enabled          bool   `json:"enabled"`
	Network          string `json:"network"`
	Storage          string `json:"storage"`
	VCPUOptions      []int  `json:"vcpu_options"`
	MemoryMiBOptions []int  `json:"memory_mib_options"`
	DiskGiBOptions   []int  `json:"disk_gib_options"`
	// Ready is true only when a create would be accepted and can succeed; Reasons are closed codes the UI turns into operator
	// guidance (no paths, no libvirt text).
	Ready   bool     `json:"ready"`
	Reasons []string `json:"reasons"`
}

// creationFor describes whether creating a VM is possible and what to offer. When creation is not enabled nothing is asked of
// the mutation agent and no choices are offered.
func (h *Handler) creationFor(ctx context.Context, info hostinfo.Info) creationJSON {
	c := creationJSON{Network: "unknown", Storage: "unknown", VCPUOptions: []int{}, MemoryMiBOptions: []int{}, DiskGiBOptions: []int{}, Reasons: []string{}}
	cr := h.deps.Creation
	if cr == nil || !cr.Enabled {
		c.Reasons = append(c.Reasons, "mutation_disabled")
		return c
	}
	c.Enabled = true
	if cr.Preflight != nil {
		cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		if r, err := cr.Preflight(cctx); err == nil {
			c.Network, c.Storage = r.Network, r.Pool
		}
	}
	o := provision.Choices(info.CPUCount, int(info.MemoryMiB))
	c.VCPUOptions, c.MemoryMiBOptions, c.DiskGiBOptions = nonNil(o.VCPUs), nonNil(o.MemoryMiB), nonNil(o.DiskGiB)

	blocked := false
	block := func(code string) { c.Reasons = append(c.Reasons, code); blocked = true }
	if c.Network != "available" {
		block("network_unavailable")
	}
	if c.Storage != "available" {
		block("storage_unavailable")
	}
	if cr.RequireKVM && (info.Hardware == hostinfo.Unavailable || info.KVMDevice == hostinfo.Unavailable) {
		block("virtualization_unavailable")
	}
	usable, qualified := 0, 0
	if ims, err := h.usableImages(); err == nil {
		for _, im := range ims {
			if im.State == provision.StateVerified || im.State == provision.StateQualified {
				usable++
			}
			if im.State == provision.StateQualified {
				qualified++
			}
		}
	}
	switch {
	case usable == 0:
		block("no_usable_image")
	case qualified == 0:
		c.Reasons = append(c.Reasons, "image_unqualified") // informational: creation works, access is not yet proven for any image
	}
	if info.Verdict != "supported" {
		c.Reasons = append(c.Reasons, "host_not_qualified") // informational
	}
	c.Ready = !blocked
	return c
}

func nonNil(l []int) []int {
	if l == nil {
		return []int{}
	}
	return l
}

// ---- operations --------------------------------------------------------------------------------------------------------------

type createBody struct {
	VCPUs        *int    `json:"vcpus"`
	MemoryMiB    *int    `json:"memory_mib"`
	ImageID      *string `json:"image_id"`
	DiskGiB      *int    `json:"disk_gib"`
	SSHPublicKey *string `json:"ssh_public_key"`
	Network      *string `json:"network"`
	// GuestProfile is the hardware profile of a VM from installation media (DR-032): "linux" (the default) or "windows".
	GuestProfile *string `json:"guest_profile"`
}

type submitBody struct {
	Type           string      `json:"type"`
	Kind           string      `json:"kind"`
	ID             string      `json:"id"`
	IdempotencyKey string      `json:"idempotency_key"`
	Create         *createBody `json:"create"`
	Params         *paramsBody `json:"params"`
}

type operationJSON struct {
	ID            string   `json:"id"`
	ProjectID     string   `json:"project_id"`
	ResourceKind  string   `json:"resource_kind"`
	ResourceID    string   `json:"resource_id"`
	Type          string   `json:"type"`
	Status        string   `json:"status"`
	RequestedBy   string   `json:"requested_by"`
	Generation    int64    `json:"generation"`
	Attempts      int      `json:"attempts"`
	ErrorCategory *string  `json:"error_category"`
	CreatedAt     string   `json:"created_at"`
	UpdatedAt     string   `json:"updated_at"`
	Allowed       []string `json:"allowed_actions"`
}

// toOperationJSON maps the persisted record to the browser shape. The idempotency key, the create specification (including the
// SSH key), the unknown-outcome mark and every host detail are not in it.
func toOperationJSON(o operation.Operation) operationJSON {
	var cat *string
	if o.ErrorCategory != "" {
		c := o.ErrorCategory
		cat = &c
	}
	return operationJSON{ID: o.ID, ProjectID: o.ProjectID, ResourceKind: o.ResourceKind, ResourceID: o.ResourceID, Type: string(o.Type), Status: string(o.Status),
		RequestedBy: o.RequestedBy, Generation: o.Generation, Attempts: o.Attempts, ErrorCategory: cat,
		CreatedAt: o.CreatedAt.UTC().Format(time.RFC3339), UpdatedAt: o.UpdatedAt.UTC().Format(time.RFC3339), Allowed: []string{}}
}

func (h *Handler) opError(w http.ResponseWriter, err error) {
	switch operation.CategoryOf(err) {
	case operation.CatValidation:
		h.reject(w, categoryValidation)
	case operation.CatForbidden:
		h.reject(w, categoryForbidden)
	case operation.CatNotFound:
		h.reject(w, categoryNotFound)
	case operation.CatConflict:
		h.reject(w, categoryConflict)
	case operation.CatUnavailable:
		h.reject(w, categoryUnavailable)
	default:
		h.reject(w, categoryInternal)
	}
}

var keyRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$`)

const maxSubmitBytes = 8 << 10

func (h *Handler) submitOperation(w http.ResponseWriter, r *http.Request) {
	cr := h.deps.Creation
	if h.deps.Auth == nil || cr == nil {
		h.reject(w, categoryUnauthenticated)
		return
	}
	sess, _, ok, failed := h.session(r)
	switch {
	case failed:
		h.reject(w, categoryUnavailable)
		return
	case !ok:
		h.reject(w, categoryUnauthenticated)
		return
	}
	if !h.sameOrigin(r) || !sess.CSRFMatches(r.Header.Get(csrfHeader)) {
		h.reject(w, categoryForbidden)
		return
	}
	if !sess.Role.AtLeast(auth.RoleOperator) { // a viewer submits nothing; the exact type is checked below once the body is read
		h.reject(w, categoryForbidden)
		return
	}
	if !cr.Enabled || cr.Ops == nil { // Development Preview mutation switch: closed unless the operator opened it
		h.reject(w, categoryProhibited)
		return
	}
	var b submitBody
	if !decodeBodyLimit(w, r, &b, maxSubmitBytes) || !keyRE.MatchString(b.IdempotencyKey) || !keyRE.MatchString(b.ID) {
		h.reject(w, categoryValidation)
		return
	}
	typ := operation.Type(b.Type)
	if (b.Kind != operation.KindVM && b.Kind != operation.KindBackup && b.Kind != operation.KindNetwork && b.Kind != operation.KindVolume && b.Kind != operation.KindEvent) || !lifecycleType(typ) ||
		(b.Kind == operation.KindEvent) != (typ == operation.AlertAcknowledge) ||
		(b.Kind == operation.KindBackup && typ != operation.Restore && typ != operation.Delete && typ != operation.BackupExport) || (b.Kind == operation.KindVM && typ == operation.BackupExport) ||
		(b.Kind != operation.KindVM && (typ == operation.ScheduleSet || typ == operation.ScheduleClear)) ||
		(b.Kind == operation.KindNetwork) != networkType(typ) || (b.Kind == operation.KindVolume) != volumeType(typ) || (b.Kind == operation.KindVM && typ == operation.Restore) {
		h.reject(w, categoryProhibited) // every other kind and type stays closed
		return
	}
	if (b.Params != nil) != paramType(typ) && !(b.Params == nil && paramOptional(typ)) {
		h.reject(w, categoryValidation) // exactly the types that take parameters carry them
		return
	}
	if !roleMay(sess.Role, typ, b.Kind) {
		h.reject(w, categoryForbidden)
		return
	}
	if typ == operation.Snapshot && !h.snapshotsAvailable(r.Context()) {
		h.reject(w, categoryConflict) // the host has not shown that its pool can hold internal snapshots (DR-023 D6)
		return
	}
	req := operation.Request{ProjectID: defaultProject, Type: typ, Kind: b.Kind, ResourceID: b.ID, IdempotencyKey: b.IdempotencyKey, Params: b.Params.toParams()}
	if paramType(typ) && !req.Params.ValidFor(typ) {
		h.reject(w, categoryValidation)
		return
	}
	switch req.Type {
	case operation.Create:
		c := b.Create
		if c == nil || c.VCPUs == nil || c.MemoryMiB == nil || c.ImageID == nil || c.DiskGiB == nil || !provision.VMNameRE.MatchString(b.ID) {
			h.reject(w, categoryValidation)
			return
		}
		req.Spec = operation.CreateSpec{VCPUs: *c.VCPUs, MemoryMiB: *c.MemoryMiB, ImageID: *c.ImageID, DiskGiB: *c.DiskGiB}
		if c.GuestProfile != nil {
			if !provision.ValidProfile(*c.GuestProfile) || *c.GuestProfile == "" {
				h.reject(w, categoryValidation) // closed set: linux or windows
				return
			}
			if *c.GuestProfile == provision.ProfileWindows {
				req.Spec.Profile = provision.ProfileWindows // "linux" is the default and is stored as no profile, so an explicit linux and an omitted one are the same request
			}
		}
		if c.SSHPublicKey != nil {
			req.Spec.SSHPublicKey = *c.SSHPublicKey
		}
		chosen := ""
		if c.Network != nil && *c.Network != cr.Network {
			chosen = *c.Network
			req.Spec.Network = chosen
		}
		if !h.createPrechecks(w, r, b.ID, chosen) {
			return
		}
	default: // start, stop, reboot, force_off, delete and the M2 operations: an action on one existing VM or backup
		if b.Create != nil {
			h.reject(w, categoryValidation)
			return
		}
		switch {
		case b.Kind == operation.KindEvent:
			if !h.alertPrechecks(w, r, req) {
				return
			}
		case req.Type == operation.ScheduleSet || req.Type == operation.ScheduleClear:
			if !h.schedulePrechecks(w, r, req) {
				return
			}
		case b.Kind == operation.KindVolume:
			if !h.volumePrechecks(w, r, req) {
				return
			}
		case b.Kind == operation.KindNetwork:
			if !h.networkPrechecks(w, r, req) {
				return
			}
		case vmNetType(req.Type):
			if !h.vmNetPrechecks(w, r, req) {
				return
			}
		case storageType(req.Type) || b.Kind == operation.KindBackup:
			if !h.storagePrechecks(w, r, b, req) {
				return
			}
		case !h.lifecyclePrechecks(w, r, b.ID, req.Type):
			return
		}
	}
	op, err := cr.Ops.Submit(operation.Actor{ID: sess.Username}, req)
	if err != nil {
		h.opError(w, err)
		return
	}
	if cr.Notify != nil {
		cr.Notify()
	}
	writeJSON(w, http.StatusAccepted, toOperationJSON(op))
}

// createPrechecks refuses, before anything is stored, a create that cannot succeed because the host is not ready or the name is
// taken. (The host layer re-checks both: these are early, friendly answers, not the safety net.)
func (h *Handler) createPrechecks(w http.ResponseWriter, r *http.Request, name, network string) bool {
	cr := h.deps.Creation
	if cr.Preflight != nil {
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()
		rd, err := cr.Preflight(ctx)
		if err != nil || rd.Network != "available" || rd.Pool != "available" {
			h.reject(w, categoryUnavailable)
			return false
		}
	}
	if network != "" {
		// A VM may attach to the configured network or to an ACTIVE Svavyom-managed one; any other libvirt network is refused.
		idx, ok := h.networkIndex(r.Context())
		if !ok {
			h.reject(w, categoryUnavailable)
			return false
		}
		n, found := idx[network]
		switch {
		case !found || !n.Managed:
			h.reject(w, categoryValidation)
			return false
		case !n.Active:
			h.reject(w, categoryUnavailable)
			return false
		}
	}
	if h.deps.VMs != nil {
		_, err := h.deps.VMs.Lookup(r.Context(), name)
		switch hypervisor.CategoryOf(err) {
		case "":
			h.reject(w, categoryConflict) // a VM of that name exists
			return false
		case hypervisor.NotFound:
		default:
			h.reject(w, categoryUnavailable)
			return false
		}
	}
	return true
}

// lifecyclePrechecks allows a lifecycle action only for a Svavyom-managed VM in a state the action applies to. These are early,
// friendly answers; the mutation helper re-proves ownership and state before it acts, and is the safety net.
func (h *Handler) lifecyclePrechecks(w http.ResponseWriter, r *http.Request, name string, t operation.Type) bool {
	if h.deps.VMs == nil {
		h.reject(w, categoryUnavailable)
		return false
	}
	d, err := h.deps.VMs.Lookup(r.Context(), name)
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
		h.reject(w, categoryProhibited) // not created by Svavyom: not ours to act on
		return false
	}
	if !actionApplies(t, d.State) {
		h.reject(w, categoryConflict)
		return false
	}
	if t == operation.Start && d.Network != "" {
		if nets, known := h.networkIndex(r.Context()); known {
			if n, ok := nets[d.Network]; ok && !n.Active {
				h.reject(w, categoryConflict) // the VM's network is not active: start the network first
				return false
			}
		}
	}
	return true
}

// actionApplies is the state each lifecycle action applies to. Delete requires Stopped: a running VM is never deleted implicitly.
func actionApplies(t operation.Type, s hypervisor.State) bool {
	switch t {
	case operation.Start, operation.Delete:
		return s == hypervisor.StateShutoff
	case operation.Stop, operation.Reboot:
		return s == hypervisor.StateRunning
	case operation.ForceOff:
		return s == hypervisor.StateRunning || s == hypervisor.StatePaused || s == hypervisor.StateCrashed
	}
	return false
}

// allowedActions lists, for presentation, the actions that apply to a managed VM in state s.
func allowedActions(d hypervisor.Domain, nets map[string]hypervisor.Network, netsKnown bool) []string {
	out := []string{}
	for _, t := range []operation.Type{operation.Start, operation.Stop, operation.Reboot, operation.ForceOff, operation.Delete} {
		if actionApplies(t, d.State) {
			out = append(out, string(t))
		}
	}
	if d.State == hypervisor.StateShutoff { // the M2 storage and recovery actions apply to a Stopped VM
		owned := 0
		for _, sn := range d.Snapshots {
			if snapshotRE.MatchString(sn.ID) {
				owned++
			}
		}
		// Offer only what would be accepted: qcow2 cannot resize an image that holds snapshots, and reinstall and backup refuse one that does.
		if owned == 0 && len(d.Snapshots) == 0 {
			out = append(out, string(operation.Resize))
			if len(d.DataVolumes) == 0 && d.Media != "iso" && d.RescueSHA256 == "" { // a reinstall would drop the attached volumes from the definition (detach them first), and installation media has no image to reinstall from
				out = append(out, string(operation.Reinstall))
			}
		}
		if owned < provision.MaxSnapshots {
			out = append(out, string(operation.Snapshot))
		}
		if owned == 0 && len(d.Snapshots) == 0 && d.Media != "iso" && d.RescueSHA256 == "" {
			out = append(out, string(operation.Backup))
		}
		if d.ISOSHA256 != "" && d.RescueSHA256 == "" {
			out = append(out, string(operation.EjectISO))
		}
		if !d.Graphics {
			out = append(out, string(operation.GraphicsEnable))
		}
		if len(d.ISOSHA256s) < provision.MaxMedia && d.RescueSHA256 == "" {
			out = append(out, string(operation.ISOAttach)) // a second medium is allowed (DR-031); a third is not
		}
		if d.ISOSHA256 == "" && len(d.ISOSHA256s) == 0 && d.RescueSHA256 == "" && d.Graphics {
			out = append(out, string(operation.Rescue)) // rescue needs no other medium
		}
		if d.RescueSHA256 != "" {
			out = append(out, string(operation.Unrescue))
		}
	}
	return append(out, netActions(d, nets, netsKnown)...)
}

func (h *Handler) readOperation(w http.ResponseWriter, r *http.Request) {
	cr := h.deps.Creation
	if h.deps.Auth == nil || cr == nil {
		h.reject(w, categoryUnauthenticated)
		return
	}
	sess, _, ok, failed := h.session(r)
	switch {
	case failed:
		h.reject(w, categoryUnavailable)
		return
	case !ok:
		h.reject(w, categoryUnauthenticated)
		return
	}
	if len(r.URL.Query()) != 0 {
		h.reject(w, categoryValidation)
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/api/v1/operations/")
	if !vmIDRE.MatchString(id) {
		h.reject(w, categoryValidation)
		return
	}
	if cr.Ops == nil { // creation not enabled on this installation: there are no operations to read
		h.reject(w, categoryNotFound)
		return
	}
	op, err := cr.Ops.Get(operation.Actor{ID: sess.Username}, id)
	if err != nil {
		h.opError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, toOperationJSON(op))
}

// listOperations answers GET /api/v1/operations (DR-022): the most recent operations first, with the same limit and cursor conventions as
// the other lists. Where creation is not enabled there are no operations, so the page is empty.
func (h *Handler) listOperations(w http.ResponseWriter, r *http.Request) {
	cr := h.deps.Creation
	if h.deps.Auth == nil {
		h.reject(w, categoryUnauthenticated)
		return
	}
	sess, _, ok, failed := h.session(r)
	switch {
	case failed:
		h.reject(w, categoryUnavailable)
		return
	case !ok:
		h.reject(w, categoryUnauthenticated)
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
	items := []operationJSON{}
	var next *string
	if cr != nil && cr.Ops != nil {
		page, last, err := cr.Ops.List(operation.Actor{ID: sess.Username}, limit, after)
		if err != nil {
			h.opError(w, err)
			return
		}
		for _, o := range page {
			items = append(items, toOperationJSON(o))
		}
		if last != "" {
			c := base64.RawURLEncoding.EncodeToString([]byte(last))
			next = &c
		}
	}
	writeJSON(w, http.StatusOK, struct {
		Items   []operationJSON `json:"items"`
		Allowed []string        `json:"allowed_actions"`
		Next    *string         `json:"next_cursor"`
	}{Items: items, Allowed: []string{}, Next: next})
}

// decodeBodyLimit is decodeBody with a caller-chosen size bound.
func decodeBodyLimit(w http.ResponseWriter, r *http.Request, dst any, limit int64) bool {
	if ct := r.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		return false
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, limit))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return false
	}
	_, err := dec.Token()
	return errors.Is(err, io.EOF)
}
