package operation

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"time"

	"example.invalid/dedicatedcloud/backend/internal/hypervisor"
)

// Config tunes a Manager. Zero values select the defaults.
type Config struct {
	// MaxAttempts bounds automatic host attempts per operation (failure-matrix agent-unavailable). Default 3.
	MaxAttempts int
	// VCPUs and MemoryMiB are the minimal VM created by a `create` operation (the submit_operation schema
	// carries no sizing). Defaults 1 and 512.
	VCPUs     int
	MemoryMiB int
	// Clock and NewID are injectable for tests.
	Clock func() time.Time
	NewID func() (string, error)
	// PrepareCreate validates and completes a create definition before it is persisted (image lookup and hash, SSH key
	// normalisation and fingerprint, network profile, capacity choices). It runs with the VM name. An error is a
	// validation failure and nothing is stored. Nil keeps the minimal simulation behaviour.
	PrepareCreate func(name string, spec *CreateSpec) error
	// PrepareParams validates and completes the typed parameters of a storage/recovery operation before it is persisted (image digest lookup, SSH
	// key normalisation, name checks). An error is a validation failure and nothing is stored. Nil leaves the parameters as the caller gave them.
	PrepareParams func(t Type, resourceID string, p *Params) error
	// Local runs the operations that change only the platform's own records (alert_acknowledge, schedule_set, schedule_clear). Every method is
	// idempotent. Nil makes those operations fail as not available.
	Local Local
}

// Local is implemented by the platform records an operation of DR-024 changes. A not-found VM or alert is reported as hypervisor.NotFound, a refused
// value as hypervisor.Validation, so settle gives the usual categories.
type Local interface {
	AlertAcknowledge(ctx context.Context, id, actor string) error
	ScheduleSet(ctx context.Context, vm string, p Params, actor string) error
	ScheduleClear(ctx context.Context, vm string) error
}

// Rebooter is implemented by hosts that can ask a guest to reboot. It is separate from hypervisor.Hypervisor so the simulation
// adapters need not grow a method they cannot honestly implement.
type Rebooter interface {
	Reboot(ctx context.Context, name string) error
}

// Networking is implemented by hosts that can run the M3 network and VM configuration operations (managed NAT networks, static DHCP reservations,
// compute changes). Every method is idempotent by construction, which is why an unknown outcome is settled by running it again.
type Networking interface {
	NetworkCreate(ctx context.Context, name string, p Params) error
	NetworkStart(ctx context.Context, name string) error
	NetworkStop(ctx context.Context, name string) error
	NetworkAutostart(ctx context.Context, name string, on bool) error
	NetworkDelete(ctx context.Context, name string) error
	Compute(ctx context.Context, vm string, vcpus, memoryMiB int) error
	ReserveIP(ctx context.Context, vm, ip string) error
	ReleaseIP(ctx context.Context, vm string) error
}

// Storage is implemented by hosts that can run the M2 storage and recovery operations. Like Rebooter it is separate from hypervisor.Hypervisor.
// Every method is idempotent by construction (it identifies its work by the ids in the parameters), which is why an unknown outcome is settled by
// running it again rather than by guessing.
type Storage interface {
	Resize(ctx context.Context, name string, diskGiB int) error
	Reinstall(ctx context.Context, name string, p Params) error
	Snapshot(ctx context.Context, name, snapshotID string) error
	RestoreSnapshot(ctx context.Context, name, snapshotID string) error
	DeleteSnapshot(ctx context.Context, name, snapshotID string) error
	Backup(ctx context.Context, name, backupID string) error
	Restore(ctx context.Context, backupID string, p Params) error
	DeleteBackup(ctx context.Context, backupID string) error
	// Standalone data volumes (DR-023 D2).
	VolumeCreate(ctx context.Context, name string, diskGiB int) error
	VolumeAttach(ctx context.Context, name, vm string) error
	VolumeDetach(ctx context.Context, name string) error
	VolumeDelete(ctx context.Context, name string) error
	// EjectISO removes the installation media of a stopped VM (DR-023 D3).
	EjectISO(ctx context.Context, name string) error
	// GraphicsEnable gives a stopped VM the graphical console devices; ISOAttach attaches catalog installation media (p.ImageID, p.ImageSHA256, p.Boot);
	// Rescue boots the VM from rescue media with its own disk kept, and Unrescue puts the definition back (DR-026).
	GraphicsEnable(ctx context.Context, name string) error
	ISOAttach(ctx context.Context, name string, p Params) error
	Rescue(ctx context.Context, name string, p Params) error
	Unrescue(ctx context.Context, name string) error
	// BackupExport copies a backup to an off-host target and verifies the copy there (DR-023 D4); a verified copy already in place is success.
	BackupExport(ctx context.Context, backupID, targetID string) error
}

// Manager runs operations against a hypervisor and persists every state change.
type Manager struct {
	store Store
	hv    hypervisor.Hypervisor
	authz Authorizer
	audit AuditSink
	cfg   Config
}

type denyAll struct{}

func (denyAll) Authorize(Actor, string, Type) error { return fail(CatForbidden) }

type discard struct{}

func (discard) Emit(AuditEvent) {}

// NewManager builds a manager. A nil authorizer denies everything; a nil audit sink discards events.
func NewManager(store Store, hv hypervisor.Hypervisor, authz Authorizer, audit AuditSink, cfg Config) *Manager {
	if authz == nil {
		authz = denyAll{}
	}
	if audit == nil {
		audit = discard{}
	}
	if cfg.MaxAttempts <= 0 {
		cfg.MaxAttempts = 3
	}
	if cfg.VCPUs <= 0 {
		cfg.VCPUs = 1
	}
	if cfg.MemoryMiB <= 0 {
		cfg.MemoryMiB = 512
	}
	if cfg.Clock == nil {
		cfg.Clock = func() time.Time { return time.Now().UTC() }
	}
	if cfg.NewID == nil {
		cfg.NewID = randomID
	}
	return &Manager{store: store, hv: hv, authz: authz, audit: audit, cfg: cfg}
}

// randomID is "op-" plus 128 random bits (matches ^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$).
func randomID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return "op-" + hex.EncodeToString(b[:]), nil
}

func (m *Manager) event(op Operation, actor, event, outcome, category string) AuditEvent {
	return AuditEvent{At: m.cfg.Clock(), OperationID: op.ID, ProjectID: op.ProjectID, Actor: actor,
		Event: event, Outcome: outcome, ErrorCategory: category}
}

func (m *Manager) emit(op Operation, actor, event, outcome, category string) {
	m.audit.Emit(m.event(op, actor, event, outcome, category))
}

// Submit validates, authorizes and persists an operation as pending. It does not touch the host. A replay with the
// same (project, idempotency key) and payload returns the existing operation; the same key with another payload is
// a conflict. Authorization comes first so an unauthorized caller learns nothing about validity or existence.
func (m *Manager) Submit(actor Actor, req Request) (Operation, error) {
	denied := func(cat string) (Operation, error) {
		// The project id is caller-controlled: it reaches the audit log only if it is a well-formed id.
		audited := Operation{}
		if idRE.MatchString(req.ProjectID) {
			audited.ProjectID = req.ProjectID
		}
		m.emit(audited, actor.ID, "operation.submit", "rejected", cat)
		return Operation{}, fail(cat)
	}
	if actor.ID == "" || !idRE.MatchString(req.ProjectID) {
		return denied(CatForbidden)
	}
	if err := m.authz.Authorize(actor, req.ProjectID, req.Type); err != nil {
		return denied(CatForbidden)
	}
	if err := req.validate(); err != nil {
		return denied(CatValidation)
	}
	id, err := m.cfg.NewID()
	if err != nil {
		return denied(CatInternal)
	}
	now := m.cfg.Clock()
	spec := req.Spec
	if req.Type == Create {
		if spec.IsZero() {
			spec = CreateSpec{VCPUs: m.cfg.VCPUs, MemoryMiB: m.cfg.MemoryMiB} // fixed now; later config changes do not apply
		}
		if m.cfg.PrepareCreate != nil {
			if err := m.cfg.PrepareCreate(req.ResourceID, &spec); err != nil {
				return denied(CatValidation)
			}
		}
		// The create identity is generated by the server, once, and persisted with the operation.
		u, uerr := newUUID()
		if uerr != nil {
			return denied(CatInternal)
		}
		spec.UUID = u
		spec.Fingerprint = ComputeFingerprint(req.ResourceID, spec)
	}
	params := req.Params
	switch req.Type {
	case Snapshot:
		h, herr := randHex(6)
		if herr != nil {
			return denied(CatInternal)
		}
		params.SnapshotID = "snap-" + h
	case Backup:
		h, herr := randHex(8)
		if herr != nil {
			return denied(CatInternal)
		}
		params.BackupID = "bk-" + h
	case Reinstall:
		rev, herr := randHex(4)
		if herr != nil {
			return denied(CatInternal)
		}
		params.Rev = rev
	case Restore:
		u, uerr := newUUID()
		if uerr != nil {
			return denied(CatInternal)
		}
		params.NewUUID, params.NewFinger = u, restoreFingerprint(req.ResourceID, u, params.NewName)
	case NetworkCreate:
		u, uerr := newUUID()
		if uerr != nil {
			return denied(CatInternal)
		}
		params.NewUUID = u
	}
	if m.cfg.PrepareParams != nil && !params.IsZero() {
		if err := m.cfg.PrepareParams(req.Type, req.ResourceID, &params); err != nil {
			return denied(CatValidation)
		}
	}
	if !params.complete(req.Type, req.ResourceID) {
		return denied(CatValidation)
	}
	fresh := Operation{
		Params: params, Spec: spec, ID: id, ProjectID: req.ProjectID, ResourceKind: req.Kind, ResourceID: req.ResourceID, Type: req.Type,
		Status: Pending, IdempotencyKey: req.IdempotencyKey, RequestedBy: actor.ID, Generation: 1,
		CreatedAt: now, UpdatedAt: now,
	}
	var (
		op      Operation
		created bool
	)
	if as, ok := m.store.(AuditedStore); ok {
		// The accepted event commits atomically with the operation: no accepted operation without its audit record.
		op, created, err = as.InsertAudited(fresh, m.event(fresh, actor.ID, "operation.submit", "accepted", ""))
	} else {
		op, created, err = m.store.Insert(fresh)
		if err == nil && created {
			m.emit(op, actor.ID, "operation.submit", "accepted", "")
		}
	}
	if err != nil {
		return denied(storeCategory(err))
	}
	if !created && (op.Type != req.Type || op.ResourceKind != req.Kind || op.ResourceID != req.ResourceID ||
		(!req.Spec.IsZero() && op.Spec.Inputs() != spec.Inputs()) || op.Params.Inputs() != params.Inputs()) { // an omitted spec matches whatever was recorded
		return denied(CatConflict)
	}
	if !created {
		m.emit(op, actor.ID, "operation.submit", "replayed", "")
	} else if op.Type == ForceOff {
		m.supersedeGraceful(op)
	}
	return op, nil
}

// supersedeGraceful cancels the graceful Stop/Reboot operations of the same VM that have not reached the host (or are waiting to be
// retried, including ones that used all their attempts): an explicit Force Off must not queue behind a Stop that is stuck because the
// guest ignores it. A Stop that is executing right now is left alone; the Force Off runs after it, in submission order. Nothing
// is ever force-offed without this explicit operation.
func (m *Manager) supersedeGraceful(forced Operation) {
	open, err := m.store.NonTerminal()
	if err != nil {
		return
	}
	for _, o := range open {
		if o.ID == forced.ID || o.ProjectID != forced.ProjectID || o.ResourceKind != forced.ResourceKind || o.ResourceID != forced.ResourceID {
			continue
		}
		if (o.Type == Stop || o.Type == Reboot) && (o.Status == Pending || o.Status == RetryableFailure) {
			o.Status = Cancelled
			_, _ = m.save(o, "system", "operation.superseded", "")
		}
	}
}

// Get returns an operation. An operation the actor may not see is reported as not_found (no existence leak).
func (m *Manager) Get(actor Actor, id string) (Operation, error) {
	op, ok, err := m.store.Get(id)
	if err != nil {
		return Operation{}, fail(storeCategory(err))
	}
	if !ok || m.authz.Authorize(actor, op.ProjectID, op.Type) != nil {
		return Operation{}, fail(CatNotFound)
	}
	return op, nil
}

// List returns the most recent operations the actor may see, newest first, with the id to continue from (empty when none remain). A store that
// cannot list is reported as unavailable. Operations the actor may not see are skipped, never revealed.
func (m *Manager) List(actor Actor, limit int, after string) ([]Operation, string, error) {
	l, ok := m.store.(Lister)
	if !ok {
		return nil, "", fail(CatUnavailable)
	}
	page, more, err := l.Recent(limit, after)
	if err != nil {
		return nil, "", fail(storeCategory(err))
	}
	out := make([]Operation, 0, len(page))
	for _, op := range page {
		if m.authz.Authorize(actor, op.ProjectID, op.Type) == nil {
			out = append(out, op)
		}
	}
	next := ""
	if more && len(page) > 0 {
		next = page[len(page)-1].ID
	}
	return out, next, nil
}

// Cancel cancels an operation that has not started on the host (pending or retryable_failure). Cancelling a
// cancelled operation is a no-op; any other state is a conflict.
func (m *Manager) Cancel(actor Actor, id string) (Operation, error) {
	op, err := m.Get(actor, id)
	if err != nil {
		return Operation{}, err
	}
	switch op.Status {
	case Cancelled:
		return op, nil
	case Pending, RetryableFailure:
	default:
		return Operation{}, fail(CatConflict)
	}
	op.Status = Cancelled
	saved, err := m.save(op, actor.ID, "operation.cancel", "")
	if err != nil {
		return Operation{}, err
	}
	return saved, nil
}

// storeCategory maps a store failure to an operation category. A conflict (CAS lost, terminal record) stays a
// conflict and a store that already classified its failure keeps it; anything else is unavailable. Raw driver
// errors never leave this package.
func storeCategory(err error) string {
	switch c := CategoryOf(err); c {
	case CatConflict, CatInternal:
		return c
	}
	return CatUnavailable
}

// save persists op (the new state, carrying the generation that was read) and records one audit event for the
// transition. With an AuditedStore the event commits in the same transaction as the state change; otherwise it is
// emitted to the sink after the write.
func (m *Manager) save(op Operation, actor, event, category string) (Operation, error) {
	op.UpdatedAt = m.cfg.Clock()
	ev := m.event(op, actor, event, string(op.Status), category)
	var (
		saved Operation
		err   error
	)
	if as, ok := m.store.(AuditedStore); ok {
		saved, err = as.UpdateAudited(op, ev)
	} else if saved, err = m.store.Update(op); err == nil {
		m.audit.Emit(ev)
	}
	if err != nil {
		return Operation{}, fail(storeCategory(err))
	}
	return saved, nil
}

// Run executes one attempt of a pending or retryable operation. The attempt number is persisted before the host
// command is sent, so a crash leaves a `running` record that Reconcile resolves by observation.
func (m *Manager) Run(ctx context.Context, id string) (Operation, error) {
	op, ok, err := m.store.Get(id)
	if err != nil {
		return Operation{}, fail(storeCategory(err))
	}
	if !ok {
		return Operation{}, fail(CatNotFound)
	}
	if op.Type == Create && op.UnknownOutcome && op.Status == RetryableFailure {
		// Before a create is sent again after an unknown outcome, look at the host: the earlier attempt may have completed
		// late. Present -> decide against the persisted definition without sending anything; observation failure -> change
		// nothing and send nothing; absent -> the retry may proceed.
		d, lerr := m.hv.Lookup(ctx, op.ResourceID)
		switch {
		case lerr == nil:
			st, cat := decideCreate(op, d)
			op.Status, op.ErrorCategory = st, cat
			return m.save(op, "system", "operation.reconciled", cat)
		case hypervisor.CategoryOf(lerr) != hypervisor.NotFound:
			return op, fail(CatUnavailable)
		}
	}
	switch op.Status {
	case Pending:
	case RetryableFailure:
		if op.Attempts >= m.cfg.MaxAttempts {
			return op, fail(CatUnavailable)
		}
	case Running:
		return op, fail(CatConflict) // outcome pending: Reconcile, never a blind re-execution
	default:
		return op, nil
	}
	op.Status, op.Attempts, op.ErrorCategory = Running, op.Attempts+1, ""
	if op, err = m.save(op, "system", "operation.status", ""); err != nil {
		return Operation{}, err
	}
	return m.settle(ctx, op, m.execute(ctx, op))
}

func (m *Manager) execute(ctx context.Context, op Operation) error {
	switch op.Type {
	case Create:
		if op.Spec.IsZero() {
			// No persisted definition (a record from before specs were stored): never invent one from process defaults.
			return hypervisor.NewError(hypervisor.Validation, "define", op.ResourceID, "no persisted definition")
		}
		_, err := m.hv.Define(ctx, op.Spec.DomainSpec(op.ResourceID))
		return err
	case Start:
		return m.hv.Start(ctx, op.ResourceID)
	case Stop:
		return m.hv.Stop(ctx, op.ResourceID) // graceful; a timeout is reconciled by observation and never becomes a force-off
	case Reboot:
		rb, ok := m.hv.(Rebooter)
		if !ok {
			return hypervisor.NewError(hypervisor.Prohibited, "reboot", op.ResourceID, "not available")
		}
		return rb.Reboot(ctx, op.ResourceID)
	case ForceOff:
		return m.hv.Destroy(ctx, op.ResourceID)
	case Delete:
		if op.ResourceKind == KindBackup {
			return m.storage("delete_backup", func(st Storage) error { return st.DeleteBackup(ctx, op.ResourceID) })
		}
		return m.hv.Undefine(ctx, op.ResourceID) // a running domain is a conflict: no implicit force-off
	case Resize:
		return m.storage("resize", func(st Storage) error { return st.Resize(ctx, op.ResourceID, op.Params.DiskGiB) })
	case Reinstall:
		return m.storage("reinstall", func(st Storage) error { return st.Reinstall(ctx, op.ResourceID, op.Params) })
	case Snapshot:
		return m.storage("snapshot", func(st Storage) error { return st.Snapshot(ctx, op.ResourceID, op.Params.SnapshotID) })
	case RestoreSnapshot:
		return m.storage("restore_snapshot", func(st Storage) error { return st.RestoreSnapshot(ctx, op.ResourceID, op.Params.SnapshotID) })
	case DeleteSnapshot:
		return m.storage("delete_snapshot", func(st Storage) error { return st.DeleteSnapshot(ctx, op.ResourceID, op.Params.SnapshotID) })
	case Backup:
		return m.storage("backup", func(st Storage) error { return st.Backup(ctx, op.ResourceID, op.Params.BackupID) })
	case Restore:
		return m.storage("restore", func(st Storage) error { return st.Restore(ctx, op.ResourceID, op.Params) })
	case BackupExport:
		return m.storage("backup_export", func(st Storage) error { return st.BackupExport(ctx, op.ResourceID, op.Params.TargetID) })
	case EjectISO:
		return m.storage("eject_iso", func(st Storage) error { return st.EjectISO(ctx, op.ResourceID) })
	case GraphicsEnable:
		return m.storage("graphics_enable", func(st Storage) error { return st.GraphicsEnable(ctx, op.ResourceID) })
	case ISOAttach:
		return m.storage("iso_attach", func(st Storage) error { return st.ISOAttach(ctx, op.ResourceID, op.Params) })
	case Rescue:
		return m.storage("rescue", func(st Storage) error { return st.Rescue(ctx, op.ResourceID, op.Params) })
	case Unrescue:
		return m.storage("unrescue", func(st Storage) error { return st.Unrescue(ctx, op.ResourceID) })
	case VolumeCreate:
		return m.storage("volume_create", func(st Storage) error { return st.VolumeCreate(ctx, op.ResourceID, op.Params.DiskGiB) })
	case VolumeAttach:
		return m.storage("volume_attach", func(st Storage) error { return st.VolumeAttach(ctx, op.ResourceID, op.Params.VMID) })
	case VolumeDetach:
		return m.storage("volume_detach", func(st Storage) error { return st.VolumeDetach(ctx, op.ResourceID) })
	case VolumeDelete:
		return m.storage("volume_delete", func(st Storage) error { return st.VolumeDelete(ctx, op.ResourceID) })
	case NetworkCreate:
		return m.networking("network_create", func(n Networking) error { return n.NetworkCreate(ctx, op.ResourceID, op.Params) })
	case NetworkStart:
		return m.networking("network_start", func(n Networking) error { return n.NetworkStart(ctx, op.ResourceID) })
	case NetworkStop:
		return m.networking("network_stop", func(n Networking) error { return n.NetworkStop(ctx, op.ResourceID) })
	case NetworkAutostart:
		return m.networking("network_autostart", func(n Networking) error { return n.NetworkAutostart(ctx, op.ResourceID, op.Params.Autostart == "on") })
	case NetworkDelete:
		return m.networking("network_delete", func(n Networking) error { return n.NetworkDelete(ctx, op.ResourceID) })
	case Compute:
		return m.networking("compute", func(n Networking) error { return n.Compute(ctx, op.ResourceID, op.Params.VCPUs, op.Params.MemoryMiB) })
	case ReserveIP:
		return m.networking("reserve_ip", func(n Networking) error { return n.ReserveIP(ctx, op.ResourceID, op.Params.IPAddress) })
	case ReleaseIP:
		return m.networking("release_ip", func(n Networking) error { return n.ReleaseIP(ctx, op.ResourceID) })
	case AlertAcknowledge, ScheduleSet, ScheduleClear:
		if m.cfg.Local == nil {
			return hypervisor.NewError(hypervisor.Prohibited, string(op.Type), "", "not available")
		}
		switch op.Type {
		case AlertAcknowledge:
			return m.cfg.Local.AlertAcknowledge(ctx, op.ResourceID, op.RequestedBy)
		case ScheduleSet:
			return m.cfg.Local.ScheduleSet(ctx, op.ResourceID, op.Params, op.RequestedBy)
		}
		return m.cfg.Local.ScheduleClear(ctx, op.ResourceID)
	}
	return fail(CatInternal)
}

// networking runs fn against the host's Networking capability, or reports the operation as not available when the host has none.
func (m *Manager) networking(op string, fn func(Networking) error) error {
	n, ok := m.hv.(Networking)
	if !ok {
		return hypervisor.NewError(hypervisor.Prohibited, op, "", "not available")
	}
	return fn(n)
}

// storage runs fn against the host's Storage capability, or reports the operation as not available when the host has none.
func (m *Manager) storage(op string, fn func(Storage) error) error {
	st, ok := m.hv.(Storage)
	if !ok {
		return hypervisor.NewError(hypervisor.Prohibited, op, "", "not available")
	}
	return fn(st)
}

// settle records the outcome of an attempt. A timeout, or any error that is not a typed hypervisor error, leaves
// the operation `running` with category timeout: the host outcome is unknown until observed.
func (m *Manager) settle(ctx context.Context, op Operation, hostErr error) (Operation, error) {
	status, cat := Succeeded, ""
	if hostErr != nil {
		switch hypervisor.CategoryOf(hostErr) {
		case hypervisor.Unavailable:
			status, cat = RetryableFailure, CatUnavailable
		case hypervisor.Validation, hypervisor.Prohibited:
			status, cat = Failed, CatValidation
		case hypervisor.NotFound:
			status, cat = Failed, CatNotFound
		case hypervisor.Conflict:
			status, cat = Failed, CatConflict
			if op.Type == Create && op.UnknownOutcome {
				// An earlier attempt may have completed late, so this Conflict may be our own VM. Decide from the host,
				// against the persisted definition. A first attempt (no unknown outcome) keeps the plain Conflict.
				status, cat = m.conflictOnRetriedCreate(ctx, op)
			}
		case hypervisor.HostError:
			status, cat = Failed, CatHostError
		default: // Timeout, cancelled context, or an untyped error
			status, cat = Running, CatTimeout
			op.UnknownOutcome = true
		}
	}
	op.Status, op.ErrorCategory = status, cat
	saved, err := m.save(op, "system", "operation.status", cat)
	if err != nil {
		return Operation{}, err // stays `running` in the store; Reconcile resolves it
	}
	return saved, nil
}

// ObserveUncertain is the observation-only path for a create whose earlier outcome is unknown (UnknownOutcome) and which
// is waiting as retryable_failure. It looks at the host and nothing else: it never sends a command, never changes
// Attempts, and so also works for an operation that has used all its attempts (TD-D: a late host success must not stay
// "will be retried" forever). Present -> decided by the persisted definition; absent -> unchanged; observation failure
// -> unchanged and a typed unavailable error. Any other operation is returned as it is.
func (m *Manager) ObserveUncertain(ctx context.Context, id string) (Operation, error) {
	op, ok, err := m.store.Get(id)
	if err != nil {
		return Operation{}, fail(storeCategory(err))
	}
	if !ok {
		return Operation{}, fail(CatNotFound)
	}
	if op.Type != Create || !op.UnknownOutcome || op.Status != RetryableFailure {
		return op, nil
	}
	d, lerr := m.hv.Lookup(ctx, op.ResourceID)
	switch {
	case lerr == nil:
		st, cat := decideCreate(op, d)
		op.Status, op.ErrorCategory = st, cat
		return m.save(op, "system", "operation.reconciled", cat)
	case hypervisor.CategoryOf(lerr) == hypervisor.NotFound:
		return op, nil
	}
	return op, fail(CatUnavailable)
}

// conflictOnRetriedCreate resolves a Define Conflict of a create that has an unknown earlier outcome. Observation that
// cannot be completed leaves the operation unknown (running/timeout, reconciled later); it never infers success.
func (m *Manager) conflictOnRetriedCreate(ctx context.Context, op Operation) (Status, string) {
	d, err := m.hv.Lookup(ctx, op.ResourceID)
	if err != nil { // including NotFound right after a Conflict: contradictory, so still unknown
		return Running, CatTimeout
	}
	return decideCreate(op, d)
}

// decideCreate compares an existing domain with the persisted create definition. Existence is not identity: success only
// when the definitions are equal; a different definition is a conflict; an unestablishable one fails closed.
func decideCreate(op Operation, d hypervisor.Domain) (Status, string) {
	switch {
	case op.Spec.IsZero() || op.Spec.UUID == "" || d.VCPUs == 0 || d.MemoryMiB == 0:
		return Failed, CatHostError
	case !d.Managed || d.UUID != op.Spec.UUID || d.Fingerprint != op.Spec.Fingerprint:
		return Failed, CatConflict // somebody else's VM (or one this operation did not create), whatever its size
	case d.VCPUs != op.Spec.VCPUs || d.MemoryMiB != op.Spec.MemoryMiB:
		return Failed, CatConflict
	}
	return Succeeded, ""
}

// Reconcile resolves every `running` operation by observing host state, never by re-sending a command. It is
// what a restarted manager runs first. An operation whose observation fails stays `running` (state is never
// guessed); the first such category is returned alongside the operations that were resolved.
func (m *Manager) Reconcile(ctx context.Context) ([]Operation, error) {
	ops, err := m.store.NonTerminal()
	if err != nil {
		return nil, fail(storeCategory(err))
	}
	var resolved []Operation
	var firstErr error
	for _, op := range ops {
		if op.Status != Running {
			continue
		}
		saved, err := m.reconcile(ctx, op)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		resolved = append(resolved, saved)
	}
	return resolved, firstErr
}

// ReconcileOne resolves a single `running` operation by observation. Any other status is returned unchanged. Only
// the owner of the in-flight attempt (the worker, after its attempt returned) or a restarted process may call it:
// reconciling an attempt that is still executing could observe a half-applied host and schedule a duplicate.
func (m *Manager) ReconcileOne(ctx context.Context, id string) (Operation, error) {
	op, ok, err := m.store.Get(id)
	if err != nil {
		return Operation{}, fail(storeCategory(err))
	}
	if !ok {
		return Operation{}, fail(CatNotFound)
	}
	if op.Status != Running {
		return op, nil
	}
	return m.reconcile(ctx, op)
}

func (m *Manager) reconcile(ctx context.Context, op Operation) (Operation, error) {
	status, cat, ok := m.observe(ctx, op)
	if !ok {
		return Operation{}, fail(CatUnavailable)
	}
	if status == RetryableFailure && cat == CatTimeout {
		op.UnknownOutcome = true // an attempt may have reached the host and the host does not show it (yet)
	}
	op.Status, op.ErrorCategory = status, cat
	return m.save(op, "system", "operation.reconciled", cat)
}

// observe decides the status of a running operation from host state. ok is false when the host could not be read.
func (m *Manager) observe(ctx context.Context, op Operation) (Status, string, bool) {
	switch op.Type {
	case Resize, Reinstall, Snapshot, RestoreSnapshot, DeleteSnapshot, Backup, Restore, BackupExport, EjectISO, GraphicsEnable, ISOAttach, Rescue, Unrescue, VolumeCreate, VolumeAttach, VolumeDetach, VolumeDelete, NetworkCreate, NetworkStart, NetworkStop, NetworkAutostart, NetworkDelete, Compute, ReserveIP, ReleaseIP, AlertAcknowledge, ScheduleSet, ScheduleClear:
		// These operations identify their own work (sizes, revision tokens, snapshot and backup ids, a new UUID), so running one again after an
		// unknown outcome finishes it or finds it finished; there is nothing to guess from a VM lookup.
		return RetryableFailure, CatTimeout, true
	case Delete:
		if op.ResourceKind == KindBackup {
			return RetryableFailure, CatTimeout, true
		}
	}
	d, err := m.hv.Lookup(ctx, op.ResourceID)
	absent := hypervisor.CategoryOf(err) == hypervisor.NotFound
	if err != nil && !absent {
		return "", "", false
	}
	retry := func() (Status, string, bool) { return RetryableFailure, CatTimeout, true }
	switch op.Type {
	case Create:
		if absent {
			return retry()
		}
		st, cat := decideCreate(op, d)
		return st, cat, true
	case Reboot:
		// The host observes the restart itself (provision.Reboot) before it reports success, so an attempt whose outcome is unknown
		// was NOT seen to restart the guest. It is never sent again (a second reboot is not harmless) and never reported as done: it
		// fails with category timeout, "not confirmed".
		if absent {
			return Failed, CatNotFound, true
		}
		return Failed, CatTimeout, true
	case Start, Stop, ForceOff:
		if absent {
			return Failed, CatNotFound, true
		}
		want := hypervisor.StateRunning
		if op.Type == Stop || op.Type == ForceOff {
			want = hypervisor.StateShutoff
		}
		if d.State == want {
			return Succeeded, "", true
		}
		return retry()
	case Delete:
		if absent {
			return Succeeded, "", true
		}
		return retry()
	}
	return Failed, CatInternal, true
}
