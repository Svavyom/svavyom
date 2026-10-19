// Package operation is the operation manager: the durable job state machine of ADR-003 (story M0-E02-S07).
//
// It is the single writer of operation state. A submitted operation is persisted before anything touches the host,
// every host command is recorded (attempt number persisted first), and after a crash or an unknown outcome the manager
// observes host state before it does anything else; it never blindly re-executes a command. Statuses and persisted
// fields come from contracts/interfaces/resources.json, error categories from contracts/interfaces/errors.json.
//
// Only the VM resource kind is executable; the types are the submit_operation types of request-schemas.json.
// The host side is the typed hypervisor.Hypervisor interface, so this package never builds shell, XML or paths.
package operation

import (
	"fmt"
	"regexp"
	"strings"
	"time"
)

// Status is the persisted operation status (resources.json operation_status).
type Status string

// Operation statuses.
const (
	Pending          Status = "pending"
	Running          Status = "running"
	Succeeded        Status = "succeeded"
	Failed           Status = "failed"
	RetryableFailure Status = "retryable_failure"
	Cancelled        Status = "cancelled"
)

// Terminal reports whether the status is final.
func (s Status) Terminal() bool { return s == Succeeded || s == Failed || s == Cancelled }

// Type is a submit_operation type.
type Type string

// Operation types.
const (
	Create Type = "create"
	Start  Type = "start"
	Stop   Type = "stop"
	Delete Type = "delete"
	// Reboot asks the guest to reboot; ForceOff powers a VM off immediately (an explicit destructive action, never the
	// automatic follow-up of a Stop).
	Reboot   Type = "reboot"
	ForceOff Type = "force_off"
	// Storage and recovery (M2). All act on a Stopped VM; their parameters are the typed Params.
	Resize          Type = "resize"
	Reinstall       Type = "reinstall"
	Snapshot        Type = "snapshot"
	RestoreSnapshot Type = "restore_snapshot"
	DeleteSnapshot  Type = "delete_snapshot"
	Backup          Type = "backup"
	// Restore (kind Backup) creates a NEW VM from a backup; Delete with kind Backup removes the backup.
	Restore Type = "restore"
	// Networking and VM configuration (M3). The network_* types act on a Svavyom-managed network (kind VirtualNetwork); Compute, ReserveIP and
	// ReleaseIP act on a Svavyom-managed VM.
	NetworkCreate    Type = "network_create"
	NetworkStart     Type = "network_start"
	NetworkStop      Type = "network_stop"
	NetworkAutostart Type = "network_autostart"
	NetworkDelete    Type = "network_delete"
	Compute          Type = "compute"
	ReserveIP        Type = "reserve_ip"
	ReleaseIP        Type = "release_ip"
	// Standalone data volumes (DR-023 D2). The kind is Volume and the resource id is the volume's own name; volume_attach carries the VM in Params.
	VolumeCreate Type = "volume_create"
	VolumeAttach Type = "volume_attach"
	VolumeDetach Type = "volume_detach"
	VolumeDelete Type = "volume_delete"
	// EjectISO removes the installation media of a Stopped VM created from an ISO (DR-023 D3); the VM then boots from its disk.
	EjectISO Type = "eject_iso"
	// BackupExport (kind Backup) copies a backup to an off-host target the operator declared (DR-023 D4).
	BackupExport Type = "backup_export"
	// Local operations (DR-024): they change only the platform's own records and never reach the host. alert_acknowledge has kind Event and the
	// alert id as resource id; schedule_set and schedule_clear have kind VM.
	AlertAcknowledge Type = "alert_acknowledge"
	ScheduleSet      Type = "schedule_set"
	ScheduleClear    Type = "schedule_clear"
	// Graphical console, installation media and rescue on an existing VM (DR-026). All four act on a Stopped Svavyom VM (kind VM).
	GraphicsEnable Type = "graphics_enable"
	ISOAttach      Type = "iso_attach"
	Rescue         Type = "rescue"
	Unrescue       Type = "unrescue"
)

// The resource kinds this package executes: VMs, and backups (restore creates a VM from one; delete removes one).
const (
	KindVM      = "VM"
	KindBackup  = "Backup"
	KindNetwork = "VirtualNetwork"
	KindVolume  = "Volume"
	KindEvent   = "Event"
)

// Error categories (subset of contracts/interfaces/errors.json).
const (
	CatValidation  = "validation"
	CatForbidden   = "forbidden"
	CatNotFound    = "not_found"
	CatConflict    = "conflict"
	CatUnavailable = "unavailable"
	CatTimeout     = "timeout"
	CatHostError   = "host_error"
	CatInternal    = "internal"
)

// Operation is the persisted record; the API-visible fields are exactly resources.json operation_persisted_fields.
// A Running operation whose ErrorCategory is "timeout" has an unknown host outcome. Spec is stored with the record but
// is internal to the operation manager and never part of the browser-api shape (hence `json:"-"`).
type Operation struct {
	ID             string
	ProjectID      string
	ResourceKind   string
	ResourceID     string
	Type           Type
	Status         Status
	IdempotencyKey string
	RequestedBy    string
	Generation     int64
	Attempts       int
	ErrorCategory  string
	CreatedAt      time.Time
	UpdatedAt      time.Time
	Spec           CreateSpec `json:"-"`
	Params         Params     `json:"-"`
	// UnknownOutcome is set, and never cleared, once an attempt of this operation may have reached the host without a
	// known result (a timeout, or a crash that reconciliation resolved to "not there yet"). Internal, like Spec. A create
	// with this mark must observe the host before it is sent again and treats a Conflict as "maybe my own late success".
	UnknownOutcome bool `json:"-"`
}

// Error is the only error type the manager returns. It carries a category and no free text from the host.
type Error struct{ Category string }

func (e *Error) Error() string { return "operation: " + e.Category }

func fail(category string) error { return &Error{Category: category} }

// CategoryOf returns the category of an error returned by this package, or "" for others.
func CategoryOf(err error) string {
	if e, ok := err.(*Error); ok {
		return e.Category
	}
	return ""
}

// Actor is a propagated caller identity. In M0 it is synthetic: authentication is M1-E04-S05 (DR-013).
type Actor struct{ ID string }

// Authorizer decides whether an actor may act in a project. It is deny by default: an implementation must return
// nil only for an affirmative grant.
type Authorizer interface {
	Authorize(actor Actor, projectID string, t Type) error
}

// AuditEvent is one audit record. It carries identifiers and categories only: never a secret, a raw host message
// or a path.
type AuditEvent struct {
	At            time.Time
	OperationID   string
	ProjectID     string
	Actor         string
	Event         string
	Outcome       string
	ErrorCategory string
}

// AuditSink receives audit events.
type AuditSink interface{ Emit(AuditEvent) }

var idRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$`)

// Request is a submit_operation request plus its project scope.
type Request struct {
	ProjectID      string
	Type           Type
	Kind           string
	ResourceID     string
	IdempotencyKey string
	// Spec is the requested definition of a create; zero selects the manager's defaults. It must be zero for other types.
	Spec CreateSpec
	// Params carries the typed inputs of the M2 operations (see Params). Zero for every other type.
	Params Params
}

// kindTypes is the closed matrix of which operation types apply to which resource kind.
var kindTypes = map[string][]Type{
	KindVM:      {Create, Start, Stop, Reboot, ForceOff, Delete, Resize, Reinstall, Snapshot, RestoreSnapshot, DeleteSnapshot, Backup, Compute, ReserveIP, ReleaseIP, EjectISO, ScheduleSet, ScheduleClear, GraphicsEnable, ISOAttach, Rescue, Unrescue},
	KindBackup:  {Restore, Delete, BackupExport},
	KindNetwork: {NetworkCreate, NetworkStart, NetworkStop, NetworkAutostart, NetworkDelete},
	KindVolume:  {VolumeCreate, VolumeAttach, VolumeDetach, VolumeDelete},
	KindEvent:   {AlertAcknowledge},
}

func typeAllowed(kind string, t Type) bool {
	for _, x := range kindTypes[kind] {
		if x == t {
			return true
		}
	}
	return false
}

func (r Request) validate() error {
	if !typeAllowed(r.Kind, r.Type) {
		return fail(CatValidation)
	}
	if r.Type != Create && !r.Spec.IsZero() {
		return fail(CatValidation)
	}
	if !r.Spec.IsZero() && (r.Spec.VCPUs < 1 || r.Spec.VCPUs > 64 || r.Spec.MemoryMiB < 64 || r.Spec.MemoryMiB > 1048576 ||
		r.Spec.DiskGiB < 0 || r.Spec.DiskGiB > 4096 || len(r.Spec.SSHPublicKey) > 2048) {
		return fail(CatValidation)
	}
	if r.Spec.UUID != "" || r.Spec.Fingerprint != "" || r.Spec.ImageSHA256 != "" || r.Spec.SSHFingerprint != "" || (r.Spec.Network != "" && !idRE.MatchString(r.Spec.Network)) {
		return fail(CatValidation) // server generated or server resolved fields can never come from the caller; the network may be CHOSEN (checked against the host by PrepareCreate)
	}
	if !r.Params.validFor(r.Type) {
		return fail(CatValidation)
	}
	if r.Kind == KindVolume && (!ParamVolumeRE.MatchString(r.ResourceID) || strings.HasSuffix(r.ResourceID, "-root")) {
		return fail(CatValidation)
	}
	for _, v := range []string{r.ProjectID, r.ResourceID, r.IdempotencyKey} {
		if !idRE.MatchString(v) {
			return fail(CatValidation)
		}
	}
	return nil
}

func (o Operation) String() string {
	return fmt.Sprintf("%s %s %s/%s", o.ID, o.Status, o.ResourceKind, o.ResourceID)
}
