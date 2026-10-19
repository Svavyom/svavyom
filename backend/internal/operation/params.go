package operation

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"regexp"
	"strings"
)

// Params are the typed inputs of the storage and recovery operations, fixed when the operation is accepted and persisted with it (like
// CreateSpec for a create). No XML, no path, no volume name, no free text: every value has a closed grammar. The browser chooses DiskGiB, ImageID,
// SSHPublicKey, SnapshotID (to restore or delete an existing one) and NewName; the server resolves ImageSHA256 and generates Rev, SnapshotID (for a new
// snapshot), BackupID, NewUUID and NewFingerprint at submission, so a retry after an unknown outcome repeats exactly the same request.
type Params struct {
	DiskGiB      int    `json:"disk_gib,omitempty"`        // resize: the new size
	ImageID      string `json:"image_id,omitempty"`        // reinstall: the qualified image
	ImageSHA256  string `json:"image_sha256,omitempty"`    // reinstall: server resolved
	SSHPublicKey string `json:"ssh_public_key,omitempty"`  // reinstall, restore: normalised
	Rev          string `json:"rev,omitempty"`             // reinstall: server generated revision token
	SnapshotID   string `json:"snapshot_id,omitempty"`     // snapshot (server generated), restore_snapshot, delete_snapshot
	BackupID     string `json:"backup_id,omitempty"`       // backup (server generated)
	NewName      string `json:"new_name,omitempty"`        // restore: the new VM's name
	NewUUID      string `json:"new_uuid,omitempty"`        // restore: server generated
	NewFinger    string `json:"new_fingerprint,omitempty"` // restore: server generated
	// M3. NewUUID doubles as the managed network's UUID (network_create, server generated).
	Subnet    string `json:"subnet,omitempty"`     // network_create: CIDR
	DHCPStart string `json:"dhcp_start,omitempty"` // network_create
	DHCPEnd   string `json:"dhcp_end,omitempty"`   // network_create
	Bridge    string `json:"bridge,omitempty"`     // network_create: a bridge-mode network on this existing host bridge (DR-024 D5); then no subnet and no DHCP range
	Autostart string `json:"autostart,omitempty"`  // network_autostart: "on" | "off"
	VCPUs     int    `json:"vcpus,omitempty"`      // compute
	MemoryMiB int    `json:"memory_mib,omitempty"` // compute
	IPAddress string `json:"ip_address,omitempty"` // reserve_ip
	// DR-023 D2. volume_create uses DiskGiB.
	VMID string `json:"vm_id,omitempty"` // volume_attach: the VM (a Svavyom VM name)
	// DR-023 D4.
	TargetID string `json:"target_id,omitempty"` // backup_export: one of the off-host targets the operator declared; schedule_set: optional copy target
	// DR-024 D3. schedule_set: exactly one of EveryHours and At; DowntimeAck must be true (the person scheduling saw the downtime warning).
	EveryHours  int    `json:"every_hours,omitempty"`
	At          string `json:"at,omitempty"` // HH:MM, host local time
	KeepLocal   int    `json:"keep_local,omitempty"`
	KeepOffsite int    `json:"keep_offsite,omitempty"`
	DowntimeAck bool   `json:"downtime_acknowledged,omitempty"`
	// DR-026. iso_attach and rescue take ImageID (a catalog ISO, digest resolved by the server into ImageSHA256); iso_attach also takes Boot.
	Boot string `json:"boot,omitempty"` // iso_attach: "cdrom" boots from the media next time, "disk" just attaches it
}

var (
	paramSnapRE   = regexp.MustCompile(`^snap-[0-9a-f]{12}$`)
	paramBackupRE = regexp.MustCompile(`^bk-[0-9a-f]{16}$`)
	paramRevRE    = regexp.MustCompile(`^[0-9a-f]{8}$`)
	paramNameRE   = regexp.MustCompile(`^[a-z]([a-z0-9-]{0,61}[a-z0-9])?$`)
	paramImageRE  = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,62}$`)
	paramUUIDRE   = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	paramHexRE    = regexp.MustCompile(`^[0-9a-f]{64}$`)
	paramBridgeRE = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9_.:-]{0,14}$`)
	paramCIDRRE   = regexp.MustCompile(`^[0-9]{1,3}(\.[0-9]{1,3}){3}/[0-9]{1,2}$`)
	// ParamVolumeRE is the grammar of a data volume's name (the resource id of kind Volume).
	ParamVolumeRE = regexp.MustCompile(`^[a-z][a-z0-9-]{1,30}[a-z0-9]$`)
	paramAtRE     = regexp.MustCompile(`^([01][0-9]|2[0-3]):[0-5][0-9]$`)
	paramIPv4RE   = regexp.MustCompile(`^[0-9]{1,3}(\.[0-9]{1,3}){3}$`)
)

// IsZero reports whether no parameter is set.
func (p Params) IsZero() bool { return p == Params{} }

// serverFilled reports whether any server-generated or server-resolved field is set.
func (p Params) serverFilled() bool {
	return p.ImageSHA256 != "" || p.Rev != "" || p.BackupID != "" || p.NewUUID != "" || p.NewFinger != ""
}

// Inputs is the part of the parameters a caller chose, with everything the server generates or resolves cleared: two submissions with the same
// idempotency key are the same request exactly when their Inputs are equal.
func (p Params) Inputs() Params {
	p.ImageSHA256, p.Rev, p.BackupID, p.NewUUID, p.NewFinger = "", "", "", "", ""
	return p
}

// ValidFor reports whether a caller's parameters are acceptable for the type (the API checks this before any precheck, so a malformed request is a
// validation error rather than whatever the host state would have said first).
func (p Params) ValidFor(t Type) bool { return p.validFor(t) }

// validFor checks a caller's parameters for the type: exactly the fields that type takes, in their grammars, and no server-filled field.
func (p Params) validFor(t Type) bool {
	if p.serverFilled() {
		return false
	}
	key := func(s string) bool { return len(s) >= 1 && len(s) <= 2048 && !strings.ContainsAny(s, "\r\n\x00") }
	switch t {
	case Resize:
		return p.DiskGiB >= 1 && p.DiskGiB <= 4096 && p == Params{DiskGiB: p.DiskGiB}
	case Reinstall:
		return paramImageRE.MatchString(p.ImageID) && key(p.SSHPublicKey) && p == Params{ImageID: p.ImageID, SSHPublicKey: p.SSHPublicKey}
	case RestoreSnapshot, DeleteSnapshot:
		return paramSnapRE.MatchString(p.SnapshotID) && p == Params{SnapshotID: p.SnapshotID}
	case Restore:
		return paramNameRE.MatchString(p.NewName) && key(p.SSHPublicKey) && p == Params{NewName: p.NewName, SSHPublicKey: p.SSHPublicKey}
	case NetworkCreate:
		if p.Bridge != "" {
			return paramBridgeRE.MatchString(p.Bridge) && p == Params{Bridge: p.Bridge}
		}
		return paramCIDRRE.MatchString(p.Subnet) && paramIPv4RE.MatchString(p.DHCPStart) && paramIPv4RE.MatchString(p.DHCPEnd) &&
			p == Params{Subnet: p.Subnet, DHCPStart: p.DHCPStart, DHCPEnd: p.DHCPEnd}
	case NetworkAutostart:
		return (p.Autostart == "on" || p.Autostart == "off") && p == Params{Autostart: p.Autostart}
	case Compute:
		return p.VCPUs >= 1 && p.VCPUs <= 64 && p.MemoryMiB >= 64 && p.MemoryMiB <= 1048576 && p.MemoryMiB%64 == 0 && p == Params{VCPUs: p.VCPUs, MemoryMiB: p.MemoryMiB}
	case ReserveIP:
		return paramIPv4RE.MatchString(p.IPAddress) && p == Params{IPAddress: p.IPAddress}
	case BackupExport:
		return ParamVolumeRE.MatchString(p.TargetID) && p == Params{TargetID: p.TargetID}
	case ScheduleSet:
		return p.validSchedule()
	case ISOAttach:
		return paramImageRE.MatchString(p.ImageID) && (p.Boot == "cdrom" || p.Boot == "disk") && p == Params{ImageID: p.ImageID, Boot: p.Boot}
	case Rescue:
		return paramImageRE.MatchString(p.ImageID) && p == Params{ImageID: p.ImageID}
	case VolumeCreate:
		return p.DiskGiB >= 1 && p.DiskGiB <= 4096 && p == Params{DiskGiB: p.DiskGiB}
	case VolumeAttach:
		return paramNameRE.MatchString(p.VMID) && p == Params{VMID: p.VMID}
	}
	return p.IsZero() // create, start, stop, reboot, force_off, delete, snapshot, backup, network_start/stop/delete, release_ip take none from the caller
}

// validSchedule checks the parameters of schedule_set: one cadence, bounded retention, an optional target (required when off-host copies are kept),
// and the acknowledgement that the VM goes down during the window.
func (p Params) validSchedule() bool {
	if (p.EveryHours == 0) == (p.At == "") || !p.DowntimeAck {
		return false
	}
	if p.EveryHours != 0 && (p.EveryHours < 1 || p.EveryHours > 168) || p.At != "" && !paramAtRE.MatchString(p.At) {
		return false
	}
	if p.KeepLocal < 1 || p.KeepLocal > 30 || p.KeepOffsite < 0 || p.KeepOffsite > 30 {
		return false
	}
	if p.TargetID != "" && !ParamVolumeRE.MatchString(p.TargetID) || (p.KeepOffsite > 0) != (p.TargetID != "") {
		return false // off-host copies need a target and a target is only named to keep copies there
	}
	return p == Params{EveryHours: p.EveryHours, At: p.At, KeepLocal: p.KeepLocal, KeepOffsite: p.KeepOffsite, DowntimeAck: true, TargetID: p.TargetID}
}

// complete reports whether a stored operation of type t carries every field its execution needs (after the server filled its part).
func (p Params) complete(t Type, resourceID string) bool {
	switch t {
	case Resize:
		return p.DiskGiB >= 1 && p.DiskGiB <= 4096
	case Reinstall:
		return paramImageRE.MatchString(p.ImageID) && paramHexRE.MatchString(p.ImageSHA256) && paramRevRE.MatchString(p.Rev) && p.SSHPublicKey != ""
	case Snapshot, RestoreSnapshot, DeleteSnapshot:
		return paramSnapRE.MatchString(p.SnapshotID)
	case Backup:
		return paramBackupRE.MatchString(p.BackupID)
	case NetworkCreate:
		return paramUUIDRE.MatchString(p.NewUUID) && (p.Subnet != "" || p.Bridge != "")
	case BackupExport:
		return ParamVolumeRE.MatchString(p.TargetID) && paramBackupRE.MatchString(resourceID)
	case ScheduleSet:
		return p.validSchedule()
	case VolumeCreate:
		return p.DiskGiB >= 1 && p.DiskGiB <= 4096
	case VolumeAttach:
		return paramNameRE.MatchString(p.VMID)
	case Restore:
		return paramBackupRE.MatchString(resourceID) && paramNameRE.MatchString(p.NewName) && paramUUIDRE.MatchString(p.NewUUID) && paramHexRE.MatchString(p.NewFinger) && p.SSHPublicKey != ""
	}
	return true
}

// ErrParams means a stored parameter blob is not acceptable.
var ErrParams = errors.New("operation: invalid stored parameters")

// MarshalParams encodes p for storage ("" for none).
func MarshalParams(p Params) (string, error) {
	if p.IsZero() {
		return "", nil
	}
	b, err := json.Marshal(p)
	if err != nil || len(b) > 4096 {
		return "", ErrParams
	}
	return string(b), nil
}

// UnmarshalParams decodes a stored blob strictly.
func UnmarshalParams(s string) (Params, error) {
	if s == "" {
		return Params{}, nil
	}
	if len(s) > 4096 {
		return Params{}, ErrParams
	}
	var p Params
	dec := json.NewDecoder(strings.NewReader(s))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		return Params{}, ErrParams
	}
	return p, nil
}

func randHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func restoreFingerprint(backupID, uuid, name string) string {
	sum := sha256.Sum256([]byte("svavyom-restore-v1:" + backupID + ":" + uuid + ":" + name))
	return hex.EncodeToString(sum[:])
}
