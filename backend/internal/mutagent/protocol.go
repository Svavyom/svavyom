// Package mutagent is the MUTATING host-agent boundary of the VM-creation slice: a separate Unix socket and a separate, closed
// protocol from the read-only inventory agent (package agent), served by a supervisor that never links libvirt. Each request is
// executed by a short-lived helper process under a hard deadline; if the helper exceeds it, the whole process group is killed
// and reaped and the caller is told the outcome is UNKNOWN (category timeout), because killing a helper proves nothing about
// what it already did. The operation manager then reconciles by observation.
//
// Operations (closed set): preflight (read-only readiness), provision (define a stopped, Svavyom-owned VM), start, stop (graceful),
// reboot (guest), force_off (immediate power-off, separate and explicit), delete (ownership-proving removal of a stopped VM, its volumes and its
// definition), and the M2 storage and recovery operations: resize (grow only), reinstall, snapshot / restore_snapshot / delete_snapshot, backup,
// restore, delete_backup, plus the read-only list_backups and stats. Every operation names one VM or one backup by id; none carries XML, a path, a
// volume name or a shell fragment, and there is no network mutation.
package mutagent

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"regexp"

	"example.invalid/dedicatedcloud/backend/internal/backupstore"
	"example.invalid/dedicatedcloud/backend/internal/provision"
)

// Protocol limits.
const (
	Version         = 1
	MaxRequestBytes = 8 << 10
	MaxReplyBytes   = 64 << 10
)

// Operations.
const (
	OpPreflight = "preflight"
	OpProvision = "provision"
	OpStart     = "start"
	OpStop      = "stop"
	OpReboot    = "reboot"
	OpForceOff  = "force_off"
	OpDelete    = "delete"
	// M2 storage and recovery.
	OpResize          = "resize"
	OpReinstall       = "reinstall"
	OpSnapshot        = "snapshot"
	OpRestoreSnapshot = "restore_snapshot"
	OpDeleteSnapshot  = "delete_snapshot"
	OpBackup          = "backup"
	OpRestore         = "restore"
	OpDeleteBackup    = "delete_backup"
	OpListBackups     = "list_backups"
	OpStats           = "stats"
	// M3 networks and VM configuration. The network operations name a Svavyom-managed network; compute, reserve_ip and release_ip name a VM.
	OpNetCreate    = "net_create"
	OpNetStart     = "net_start"
	OpNetStop      = "net_stop"
	OpNetAutostart = "net_autostart"
	OpNetDelete    = "net_delete"
	OpCompute      = "compute"
	OpReserveIP    = "reserve_ip"
	OpReleaseIP    = "release_ip"
	// Standalone data volumes (DR-023 D2): Name is the volume's own name; volume_create takes DiskGiB and volume_attach the VM.
	OpVolCreate = "volume_create"
	OpVolAttach = "volume_attach"
	OpVolDetach = "volume_detach"
	OpVolDelete = "volume_delete"
	// OpEjectISO removes the installation media of a stopped VM (DR-023 D3).
	OpEjectISO = "eject_iso"
	// Graphical console, installation media and rescue on an existing stopped VM (DR-026).
	OpGraphicsEnable = "graphics_enable"
	OpISOAttach      = "iso_attach"
	OpRescue         = "rescue"
	OpUnrescue       = "unrescue"
)

// only reports whether the scalar fields of n are exactly those of w and no host prefix is carried.
func (n *Net) only(w Net) bool {
	return len(n.Avoid) == 0 && n.UUID == w.UUID && n.Subnet == w.Subnet && n.DHCPStart == w.DHCPStart && n.DHCPEnd == w.DHCPEnd && n.HostBridge == w.HostBridge && n.Autostart == w.Autostart &&
		n.IP == w.IP && n.VCPUs == w.VCPUs && n.MemoryMiB == w.MemoryMiB
}

// MaxAvoid bounds the host prefixes a network_create may carry.
const MaxAvoid = 64

// LongOps are the operations that may move gigabytes and therefore get the long deadline.
func LongOp(op string) bool {
	switch op {
	case OpBackup, OpRestore, OpReinstall:
		return true
	}
	return false
}

// Request is the only message a client may send. Exactly the fields an operation takes may be set (Valid); none is a path, XML or free text.
type Request struct {
	V         int             `json:"v"`
	Op        string          `json:"op"`
	Name      string          `json:"name,omitempty"`
	Provision *provision.Spec `json:"provision,omitempty"`
	// DiskGiB (resize), ID (snapshot or backup id), Reinstall and Restore carry the typed inputs of the M2 operations.
	DiskGiB   int        `json:"disk_gib,omitempty"`
	ID        string     `json:"id,omitempty"`
	Reinstall *Reinstall `json:"reinstall,omitempty"`
	Restore   *Restore   `json:"restore,omitempty"`
	Net       *Net       `json:"net,omitempty"`
	// VM is the VM a data volume is attached to (volume_attach only).
	VM string `json:"vm,omitempty"`
	// Media names the catalog ISO of iso_attach and rescue by id and digest (the helper re-verifies the file); Boot is only for iso_attach.
	Media *Media `json:"media,omitempty"`
}

// Media is the input of iso_attach and rescue.
type Media struct {
	ImageID     string `json:"image_id"`
	ImageSHA256 string `json:"image_sha256"`
	Boot        string `json:"boot,omitempty"` // iso_attach: cdrom | disk
}

// Net carries the typed inputs of the M3 operations. Avoid lists the host's own subnets and routes as the API found them (the confined helper cannot
// see them): extra reasons to REFUSE a new network, never a way to allow one.
type Net struct {
	UUID      string `json:"uuid,omitempty"`
	Subnet    string `json:"subnet,omitempty"`
	DHCPStart string `json:"dhcp_start,omitempty"`
	DHCPEnd   string `json:"dhcp_end,omitempty"`
	// HostBridge makes network_create a bridge-mode network on that existing host bridge (no subnet, no DHCP range, no avoid list).
	HostBridge string   `json:"host_bridge,omitempty"`
	Avoid      []string `json:"avoid,omitempty"`
	Autostart  string   `json:"autostart,omitempty"`
	IP         string   `json:"ip,omitempty"`
	VCPUs      int      `json:"vcpus,omitempty"`
	MemoryMiB  int      `json:"memory_mib,omitempty"`
}

// Reinstall is the input of a reinstall.
type Reinstall struct {
	ImageID      string `json:"image_id"`
	ImageSHA256  string `json:"image_sha256"`
	SSHPublicKey string `json:"ssh_public_key"`
	Rev          string `json:"rev"`
}

// Restore is the input of a restore: the new VM's name is Request.Name, the backup is Request.ID.
type Restore struct {
	UUID         string `json:"uuid"`
	Fingerprint  string `json:"fingerprint"`
	SSHPublicKey string `json:"ssh_public_key"`
}

// BackupSummary is one backup as listed.
type BackupSummary struct {
	ID        string `json:"id"`
	VM        string `json:"vm"`
	CreatedAt string `json:"created_at"`
	SizeBytes int64  `json:"size_bytes"`
	DiskGiB   int    `json:"disk_gib"`
	ImageID   string `json:"image_id"`
	Valid     bool   `json:"valid"`
}

// Stats are the storage facts the Host summary shows: the configured pool and the backup store (zero BackupDir facts when none is configured).
type Stats struct {
	PoolCapacity   int64 `json:"pool_capacity"`
	PoolAvailable  int64 `json:"pool_available"`
	PoolAllocation int64 `json:"pool_allocation"`
	BackupsKnown   bool  `json:"backups_known"`
	BackupBytes    int64 `json:"backup_bytes"`
	BackupFree     int64 `json:"backup_free"`
	BackupTotal    int64 `json:"backup_total,omitempty"` // the size of the backup store's filesystem; 0 from an older helper
	// Snapshots is whether the pool can hold Svavyom's internal qcow2 snapshots: available | unavailable | unknown (DR-023 D6).
	Snapshots string `json:"snapshots"`
}

// Preflight is the readiness reported for the configured network and pool.
type Preflight struct {
	Network string `json:"network"`
	Pool    string `json:"pool"`
}

// Reply is the only message the supervisor sends. On failure OK is false and Category is a hypervisor category.
type Reply struct {
	V         int             `json:"v"`
	OK        bool            `json:"ok"`
	Category  string          `json:"category,omitempty"`
	Preflight *Preflight      `json:"preflight,omitempty"`
	Backups   []BackupSummary `json:"backups,omitempty"`
	Stats     *Stats          `json:"stats,omitempty"`
}

// Valid reports whether the request is well formed for its operation: the operation's fields in their grammars and nothing else.
func (q Request) Valid() bool {
	if q.V != Version {
		return false
	}
	extra := q.DiskGiB != 0 || q.ID != "" || q.Reinstall != nil || q.Restore != nil || q.Net != nil || q.VM != "" || q.Media != nil
	if q.Media != nil && q.Op != OpISOAttach && q.Op != OpRescue {
		return false
	}
	vm := provision.VMNameRE.MatchString(q.Name)
	snap := provision.SnapshotIDRE.MatchString(q.ID)
	switch q.Op {
	case OpPreflight, OpListBackups, OpStats:
		return q.Name == "" && q.Provision == nil && !extra
	case OpProvision:
		return q.Name == "" && q.Provision != nil && q.Provision.ValidateAnyMedia() == nil && !extra
	case OpStart, OpStop, OpReboot, OpForceOff, OpDelete, OpEjectISO, OpGraphicsEnable, OpUnrescue:
		return vm && q.Provision == nil && !extra
	case OpISOAttach, OpRescue:
		m := q.Media
		return vm && q.Provision == nil && m != nil && imageIDOK(m.ImageID) && sha256OK(m.ImageSHA256) && q.DiskGiB == 0 && q.ID == "" && q.Reinstall == nil &&
			q.Restore == nil && q.Net == nil && q.VM == "" && ((q.Op == OpISOAttach && (m.Boot == "cdrom" || m.Boot == "disk")) || (q.Op == OpRescue && m.Boot == ""))
	case OpResize:
		return vm && q.Provision == nil && q.DiskGiB >= 1 && q.DiskGiB <= provision.MaxDiskGiB && q.ID == "" && q.Reinstall == nil && q.Restore == nil
	case OpSnapshot, OpRestoreSnapshot, OpDeleteSnapshot:
		return vm && q.Provision == nil && snap && q.DiskGiB == 0 && q.Reinstall == nil && q.Restore == nil
	case OpBackup:
		return vm && q.Provision == nil && backupIDOK(q.ID) && q.DiskGiB == 0 && q.Reinstall == nil && q.Restore == nil
	case OpDeleteBackup:
		return q.Name == "" && q.Provision == nil && backupIDOK(q.ID) && q.DiskGiB == 0 && q.Reinstall == nil && q.Restore == nil
	case OpReinstall:
		r := q.Reinstall
		return vm && q.Provision == nil && r != nil && q.ID == "" && q.DiskGiB == 0 && q.Restore == nil && provision.RevRE.MatchString(r.Rev) &&
			imageIDOK(r.ImageID) && sha256OK(r.ImageSHA256) && keyOK(r.SSHPublicKey)
	case OpNetStart, OpNetStop, OpNetDelete:
		return provision.NetNameOK(q.Name) && q.Provision == nil && !extra
	case OpNetCreate:
		n := q.Net
		if !provision.NetNameOK(q.Name) || q.Provision != nil || n == nil || q.DiskGiB != 0 || q.ID != "" || q.Reinstall != nil || q.Restore != nil || len(n.Avoid) > MaxAvoid ||
			n.Autostart != "" || n.IP != "" || n.VCPUs != 0 || n.MemoryMiB != 0 {
			return false
		}
		if (provision.NetworkSpec{Name: q.Name, UUID: n.UUID, Subnet: n.Subnet, DHCPStart: n.DHCPStart, DHCPEnd: n.DHCPEnd, HostBridge: n.HostBridge}).Validate() != nil {
			return false
		}
		if n.HostBridge != "" && len(n.Avoid) != 0 {
			return false // a bridge-mode network has no subnet to keep apart from anything
		}
		for _, a := range n.Avoid {
			if _, err := provision.ParsePrefixStrict(a); err != nil {
				return false
			}
		}
		return true
	case OpNetAutostart:
		n := q.Net
		return provision.NetNameOK(q.Name) && q.Provision == nil && n != nil && (n.Autostart == "on" || n.Autostart == "off") && n.only(Net{Autostart: n.Autostart}) &&
			q.DiskGiB == 0 && q.ID == "" && q.Reinstall == nil && q.Restore == nil
	case OpCompute:
		n := q.Net
		return vm && q.Provision == nil && n != nil && n.VCPUs >= 1 && n.VCPUs <= provision.MaxVCPUs && n.MemoryMiB >= provision.MinMemoryMiB &&
			n.MemoryMiB <= provision.MaxMemoryMiB && n.MemoryMiB%provision.MinMemoryMiB == 0 && n.only(Net{VCPUs: n.VCPUs, MemoryMiB: n.MemoryMiB}) &&
			q.DiskGiB == 0 && q.ID == "" && q.Reinstall == nil && q.Restore == nil
	case OpReserveIP:
		n := q.Net
		return vm && q.Provision == nil && n != nil && provision.IsIPv4(n.IP) && n.only(Net{IP: n.IP}) && q.DiskGiB == 0 && q.ID == "" && q.Reinstall == nil && q.Restore == nil
	case OpReleaseIP:
		return vm && q.Provision == nil && !extra
	case OpVolCreate:
		return provision.ValidDataName(q.Name) && q.Provision == nil && q.DiskGiB >= 1 && q.DiskGiB <= provision.MaxDiskGiB && q.ID == "" && q.Reinstall == nil &&
			q.Restore == nil && q.Net == nil && q.VM == ""
	case OpVolAttach:
		return provision.ValidDataName(q.Name) && q.Provision == nil && vmNameOK(q.VM) && q.DiskGiB == 0 && q.ID == "" && q.Reinstall == nil && q.Restore == nil && q.Net == nil
	case OpVolDetach, OpVolDelete:
		return provision.ValidDataName(q.Name) && q.Provision == nil && !extra
	case OpRestore:
		r := q.Restore
		return vm && q.Provision == nil && r != nil && backupIDOK(q.ID) && q.DiskGiB == 0 && q.Reinstall == nil && uuidOK(r.UUID) && sha256OK(r.Fingerprint) && keyOK(r.SSHPublicKey)
	}
	return false
}

func vmNameOK(s string) bool { return provision.VMNameRE.MatchString(s) }

func backupIDOK(id string) bool { return backupstore.ValidID(id) }

func imageIDOK(s string) bool {
	return regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,62}$`).MatchString(s)
}

func sha256OK(s string) bool { return regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(s) }

func uuidOK(s string) bool {
	return regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`).MatchString(s)
}

// keyOK accepts only a key that is already in the normalised one-line form.
func keyOK(s string) bool {
	k, err := provision.NormalizeSSHKey(s)
	return err == nil && k.Authorized == s
}

var errFrame = errors.New("mutagent: bad frame")

func writeFrame(w io.Writer, v any, max int) error {
	body, err := json.Marshal(v)
	if err != nil || len(body) > max {
		return errFrame
	}
	buf := make([]byte, 4+len(body))
	binary.BigEndian.PutUint32(buf, uint32(len(body))) // #nosec G115 -- bounded by max
	copy(buf[4:], body)
	_, err = w.Write(buf)
	return err
}

func readFrame(r io.Reader, dst any, max int) error {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n == 0 || int64(n) > int64(max) {
		return errFrame
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(r, body); err != nil {
		return err
	}
	return decodeStrict(body, dst)
}

// decodeStrict decodes exactly one JSON value: no unknown fields, no trailing data.
func decodeStrict(body []byte, dst any) error {
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return errFrame
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return errFrame
	}
	return nil
}

func writeJSON(w io.Writer, v any) error {
	b, err := json.Marshal(v)
	if err != nil || len(b) > MaxReplyBytes {
		return errFrame
	}
	_, err = w.Write(b)
	return err
}
