// Package provision holds everything the VM-creation slice derives on the SERVER side: the typed create specification and its
// limits, SSH public-key normalisation, the image catalog, the NoCloud seed, the libvirt domain template and the step runner
// that provisions a VM on a host through a narrow HostOps interface. Nothing here accepts a path, XML, a URL or a shell
// fragment from a caller; every name that reaches the host is derived from the VM identity and server configuration.
package provision

import (
	"errors"
	"regexp"
	"slices"
	"strings"
)

// Product limits. The browser chooses from these lists only; the server enforces the same lists (narrowed by host capacity in
// Choices) and a hard ceiling here.
var (
	vcpuChoices   = []int{1, 2, 4, 8}
	memoryChoices = []int{512, 1024, 2048, 4096, 8192}
	diskChoices   = []int{10, 20, 40, 80, 160}
)

// VMNameRE is the name grammar of a Svavyom VM: a lower-case DNS label (it becomes the guest hostname and the libvirt domain
// name). It is a strict subset of the API id grammar.
var VMNameRE = regexp.MustCompile(`^[a-z]([a-z0-9-]{0,61}[a-z0-9])?$`)

var (
	uuidRE        = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	fingerprintRE = regexp.MustCompile(`^[0-9a-f]{64}$`)
	imageIDRE     = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,62}$`)
	resourceRE    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$`)
)

// Errors of the specification layer (they carry no caller input).
var (
	ErrInvalidSpec   = errors.New("provision: invalid specification")
	ErrInvalidConfig = errors.New("provision: invalid configuration")
)

// Spec is the complete, typed input of one provisioning request. UUID and Fingerprint are server generated at operation
// submission; ImageSHA256 is the catalog hash recorded then (the host refuses to build from an image that no longer matches).
type Spec struct {
	Name         string `json:"name"`
	UUID         string `json:"uuid"`
	Fingerprint  string `json:"fingerprint"`
	VCPUs        int    `json:"vcpus"`
	MemoryMiB    int    `json:"memory_mib"`
	ImageID      string `json:"image_id"`
	ImageSHA256  string `json:"image_sha256"`
	DiskGiB      int    `json:"disk_gib"`
	SSHPublicKey string `json:"ssh_public_key"` // normalised; empty for an ISO install
	Network      string `json:"network"`
	// Media is "iso" for installation media (DR-023 D3): then there is no SSH key, no seed and no cloud-init. It is never read from a request: the
	// step runner sets it from the catalog image the spec names, so nothing persisted has to carry it.
	Media string `json:"-"`
}

// IsISO reports whether the VM is created from installation media.
func (s Spec) IsISO() bool { return s.Media == MediaISO }

// validSSH checks the key: one normalised key, or (needKey false, installation media) none at all.
func (s Spec) validSSH(needKey bool) bool {
	if s.SSHPublicKey == "" {
		return !needKey
	}
	k, err := NormalizeSSHKey(s.SSHPublicKey)
	return err == nil && k.Authorized == s.SSHPublicKey
}

// Validate checks every field against its grammar and the hard product limits. The SSH key must already be normalised.
func (s Spec) Validate() error { return s.validate(true) }

// ValidateAnyMedia is Validate for a spec whose media is not yet known: the SSH key may be empty (an ISO install). The step runner requires a key for
// a cloud image and none for an ISO once it has read the catalog.
func (s Spec) ValidateAnyMedia() error { return s.validate(false) }

func (s Spec) validate(needKey bool) error {
	if !VMNameRE.MatchString(s.Name) || !uuidRE.MatchString(s.UUID) || !fingerprintRE.MatchString(s.Fingerprint) ||
		!imageIDRE.MatchString(s.ImageID) || !fingerprintRE.MatchString(s.ImageSHA256) || !resourceRE.MatchString(s.Network) ||
		!slices.Contains(vcpuChoices, s.VCPUs) || !slices.Contains(memoryChoices, s.MemoryMiB) || !slices.Contains(diskChoices, s.DiskGiB) {
		return ErrInvalidSpec
	}
	if !s.validSSH(needKey) {
		return ErrInvalidSpec
	}
	return nil
}

// Options are the values the UI may offer for this host: the product lists narrowed so a VM cannot be larger than the host
// can sensibly run (CPUs up to the host count, memory up to three quarters of host memory) and disks not below minDiskGiB.
type Options struct {
	VCPUs     []int `json:"vcpus"`
	MemoryMiB []int `json:"memory_mib"`
	DiskGiB   []int `json:"disk_gib"`
}

// Choices computes Options for a host with the given capacity (0 means unknown and yields the smallest choices only).
func Choices(hostCPUs, hostMemoryMiB int) Options {
	var o Options
	for _, v := range vcpuChoices {
		if v <= hostCPUs || v == vcpuChoices[0] {
			o.VCPUs = append(o.VCPUs, v)
		}
	}
	for _, m := range memoryChoices {
		if m*4 <= hostMemoryMiB*3 || m == memoryChoices[0] && hostMemoryMiB > 0 {
			o.MemoryMiB = append(o.MemoryMiB, m)
		}
	}
	o.DiskGiB = slices.Clone(diskChoices)
	return o
}

// DiskChoicesFor filters disk sizes to those an image can use.
func DiskChoicesFor(minDiskGiB int, all []int) []int {
	var out []int
	for _, d := range all {
		if d >= minDiskGiB {
			out = append(out, d)
		}
	}
	return out
}

// Names of the host objects, derived only from the VM identity (never from caller text). The UUID is server generated, so a
// name derived from it identifies the resources of exactly one create operation. The disks a create made carry no revision; a reinstall
// builds a new pair next to them under a server-generated revision token, switches the domain over, and only then removes the old pair, so an
// interrupted reinstall never touches the disk in use and a retry with the same token finds its own half-built volumes.
func RootVolumeName(uuid string) string { return RootVolumeNameRev(uuid, "") }

// SeedVolumeName is the NoCloud seed volume of a VM (no revision).
func SeedVolumeName(uuid string) string { return SeedVolumeNameRev(uuid, "") }

// RootVolumeNameRev is the root overlay of revision rev ("" for the disk a create made, else 8 lower-case hex digits).
func RootVolumeNameRev(uuid, rev string) string {
	if rev == "" {
		return "svavyom-" + uuid + "-root.qcow2"
	}
	return "svavyom-" + uuid + "-root-r" + rev + ".qcow2"
}

// SeedVolumeNameRev is the NoCloud seed of revision rev.
func SeedVolumeNameRev(uuid, rev string) string {
	if rev == "" {
		return "svavyom-" + uuid + "-seed.iso"
	}
	return "svavyom-" + uuid + "-seed-r" + rev + ".iso"
}

// DataVolumeName is the pool file of a standalone data volume (DR-023 D2). The "svavyom-vol-" prefix is the ownership marker in the name: Svavyom
// creates, attaches, detaches and deletes only volumes that carry it, and a root or seed volume can never be mistaken for one (their names differ).
func DataVolumeName(name string) string { return "svavyom-vol-" + name + ".qcow2" }

// DataNameRE is the grammar of a data volume's own name (the part after the prefix).
var DataNameRE = regexp.MustCompile(`^[a-z][a-z0-9-]{1,30}[a-z0-9]$`)

var dataVolFileRE = regexp.MustCompile(`^svavyom-vol-([a-z][a-z0-9-]{1,30}[a-z0-9])\.qcow2$`)

// ValidDataName reports whether name is a valid data volume name: the grammar, and not ending in "-root" (a root disk's resource id is "<vm>-root", so
// a data volume could otherwise take the id of a VM's root disk).
func ValidDataName(name string) bool {
	return DataNameRE.MatchString(name) && !strings.HasSuffix(name, "-root")
}

// ParseDataVolumeName recovers the data volume's name from its pool file name; ok is false for any other name.
func ParseDataVolumeName(file string) (name string, ok bool) {
	m := dataVolFileRE.FindStringSubmatch(file)
	if m == nil || !ValidDataName(m[1]) {
		return "", false
	}
	return m[1], true
}

// MaxDataDisks is the most data volumes one VM carries (targets vdb to vdi).
const MaxDataDisks = 8

// RevRE is the grammar of a revision token.
var RevRE = regexp.MustCompile(`^[0-9a-f]{8}$`)

var volNameRE = regexp.MustCompile(`^svavyom-([0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})-(root|seed)(?:-r([0-9a-f]{8}))?\.(qcow2|iso)$`)

// ParseVolumeName recovers (uuid, role, revision) from a Svavyom volume name; ok is false for any other name, including a role whose
// extension does not belong to it.
func ParseVolumeName(name string) (uuid, role, rev string, ok bool) {
	m := volNameRE.FindStringSubmatch(name)
	if m == nil || (m[2] == "root") != (m[4] == "qcow2") {
		return "", "", "", false
	}
	return m[1], m[2], m[3], true
}

// Hard ceilings for a VM that already exists (restore, reinstall, resize): the create-time choice lists do not apply to a disk that
// was grown or a VM whose compute was changed, only these limits do.
const (
	MaxDiskGiB   = 4096
	MaxVCPUs     = 64
	MaxMemoryMiB = 1048576
)

// ValidateExisting is Validate for a VM that already exists: the same grammars, the hard ceilings instead of the create-time choice lists.
func (s Spec) ValidateExisting() error {
	if !VMNameRE.MatchString(s.Name) || !uuidRE.MatchString(s.UUID) || !fingerprintRE.MatchString(s.Fingerprint) ||
		!imageIDRE.MatchString(s.ImageID) || !fingerprintRE.MatchString(s.ImageSHA256) || !resourceRE.MatchString(s.Network) ||
		s.VCPUs < 1 || s.VCPUs > MaxVCPUs || s.MemoryMiB < 64 || s.MemoryMiB > MaxMemoryMiB || s.DiskGiB < 1 || s.DiskGiB > MaxDiskGiB {
		return ErrInvalidSpec
	}
	if !s.validSSH(true) {
		return ErrInvalidSpec
	}
	return nil
}

// SeedCapacityBytes is the fixed size of every seed volume (the ISO is far smaller).
const SeedCapacityBytes = 2 << 20

// MAC returns the guest MAC address, derived from the UUID so a retried create defines the identical interface.
func MAC(uuid string) string {
	sum := sha256Sum([]byte("svavyom-mac-v1:" + uuid))
	const hex = "0123456789abcdef"
	b := []byte("52:54:00:00:00:00")
	for i := 0; i < 3; i++ {
		b[9+3*i] = hex[sum[i]>>4]
		b[10+3*i] = hex[sum[i]&0x0f]
	}
	return string(b)
}
