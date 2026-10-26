package operation

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"

	"example.invalid/dedicatedcloud/backend/internal/hypervisor"
)

// CreateSpec is the immutable desired definition of a `create` operation, fixed when the operation is accepted. It is what
// reconciliation compares the host against: domain existence alone never proves that this operation created the intended
// VM; the Svavyom identity (UUID and Fingerprint, written into the domain's ownership metadata) does.
//
// Typed values only: no XML, no paths, no free-form JSON/YAML. The browser supplies VCPUs, MemoryMiB, ImageID, DiskGiB and
// SSHPublicKey; the server fills ImageSHA256 (from its catalog), the normalised SSHPublicKey and its SSHFingerprint, the fixed
// Network profile, and generates UUID and Fingerprint at submission.
type CreateSpec struct {
	VCPUs          int
	MemoryMiB      int
	UUID           string // server generated, random (version 4)
	Fingerprint    string // sha256 over the immutable inputs and the UUID
	ImageID        string
	ImageSHA256    string
	DiskGiB        int
	SSHPublicKey   string // normalised authorized_keys form (type + base64), no options, no comment
	SSHFingerprint string // SHA256:... of the key
	Network        string // the single server-configured network profile
	// Profile is the guest profile of a VM from installation media (DR-032): "windows", or "" for linux. The server normalises "linux" to "".
	Profile string
}

// IsZero reports whether no definition was recorded.
func (c CreateSpec) IsZero() bool { return c == CreateSpec{} }

// Inputs is the part of the spec a caller chose, with everything server generated or server resolved cleared. Two
// submissions with the same key are the same request exactly when their Inputs are equal.
func (c CreateSpec) Inputs() CreateSpec {
	c.UUID, c.Fingerprint, c.ImageSHA256, c.SSHPublicKey = "", "", "", ""
	return c
}

// ComputeFingerprint derives the create fingerprint: sha256 over a versioned, length-delimited encoding of the VM name and
// every immutable spec field except the fingerprint itself.
func ComputeFingerprint(name string, c CreateSpec) string {
	h := sha256.New()
	for _, part := range []string{"svavyom-create-v1", name, c.UUID, strconv.Itoa(c.VCPUs), strconv.Itoa(c.MemoryMiB), c.ImageID,
		c.ImageSHA256, strconv.Itoa(c.DiskGiB), c.SSHFingerprint, c.Network} {
		fmt.Fprintf(h, "%d:%s;", len(part), part)
	}
	if c.Profile != "" { // a VM without a profile keeps the fingerprint it always had
		fmt.Fprintf(h, "%d:%s;", len("profile:"+c.Profile), "profile:"+c.Profile)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// DomainSpec is what the host adapter is asked to create for name.
func (c CreateSpec) DomainSpec(name string) hypervisor.DomainSpec {
	return hypervisor.DomainSpec{Name: name, VCPUs: c.VCPUs, MemoryMiB: c.MemoryMiB, UUID: c.UUID, Fingerprint: c.Fingerprint,
		ImageID: c.ImageID, ImageSHA256: c.ImageSHA256, DiskGiB: c.DiskGiB, SSHPublicKey: c.SSHPublicKey,
		SSHFingerprint: c.SSHFingerprint, Network: c.Network, Profile: c.Profile}
}

// newUUID returns a random RFC 4122 version 4 UUID in canonical lower-case form.
func newUUID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	h := hex.EncodeToString(b[:])
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:], nil
}
