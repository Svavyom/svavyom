package mutagent

import (
	"strings"
	"testing"

	"example.invalid/dedicatedcloud/backend/internal/provision"
)

// A VM created from installation media carries no SSH key. The request must pass the protocol check that a cloud-image request passes, so the real
// supervisor accepts it (the in-process test host skipped this path).
func TestProvisionRequestWithoutAKeyIsWellFormedForInstallationMedia(t *testing.T) {
	spec := provision.Spec{Name: "inst-1", UUID: "11111111-2222-4333-8444-555555555555", Fingerprint: strings.Repeat("cd", 32), VCPUs: 1, MemoryMiB: 512,
		ImageID: "alpine-iso", ImageSHA256: strings.Repeat("ab", 32), DiskGiB: 10, Network: "default"}
	if !(Request{V: Version, Op: OpProvision, Provision: &spec}).Valid() {
		t.Fatal("a provision request with no key must be well formed")
	}
	spec.SSHPublicKey = "not a key"
	if (Request{V: Version, Op: OpProvision, Provision: &spec}).Valid() {
		t.Fatal("a key that is present must still be a normalised key")
	}
}
