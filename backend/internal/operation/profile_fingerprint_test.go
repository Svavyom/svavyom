package operation

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"
	"testing"
)

// DR-032: a VM without a profile keeps the fingerprint it always had; a Windows VM's fingerprint covers the profile.
func TestProfileJoinsTheFingerprintOnlyWhenSet(t *testing.T) {
	c := CreateSpec{VCPUs: 2, MemoryMiB: 1024, UUID: "11111111-2222-4333-8444-555555555555", ImageID: "alpine-iso", ImageSHA256: "ab", DiskGiB: 20, Network: "svavyom-nat"}
	// the encoding before profiles existed, written out here so the test fails if the old fingerprint ever changes
	h := sha256.New()
	for _, part := range []string{"svavyom-create-v1", "inst-1", c.UUID, strconv.Itoa(c.VCPUs), strconv.Itoa(c.MemoryMiB), c.ImageID, c.ImageSHA256, strconv.Itoa(c.DiskGiB), c.SSHFingerprint, c.Network} {
		fmt.Fprintf(h, "%d:%s;", len(part), part)
	}
	old := hex.EncodeToString(h.Sum(nil))
	if got := ComputeFingerprint("inst-1", c); got != old {
		t.Fatalf("a spec without a profile changed its fingerprint: %s != %s", got, old)
	}
	c.Profile = "windows"
	if w := ComputeFingerprint("inst-1", c); w == old || len(w) != 64 {
		t.Fatalf("the profile is part of the identity: %s", w)
	}
	// the profile is a caller input: it survives Inputs, so a replay with another profile is a different request
	if c.Inputs().Profile != "windows" {
		t.Fatal("Inputs drops the profile")
	}
	d := c.DomainSpec("inst-1")
	if d.Profile != "windows" {
		t.Fatalf("the host adapter is told the profile: %+v", d)
	}
}
