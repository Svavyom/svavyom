package mutagent

import (
	"example.invalid/dedicatedcloud/backend/internal/provision"
	"strings"
	"testing"
)

// DR-031: an eject may name the medium to remove (by id and digest); nothing else may carry a Media.
func TestEjectRequestMayNameTheMedium(t *testing.T) {
	sha := strings.Repeat("a", 64)
	ok := []Request{
		{V: Version, Op: OpEjectISO, Name: "web-1"},
		{V: Version, Op: OpEjectISO, Name: "web-1", Media: &Media{ImageID: "tools-iso", ImageSHA256: sha}},
	}
	for _, q := range ok {
		if !q.Valid() {
			t.Errorf("refused: %+v", q)
		}
	}
	bad := map[string]Request{
		"a boot choice":     {V: Version, Op: OpEjectISO, Name: "web-1", Media: &Media{ImageID: "tools-iso", ImageSHA256: sha, Boot: "disk"}},
		"a bad digest":      {V: Version, Op: OpEjectISO, Name: "web-1", Media: &Media{ImageID: "tools-iso", ImageSHA256: "zz"}},
		"a bad image id":    {V: Version, Op: OpEjectISO, Name: "web-1", Media: &Media{ImageID: "../x", ImageSHA256: sha}},
		"no digest":         {V: Version, Op: OpEjectISO, Name: "web-1", Media: &Media{ImageID: "tools-iso"}},
		"an extra field":    {V: Version, Op: OpEjectISO, Name: "web-1", DiskGiB: 5},
		"a bad VM name":     {V: Version, Op: OpEjectISO, Name: "Web 1"},
		"media on a stop":   {V: Version, Op: OpStop, Name: "web-1", Media: &Media{ImageID: "tools-iso", ImageSHA256: sha}},
		"media on a delete": {V: Version, Op: OpDelete, Name: "web-1", Media: &Media{ImageID: "tools-iso", ImageSHA256: sha}},
	}
	for name, q := range bad {
		if q.Valid() {
			t.Errorf("%s accepted", name)
		}
	}
}

// DR-032: a provision request carries the profile in its spec, and only a valid one.
func TestProvisionRequestCarriesTheProfile(t *testing.T) {
	spec := provision.Spec{Name: "inst-1", UUID: "11111111-2222-4333-8444-555555555555", Fingerprint: strings.Repeat("cd", 32), VCPUs: 2, MemoryMiB: 1024,
		ImageID: "alpine-iso", ImageSHA256: strings.Repeat("ab", 32), DiskGiB: 20, Network: "svavyom-nat"}
	for _, p := range []string{"", "linux", "windows"} {
		spec.Profile = p
		if !(Request{V: Version, Op: OpProvision, Provision: &spec}).Valid() {
			t.Errorf("%q refused", p)
		}
	}
	for _, p := range []string{"Windows", "mac", "windows'/>"} {
		spec.Profile = p
		if (Request{V: Version, Op: OpProvision, Provision: &spec}).Valid() {
			t.Errorf("%q accepted", p)
		}
	}
}
