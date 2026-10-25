package operation

import (
	"strings"
	"testing"
)

// DR-031: eject_iso takes an optional image_id; what the caller may send and what a stored operation must carry.
func TestEjectISOParameters(t *testing.T) {
	good := []Params{{}, {ImageID: "tools-iso"}}
	for _, p := range good {
		if !p.ValidFor(EjectISO) {
			t.Errorf("%+v refused", p)
		}
	}
	bad := map[string]Params{
		"boot":          {ImageID: "tools-iso", Boot: "disk"},
		"boot alone":    {Boot: "disk"},
		"capitals":      {ImageID: "Tools"},
		"a path":        {ImageID: "../tools-iso"},
		"too long":      {ImageID: strings.Repeat("a", 64)},
		"a digest":      {ImageID: "tools-iso", ImageSHA256: strings.Repeat("a", 64)},
		"another field": {ImageID: "tools-iso", DiskGiB: 10},
		"only a digest": {ImageSHA256: strings.Repeat("a", 64)},
	}
	for name, p := range bad {
		if p.ValidFor(EjectISO) {
			t.Errorf("%s accepted: %+v", name, p)
		}
	}
	// the other types are unchanged: none of them take an image_id they did not take before
	for _, ty := range []Type{Start, Stop, Delete, Snapshot, Backup, GraphicsEnable, Unrescue} {
		if (Params{ImageID: "tools-iso"}).ValidFor(ty) {
			t.Errorf("%s accepts image_id", ty)
		}
	}
	// a stored eject names no medium, or names one with its resolved digest, never a half
	if !(Params{}).complete(EjectISO, "web-1") || !(Params{ImageID: "tools-iso", ImageSHA256: strings.Repeat("a", 64)}).complete(EjectISO, "web-1") {
		t.Error("complete forms refused")
	}
	if (Params{ImageID: "tools-iso"}).complete(EjectISO, "web-1") || (Params{ImageSHA256: strings.Repeat("a", 64)}).complete(EjectISO, "web-1") {
		t.Error("a half-resolved eject accepted")
	}
}
