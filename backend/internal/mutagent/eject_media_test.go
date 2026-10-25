package mutagent

import (
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
