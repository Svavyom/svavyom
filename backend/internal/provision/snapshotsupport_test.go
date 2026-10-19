package provision

import "testing"

func TestSnapshotSupportByPoolType(t *testing.T) {
	for typ, want := range map[string]string{"dir": "available", "fs": "available", "netfs": "available", "logical": "unavailable", "rbd": "unavailable", "iscsi": "unavailable", "": "unknown"} {
		if got := SnapshotSupport(typ); got != want {
			t.Errorf("%q: %s, want %s", typ, got, want)
		}
	}
}
