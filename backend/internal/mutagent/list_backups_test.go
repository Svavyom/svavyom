package mutagent

import (
	"context"
	"fmt"
	"testing"
	"time"

	"example.invalid/dedicatedcloud/backend/internal/backupstore"
)

func summaries(n int) []backupstore.Summary {
	var l []backupstore.Summary
	for i := n; i >= 1; i-- { // newest first, as the store lists them
		var s backupstore.Summary
		s.Manifest.BackupID = fmt.Sprintf("bk-%016x", i)
		s.Valid = true
		l = append(l, s)
	}
	return l
}

// The reply says when a cap cut the list, for both the ordinary cap and the complete listing's (M0-E01-S08). A silently capped list made the scheduler's retention
// treat every backup beyond the cap as gone.
func TestListedBackupsSignalsTruncation(t *testing.T) {
	cases := []struct {
		have, limit int
		wantLen     int
		truncated   bool
	}{
		{0, 100, 0, false}, {99, 100, 99, false}, {100, 100, 100, false}, {101, 100, 100, true}, {150, 100, 100, true},
		{150, maxFullListedBackups, 150, false}, {maxFullListedBackups + 1, maxFullListedBackups, maxFullListedBackups, true},
	}
	for _, c := range cases {
		got, truncated := listedBackups(summaries(c.have), c.limit)
		if len(got) != c.wantLen || truncated != c.truncated {
			t.Errorf("%d backups, limit %d: got %d truncated=%v, want %d truncated=%v", c.have, c.limit, len(got), truncated, c.wantLen, c.truncated)
		}
		if len(got) > 0 && got[0].ID != fmt.Sprintf("bk-%016x", c.have) {
			t.Errorf("the newest must come first: %s", got[0].ID)
		}
	}
	if maxFullListedBackups <= maxListedBackups {
		t.Fatal("the complete listing must carry more than the ordinary one")
	}
}

// With the real supervisor, helper and backup store: more backups than the ordinary cap exist, the ordinary listing says it is cut, and the complete listing carries
// all of them and says it is not cut (the reviewer's 105-backup case).
func TestRealStoreWithMoreThanTheOrdinaryCap(t *testing.T) {
	if testing.Short() {
		t.Skip("creates 105 backups")
	}
	r := newRig(t, 60*time.Second, "")
	ctx := context.Background()
	r.withBackups()
	if err := r.client.Provision(ctx, r.spec); err != nil {
		t.Fatal(err)
	}
	const n = maxListedBackups + 5
	for i := 1; i <= n; i++ {
		if err := r.client.Backup(ctx, "web-1", fmt.Sprintf("bk-%016x", i)); err != nil {
			t.Fatalf("backup %d: %v", i, err)
		}
	}
	rep, err := r.client.call(ctx, Request{Op: OpListBackups})
	if err != nil || len(rep.Backups) != maxListedBackups || !rep.Truncated {
		t.Fatalf("ordinary listing: %d backups, truncated=%v, %v", len(rep.Backups), rep.Truncated, err)
	}
	l, truncated, err := r.client.ListBackupsComplete(ctx)
	if err != nil || len(l) != n || truncated {
		t.Fatalf("complete listing: %d backups, truncated=%v, %v", len(l), truncated, err)
	}
	seen := map[string]bool{}
	for _, b := range l {
		seen[b.ID] = true
	}
	for i := 1; i <= n; i++ {
		if !seen[fmt.Sprintf("bk-%016x", i)] {
			t.Fatalf("backup %d is missing from the complete listing", i)
		}
	}
}

// Full is a list_backups field only: every other operation refuses it, and list_backups takes it with nothing else.
func TestFullIsOnlyForListBackups(t *testing.T) {
	if !(Request{V: 1, Op: OpListBackups, Full: true}).Valid() {
		t.Fatal("list_backups with full refused")
	}
	if (Request{V: 1, Op: OpListBackups, Full: true, Name: "web-1"}).Valid() {
		t.Fatal("list_backups with full and a name accepted")
	}
	for _, op := range []string{OpStats, OpPreflight} {
		if (Request{V: 1, Op: op, Full: true}).Valid() {
			t.Fatalf("%s accepted full", op)
		}
	}
	if (Request{V: 1, Op: OpStart, Name: "web-1", Full: true}).Valid() {
		t.Fatal("start accepted full")
	}
}
