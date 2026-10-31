package schedule

import (
	"context"
	"fmt"
	"testing"
	"time"

	"example.invalid/dedicatedcloud/backend/internal/operation"
)

// Retention works on the complete list: with far more than 100 backups made by the scheduler the ones beyond the keep count are all deleted, and none of the scheduler's
// records is forgotten while its backup is still on disk (M0-E01-S08). A listing capped at 100 used to make everything beyond the cap look gone.
func TestRetentionWithMoreThanAHundredBackups(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	const n = 150
	var made []string
	for i := 1; i <= n; i++ {
		id := fmt.Sprintf("bk-%016x", i+1000)
		made = append(made, id)
		_ = r.store.Made(ctx, id, "web-1", "earlier", r.now.Add(time.Duration(i)*time.Minute-time.Hour*24*400))
		r.world.backups = append(r.world.backups, BackupInfo{ID: id, VM: "web-1", Valid: true})
	}
	r.set("web-1", Spec{EveryHours: 1, KeepLocal: 2})
	newest := fullWindow(r, "web-1")
	r.tick(10 * time.Second)
	dels := r.ops.of(operation.Delete)
	if len(dels) != n-1 { // the 150 earlier ones and the new one are 151; two are kept
		t.Fatalf("expected %d deletes (every backup beyond the two newest, including the ones past a 100-entry list), got %d", n-1, len(dels))
	}
	got := map[string]bool{}
	for _, d := range dels {
		got[d.ResourceID] = true
	}
	if got[newest] || got[made[n-1]] {
		t.Fatalf("the two newest must stay: %v %v", got[newest], got[made[n-1]])
	}
	if !got[made[0]] || !got[made[n-3]] {
		t.Fatal("the oldest backups beyond the keep count must go")
	}
	kept, err := r.store.MadeBy(ctx, "web-1")
	if err != nil || len(kept) != n+1 {
		t.Fatalf("no record is forgotten while its backup is still on disk: %d records, %v", len(kept), err)
	}
}

// A listing that is incomplete (the store holds more than a listing can carry, or it could not be read) makes retention act on nothing: it deletes no backup and
// forgets no record, says why, keeps the window open, and carries on when the full list is back.
func TestRetentionDoesNothingOnAnIncompleteListing(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	for i := 1; i <= 3; i++ {
		id := fmt.Sprintf("bk-%016x", i+1000)
		_ = r.store.Made(ctx, id, "web-1", "earlier", r.now.Add(time.Duration(i)*time.Minute-time.Hour*24))
		r.world.backups = append(r.world.backups, BackupInfo{ID: id, VM: "web-1", Valid: true})
	}
	r.set("web-1", Spec{EveryHours: 1, KeepLocal: 1})
	fullWindow(r, "web-1")
	before, _ := r.store.MadeBy(ctx, "web-1")

	for _, e := range []error{ErrIncomplete, fmt.Errorf("list: %w", ErrIncomplete), context.DeadlineExceeded} {
		r.world.mu.Lock()
		r.world.backupsErr = e
		r.world.mu.Unlock()
		r.tick(10 * time.Second)
		if n := len(r.ops.of(operation.Delete)); n != 0 {
			t.Fatalf("%v: retention deleted %d backups from an incomplete listing", e, n)
		}
		after, _ := r.store.MadeBy(ctx, "web-1")
		if len(after) != len(before) {
			t.Fatalf("%v: records %d -> %d: retention forgot backups it could not list", e, len(before), len(after))
		}
		if len(r.active()) != 1 {
			t.Fatalf("%v: the window must stay open until retention could run", e)
		}
	}
	r.world.mu.Lock()
	r.world.backupsErr = nil
	r.world.mu.Unlock()
	r.tick(10 * time.Second)
	if n := len(r.ops.of(operation.Delete)); n != 3 { // 4 backups, one kept
		t.Fatalf("with the full list back retention must run: %d deletes", n)
	}
}
