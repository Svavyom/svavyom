package operation

import "testing"

// A request replayed with the same idempotency key returns the operation it created, for every type whose submission generates server fields (M0-E01-S07).
// A Snapshot used to get a fresh snapshot id on each submit, and the id was compared as if the caller had chosen it: the replay came back as a conflict.
func TestReplayReturnsTheFirstOperationWhateverTheServerGenerates(t *testing.T) {
	cases := []struct {
		name string
		r    Request
	}{
		{"snapshot (server generates the snapshot id)", Request{Type: Snapshot, ResourceID: "vm-a"}},
		{"backup (server generates the backup id)", Request{Type: Backup, ResourceID: "vm-a"}},
		{"resize (no server field)", Request{Type: Resize, ResourceID: "vm-a", Params: Params{DiskGiB: 20}}},
		{"restore a snapshot (the caller names it)", Request{Type: RestoreSnapshot, ResourceID: "vm-a", Params: Params{SnapshotID: "snap-0a1b2c3d4e5f"}}},
		{"delete a snapshot (the caller names it)", Request{Type: DeleteSnapshot, ResourceID: "vm-a", Params: Params{SnapshotID: "snap-0a1b2c3d4e5f"}}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := newEnv(t)
			r := c.r
			r.ProjectID, r.Kind, r.IdempotencyKey = "p1", KindVM, "k-replay"
			first, err := e.m.Submit(alice, r)
			if err != nil {
				t.Fatalf("first submit: %v", CategoryOf(err))
			}
			again, err := e.m.Submit(alice, r)
			if err != nil {
				t.Fatalf("the replay was refused as %q, it must return the first operation", CategoryOf(err))
			}
			if again.ID != first.ID {
				t.Fatalf("the replay created %s, the first operation is %s", again.ID, first.ID)
			}
			if again.Params.SnapshotID != first.Params.SnapshotID || again.Params.BackupID != first.Params.BackupID {
				t.Fatal("the replay returned different generated ids")
			}
		})
	}
}

// A snapshot id the caller names is an input: the same key with another id is a different request, and a different type or resource is still a conflict.
func TestReplayWithDifferentInputsIsStillAConflict(t *testing.T) {
	e := newEnv(t)
	r := Request{ProjectID: "p1", Kind: KindVM, Type: RestoreSnapshot, ResourceID: "vm-a", IdempotencyKey: "k-diff", Params: Params{SnapshotID: "snap-0a1b2c3d4e5f"}}
	if _, err := e.m.Submit(alice, r); err != nil {
		t.Fatal(CategoryOf(err))
	}
	other := r
	other.Params = Params{SnapshotID: "snap-ffffffffffff"}
	if _, err := e.m.Submit(alice, other); CategoryOf(err) != CatConflict {
		t.Fatalf("another snapshot id under the same key: %q, want conflict", CategoryOf(err))
	}
	snap := Request{ProjectID: "p1", Kind: KindVM, Type: Snapshot, ResourceID: "vm-a", IdempotencyKey: "k-snap"}
	if _, err := e.m.Submit(alice, snap); err != nil {
		t.Fatal(CategoryOf(err))
	}
	snap.ResourceID = "vm-b"
	if _, err := e.m.Submit(alice, snap); CategoryOf(err) != CatConflict {
		t.Fatalf("a Snapshot of another VM under the same key: %q, want conflict", CategoryOf(err))
	}
}

func TestInputsForClearsTheSnapshotIDOnlyForASnapshot(t *testing.T) {
	p := Params{SnapshotID: "snap-0a1b2c3d4e5f", BackupID: "bk-0123456789abcdef", Rev: "r"}
	if got := p.InputsFor(Snapshot); got.SnapshotID != "" || got.BackupID != "" || got.Rev != "" {
		t.Fatalf("Snapshot: %+v", got)
	}
	if got := p.InputsFor(RestoreSnapshot); got.SnapshotID != "snap-0a1b2c3d4e5f" {
		t.Fatalf("RestoreSnapshot must keep the caller's id: %+v", got)
	}
	if got := p.InputsFor(DeleteSnapshot); got.SnapshotID != "snap-0a1b2c3d4e5f" {
		t.Fatalf("DeleteSnapshot must keep the caller's id: %+v", got)
	}
}
