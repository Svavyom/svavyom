package operation

import (
	"context"
	"database/sql"
	"fmt"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"example.invalid/dedicatedcloud/backend/internal/sqlitedb"
)

func sqliteStore(t *testing.T) (*SQLiteStore, *sql.DB, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ops.db")
	db, err := sqlitedb.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	s, err := OpenSQLite(context.Background(), db)
	if err != nil {
		t.Fatal(err)
	}
	return s, db, path
}

// stores runs a contract test against every Store implementation: the in-memory one used for fast tests and the
// durable one must be observably identical.
func stores(t *testing.T, fn func(t *testing.T, s Store)) {
	t.Run("mem", func(t *testing.T) { fn(t, NewMemStore()) })
	t.Run("sqlite", func(t *testing.T) { s, _, _ := sqliteStore(t); fn(t, s) })
}

var t0 = time.Unix(1_700_000_000, 0).UTC()

func newOp(n int, key string) Operation {
	return Operation{ID: fmt.Sprintf("op-%04d", n), ProjectID: "p1", ResourceKind: KindVM, ResourceID: "vm-a", Type: Create,
		Status: Pending, IdempotencyKey: key, RequestedBy: "alice", Generation: 1, CreatedAt: t0, UpdatedAt: t0}
}

func TestStoreContract_InsertIdempotencyAndRoundTrip(t *testing.T) {
	stores(t, func(t *testing.T, s Store) {
		a := newOp(1, "k1")
		got, created, err := s.Insert(a)
		if err != nil || !created || got != a {
			t.Fatalf("insert: %+v %v %v", got, created, err)
		}
		dup := newOp(2, "k1") // same key, new id
		again, created, err := s.Insert(dup)
		if err != nil || created || again.ID != a.ID {
			t.Fatalf("replay must return the original: %+v %v %v", again, created, err)
		}
		other := newOp(3, "k1")
		other.ProjectID = "p2" // keys are scoped by project
		if _, created, err := s.Insert(other); err != nil || !created {
			t.Fatalf("other project: %v %v", created, err)
		}
		read, ok, err := s.Get(a.ID)
		if err != nil || !ok || read != a {
			t.Fatalf("get: %+v %v %v", read, ok, err)
		}
		if _, ok, err := s.Get("op-missing"); ok || err != nil {
			t.Fatalf("missing: %v %v", ok, err)
		}
	})
}

func TestStoreContract_UpdateIsCompareAndSwap(t *testing.T) {
	stores(t, func(t *testing.T, s Store) {
		a := newOp(1, "k1")
		_, _, _ = s.Insert(a)
		a.Status, a.Attempts = Running, 1
		saved, err := s.Update(a)
		if err != nil || saved.Generation != 2 || saved.Status != Running || saved.Attempts != 1 {
			t.Fatalf("update: %+v %v", saved, err)
		}
		if _, err := s.Update(a); CategoryOf(err) != CatConflict { // stale generation 1
			t.Fatalf("stale update: %v", err)
		}
		ghost := newOp(9, "kx")
		if _, err := s.Update(ghost); CategoryOf(err) != CatConflict {
			t.Fatalf("unknown id: %v", err)
		}
	})
}

func TestStoreContract_TerminalRecordsAreImmutable(t *testing.T) {
	stores(t, func(t *testing.T, s Store) {
		a := newOp(1, "k1")
		_, _, _ = s.Insert(a)
		a.Status = Succeeded
		done, err := s.Update(a)
		if err != nil {
			t.Fatal(err)
		}
		for _, to := range []Status{Pending, Running, Failed, RetryableFailure, Cancelled} {
			done.Status = to
			if _, err := s.Update(done); CategoryOf(err) != CatConflict {
				t.Fatalf("terminal -> %s must be a conflict, got %v", to, err)
			}
		}
		got, _, _ := s.Get(a.ID)
		if got.Status != Succeeded || got.Generation != 2 {
			t.Fatalf("terminal record changed: %+v", got)
		}
	})
}

func TestStoreContract_NonTerminalIsOldestFirstAndExcludesTerminal(t *testing.T) {
	stores(t, func(t *testing.T, s Store) {
		for i := 1; i <= 4; i++ {
			_, _, _ = s.Insert(newOp(i, fmt.Sprintf("k%d", i)))
		}
		two, _, _ := s.Get("op-0002")
		two.Status = Failed
		_, _ = s.Update(two)
		three, _, _ := s.Get("op-0003")
		three.Status = RetryableFailure
		_, _ = s.Update(three)
		ops, err := s.NonTerminal()
		if err != nil || len(ops) != 3 || ops[0].ID != "op-0001" || ops[1].ID != "op-0003" || ops[2].ID != "op-0004" {
			t.Fatalf("%+v %v", ops, err)
		}
	})
}

func TestStoreContract_ConcurrentSameKeyCreatesExactlyOne(t *testing.T) {
	stores(t, func(t *testing.T, s Store) {
		var created, ids atomic.Int32
		var wg sync.WaitGroup
		for i := 0; i < 16; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_, c, err := s.Insert(newOp(int(ids.Add(1)), "same"))
				if err != nil {
					t.Error(err)
				}
				if c {
					created.Add(1)
				}
			}()
		}
		wg.Wait()
		if created.Load() != 1 {
			t.Fatalf("%d creators for one idempotency key", created.Load())
		}
		if ops, _ := s.NonTerminal(); len(ops) != 1 {
			t.Fatalf("%d rows", len(ops))
		}
	})
}

func TestStoreContract_ConcurrentUpdatesOneWinnerPerGeneration(t *testing.T) {
	stores(t, func(t *testing.T, s Store) {
		a := newOp(1, "k1")
		_, _, _ = s.Insert(a)
		a.Status, a.Attempts = Running, 1
		var wins atomic.Int32
		var wg sync.WaitGroup
		for i := 0; i < 16; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if _, err := s.Update(a); err == nil {
					wins.Add(1)
				} else if CategoryOf(err) != CatConflict {
					t.Error(err)
				}
			}()
		}
		wg.Wait()
		if wins.Load() != 1 {
			t.Fatalf("%d winners", wins.Load())
		}
		if got, _, _ := s.Get(a.ID); got.Generation != 2 {
			t.Fatalf("generation %d", got.Generation)
		}
	})
}

func reopen(t *testing.T, path string) (*SQLiteStore, *sql.DB) {
	t.Helper()
	db, err := sqlitedb.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	s, err := OpenSQLite(context.Background(), db)
	if err != nil {
		t.Fatal(err)
	}
	return s, db
}
