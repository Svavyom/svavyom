package bootpolicy

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"example.invalid/dedicatedcloud/backend/internal/sqlitedb"
)

func open(t *testing.T) *Store {
	t.Helper()
	db, err := sqlitedb.Open(filepath.Join(t.TempDir(), "b.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	s, err := OpenSQLite(context.Background(), db)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestTheAutostartFlagIsTheBoxAndTheIntentTogether(t *testing.T) {
	for _, c := range []struct {
		box    bool
		intent string
		want   bool
	}{{true, Running, true}, {true, Stopped, false}, {false, Running, false}, {false, Stopped, false}} {
		if got := (Policy{StartOnBoot: c.box, Intent: c.intent}).Autostart(); got != c.want {
			t.Errorf("box %v intent %s: %v, want %v", c.box, c.intent, got, c.want)
		}
	}
}

func TestEnsureKeepsAnExistingRowAndDefaultsTheBoxOn(t *testing.T) {
	s, ctx := open(t), context.Background()
	p, err := s.Ensure(ctx, "web-1", true, Running, "admin")
	if err != nil || !p.StartOnBoot || p.Intent != Running || p.UpdatedBy != "admin" {
		t.Fatalf("%+v %v", p, err)
	}
	if _, err := s.SetStartOnBoot(ctx, "web-1", false, "olly"); err != nil {
		t.Fatal(err)
	}
	// a retried create must not undo a later choice
	p, _ = s.Ensure(ctx, "web-1", true, Stopped, "admin")
	if p.StartOnBoot || p.Intent != Running {
		t.Fatalf("the row was overwritten: %+v", p)
	}
}

func TestIntentFollowsTheConsoleAndCreatesTheRowWithTheBoxOn(t *testing.T) {
	s, ctx := open(t), context.Background()
	p, err := s.SetIntent(ctx, "db-1", Running, "olly")
	if err != nil || !p.StartOnBoot || !p.Autostart() {
		t.Fatalf("%+v %v", p, err)
	}
	p, _ = s.SetIntent(ctx, "db-1", Stopped, "olly")
	if p.Autostart() || p.Intent != Stopped || !p.StartOnBoot {
		t.Fatalf("a stopped VM keeps its box but is not autostarted: %+v", p)
	}
	p, _ = s.SetStartOnBoot(ctx, "db-1", false, "olly")
	p, _ = s.SetIntent(ctx, "db-1", Running, "olly")
	if p.Autostart() || p.StartOnBoot {
		t.Fatalf("an unticked box wins over a running intent: %+v", p)
	}
}

func TestListAndDeleteAndValidation(t *testing.T) {
	s, ctx := open(t), context.Background()
	_, _ = s.SetIntent(ctx, "a", Running, "x")
	_, _ = s.SetIntent(ctx, "b", Stopped, "x")
	all, err := s.All(ctx)
	if err != nil || len(all) != 2 || all["a"].Intent != Running {
		t.Fatalf("%v %v", all, err)
	}
	if err := s.Delete(ctx, "a"); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := s.Get(ctx, "a"); ok {
		t.Fatal("deleted")
	}
	if _, err := s.SetIntent(ctx, "", Running, "x"); !errors.Is(err, ErrInvalid) {
		t.Errorf("empty name: %v", err)
	}
	if _, err := s.SetIntent(ctx, "a b", Running, "x"); !errors.Is(err, ErrInvalid) {
		t.Errorf("space in name: %v", err)
	}
	if _, err := s.SetIntent(ctx, "a", "paused", "x"); !errors.Is(err, ErrInvalid) {
		t.Errorf("intent: %v", err)
	}
}
