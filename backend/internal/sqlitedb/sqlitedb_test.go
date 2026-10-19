package sqlitedb

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func open(t *testing.T) (string, func()) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "t.db")
	return p, func() {}
}

func TestMigrateIsIdempotentAndResumable(t *testing.T) {
	ctx := context.Background()
	p, _ := open(t)
	db, err := Open(p)
	if err != nil {
		t.Fatal(err)
	}
	steps := []string{`CREATE TABLE a (x INTEGER)`, `CREATE TABLE b (y INTEGER)`}
	if err := Migrate(ctx, db, "demo", steps[:1]); err != nil {
		t.Fatal(err)
	}
	_ = db.Close()
	db, err = Open(p) // restart
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for i := 0; i < 2; i++ {
		if err := Migrate(ctx, db, "demo", steps); err != nil {
			t.Fatal(err)
		}
	}
	for _, tbl := range []string{"a", "b"} {
		if _, err := db.Exec(`INSERT INTO ` + tbl + ` VALUES (1)`); err != nil {
			t.Fatalf("table %s: %v", tbl, err)
		}
	}
}

func TestMigrateFailureRollsBackStepAndLedger(t *testing.T) {
	ctx := context.Background()
	p, _ := open(t)
	db, _ := Open(p)
	defer db.Close()
	bad := []string{`CREATE TABLE a (x INTEGER)`, `CREATE TABLE c (z INTEGER); THIS IS NOT SQL`}
	if err := Migrate(ctx, db, "demo", bad); err == nil {
		t.Fatal("want error")
	}
	var v int
	if err := db.QueryRow(`SELECT version FROM schema_migrations WHERE component='demo'`).Scan(&v); err != nil || v != 1 {
		t.Fatalf("version %d err %v, want 1", v, err)
	}
	if _, err := db.Exec(`INSERT INTO c VALUES (1)`); err == nil {
		t.Fatal("failed step must not leave table c behind")
	}
}

func TestMigrateRefusesNewerSchema(t *testing.T) {
	ctx := context.Background()
	p, _ := open(t)
	db, _ := Open(p)
	defer db.Close()
	if err := Migrate(ctx, db, "demo", []string{`CREATE TABLE a (x INTEGER)`, `CREATE TABLE b (x INTEGER)`}); err != nil {
		t.Fatal(err)
	}
	if err := Migrate(ctx, db, "demo", []string{`CREATE TABLE a (x INTEGER)`}); !errors.Is(err, ErrSchemaNewer) {
		t.Fatalf("got %v, want ErrSchemaNewer", err)
	}
}

func TestMigrateRejectsBadComponentAndEmptyPath(t *testing.T) {
	p, _ := open(t)
	db, _ := Open(p)
	defer db.Close()
	if err := Migrate(context.Background(), db, "Bad Name;", nil); err == nil {
		t.Fatal("want error")
	}
	if _, err := Open(""); err == nil {
		t.Fatal("want error")
	}
}

func TestConcurrentMigrateAppliesEachStepOnce(t *testing.T) {
	p, _ := open(t)
	db, _ := Open(p)
	defer db.Close()
	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs <- Migrate(context.Background(), db, "demo", []string{`CREATE TABLE a (x INTEGER)`})
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
}

func TestPragmasApplyToEveryConnection(t *testing.T) {
	p, _ := open(t)
	db, _ := Open(p)
	defer db.Close()
	db.SetMaxOpenConns(4)
	ctx := context.Background()
	var conns []interface{ Close() error }
	for i := 0; i < 3; i++ {
		c, err := db.Conn(ctx)
		if err != nil {
			t.Fatal(err)
		}
		conns = append(conns, c)
		var fk int
		if err := c.QueryRowContext(ctx, `PRAGMA foreign_keys`).Scan(&fk); err != nil || fk != 1 {
			t.Fatalf("foreign_keys=%d err=%v", fk, err)
		}
	}
	for _, c := range conns {
		_ = c.Close()
	}
}

func TestLockProcessIsExclusiveAndReleasable(t *testing.T) {
	p, _ := open(t)
	rel, err := LockProcess(p)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := LockProcess(p); !errors.Is(err, ErrLocked) {
		t.Fatalf("second lock: %v", err)
	}
	rel()
	rel2, err := LockProcess(p)
	if err != nil {
		t.Fatalf("after release: %v", err)
	}
	rel2()
}

func TestDatabaseFilesAreOwnerOnly(t *testing.T) {
	p, _ := open(t)
	if err := os.WriteFile(p, nil, 0o644); err != nil { // an existing, too-open file is tightened
		t.Fatal(err)
	}
	db, err := Open(p)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := Migrate(context.Background(), db, "demo", []string{`CREATE TABLE a (x INTEGER)`}); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO a VALUES (1)`); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{p, p + "-wal", p + "-shm"} {
		st, err := os.Stat(f)
		if err != nil {
			continue // not every journal file exists at every moment
		}
		if st.Mode().Perm()&0o077 != 0 {
			t.Errorf("%s has mode %v: group/other access", f, st.Mode().Perm())
		}
	}
}
