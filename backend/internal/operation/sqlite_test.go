package operation

import (
	"context"
	"database/sql"
	"strings"
	"testing"

	"example.invalid/dedicatedcloud/backend/internal/hypervisor/fake"
	"example.invalid/dedicatedcloud/backend/internal/sqlitedb"
)

func TestSQLite_SurvivesRestartIncludingIdempotencyKeysAndAttempts(t *testing.T) {
	s, db, path := sqliteStore(t)
	hv := fake.New()
	m := NewManager(s, hv, owners{"p1": "alice"}, nil, Config{})
	first := mustSubmit(t, m, req(Create, "vm-a", "k1"))
	hv.Inject(1, fake.FaultConnLoss, false)
	mustRun(t, m, first.ID, RetryableFailure) // attempt 1 persisted
	_ = db.Close()                            // process exit

	db2, err := sqlitedb.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db2.Close()
	s2, err := OpenSQLite(context.Background(), db2) // migrations are idempotent on an existing file
	if err != nil {
		t.Fatal(err)
	}
	m2 := NewManager(s2, hv, owners{"p1": "alice"}, nil, Config{})
	again, err := m2.Submit(alice, req(Create, "vm-a", "k1"))
	if err != nil || again.ID != first.ID || again.Attempts != 1 || again.Status != RetryableFailure {
		t.Fatalf("restart lost state: %+v %v", again, err)
	}
	if _, err := m2.Submit(alice, req(Delete, "vm-a", "k1")); CategoryOf(err) != CatConflict {
		t.Fatalf("key reuse with another payload after restart: %v", err)
	}
	mustRun(t, m2, first.ID, Succeeded)
}

func TestSQLite_AuditCommitsAtomicallyWithState(t *testing.T) {
	s, db, _ := sqliteStore(t)
	hv := fake.New()
	m := NewManager(s, hv, owners{"p1": "alice"}, nil, Config{})
	op := mustSubmit(t, m, req(Create, "vm-a", "k1"))
	mustRun(t, m, op.ID, Succeeded)
	ev, err := s.Audit(op.ID)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, e := range ev {
		got = append(got, e.Event+":"+e.Outcome)
	}
	if want := "operation.submit:accepted operation.status:running operation.status:succeeded"; strings.Join(got, " ") != want {
		t.Fatalf("audit %q, want %q", strings.Join(got, " "), want)
	}
	// An audit write that fails must roll the state change back: no unaudited transition.
	if _, err := db.Exec(`CREATE TRIGGER audit_fail BEFORE INSERT ON operation_audit WHEN NEW.outcome = 'running'
		BEGIN SELECT RAISE(ABORT, 'x'); END`); err != nil {
		t.Fatal(err)
	}
	op2 := mustSubmit(t, m, req(Create, "vm-b", "k2"))
	if _, err := m.Run(context.Background(), op2.ID); CategoryOf(err) != CatInternal {
		t.Fatalf("want internal, got %v", err)
	}
	if got, _, _ := s.Get(op2.ID); got.Status != Pending || got.Attempts != 0 || got.Generation != 1 {
		t.Fatalf("state changed without its audit record: %+v", got)
	}
	if len(hv.Snapshot()) != 1 {
		t.Fatalf("host was touched although the attempt could not be recorded: %v", hv.Snapshot())
	}
}

func TestSQLite_SchemaRejectsInvalidRowsAndForbiddenChanges(t *testing.T) {
	s, db, _ := sqliteStore(t)
	_, _, _ = s.Insert(newOp(1, "k1"))
	for name, stmt := range map[string]string{
		"bad status":      `UPDATE operations SET status = 'bogus'`,
		"bad category":    `UPDATE operations SET error_category = 'free text with secret=hunter2'`,
		"identity change": `UPDATE operations SET resource_id = 'other'`,
		"attempts down":   `UPDATE operations SET attempts = attempts - 1 WHERE attempts > 0`,
		"audit rewrite":   `UPDATE operation_audit SET outcome = 'x'`,
		"audit delete":    `DELETE FROM operation_audit`,
	} {
		if name == "attempts down" {
			_, _ = db.Exec(`UPDATE operations SET attempts = 2`)
		}
		if name == "audit rewrite" || name == "audit delete" {
			_, _ = db.Exec(`INSERT INTO operation_audit (at, operation_id, project_id, actor, event, outcome) VALUES (1,'op-0001','p1','a','e','o')`)
		}
		if _, err := db.Exec(stmt); err == nil {
			t.Errorf("%s: statement succeeded", name)
		}
	}
	if _, err := db.Exec(`UPDATE operations SET status = 'succeeded'`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE operations SET status = 'running'`); err == nil {
		t.Error("terminal record was reopened")
	}
}

func TestSQLite_ErrorsAreTypedInternalAndDoNotLeakDriverText(t *testing.T) {
	s, db, _ := sqliteStore(t)
	_ = db.Close() // database gone
	_, _, err := s.Insert(newOp(1, "k"))
	if CategoryOf(err) != CatInternal || strings.Contains(err.Error(), "sql") && !strings.HasPrefix(err.Error(), "operation:") {
		t.Fatalf("insert: %v", err)
	}
	if _, _, err := s.Get("x"); CategoryOf(err) != CatInternal {
		t.Fatalf("get: %v", err)
	}
	if _, err := s.Update(newOp(1, "k")); CategoryOf(err) != CatInternal {
		t.Fatalf("update: %v", err)
	}
	if _, err := s.NonTerminal(); CategoryOf(err) != CatInternal {
		t.Fatalf("nonterminal: %v", err)
	}
	m := NewManager(s, fake.New(), owners{"p1": "alice"}, nil, Config{})
	if _, err := m.Submit(alice, req(Create, "vm-a", "k")); CategoryOf(err) != CatInternal {
		t.Fatalf("manager: %v", err)
	}
}

func TestSQLite_NoSecretColumns(t *testing.T) {
	_, db, _ := sqliteStore(t)
	for _, table := range []string{"operations", "operation_audit"} {
		rows, err := db.Query(`SELECT name FROM pragma_table_info(?)`, table)
		if err != nil {
			t.Fatal(err)
		}
		for rows.Next() {
			var n string
			_ = rows.Scan(&n)
			for _, bad := range []string{"password", "secret", "token", "credential", "message", "detail", "path"} {
				if strings.Contains(n, bad) {
					t.Errorf("%s.%s looks like a secret or free-text column", table, n)
				}
			}
		}
		_ = rows.Close()
	}
}

func TestSQLite_RefusesNewerSchema(t *testing.T) {
	_, db, _ := sqliteStore(t)
	if _, err := db.Exec(`UPDATE schema_migrations SET version = 99 WHERE component = 'operation'`); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenSQLite(context.Background(), db); CategoryOf(err) != CatInternal {
		t.Fatalf("got %v", err)
	}
	var _ *sql.DB = db
}
