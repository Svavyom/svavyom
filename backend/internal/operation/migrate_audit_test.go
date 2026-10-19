package operation

import (
	"context"
	"path/filepath"
	"testing"

	"example.invalid/dedicatedcloud/backend/internal/sqlitedb"
)

// A database that already holds operations AND audit rows (which point at the operations table) must migrate through every rebuild of that table: the
// installed system has such rows, and a migration that only worked on an empty database broke the first upgrade attempt of 0.1.0-preview.4.
func TestRebuildMigrationsKeepOperationsAndTheirAuditRows(t *testing.T) {
	ctx := context.Background()
	db, err := sqlitedb.Open(filepath.Join(t.TempDir(), "o.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	old := len(schema) - 1
	if err := sqlitedb.Migrate(ctx, db, "operation", schema[:old]); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO operations (id, project_id, resource_kind, resource_id, type, status, idempotency_key, requested_by, generation, attempts, error_category, created_at, updated_at)
		VALUES ('op-1','default','VM','web-1','create','succeeded','k1','admin',1,1,'',1,1)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO operation_audit (at, operation_id, project_id, actor, event, outcome) VALUES (1,'op-1','default','admin','operation.submit','accepted')`); err != nil {
		t.Fatal(err)
	}
	if err := sqlitedb.Migrate(ctx, db, "operation", schema); err != nil {
		t.Fatalf("the last rebuild must work with audit rows present: %v", err)
	}
	var n, a int
	_ = db.QueryRowContext(ctx, `SELECT count(*) FROM operations`).Scan(&n)
	_ = db.QueryRowContext(ctx, `SELECT count(*) FROM operation_audit`).Scan(&a)
	if n != 1 || a != 1 {
		t.Fatalf("operations %d, audit rows %d", n, a)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO operations (id, project_id, resource_kind, resource_id, type, status, idempotency_key, requested_by, generation, attempts, error_category, created_at, updated_at)
		VALUES ('op-2','default','Volume','data-1','volume_create','pending','k2','admin',1,0,'',2,2)`); err != nil {
		t.Fatalf("the new kind and types are accepted: %v", err)
	}
	// foreign keys are on again afterwards: an audit row for no operation is refused
	if _, err := db.ExecContext(ctx, `INSERT INTO operation_audit (at, operation_id, project_id, actor, event, outcome) VALUES (3,'op-missing','default','admin','x','y')`); err == nil {
		t.Fatal("foreign keys must be enforced again after the rebuild")
	}
}
