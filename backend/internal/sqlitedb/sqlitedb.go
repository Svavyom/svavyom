// Package sqlitedb opens the single SQLite database of the Svavyom control plane (ADR-003; D1 = modernc.org/sqlite,
// pure Go, no cgo) and applies ordered, versioned schema migrations deterministically.
//
// It is deliberately not a database abstraction: it owns the connection pragmas and the migration ledger, nothing else.
package sqlitedb

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"strings"

	_ "modernc.org/sqlite" // registers the "sqlite" driver
)

// ErrSchemaNewer is returned when the database was migrated by a newer build than this one.
var ErrSchemaNewer = errors.New("sqlitedb: database schema is newer than this build")

// Open opens (creating if absent) the database file at path. Every connection enforces foreign keys, waits up to
// five seconds on a lock instead of failing, and begins write transactions immediately so concurrent writers
// serialize rather than deadlock on lock upgrade. WAL keeps committed data durable across a process kill.
func Open(path string) (*sql.DB, error) {
	if path == "" {
		return nil, errors.New("sqlitedb: empty path")
	}
	// The database holds the password hash and session hashes: owner-only, set before SQLite creates it (its -wal and
	// -shm files inherit the mode) and tightened if an existing file is wider.
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600) // #nosec G304 -- operator-configured path
	if err != nil {
		return nil, fmt.Errorf("sqlitedb: open: %w", err)
	}
	if err := f.Chmod(0o600); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("sqlitedb: open: %w", err)
	}
	_ = f.Close()
	q := url.Values{}
	q.Add("_pragma", "busy_timeout(5000)")
	q.Add("_pragma", "foreign_keys(1)")
	q.Add("_pragma", "journal_mode(WAL)")
	q.Add("_pragma", "synchronous(FULL)")
	q.Set("_txlock", "immediate")
	db, err := sql.Open("sqlite", "file:"+(&url.URL{Path: path}).EscapedPath()+"?"+q.Encode())
	if err != nil {
		return nil, fmt.Errorf("sqlitedb: open: %w", err)
	}
	if err := db.PingContext(context.Background()); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("sqlitedb: open: %w", err)
	}
	return db, nil
}

var componentRE = regexp.MustCompile(`^[a-z][a-z0-9_]{0,31}$`)

// Migrate applies steps[v:] for component, where v is the component's recorded version. Step i brings the schema to
// version i+1 and runs in one transaction together with its ledger row, so a crash leaves either the old or the new
// version, never a mixture. Steps are append-only: editing an applied step is not detected, so tests pin them.
func Migrate(ctx context.Context, db *sql.DB, component string, steps []string) error {
	if !componentRE.MatchString(component) {
		return errors.New("sqlitedb: invalid component name")
	}
	if _, err := db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
		component TEXT PRIMARY KEY, version INTEGER NOT NULL CHECK (version >= 0))`); err != nil {
		return fmt.Errorf("sqlitedb: ledger: %w", err)
	}
	// FKOff marks a step that rebuilds a table other tables point at (create the new table, copy, drop the old one, rename): SQLite counts the DROP as
	// deleting every parent row, so such a step runs with foreign keys off, as SQLite's own guidance says, and must leave `PRAGMA foreign_key_check` empty.
	conn, err := db.Conn(ctx)
	if err != nil {
		return fmt.Errorf("sqlitedb: migrate: %w", err)
	}
	defer conn.Close()
	for {
		var v int
		err := conn.QueryRowContext(ctx, `SELECT version FROM schema_migrations WHERE component = ?`, component).Scan(&v)
		if errors.Is(err, sql.ErrNoRows) {
			v, err = 0, nil
		}
		if err != nil {
			return fmt.Errorf("sqlitedb: migrate: %w", err)
		}
		if v > len(steps) {
			return ErrSchemaNewer
		}
		if v == len(steps) {
			return nil
		}
		fkOff := strings.HasPrefix(strings.TrimLeft(steps[v], "\n"), FKOff)
		if fkOff {
			if _, err := conn.ExecContext(ctx, `PRAGMA foreign_keys = OFF`); err != nil {
				return fmt.Errorf("sqlitedb: migrate: %w", err)
			}
		}
		err = runStep(ctx, conn, component, v, steps[v], fkOff)
		if fkOff {
			if _, perr := conn.ExecContext(ctx, `PRAGMA foreign_keys = ON`); perr != nil && err == nil {
				err = perr
			}
		}
		if err != nil {
			return fmt.Errorf("sqlitedb: migrate %s step %d: %w", component, v+1, err)
		}
	}
}

// FKOff is the first line of a migration step that must run with foreign keys off (see Migrate).
const FKOff = "-- sqlitedb:foreign-keys-off\n"

func runStep(ctx context.Context, conn *sql.Conn, component string, v int, step string, fkOff bool) error {
	tx, err := conn.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	// The version is read again inside the transaction: another process may have applied this step since it was peeked at. Then there is nothing to do.
	var cur int
	switch qerr := tx.QueryRowContext(ctx, `SELECT version FROM schema_migrations WHERE component = ?`, component).Scan(&cur); {
	case errors.Is(qerr, sql.ErrNoRows):
		cur = 0
	case qerr != nil:
		_ = tx.Rollback()
		return qerr
	}
	if cur != v {
		return tx.Rollback()
	}
	if _, err = tx.ExecContext(ctx, step); err == nil {
		_, err = tx.ExecContext(ctx, `INSERT INTO schema_migrations (component, version) VALUES (?, ?)
			ON CONFLICT(component) DO UPDATE SET version = excluded.version`, component, v+1)
	}
	if err == nil && fkOff {
		var rows *sql.Rows
		if rows, err = tx.QueryContext(ctx, `PRAGMA foreign_key_check`); err == nil {
			bad := rows.Next()
			_ = rows.Close()
			if bad {
				err = errors.New("foreign key check failed after the rebuild")
			}
		}
	}
	if err != nil {
		_ = tx.Rollback()
		return err
	}
	return tx.Commit()
}

// OpenReadOnly opens an existing database file for reading only: it never creates the file, never writes (not even the WAL index of a database that no
// process has open), and changes nothing. The operator tool uses it to read the schema versions and recent operation states.
func OpenReadOnly(path string) (*sql.DB, error) {
	if path == "" {
		return nil, errors.New("sqlitedb: empty path")
	}
	if fi, err := os.Stat(path); err != nil || !fi.Mode().IsRegular() {
		return nil, errors.New("sqlitedb: no such database")
	}
	q := url.Values{}
	q.Set("mode", "ro")
	q.Add("_pragma", "busy_timeout(5000)")
	q.Add("_pragma", "query_only(1)")
	db, err := sql.Open("sqlite", "file:"+(&url.URL{Path: path}).EscapedPath()+"?"+q.Encode())
	if err != nil {
		return nil, fmt.Errorf("sqlitedb: open: %w", err)
	}
	if err := db.PingContext(context.Background()); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("sqlitedb: open: %w", err)
	}
	return db, nil
}

// Versions returns the recorded schema version of every component (empty if the ledger does not exist yet).
func Versions(ctx context.Context, db *sql.DB) (map[string]int, error) {
	rows, err := db.QueryContext(ctx, `SELECT component, version FROM schema_migrations`)
	if err != nil {
		return map[string]int{}, nil // no ledger: a database no build has migrated
	}
	defer rows.Close()
	out := map[string]int{}
	for rows.Next() {
		var c string
		var v int
		if err := rows.Scan(&c, &v); err != nil {
			return nil, err
		}
		out[c] = v
	}
	return out, rows.Err()
}
