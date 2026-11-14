// Package bootpolicy is what the owner meant for each managed VM (DR-042): whether it should start when the host boots (the "start on host boot" box, on
// by default) and whether it is meant to be running or stopped (the intent, set by the console's own start, reboot, stop and force-off). From the two it
// derives the libvirt autostart flag, so a VM comes back after a host reboot if and only if the box is ticked AND the owner left it running. The store is
// the one place that knows the owner's intent; the observation alone cannot, because after a reboot everything is stopped.
package bootpolicy

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"example.invalid/dedicatedcloud/backend/internal/sqlitedb"
)

// Intent values.
const (
	Running = "running"
	Stopped = "stopped"
)

// Policy is one VM's row.
type Policy struct {
	Name        string
	StartOnBoot bool   // the owner's box; true by default
	Intent      string // Running or Stopped, as last asked through the console
	UpdatedAt   time.Time
	UpdatedBy   string
}

// Autostart is the libvirt autostart flag this policy calls for: the box is ticked and the owner left the VM running.
func (p Policy) Autostart() bool { return p.StartOnBoot && p.Intent == Running }

// ErrInvalid is returned for a bad name or intent.
var ErrInvalid = errors.New("bootpolicy: invalid name or intent")

var schema = []string{`CREATE TABLE vm_boot_policy (
	name          TEXT PRIMARY KEY CHECK (length(name) BETWEEN 1 AND 63),
	start_on_boot INTEGER NOT NULL DEFAULT 1 CHECK (start_on_boot IN (0,1)),
	intent        TEXT NOT NULL CHECK (intent IN ('running','stopped')),
	updated_at    INTEGER NOT NULL,
	updated_by    TEXT NOT NULL
)`}

// Store is the intent table over the control plane's database.
type Store struct {
	db  *sql.DB
	now func() time.Time
}

// OpenSQLite migrates the schema in db and returns a store over it. The caller owns db.
func OpenSQLite(ctx context.Context, db *sql.DB) (*Store, error) {
	if err := sqlitedb.Migrate(ctx, db, "bootpolicy", schema); err != nil {
		return nil, fmt.Errorf("bootpolicy: migrate: %w", err)
	}
	return &Store{db: db, now: time.Now}, nil
}

func validName(n string) bool {
	if n == "" || len(n) > 63 {
		return false
	}
	return !strings.ContainsAny(n, " /\\\x00")
}

func validIntent(i string) bool { return i == Running || i == Stopped }

const cols = `name, start_on_boot, intent, updated_at, updated_by`

func scan(r interface{ Scan(...any) error }) (Policy, error) {
	var (
		p    Policy
		b    int
		unix int64
	)
	if err := r.Scan(&p.Name, &b, &p.Intent, &unix, &p.UpdatedBy); err != nil {
		return Policy{}, err
	}
	p.StartOnBoot, p.UpdatedAt = b == 1, time.Unix(0, unix).UTC()
	return p, nil
}

// Get returns the policy of name.
func (s *Store) Get(ctx context.Context, name string) (Policy, bool, error) {
	p, err := scan(s.db.QueryRowContext(ctx, `SELECT `+cols+` FROM vm_boot_policy WHERE name = ?`, name))
	if errors.Is(err, sql.ErrNoRows) {
		return Policy{}, false, nil
	}
	return p, err == nil, err
}

// All returns every policy by VM name.
func (s *Store) All(ctx context.Context) (map[string]Policy, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+cols+` FROM vm_boot_policy`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	out := map[string]Policy{}
	for rows.Next() {
		p, err := scan(rows)
		if err != nil {
			return nil, err
		}
		out[p.Name] = p
	}
	return out, rows.Err()
}

// Ensure creates the row of a VM that has none, with the box ticked unless startOnBoot says otherwise and the given intent. A row that exists is left alone
// (the upgrade gives every existing managed VM a row; a retried create must not overwrite a later choice).
func (s *Store) Ensure(ctx context.Context, name string, startOnBoot bool, intent, actor string) (Policy, error) {
	if !validName(name) || !validIntent(intent) {
		return Policy{}, ErrInvalid
	}
	b := 0
	if startOnBoot {
		b = 1
	}
	if _, err := s.db.ExecContext(ctx, `INSERT INTO vm_boot_policy (`+cols+`) VALUES (?,?,?,?,?) ON CONFLICT(name) DO NOTHING`, name, b, intent, s.now().UnixNano(), actor); err != nil {
		return Policy{}, err
	}
	p, _, err := s.Get(ctx, name)
	return p, err
}

// SetIntent records what the owner now wants the VM to be; the row is created (box ticked) if it is not there.
func (s *Store) SetIntent(ctx context.Context, name, intent, actor string) (Policy, error) {
	if !validName(name) || !validIntent(intent) {
		return Policy{}, ErrInvalid
	}
	if _, err := s.Ensure(ctx, name, true, intent, actor); err != nil {
		return Policy{}, err
	}
	if _, err := s.db.ExecContext(ctx, `UPDATE vm_boot_policy SET intent = ?, updated_at = ?, updated_by = ? WHERE name = ?`, intent, s.now().UnixNano(), actor, name); err != nil {
		return Policy{}, err
	}
	p, _, err := s.Get(ctx, name)
	return p, err
}

// SetStartOnBoot sets the owner's box; the row is created (intent stopped) if it is not there.
func (s *Store) SetStartOnBoot(ctx context.Context, name string, on bool, actor string) (Policy, error) {
	if !validName(name) {
		return Policy{}, ErrInvalid
	}
	if _, err := s.Ensure(ctx, name, on, Stopped, actor); err != nil {
		return Policy{}, err
	}
	b := 0
	if on {
		b = 1
	}
	if _, err := s.db.ExecContext(ctx, `UPDATE vm_boot_policy SET start_on_boot = ?, updated_at = ?, updated_by = ? WHERE name = ?`, b, s.now().UnixNano(), actor, name); err != nil {
		return Policy{}, err
	}
	p, _, err := s.Get(ctx, name)
	return p, err
}

// Delete forgets a VM (its domain is gone).
func (s *Store) Delete(ctx context.Context, name string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM vm_boot_policy WHERE name = ?`, name)
	return err
}
