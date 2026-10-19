// Package schedule is the backup schedule of DR-024 D3: a maintenance window per VM in which the machine is stopped gracefully, backed up, started
// again, copied off the host when a target is set, and the older copies the schedule made are removed. A window is a chain of ordinary operations
// submitted by the scheduler under its own name; a run record in the database says which step it is on, so a restart of the API resumes the chain
// instead of starting a second one. The scheduler never forces a VM off, never deletes a backup it did not make, and never keeps going silently:
// every run ends in a closed result (ok, failed or skipped) that the console shows and a failure raises an alert.
package schedule

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"regexp"
	"time"

	"example.invalid/dedicatedcloud/backend/internal/sqlitedb"
)

// Results of a run.
const (
	ResultOK      = "ok"
	ResultFailed  = "failed"
	ResultSkipped = "skipped"
)

// Steps of a run, in order.
const (
	StepStop      = "stop"
	StepBackup    = "backup"
	StepStart     = "start"
	StepExport    = "export"
	StepRetention = "retention"
)

// Spec is the part of a schedule the person chooses.
type Spec struct {
	EveryHours  int    // 1..168, or 0 when At is used
	At          string // HH:MM in the host's local time, or ""
	KeepLocal   int    // 1..30
	KeepOffsite int    // 0..30
	TargetID    string // the off-host target, "" when KeepOffsite is 0
}

var (
	atRE     = regexp.MustCompile(`^([01][0-9]|2[0-3]):[0-5][0-9]$`)
	targetRE = regexp.MustCompile(`^[a-z][a-z0-9-]{1,30}[a-z0-9]$`)
	vmRE     = regexp.MustCompile(`^[a-z]([a-z0-9-]{0,61}[a-z0-9])?$`)
)

// Valid reports whether the spec is acceptable (the same rules the operation parameters enforce).
func (s Spec) Valid() bool {
	if (s.EveryHours == 0) == (s.At == "") {
		return false
	}
	if s.EveryHours < 0 || s.EveryHours > 168 || (s.At != "" && !atRE.MatchString(s.At)) {
		return false
	}
	if s.KeepLocal < 1 || s.KeepLocal > 30 || s.KeepOffsite < 0 || s.KeepOffsite > 30 {
		return false
	}
	return (s.KeepOffsite > 0) == (s.TargetID != "") && (s.TargetID == "" || targetRE.MatchString(s.TargetID))
}

// Schedule is a stored schedule.
type Schedule struct {
	VM         string
	Spec       Spec
	SetBy      string
	CreatedAt  time.Time
	NextRun    time.Time
	LastAt     time.Time // zero when no run has ended
	LastResult string    // "" when none
}

// Run is one maintenance window in progress.
type Run struct {
	ID         string
	VM         string
	Spec       Spec // a copy: a change to the schedule does not alter a window already open
	Step       string
	WasRunning bool
	BackupID   string
	Failed     bool
	StartedAt  time.Time
	StepSince  time.Time
}

var schema = []string{`CREATE TABLE schedules (
	vm            TEXT PRIMARY KEY CHECK (length(vm) BETWEEN 1 AND 63),
	every_hours   INTEGER NOT NULL DEFAULT 0 CHECK (every_hours BETWEEN 0 AND 168),
	at            TEXT NOT NULL DEFAULT '' CHECK (length(at) <= 5),
	keep_local    INTEGER NOT NULL CHECK (keep_local BETWEEN 1 AND 30),
	keep_offsite  INTEGER NOT NULL CHECK (keep_offsite BETWEEN 0 AND 30),
	target_id     TEXT NOT NULL DEFAULT '' CHECK (length(target_id) <= 32),
	set_by        TEXT NOT NULL,
	created_at    INTEGER NOT NULL,
	next_run      INTEGER NOT NULL,
	last_at       INTEGER NOT NULL DEFAULT 0,
	last_result   TEXT NOT NULL DEFAULT '' CHECK (last_result IN ('', 'ok', 'failed', 'skipped'))
);
CREATE TABLE schedule_runs (
	id            TEXT PRIMARY KEY CHECK (length(id) BETWEEN 1 AND 40),
	vm            TEXT NOT NULL,
	every_hours   INTEGER NOT NULL, at TEXT NOT NULL, keep_local INTEGER NOT NULL, keep_offsite INTEGER NOT NULL, target_id TEXT NOT NULL,
	step          TEXT NOT NULL CHECK (step IN ('stop','backup','start','export','retention')),
	was_running   INTEGER NOT NULL CHECK (was_running IN (0,1)),
	backup_id     TEXT NOT NULL DEFAULT '' CHECK (length(backup_id) <= 19),
	failed        INTEGER NOT NULL DEFAULT 0 CHECK (failed IN (0,1)),
	started_at    INTEGER NOT NULL,
	step_since    INTEGER NOT NULL,
	ended_at      INTEGER NOT NULL DEFAULT 0
);
CREATE UNIQUE INDEX schedule_runs_active ON schedule_runs (vm) WHERE ended_at = 0;
CREATE TABLE schedule_backups (
	backup_id     TEXT PRIMARY KEY CHECK (length(backup_id) = 19),
	vm            TEXT NOT NULL,
	run_id        TEXT NOT NULL,
	created_at    INTEGER NOT NULL
);
CREATE INDEX schedule_backups_vm ON schedule_backups (vm, created_at);`}

// SchemaVersion is the schema version this build migrates the schedule tables to.
func SchemaVersion() int { return len(schema) }

// Store persists schedules, runs and the list of backups the scheduler made.
type Store struct{ db *sql.DB }

// OpenSQLite migrates the schema in db and returns a store over it. The caller owns db.
func OpenSQLite(ctx context.Context, db *sql.DB) (*Store, error) {
	if err := sqlitedb.Migrate(ctx, db, "schedule", schema); err != nil {
		return nil, fmt.Errorf("schedule: migrate: %w", err)
	}
	return &Store{db: db}, nil
}

func ts(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.UnixNano()
}

func tm(n int64) time.Time {
	if n == 0 {
		return time.Time{}
	}
	return time.Unix(0, n).UTC()
}

const schedCols = `vm, every_hours, at, keep_local, keep_offsite, target_id, set_by, created_at, next_run, last_at, last_result`

func scanSchedule(r interface{ Scan(...any) error }) (Schedule, error) {
	var (
		s                     Schedule
		created, next, lastAt int64
	)
	if err := r.Scan(&s.VM, &s.Spec.EveryHours, &s.Spec.At, &s.Spec.KeepLocal, &s.Spec.KeepOffsite, &s.Spec.TargetID, &s.SetBy, &created, &next, &lastAt, &s.LastResult); err != nil {
		return Schedule{}, err
	}
	s.CreatedAt, s.NextRun, s.LastAt = tm(created), tm(next), tm(lastAt)
	return s, nil
}

// Get returns the schedule of vm.
func (s *Store) Get(ctx context.Context, vm string) (Schedule, bool, error) {
	sc, err := scanSchedule(s.db.QueryRowContext(ctx, `SELECT `+schedCols+` FROM schedules WHERE vm = ?`, vm))
	if errors.Is(err, sql.ErrNoRows) {
		return Schedule{}, false, nil
	}
	return sc, err == nil, err
}

// All returns every schedule, ordered by next run.
func (s *Store) All(ctx context.Context) ([]Schedule, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+schedCols+` FROM schedules ORDER BY next_run, vm`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []Schedule
	for rows.Next() {
		sc, err := scanSchedule(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, sc)
	}
	return out, rows.Err()
}

// maxSchedules bounds the table.
const maxSchedules = 200

// Put inserts or replaces the schedule of sc.VM, keeping the last result of an existing one.
func (s *Store) Put(ctx context.Context, sc Schedule) error {
	if !vmRE.MatchString(sc.VM) || !sc.Spec.Valid() {
		return errors.New("schedule: invalid")
	}
	if _, ok, err := s.Get(ctx, sc.VM); err != nil {
		return err
	} else if !ok {
		var n int
		if err := s.db.QueryRowContext(ctx, `SELECT count(*) FROM schedules`).Scan(&n); err != nil {
			return err
		}
		if n >= maxSchedules {
			return errors.New("schedule: too many schedules")
		}
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO schedules (`+schedCols+`) VALUES (?,?,?,?,?,?,?,?,?,0,'')
		ON CONFLICT(vm) DO UPDATE SET every_hours=excluded.every_hours, at=excluded.at, keep_local=excluded.keep_local, keep_offsite=excluded.keep_offsite,
		target_id=excluded.target_id, set_by=excluded.set_by, next_run=excluded.next_run`,
		sc.VM, sc.Spec.EveryHours, sc.Spec.At, sc.Spec.KeepLocal, sc.Spec.KeepOffsite, sc.Spec.TargetID, sc.SetBy, ts(sc.CreatedAt), ts(sc.NextRun))
	return err
}

// Delete removes the schedule of vm (a run in progress finishes its safety steps).
func (s *Store) Delete(ctx context.Context, vm string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM schedules WHERE vm = ?`, vm)
	return err
}

// SetNext moves the next run of vm.
func (s *Store) SetNext(ctx context.Context, vm string, next time.Time) error {
	_, err := s.db.ExecContext(ctx, `UPDATE schedules SET next_run = ? WHERE vm = ?`, ts(next), vm)
	return err
}

// Record stores the outcome of a window.
func (s *Store) Record(ctx context.Context, vm, result string, at time.Time) error {
	_, err := s.db.ExecContext(ctx, `UPDATE schedules SET last_result = ?, last_at = ? WHERE vm = ?`, result, ts(at), vm)
	return err
}

const runCols = `id, vm, every_hours, at, keep_local, keep_offsite, target_id, step, was_running, backup_id, failed, started_at, step_since`

func scanRun(r interface{ Scan(...any) error }) (Run, error) {
	var (
		x                  Run
		was, failed        int
		started, stepSince int64
	)
	if err := r.Scan(&x.ID, &x.VM, &x.Spec.EveryHours, &x.Spec.At, &x.Spec.KeepLocal, &x.Spec.KeepOffsite, &x.Spec.TargetID, &x.Step, &was, &x.BackupID, &failed, &started, &stepSince); err != nil {
		return Run{}, err
	}
	x.WasRunning, x.Failed, x.StartedAt, x.StepSince = was == 1, failed == 1, tm(started), tm(stepSince)
	return x, nil
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}

// Active returns the runs that have not ended, oldest first.
func (s *Store) Active(ctx context.Context) ([]Run, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+runCols+` FROM schedule_runs WHERE ended_at = 0 ORDER BY started_at, id`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []Run
	for rows.Next() {
		r, err := scanRun(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// Begin opens a run; a VM with a run in progress cannot open another (the unique index).
func (s *Store) Begin(ctx context.Context, r Run) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO schedule_runs (`+runCols+`) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		r.ID, r.VM, r.Spec.EveryHours, r.Spec.At, r.Spec.KeepLocal, r.Spec.KeepOffsite, r.Spec.TargetID, r.Step, b2i(r.WasRunning), r.BackupID, b2i(r.Failed), ts(r.StartedAt), ts(r.StepSince))
	return err
}

// Update stores the progress of a run.
func (s *Store) Update(ctx context.Context, r Run) error {
	_, err := s.db.ExecContext(ctx, `UPDATE schedule_runs SET step = ?, backup_id = ?, failed = ?, step_since = ? WHERE id = ? AND ended_at = 0`,
		r.Step, r.BackupID, b2i(r.Failed), ts(r.StepSince), r.ID)
	return err
}

// End closes a run.
func (s *Store) End(ctx context.Context, id string, at time.Time) error {
	_, err := s.db.ExecContext(ctx, `UPDATE schedule_runs SET ended_at = ? WHERE id = ?`, ts(at), id)
	return err
}

// Made records that the scheduler asked for backup id of vm in run.
func (s *Store) Made(ctx context.Context, id, vm, run string, at time.Time) error {
	_, err := s.db.ExecContext(ctx, `INSERT OR IGNORE INTO schedule_backups (backup_id, vm, run_id, created_at) VALUES (?,?,?,?)`, id, vm, run, ts(at))
	return err
}

// MadeBy lists the backups the scheduler made for vm, newest first.
func (s *Store) MadeBy(ctx context.Context, vm string) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT backup_id FROM schedule_backups WHERE vm = ? ORDER BY created_at DESC, backup_id DESC`, vm)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// Forget drops the record of a backup the scheduler deleted.
func (s *Store) Forget(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM schedule_backups WHERE backup_id = ?`, id)
	return err
}

// Failed lists the VMs whose last window failed.
func (s *Store) Failed(ctx context.Context) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT vm FROM schedules WHERE last_result = 'failed' ORDER BY vm`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []string
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}
