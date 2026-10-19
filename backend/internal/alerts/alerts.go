// Package alerts holds the alert records of DR-024 D2 and the rules that raise them. An alert is a condition the platform can see for itself (free
// space, a crashed VM, an operation that ran out of retries, a failed scheduled backup or nightly boot): it is raised once per condition, re-opens when
// the condition returns, and resolves when the condition has cleared for two evaluations. An alert never changes the host and carries no text from the
// host: its type is a closed rule id and its only figure is a bounded integer.
package alerts

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"sync"
	"time"

	"example.invalid/dedicatedcloud/backend/internal/hypervisor"
	"example.invalid/dedicatedcloud/backend/internal/sqlitedb"
)

// Severity and state vocabularies (the Event schema enums).
const (
	Info     = "info"
	Warning  = "warning"
	Critical = "critical"

	StateOpen         = "open"
	StateAcknowledged = "acknowledged"
	StateResolved     = "resolved"
)

// Rule ids (Event.type).
const (
	PoolFreeLow        = "pool_free_low"
	BackupStoreFreeLow = "backup_store_free_low"
	HostMemoryHigh     = "host_memory_high"
	VMCrashed          = "vm_crashed"
	VMStoppedUnasked   = "vm_stopped_unexpectedly"
	RetriesExhausted   = "operation_retries_exhausted"
	ScheduledBackup    = "scheduled_backup_failed"
	NightlyBootFailed  = "nightly_boot_failed"
)

// Limits.
const (
	// MaxRows bounds the table; ClearAfter is how many evaluations in a row a condition must be clear before the alert resolves; KeepResolved is how
	// long a resolved alert stays listed.
	MaxRows      = 1000
	ClearAfter   = 2
	KeepResolved = 30 * 24 * time.Hour
)

// Alert is one stored alert.
type Alert struct {
	ID         string
	Key        string
	Type       string
	Kind       string // the resource kind the alert is about: Host, VM, Backup, Volume, ...
	ResourceID string
	Severity   string
	State      string
	Value      *int
	CreatedAt  time.Time // when this episode began (a re-opened alert starts a new episode)
	UpdatedAt  time.Time
}

var idRE = regexp.MustCompile(`^al-[0-9a-f]{16}$`)

// ValidID reports whether id has the grammar of an alert id.
func ValidID(id string) bool { return idRE.MatchString(id) }

// Store persists alerts.
type Store interface {
	ByKey(ctx context.Context, key string) (Alert, bool, error)
	ByID(ctx context.Context, id string) (Alert, bool, error)
	Put(ctx context.Context, a Alert) error
	// List returns alerts newest first (by updated_at, then id), optionally of one state, at most limit, starting after the alert with id after.
	List(ctx context.Context, state string, limit int, after string) ([]Alert, bool, error)
	// Open returns every alert that is not resolved.
	Open(ctx context.Context) ([]Alert, error)
	Prune(ctx context.Context, resolvedBefore time.Time) error
}

var schema = []string{`CREATE TABLE alerts (
	id            TEXT PRIMARY KEY CHECK (length(id) = 19),
	key           TEXT NOT NULL UNIQUE CHECK (length(key) <= 200),
	type          TEXT NOT NULL CHECK (length(type) BETWEEN 1 AND 63),
	resource_kind TEXT NOT NULL CHECK (length(resource_kind) BETWEEN 1 AND 20),
	resource_id   TEXT NOT NULL CHECK (length(resource_id) BETWEEN 1 AND 63),
	severity      TEXT NOT NULL CHECK (severity IN ('info','warning','critical')),
	state         TEXT NOT NULL CHECK (state IN ('open','acknowledged','resolved')),
	value         INTEGER CHECK (value IS NULL OR value >= 0),
	created_at    INTEGER NOT NULL,
	updated_at    INTEGER NOT NULL
);
CREATE INDEX alerts_recent ON alerts (updated_at DESC, id DESC);
CREATE INDEX alerts_state ON alerts (state, updated_at DESC);`}

// SchemaVersion is the schema version this build migrates the alert tables to.
func SchemaVersion() int { return len(schema) }

// SQLiteStore is the durable Store.
type SQLiteStore struct{ db *sql.DB }

// OpenSQLite migrates the schema in db and returns a store over it. The caller owns db.
func OpenSQLite(ctx context.Context, db *sql.DB) (*SQLiteStore, error) {
	if err := sqlitedb.Migrate(ctx, db, "alerts", schema); err != nil {
		return nil, fmt.Errorf("alerts: migrate: %w", err)
	}
	return &SQLiteStore{db: db}, nil
}

const cols = `id, key, type, resource_kind, resource_id, severity, state, value, created_at, updated_at`

func scan(r interface{ Scan(...any) error }) (Alert, error) {
	var (
		a            Alert
		v            sql.NullInt64
		created, upd int64
	)
	if err := r.Scan(&a.ID, &a.Key, &a.Type, &a.Kind, &a.ResourceID, &a.Severity, &a.State, &v, &created, &upd); err != nil {
		return Alert{}, err
	}
	if v.Valid {
		x := int(v.Int64)
		a.Value = &x
	}
	a.CreatedAt, a.UpdatedAt = time.Unix(0, created).UTC(), time.Unix(0, upd).UTC()
	return a, nil
}

func (s *SQLiteStore) one(ctx context.Context, where string, arg any) (Alert, bool, error) {
	a, err := scan(s.db.QueryRowContext(ctx, `SELECT `+cols+` FROM alerts WHERE `+where+` = ?`, arg))
	if errors.Is(err, sql.ErrNoRows) {
		return Alert{}, false, nil
	}
	return a, err == nil, err
}

// ByKey implements Store.
func (s *SQLiteStore) ByKey(ctx context.Context, key string) (Alert, bool, error) {
	return s.one(ctx, "key", key)
}

// ByID implements Store.
func (s *SQLiteStore) ByID(ctx context.Context, id string) (Alert, bool, error) {
	return s.one(ctx, "id", id)
}

// Put implements Store. It inserts, or replaces the mutable fields of the alert with the same id. A table at MaxRows refuses a new alert.
func (s *SQLiteStore) Put(ctx context.Context, a Alert) error {
	var v any
	if a.Value != nil {
		v = *a.Value
	}
	res, err := s.db.ExecContext(ctx, `UPDATE alerts SET severity = ?, state = ?, value = ?, created_at = ?, updated_at = ? WHERE id = ?`,
		a.Severity, a.State, v, a.CreatedAt.UnixNano(), a.UpdatedAt.UnixNano(), a.ID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n > 0 {
		return nil
	}
	var n int
	if err := s.db.QueryRowContext(ctx, `SELECT count(*) FROM alerts`).Scan(&n); err != nil {
		return err
	}
	if n >= MaxRows {
		return errors.New("alerts: table full")
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO alerts (`+cols+`) VALUES (?,?,?,?,?,?,?,?,?,?)`,
		a.ID, a.Key, a.Type, a.Kind, a.ResourceID, a.Severity, a.State, v, a.CreatedAt.UnixNano(), a.UpdatedAt.UnixNano())
	return err
}

// List implements Store.
func (s *SQLiteStore) List(ctx context.Context, state string, limit int, after string) ([]Alert, bool, error) {
	if limit < 1 || limit > 200 {
		limit = 50
	}
	var afterAt int64 = 1<<62 - 1
	afterID := "\xff"
	if after != "" {
		a, ok, err := s.ByID(ctx, after)
		if err != nil {
			return nil, false, err
		}
		if !ok {
			return nil, false, sql.ErrNoRows
		}
		afterAt, afterID = a.UpdatedAt.UnixNano(), a.ID
	}
	const q = `SELECT ` + cols + ` FROM alerts WHERE (? = '' OR state = ?) AND (updated_at < ? OR (updated_at = ? AND id < ?)) ORDER BY updated_at DESC, id DESC LIMIT ?`
	args := []any{state, state, afterAt, afterAt, afterID, limit + 1}
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, false, err
	}
	defer func() { _ = rows.Close() }()
	var out []Alert
	for rows.Next() {
		a, err := scan(rows)
		if err != nil {
			return nil, false, err
		}
		out = append(out, a)
	}
	if err := rows.Err(); err != nil {
		return nil, false, err
	}
	more := len(out) > limit
	if more {
		out = out[:limit]
	}
	return out, more, nil
}

// Open implements Store.
func (s *SQLiteStore) Open(ctx context.Context) ([]Alert, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+cols+` FROM alerts WHERE state <> 'resolved' ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []Alert
	for rows.Next() {
		a, err := scan(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// Prune implements Store.
func (s *SQLiteStore) Prune(ctx context.Context, resolvedBefore time.Time) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM alerts WHERE state = 'resolved' AND updated_at < ?`, resolvedBefore.UnixNano())
	return err
}

// Obs is one evaluated condition. Active means the condition holds now; Clear means it is clearly gone (past the hysteresis margin). Neither means the
// value is in the dead zone: an open alert stays as it is.
type Obs struct {
	Type       string
	Kind       string
	ResourceID string
	Severity   string
	Active     bool
	Clear      bool
	Value      *int
}

// Key is the dedup key of a condition.
func (o Obs) Key() string { return o.Type + "|" + o.Kind + "|" + o.ResourceID }

// Change is a state change worth telling someone about.
type Change struct {
	Alert Alert
	Event string // opened | reopened | escalated | resolved
}

// Engine applies observations to the store.
type Engine struct {
	Store Store
	Now   func() time.Time
	// NewID is injectable for tests.
	NewID func() (string, error)

	mu    sync.Mutex
	clear map[string]int
}

func randomID() (string, error) {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return "al-" + hex.EncodeToString(b[:]), nil
}

func (e *Engine) now() time.Time {
	if e.Now != nil {
		return e.Now().UTC()
	}
	return time.Now().UTC()
}

func rank(sev string) int {
	switch sev {
	case Critical:
		return 3
	case Warning:
		return 2
	}
	return 1
}

// Apply records the observations of one evaluation. covered lists the rule ids this evaluation judged completely: an open alert of such a rule that has no
// observation (its subject is gone) is treated as clear. A rule whose inputs were unavailable is left out of covered, so unknown data never resolves or
// raises anything.
func (e *Engine) Apply(ctx context.Context, obs []Obs, covered []string) ([]Change, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.clear == nil {
		e.clear = map[string]int{}
	}
	now := e.now()
	seen := map[string]bool{}
	var changes []Change
	for _, o := range obs {
		seen[o.Key()] = true
		cur, ok, err := e.Store.ByKey(ctx, o.Key())
		if err != nil {
			return changes, err
		}
		switch {
		case o.Active:
			delete(e.clear, o.Key())
			c, err := e.raise(ctx, cur, ok, o, now)
			if err != nil {
				return changes, err
			}
			if c != nil {
				changes = append(changes, *c)
			}
		case o.Clear && ok && cur.State != StateResolved:
			c, err := e.settle(ctx, cur, now)
			if err != nil {
				return changes, err
			}
			if c != nil {
				changes = append(changes, *c)
			}
		default:
			delete(e.clear, o.Key()) // the dead zone interrupts a clearing run
		}
	}
	cov := map[string]bool{}
	for _, t := range covered {
		cov[t] = true
	}
	open, err := e.Store.Open(ctx)
	if err != nil {
		return changes, err
	}
	for _, a := range open {
		if seen[a.Key] || !cov[a.Type] {
			continue
		}
		c, err := e.settle(ctx, a, now)
		if err != nil {
			return changes, err
		}
		if c != nil {
			changes = append(changes, *c)
		}
	}
	_ = e.Store.Prune(ctx, now.Add(-KeepResolved))
	return changes, nil
}

func (e *Engine) raise(ctx context.Context, cur Alert, ok bool, o Obs, now time.Time) (*Change, error) {
	switch {
	case !ok:
		newID := e.NewID
		if newID == nil {
			newID = randomID
		}
		id, err := newID()
		if err != nil {
			return nil, err
		}
		a := Alert{ID: id, Key: o.Key(), Type: o.Type, Kind: o.Kind, ResourceID: o.ResourceID, Severity: o.Severity, State: StateOpen, Value: o.Value, CreatedAt: now, UpdatedAt: now}
		if err := e.Store.Put(ctx, a); err != nil {
			return nil, err
		}
		return &Change{Alert: a, Event: "opened"}, nil
	case cur.State == StateResolved:
		cur.Severity, cur.State, cur.Value, cur.CreatedAt, cur.UpdatedAt = o.Severity, StateOpen, o.Value, now, now
		if err := e.Store.Put(ctx, cur); err != nil {
			return nil, err
		}
		return &Change{Alert: cur, Event: "reopened"}, nil
	case rank(o.Severity) > rank(cur.Severity):
		cur.Severity, cur.State, cur.Value, cur.UpdatedAt = o.Severity, StateOpen, o.Value, now // worse than what was acknowledged: look again
		if err := e.Store.Put(ctx, cur); err != nil {
			return nil, err
		}
		return &Change{Alert: cur, Event: "escalated"}, nil
	}
	// The same condition continues: the figure and severity follow it, the state (open or acknowledged) is kept, and no one is told again.
	if o.Severity != cur.Severity || !sameValue(cur.Value, o.Value) {
		cur.Severity, cur.Value, cur.UpdatedAt = o.Severity, o.Value, now
		return nil, e.Store.Put(ctx, cur)
	}
	return nil, nil
}

func sameValue(a, b *int) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return *a == *b
}

func (e *Engine) settle(ctx context.Context, cur Alert, now time.Time) (*Change, error) {
	e.clear[cur.Key]++
	if e.clear[cur.Key] < ClearAfter {
		return nil, nil
	}
	delete(e.clear, cur.Key)
	cur.State, cur.UpdatedAt = StateResolved, now
	if err := e.Store.Put(ctx, cur); err != nil {
		return nil, err
	}
	return &Change{Alert: cur, Event: "resolved"}, nil
}

// Acknowledge marks an open alert acknowledged. It is idempotent: an acknowledged alert stays so. An unknown alert is NotFound; a resolved one is a
// Conflict (there is nothing left to acknowledge).
func (e *Engine) Acknowledge(ctx context.Context, id string) error {
	if !ValidID(id) {
		return hypervisor.NewError(hypervisor.Validation, "alert_acknowledge", "", "invalid id")
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	a, ok, err := e.Store.ByID(ctx, id)
	switch {
	case err != nil:
		return hypervisor.NewError(hypervisor.Unavailable, "alert_acknowledge", "", "store unavailable")
	case !ok:
		return hypervisor.NewError(hypervisor.NotFound, "alert_acknowledge", "", "no such alert")
	case a.State == StateResolved:
		return hypervisor.NewError(hypervisor.Conflict, "alert_acknowledge", "", "alert already resolved")
	case a.State == StateAcknowledged:
		return nil
	}
	a.State, a.UpdatedAt = StateAcknowledged, e.now()
	if err := e.Store.Put(ctx, a); err != nil {
		return hypervisor.NewError(hypervisor.Unavailable, "alert_acknowledge", "", "store unavailable")
	}
	return nil
}
