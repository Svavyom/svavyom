package auth

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"errors"
	"regexp"
	"strings"
	"sync"
	"time"

	"example.invalid/dedicatedcloud/backend/internal/sqlitedb"
)

// Errors returned by Service. None carries user input or a secret.
var (
	ErrAlreadyBootstrapped = errors.New("auth: an administrator already exists")
	ErrNotBootstrapped     = errors.New("auth: no administrator exists")
	ErrInvalidCredentials  = errors.New("auth: invalid credentials") // wrong password and unknown user alike
	ErrUnauthenticated     = errors.New("auth: no valid session")
	ErrInternal            = errors.New("auth: internal error")
	ErrBadUsername         = errors.New("auth: invalid username")
	ErrNoSuchUser          = errors.New("auth: no such user")
	ErrUserExists          = errors.New("auth: that username is taken")
	ErrBadRole             = errors.New("auth: role must be admin, operator or viewer")
	ErrLastAdmin           = errors.New("auth: this would leave no enabled administrator")
)

// RateLimitedError reports a blocked sign-in attempt and when to try again.
type RateLimitedError struct{ RetryAfter time.Duration }

func (e *RateLimitedError) Error() string { return "auth: rate limited" }

// Config tunes a Service. Zero values select the defaults; out-of-range values are clamped to the safe bounds.
type Config struct {
	IdleTimeout     time.Duration // default 30m, bounds 1m..24h
	AbsoluteTimeout time.Duration // default 12h, bounds idle..30d
	Params          Params        // default BaselineParams; must pass Params.Validate
	// HashConcurrency bounds simultaneous Argon2id computations (each uses Params.MemoryKiB). Default 2, max 8.
	HashConcurrency int
	Clock           func() time.Time
	Audit           AuditSink
}

// AuditEvent is one authentication audit record: identifiers and closed vocabulary only.
type AuditEvent struct {
	At      time.Time
	Event   string // sign_in, sign_out, bootstrap, password_reset, session_expired
	Outcome string // success, failure, blocked, revoked
	Reason  string // closed vocabulary, never free text
	Source  string // remote host (IP) as seen by the server, "" if unknown
}

// AuditSink receives events after they are durably stored. Implementations must not block.
type AuditSink interface{ Emit(AuditEvent) }

// Session is an authenticated session as seen by request handlers. It carries no secret.
type Session struct {
	AdminID   int64 // the user id (the name is kept from the single-administrator schema)
	Username  string
	Role      Role
	ExpiresAt time.Time // earlier of absolute expiry and idle expiry
	csrf      string    // the CSRF token bound to this session; derived, never stored
}

// Role is one of the three fixed roles (DR-023 D1).
type Role string

const (
	RoleAdmin    Role = "admin"
	RoleOperator Role = "operator"
	RoleViewer   Role = "viewer"
)

// ParseRole returns the role named s, or ErrBadRole.
func ParseRole(s string) (Role, error) {
	switch Role(s) {
	case RoleAdmin, RoleOperator, RoleViewer:
		return Role(s), nil
	}
	return "", ErrBadRole
}

// AtLeast reports whether r may do everything a user of role min may: admin > operator > viewer. An unknown role is never enough.
func (r Role) AtLeast(min Role) bool {
	rank := map[Role]int{RoleViewer: 1, RoleOperator: 2, RoleAdmin: 3}
	return rank[r] > 0 && rank[r] >= rank[min]
}

// Service owns the user credentials and the sessions.
type Service struct {
	db     *sql.DB
	cfg    Config
	hashes chan struct{} // semaphore over Argon2id computations
	dummy  string        // hash compared when the username is unknown, so both paths cost the same
	dmu    sync.Mutex
	lim    *limiter
}

var usernameRE = regexp.MustCompile(`^[a-z][a-z0-9._-]{2,31}$`)

var schema = []string{`
CREATE TABLE admin_account (
	id                  INTEGER PRIMARY KEY CHECK (id = 1),
	username            TEXT NOT NULL UNIQUE,
	password_phc        TEXT NOT NULL,
	created_at          INTEGER NOT NULL,
	password_changed_at INTEGER NOT NULL
);
CREATE TABLE sessions (
	id_hash             BLOB PRIMARY KEY CHECK (length(id_hash) = 32),
	admin_id            INTEGER NOT NULL REFERENCES admin_account (id),
	created_at          INTEGER NOT NULL,
	last_activity       INTEGER NOT NULL,
	absolute_expires_at INTEGER NOT NULL,
	revoked_at          INTEGER
);
CREATE INDEX sessions_admin ON sessions (admin_id);
CREATE TABLE auth_audit (
	seq     INTEGER PRIMARY KEY AUTOINCREMENT,
	at      INTEGER NOT NULL,
	event   TEXT NOT NULL,
	outcome TEXT NOT NULL,
	reason  TEXT NOT NULL DEFAULT '',
	source  TEXT NOT NULL DEFAULT ''
);
CREATE TRIGGER auth_audit_append_only BEFORE UPDATE ON auth_audit BEGIN SELECT RAISE(ABORT, 'audit is append-only'); END;
CREATE TRIGGER auth_audit_no_delete BEFORE DELETE ON auth_audit BEGIN SELECT RAISE(ABORT, 'audit is append-only'); END;`,
	// Step 2 (DR-023 D1): several users with a fixed role. The one administrator becomes the first admin (same id, same hash); sessions now point at users.
	`CREATE TABLE users (
	id                  INTEGER PRIMARY KEY AUTOINCREMENT,
	username            TEXT NOT NULL UNIQUE,
	password_phc        TEXT NOT NULL,
	role                TEXT NOT NULL CHECK (role IN ('admin','operator','viewer')),
	disabled            INTEGER NOT NULL DEFAULT 0 CHECK (disabled IN (0,1)),
	created_at          INTEGER NOT NULL,
	password_changed_at INTEGER NOT NULL
);
INSERT INTO users (id, username, password_phc, role, created_at, password_changed_at)
	SELECT id, username, password_phc, 'admin', created_at, password_changed_at FROM admin_account;
CREATE TABLE sessions_v2 (
	id_hash             BLOB PRIMARY KEY CHECK (length(id_hash) = 32),
	admin_id            INTEGER NOT NULL REFERENCES users (id),
	created_at          INTEGER NOT NULL,
	last_activity       INTEGER NOT NULL,
	absolute_expires_at INTEGER NOT NULL,
	revoked_at          INTEGER
);
INSERT INTO sessions_v2 SELECT id_hash, admin_id, created_at, last_activity, absolute_expires_at, revoked_at FROM sessions;
DROP TABLE sessions;
ALTER TABLE sessions_v2 RENAME TO sessions;
CREATE INDEX sessions_admin ON sessions (admin_id);`}

// New migrates the schema in db and returns a Service. The caller owns db.
func New(ctx context.Context, db *sql.DB, cfg Config) (*Service, error) {
	if cfg.Clock == nil {
		cfg.Clock = func() time.Time { return time.Now().UTC() }
	}
	cfg.IdleTimeout = clamp(cfg.IdleTimeout, 30*time.Minute, time.Minute, 24*time.Hour)
	cfg.AbsoluteTimeout = clamp(cfg.AbsoluteTimeout, 12*time.Hour, cfg.IdleTimeout, 30*24*time.Hour)
	if cfg.Params == (Params{}) {
		cfg.Params = BaselineParams
	}
	if err := cfg.Params.Validate(); err != nil {
		return nil, err
	}
	if cfg.HashConcurrency <= 0 {
		cfg.HashConcurrency = 2
	}
	cfg.HashConcurrency = min(cfg.HashConcurrency, 8)
	if err := sqlitedb.Migrate(ctx, db, "auth", schema); err != nil {
		return nil, ErrInternal
	}
	s := &Service{db: db, cfg: cfg, hashes: make(chan struct{}, cfg.HashConcurrency), lim: newLimiter(cfg.Clock)}
	// Compute the unknown-user dummy hash now, so the first unknown-user request does not cost more than the rest.
	if s.dummyHash(ctx) == "" {
		return nil, ErrInternal
	}
	return s, nil
}

func clamp(v, def, lo, hi time.Duration) time.Duration {
	if v <= 0 {
		v = def
	}
	return min(max(v, lo), hi)
}

func (s *Service) emit(ctx context.Context, ev AuditEvent) {
	ev.At = s.cfg.Clock()
	_, err := s.db.ExecContext(ctx, `INSERT INTO auth_audit (at, event, outcome, reason, source) VALUES (?,?,?,?,?)`,
		ev.At.UnixNano(), ev.Event, ev.Outcome, ev.Reason, ev.Source)
	if err == nil && s.cfg.Audit != nil {
		s.cfg.Audit.Emit(ev)
	}
}

// hash runs fn while holding one of the bounded Argon2id slots.
func (s *Service) hash(ctx context.Context, fn func()) error {
	select {
	case s.hashes <- struct{}{}:
	case <-ctx.Done():
		return ctx.Err()
	}
	defer func() { <-s.hashes }()
	fn()
	return nil
}

func (s *Service) hashPassword(ctx context.Context, password string) (phc string, err error) {
	if e := s.hash(ctx, func() { phc, err = HashPassword(password, s.cfg.Params) }); e != nil {
		return "", e
	}
	return phc, err
}

func (s *Service) verify(ctx context.Context, password, phc string) (ok bool, err error) {
	if e := s.hash(ctx, func() { ok, err = VerifyPassword(password, phc) }); e != nil {
		return false, e
	}
	return ok, err
}

// ValidUsername reports whether name is acceptable as the administrator's username.
func ValidUsername(name string) bool { return usernameRE.MatchString(name) }

// Bootstrap creates the first administrator. It succeeds only while no user exists; the single INSERT ... WHERE NOT EXISTS makes
// concurrent callers race to a single winner and the rest get ErrAlreadyBootstrapped. There is no default account.
func (s *Service) Bootstrap(ctx context.Context, username, password string) error {
	if !ValidUsername(username) {
		return ErrBadUsername
	}
	if err := CheckPassword(username, password); err != nil {
		return err
	}
	phc, err := s.hashPassword(ctx, password)
	if err != nil {
		return ErrInternal
	}
	now := s.cfg.Clock().UnixNano()
	res, err := s.db.ExecContext(ctx, `INSERT INTO users (username, password_phc, role, created_at, password_changed_at)
		SELECT ?, ?, 'admin', ?, ? WHERE NOT EXISTS (SELECT 1 FROM users)`, username, phc, now, now)
	if err != nil {
		return ErrInternal
	}
	if n, err := res.RowsAffected(); err != nil || n != 1 {
		s.emit(ctx, AuditEvent{Event: "bootstrap", Outcome: "failure", Reason: "already_exists"})
		if err != nil {
			return ErrInternal
		}
		return ErrAlreadyBootstrapped
	}
	s.emit(ctx, AuditEvent{Event: "bootstrap", Outcome: "success"})
	return nil
}

// Configured reports whether at least one user exists.
func (s *Service) Configured(ctx context.Context) (bool, error) {
	var n int
	if err := s.db.QueryRowContext(ctx, `SELECT count(*) FROM users`).Scan(&n); err != nil {
		return false, ErrInternal
	}
	return n >= 1, nil
}

// ResetPassword replaces the password of the first administrator (the recovery path of the single-administrator days) and revokes every session.
func (s *Service) ResetPassword(ctx context.Context, password string) error {
	var username string
	if err := s.db.QueryRowContext(ctx, `SELECT username FROM users WHERE role = 'admin' ORDER BY id LIMIT 1`).Scan(&username); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotBootstrapped
		}
		return ErrInternal
	}
	return s.SetPassword(ctx, username, password)
}

// SetPassword replaces a user's password (operator recovery with filesystem access to the database) and revokes that user's sessions, so a
// stolen session does not survive a credential change (DR-013).
func (s *Service) SetPassword(ctx context.Context, username, password string) error {
	username = strings.ToLower(username)
	var id int64
	if err := s.db.QueryRowContext(ctx, `SELECT id FROM users WHERE username = ?`, username).Scan(&id); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNoSuchUser
		}
		return ErrInternal
	}
	if err := CheckPassword(username, password); err != nil {
		return err
	}
	phc, err := s.hashPassword(ctx, password)
	if err != nil {
		return ErrInternal
	}
	now := s.cfg.Clock().UnixNano()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return ErrInternal
	}
	defer func() { _ = tx.Rollback() }()
	if _, err = tx.ExecContext(ctx, `UPDATE users SET password_phc = ?, password_changed_at = ? WHERE id = ?`, phc, now, id); err == nil {
		_, err = tx.ExecContext(ctx, `UPDATE sessions SET revoked_at = ? WHERE admin_id = ? AND revoked_at IS NULL`, now, id)
	}
	if err != nil || tx.Commit() != nil {
		return ErrInternal
	}
	s.emit(ctx, AuditEvent{Event: "password_reset", Outcome: "success"})
	return nil
}

// User is one account as the operator's commands show it. It carries no credential.
type User struct {
	Username string
	Role     Role
	Disabled bool
	Created  time.Time
}

// AddUser creates a user with the given role. The username must be unused.
func (s *Service) AddUser(ctx context.Context, username, password string, role Role) error {
	if !ValidUsername(username) {
		return ErrBadUsername
	}
	if _, err := ParseRole(string(role)); err != nil {
		return err
	}
	if err := CheckPassword(username, password); err != nil {
		return err
	}
	phc, err := s.hashPassword(ctx, password)
	if err != nil {
		return ErrInternal
	}
	now := s.cfg.Clock().UnixNano()
	res, err := s.db.ExecContext(ctx, `INSERT INTO users (username, password_phc, role, created_at, password_changed_at) VALUES (?,?,?,?,?) ON CONFLICT DO NOTHING`,
		username, phc, string(role), now, now)
	if err != nil {
		return ErrInternal
	}
	if n, err := res.RowsAffected(); err != nil || n != 1 {
		if err != nil {
			return ErrInternal
		}
		return ErrUserExists
	}
	s.emit(ctx, AuditEvent{Event: "user_add", Outcome: "success", Reason: string(role)})
	return nil
}

// ListUsers returns every user, oldest first.
func (s *Service) ListUsers(ctx context.Context) ([]User, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT username, role, disabled, created_at FROM users ORDER BY id`)
	if err != nil {
		return nil, ErrInternal
	}
	defer func() { _ = rows.Close() }()
	var out []User
	for rows.Next() {
		var (
			u        User
			role     string
			disabled int
			at       int64
		)
		if err := rows.Scan(&u.Username, &role, &disabled, &at); err != nil {
			return nil, ErrInternal
		}
		u.Role, u.Disabled, u.Created = Role(role), disabled == 1, time.Unix(0, at).UTC()
		out = append(out, u)
	}
	return out, rows.Err()
}

// enabledAdmins counts the enabled administrators other than the user id (so a change to that user cannot leave none).
func (s *Service) enabledAdminsExcept(ctx context.Context, tx *sql.Tx, id int64) (int, error) {
	var n int
	err := tx.QueryRowContext(ctx, `SELECT count(*) FROM users WHERE role = 'admin' AND disabled = 0 AND id <> ?`, id).Scan(&n)
	return n, err
}

// SetRole changes a user's role and revokes that user's sessions (a role change takes effect at once). The last enabled administrator cannot be demoted.
func (s *Service) SetRole(ctx context.Context, username string, role Role) error {
	if _, err := ParseRole(string(role)); err != nil {
		return err
	}
	return s.change(ctx, strings.ToLower(username), "role_change", string(role), func(tx *sql.Tx, id int64, current Role) error {
		if current == RoleAdmin && role != RoleAdmin {
			if n, err := s.enabledAdminsExcept(ctx, tx, id); err != nil {
				return ErrInternal
			} else if n == 0 {
				return ErrLastAdmin
			}
		}
		_, err := tx.ExecContext(ctx, `UPDATE users SET role = ? WHERE id = ?`, string(role), id)
		return err
	})
}

// SetDisabled disables or re-enables a user and revokes that user's sessions. The last enabled administrator cannot be disabled.
func (s *Service) SetDisabled(ctx context.Context, username string, disabled bool) error {
	event, flag := "user_enable", 0
	if disabled {
		event, flag = "user_disable", 1
	}
	return s.change(ctx, strings.ToLower(username), event, "", func(tx *sql.Tx, id int64, current Role) error {
		if disabled && current == RoleAdmin {
			if n, err := s.enabledAdminsExcept(ctx, tx, id); err != nil {
				return ErrInternal
			} else if n == 0 {
				return ErrLastAdmin
			}
		}
		_, err := tx.ExecContext(ctx, `UPDATE users SET disabled = ? WHERE id = ?`, flag, id)
		return err
	})
}

func (s *Service) change(ctx context.Context, username, event, reason string, fn func(tx *sql.Tx, id int64, current Role) error) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return ErrInternal
	}
	defer func() { _ = tx.Rollback() }()
	var (
		id   int64
		role string
	)
	if err := tx.QueryRowContext(ctx, `SELECT id, role FROM users WHERE username = ?`, username).Scan(&id, &role); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNoSuchUser
		}
		return ErrInternal
	}
	if err := fn(tx, id, Role(role)); err != nil {
		if errors.Is(err, ErrLastAdmin) {
			return err
		}
		return ErrInternal
	}
	if _, err := tx.ExecContext(ctx, `UPDATE sessions SET revoked_at = ? WHERE admin_id = ? AND revoked_at IS NULL`, s.cfg.Clock().UnixNano(), id); err != nil {
		return ErrInternal
	}
	if err := tx.Commit(); err != nil {
		return ErrInternal
	}
	s.emit(ctx, AuditEvent{Event: event, Outcome: "success", Reason: reason})
	return nil
}

// Token helpers. A token is 32 random bytes, base64url without padding (43 characters).
const tokenLen = 43

var tokenRE = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)

func newToken() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}

func tokenHash(token string) []byte {
	h := sha256.Sum256([]byte(token))
	return h[:]
}

// ValidTokenFormat reports whether v can possibly be a session or CSRF token; malformed values are rejected before
// any database access.
func ValidTokenFormat(v string) bool { return len(v) == tokenLen && tokenRE.MatchString(v) }

// SignInResult is what a successful sign-in hands to the HTTP layer. The tokens exist in clear only here.
type SignInResult struct {
	SessionToken string
	CSRFToken    string
	Session      Session
}

// SignIn verifies the credentials and starts a new session. presentedSession is the session cookie the browser sent
// with the request, if any: it is revoked, never reused (session fixation). source is the remote host for throttling
// and audit. Every failure, whatever the cause, is ErrInvalidCredentials or *RateLimitedError, and the work done is
// comparable for an unknown username and a wrong password.
func (s *Service) SignIn(ctx context.Context, username, password, source, presentedSession string) (SignInResult, error) {
	username = strings.ToLower(username) // stored usernames are lower case
	userKey := username
	if len(userKey) > 64 {
		userKey = userKey[:64]
	}
	if wait := s.lim.check(source, userKey); wait > 0 {
		s.emit(ctx, AuditEvent{Event: "sign_in", Outcome: "blocked", Reason: "rate_limited", Source: source})
		return SignInResult{}, &RateLimitedError{RetryAfter: wait}
	}
	var (
		id       int64
		stored   string
		storedBy string
		role     string
		disabled int
	)
	err := s.db.QueryRowContext(ctx, `SELECT id, username, password_phc, role, disabled FROM users WHERE username = ?`, username).Scan(&id, &storedBy, &stored, &role, &disabled)
	known := err == nil && storedBy == username && disabled == 0
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return SignInResult{}, ErrInternal
	}
	if !known {
		stored = s.dummyHash(ctx)
	}
	if len(password) > MaxPasswordBytes {
		password = password[:MaxPasswordBytes] // bound the work; such a password cannot match anyway
	}
	ok, verr := s.verify(ctx, password, stored)
	switch {
	case errors.Is(verr, context.Canceled) || errors.Is(verr, context.DeadlineExceeded):
		return SignInResult{}, ErrInternal
	case verr != nil: // corrupted credential row: fail closed, and say so only in the audit log
		s.lim.failure(source, userKey)
		s.emit(ctx, AuditEvent{Event: "sign_in", Outcome: "failure", Reason: "credential_corrupt", Source: source})
		return SignInResult{}, ErrInvalidCredentials
	case !ok || !known:
		s.lim.failure(source, userKey)
		s.emit(ctx, AuditEvent{Event: "sign_in", Outcome: "failure", Reason: "invalid_credentials", Source: source})
		return SignInResult{}, ErrInvalidCredentials
	}
	s.lim.success(source, userKey)
	if NeedsRehash(stored, s.cfg.Params) { // best effort upgrade to the current baseline
		if phc, err := s.hashPassword(ctx, password); err == nil {
			_, _ = s.db.ExecContext(ctx, `UPDATE users SET password_phc = ? WHERE id = ? AND password_phc = ?`, phc, id, stored)
		}
	}
	return s.startSession(ctx, id, storedBy, Role(role), source, presentedSession)
}

func (s *Service) startSession(ctx context.Context, adminID int64, username string, role Role, source, presented string) (SignInResult, error) {
	st, err := newToken()
	if err != nil {
		return SignInResult{}, ErrInternal
	}
	ct := deriveCSRF(st, csrfSession)
	now := s.cfg.Clock()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return SignInResult{}, ErrInternal
	}
	defer func() { _ = tx.Rollback() }()
	if ValidTokenFormat(presented) { // fixation: a session presented at sign-in is ended, not adopted
		if _, err := tx.ExecContext(ctx, `UPDATE sessions SET revoked_at = ? WHERE id_hash = ? AND revoked_at IS NULL`,
			now.UnixNano(), tokenHash(presented)); err != nil {
			return SignInResult{}, ErrInternal
		}
	}
	abs := now.Add(s.cfg.AbsoluteTimeout)
	if _, err := tx.ExecContext(ctx, `INSERT INTO sessions (id_hash, admin_id, created_at, last_activity, absolute_expires_at)
		VALUES (?,?,?,?,?)`, tokenHash(st), adminID, now.UnixNano(), now.UnixNano(), abs.UnixNano()); err != nil {
		return SignInResult{}, ErrInternal
	}
	// Housekeeping: sessions that have been dead for a day carry no information worth keeping.
	cutoff := now.Add(-24 * time.Hour).UnixNano()
	if _, err := tx.ExecContext(ctx, `DELETE FROM sessions WHERE absolute_expires_at < ? OR revoked_at < ?`, cutoff, cutoff); err != nil {
		return SignInResult{}, ErrInternal
	}
	if err := tx.Commit(); err != nil {
		return SignInResult{}, ErrInternal
	}
	s.emit(ctx, AuditEvent{Event: "sign_in", Outcome: "success", Source: source})
	return SignInResult{SessionToken: st, CSRFToken: ct, Session: Session{AdminID: adminID, Username: username, Role: role,
		ExpiresAt: s.expiry(now, abs), csrf: ct}}, nil
}

func (s *Service) expiry(lastActivity, absolute time.Time) time.Time {
	idle := lastActivity.Add(s.cfg.IdleTimeout)
	if idle.Before(absolute) {
		return idle
	}
	return absolute
}

// touchEvery limits write amplification: last_activity is persisted at most this often per session, so idle expiry
// is accurate to this granularity.
const touchEvery = 10 * time.Second

// Authenticate resolves a session token to a Session, enforcing revocation, idle and absolute expiry, and records
// activity. Any malformed, unknown, revoked or expired token is ErrUnauthenticated, indistinguishably.
func (s *Service) Authenticate(ctx context.Context, token string) (Session, error) {
	if !ValidTokenFormat(token) {
		return Session{}, ErrUnauthenticated
	}
	var (
		adminID        int64
		username       string
		role           string
		last, abs      int64
		revoked        sql.NullInt64
		now            = s.cfg.Clock()
		h              = tokenHash(token)
		lastT, absT    time.Time
		expiredBecause string
	)
	err := s.db.QueryRowContext(ctx, `SELECT s.admin_id, a.username, a.role, s.last_activity, s.absolute_expires_at, s.revoked_at
		FROM sessions s JOIN users a ON a.id = s.admin_id WHERE s.id_hash = ? AND a.disabled = 0`, h).
		Scan(&adminID, &username, &role, &last, &abs, &revoked)
	if errors.Is(err, sql.ErrNoRows) {
		return Session{}, ErrUnauthenticated
	}
	if err != nil {
		return Session{}, ErrInternal
	}
	lastT, absT = time.Unix(0, last).UTC(), time.Unix(0, abs).UTC()
	switch {
	case revoked.Valid:
		return Session{}, ErrUnauthenticated
	case !now.Before(absT):
		expiredBecause = "absolute_timeout"
	case !now.Before(lastT.Add(s.cfg.IdleTimeout)):
		expiredBecause = "idle_timeout"
	}
	if expiredBecause != "" {
		// Revoke so the token can never come back to life (a clock step backwards, a later config change).
		if res, err := s.db.ExecContext(ctx, `UPDATE sessions SET revoked_at = ? WHERE id_hash = ? AND revoked_at IS NULL`, now.UnixNano(), h); err == nil {
			if n, _ := res.RowsAffected(); n == 1 {
				s.emit(ctx, AuditEvent{Event: "session_expired", Outcome: "revoked", Reason: expiredBecause})
			}
		}
		return Session{}, ErrUnauthenticated
	}
	if now.Sub(lastT) >= touchEvery {
		// Conditional on revoked_at IS NULL so a concurrent sign-out wins over a touch.
		if _, err := s.db.ExecContext(ctx, `UPDATE sessions SET last_activity = ? WHERE id_hash = ? AND revoked_at IS NULL AND last_activity < ?`,
			now.UnixNano(), h, now.UnixNano()); err != nil {
			return Session{}, ErrInternal
		}
		lastT = now
	}
	return Session{AdminID: adminID, Username: username, Role: Role(role), ExpiresAt: s.expiry(lastT, absT), csrf: deriveCSRF(token, csrfSession)}, nil
}

// SignOut revokes the session of token. It is idempotent and does not reveal whether the token was valid.
func (s *Service) SignOut(ctx context.Context, token string) error {
	if !ValidTokenFormat(token) {
		return nil
	}
	res, err := s.db.ExecContext(ctx, `UPDATE sessions SET revoked_at = ? WHERE id_hash = ? AND revoked_at IS NULL`,
		s.cfg.Clock().UnixNano(), tokenHash(token))
	if err != nil {
		return ErrInternal
	}
	if n, _ := res.RowsAffected(); n == 1 {
		s.emit(ctx, AuditEvent{Event: "sign_out", Outcome: "success"})
	}
	return nil
}

// CSRF tokens are derived, not stored: HMAC-SHA256 keyed by a secret only the legitimate browser holds (the session
// token for signed-in requests, the pre-sign-in nonce for sign-in itself), over a purpose label. They are therefore
// unpredictable to a third party, bound to exactly one session, stable across tabs and reloads, survive a restart, and
// need no server-side secret at rest. The label keeps a session CSRF token from doubling as a login token.
const (
	csrfSession = "svavyom-csrf-session-v1"
	csrfLogin   = "svavyom-csrf-login-v1"
)

func deriveCSRF(secret, purpose string) string {
	m := hmac.New(sha256.New, []byte(secret))
	m.Write([]byte(purpose))
	return base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}

// CSRFToken returns the token the browser must echo in X-CSRF-Token on state-changing requests of this session.
func (sess Session) CSRFToken() string { return sess.csrf }

// CSRFMatches reports, in constant time, whether presented is the CSRF token of sess.
func (sess Session) CSRFMatches(presented string) bool {
	if !ValidTokenFormat(presented) || !ValidTokenFormat(sess.csrf) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(presented), []byte(sess.csrf)) == 1
}

// NewLoginNonce returns a fresh nonce for the pre-sign-in cookie and the CSRF token bound to it (login CSRF).
func (s *Service) NewLoginNonce() (nonce, csrf string, err error) {
	nonce, err = newToken()
	if err != nil {
		return "", "", ErrInternal
	}
	return nonce, LoginCSRF(nonce), nil
}

// LoginCSRF derives the pre-sign-in CSRF token from the nonce held in the HttpOnly pre-sign-in cookie.
func LoginCSRF(nonce string) string { return deriveCSRF(nonce, csrfLogin) }

// LoginCSRFValid checks a pre-sign-in token against the nonce cookie in constant time.
func LoginCSRFValid(nonce, presented string) bool {
	if !ValidTokenFormat(nonce) || !ValidTokenFormat(presented) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(LoginCSRF(nonce)), []byte(presented)) == 1
}

// dummyHash is computed once, with the current parameters, for the unknown-username path.
func (s *Service) dummyHash(ctx context.Context) string {
	s.dmu.Lock()
	defer s.dmu.Unlock()
	if s.dummy == "" {
		if phc, err := s.hashPassword(ctx, "dummy-password-never-valid"); err == nil {
			s.dummy = phc
		}
	}
	return s.dummy
}

// Audit returns the stored authentication audit events, oldest first (tests and the later history view).
func (s *Service) Audit(ctx context.Context) ([]AuditEvent, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT at, event, outcome, reason, source FROM auth_audit ORDER BY seq`)
	if err != nil {
		return nil, ErrInternal
	}
	defer func() { _ = rows.Close() }()
	var out []AuditEvent
	for rows.Next() {
		var (
			ev AuditEvent
			at int64
		)
		if err := rows.Scan(&at, &ev.Event, &ev.Outcome, &ev.Reason, &ev.Source); err != nil {
			return nil, ErrInternal
		}
		ev.At = time.Unix(0, at).UTC()
		out = append(out, ev)
	}
	return out, rows.Err()
}

// SchemaVersion is the schema version this build migrates the authentication tables to.
func SchemaVersion() int { return len(schema) }
