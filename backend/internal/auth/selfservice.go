package auth

import (
	"context"
	"database/sql"
	"errors"
	"strings"
)

// ErrWrongPassword is returned by ChangeOwnPassword when the current password is not the user's. It says nothing else.
var ErrWrongPassword = errors.New("auth: the current password is not correct")

// ErrSamePassword is returned when the new password equals the current one.
var ErrSamePassword = errors.New("auth: the new password must differ from the current one")

// ChangeOwnPassword changes the password of the signed-in user (DR-041 D1). The current password is verified with the same limiter and slow-down as
// sign-in (so a stolen session cannot be used to guess it), the new one must meet the policy and differ, every OTHER session of the user ends while the
// one in use (sessionToken) stays, and a temporary password stops being temporary. Neither password is ever returned, logged or audited.
func (s *Service) ChangeOwnPassword(ctx context.Context, sess Session, sessionToken, current, next, source string) error {
	userKey := strings.ToLower(sess.Username)
	if len(userKey) > 64 {
		userKey = userKey[:64]
	}
	if wait := s.lim.check(source, userKey); wait > 0 {
		s.emit(ctx, AuditEvent{Event: "password_change", Outcome: "blocked", Reason: "rate_limited", Source: source, Username: userKey})
		return &RateLimitedError{RetryAfter: wait}
	}
	if d := s.lim.slow(userKey); d > 0 {
		s.cfg.Sleep(ctx, d)
	}
	var stored string
	if err := s.db.QueryRowContext(ctx, `SELECT password_phc FROM users WHERE id = ? AND disabled = 0`, sess.AdminID).Scan(&stored); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrUnauthenticated
		}
		return ErrInternal
	}
	if len(current) > MaxPasswordBytes {
		current = current[:MaxPasswordBytes]
	}
	ok, verr := s.verify(ctx, current, stored)
	switch {
	case errors.Is(verr, context.Canceled) || errors.Is(verr, context.DeadlineExceeded):
		return ErrInternal
	case verr != nil || !ok:
		s.lim.failure(source, userKey)
		s.emit(ctx, AuditEvent{Event: "password_change", Outcome: "failure", Reason: "invalid_credentials", Source: source, Username: userKey})
		return ErrWrongPassword
	}
	if err := CheckPassword(sess.Username, next); err != nil {
		return err
	}
	if next == current {
		return ErrSamePassword
	}
	phc, err := s.hashPassword(ctx, next)
	if err != nil {
		return ErrInternal
	}
	now := s.cfg.Clock().UnixNano()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return ErrInternal
	}
	defer func() { _ = tx.Rollback() }()
	if _, err = tx.ExecContext(ctx, `UPDATE users SET password_phc = ?, password_changed_at = ?, must_change = 0 WHERE id = ?`, phc, now, sess.AdminID); err == nil {
		_, err = tx.ExecContext(ctx, `UPDATE sessions SET revoked_at = ? WHERE admin_id = ? AND revoked_at IS NULL AND id_hash <> ?`, now, sess.AdminID, tokenHash(sessionToken))
	}
	if err != nil || tx.Commit() != nil {
		return ErrInternal
	}
	s.lim.success(source, userKey)
	s.emit(ctx, AuditEvent{Event: "password_change", Outcome: "success", Source: source, Username: userKey})
	return nil
}

// MustChangePassword reports whether the session's user has a temporary password. It is a read: it does not touch the session. An unknown, revoked
// or expired session reports false (the request is then refused for that reason by the route itself).
func (s *Service) MustChangePassword(ctx context.Context, token string) bool {
	if !ValidTokenFormat(token) {
		return false
	}
	var must int
	err := s.db.QueryRowContext(ctx, `SELECT a.must_change FROM sessions s JOIN users a ON a.id = s.admin_id WHERE s.id_hash = ? AND s.revoked_at IS NULL AND a.disabled = 0`, tokenHash(token)).Scan(&must)
	return err == nil && must == 1
}
