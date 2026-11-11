package api

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"example.invalid/dedicatedcloud/backend/internal/auth"
)

// Users and passwords in the console (DR-041). The routes call the same auth.Service methods as the host's `api user-*` commands, so the guards (the last
// enabled administrator, the password policy, sessions revoked on every credential or role change) and the audit are the same. No response carries a
// password or a hash.

type userJSON struct {
	Username   string   `json:"username"`
	Role       string   `json:"role"`
	Disabled   bool     `json:"disabled"`
	MustChange bool     `json:"must_change_password"`
	CreatedAt  string   `json:"created_at"`
	Allowed    []string `json:"allowed_actions"`
}

// toUserJSON describes u to the administrator who asks. An administrator cannot change their own role, disable or reset themselves here (a slip could
// lock the installation; the host's CLI stays the recovery path and the password change is how you change your own password), so own row offers nothing.
func toUserJSON(u auth.User, me string) userJSON {
	allowed := []string{}
	if u.Username != me {
		allowed = append(allowed, "set_role", "reset_password")
		if u.Disabled {
			allowed = append(allowed, "enable")
		} else {
			allowed = append(allowed, "disable")
		}
	}
	return userJSON{Username: u.Username, Role: string(u.Role), Disabled: u.Disabled, MustChange: u.MustChange, CreatedAt: u.Created.UTC().Format(time.RFC3339), Allowed: allowed}
}

type addUserBody struct {
	Username string `json:"username"`
	Role     string `json:"role"`
	Password string `json:"password"`
}

type roleBody struct {
	Role string `json:"role"`
}

type passwordBody struct {
	Password string `json:"password"`
}

type changePasswordBody struct {
	Current string `json:"current_password"`
	New     string `json:"new_password"`
}

// userAdminSession resolves the session for a Users route: an administrator, with the CSRF token and the same origin for a change.
func (h *Handler) userAdminSession(w http.ResponseWriter, r *http.Request, changes bool) (auth.Session, bool) {
	if h.deps.Auth == nil {
		h.reject(w, categoryUnauthenticated)
		return auth.Session{}, false
	}
	sess, _, ok, failed := h.session(r)
	switch {
	case failed:
		h.reject(w, categoryUnavailable)
		return auth.Session{}, false
	case !ok:
		h.reject(w, categoryUnauthenticated)
		return auth.Session{}, false
	}
	if changes && (!h.sameOrigin(r) || !sess.CSRFMatches(r.Header.Get(csrfHeader))) {
		h.reject(w, categoryForbidden)
		return auth.Session{}, false
	}
	if !sess.Role.AtLeast(auth.RoleAdmin) {
		h.reject(w, categoryForbidden)
		return auth.Session{}, false
	}
	return sess, true
}

func (h *Handler) userError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, auth.ErrBadUsername), errors.Is(err, auth.ErrBadRole), errors.Is(err, auth.ErrPasswordPolicy):
		h.reject(w, categoryValidation)
	case errors.Is(err, auth.ErrUserExists), errors.Is(err, auth.ErrLastAdmin):
		h.reject(w, categoryConflict)
	case errors.Is(err, auth.ErrNoSuchUser):
		h.reject(w, categoryNotFound)
	default:
		h.reject(w, categoryInternal)
	}
}

// targetUser reads the user named in /api/v1/users/{id}/..., refusing a malformed name, the caller themselves, and an unknown user.
func (h *Handler) targetUser(w http.ResponseWriter, r *http.Request, sess auth.Session, suffix string) (string, bool) {
	name := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/api/v1/users/"), "/"+suffix)
	if len(r.URL.Query()) != 0 || !auth.ValidUsername(name) {
		h.reject(w, categoryValidation)
		return "", false
	}
	if name == sess.Username {
		h.reject(w, categoryForbidden)
		return "", false
	}
	return name, true
}

// oneUser returns the user as the administrator sees them now.
func (h *Handler) oneUser(ctx context.Context, name, me string) (userJSON, error) {
	users, err := h.deps.Auth.ListUsers(ctx)
	if err != nil {
		return userJSON{}, err
	}
	for _, u := range users {
		if u.Username == name {
			return toUserJSON(u, me), nil
		}
	}
	return userJSON{}, auth.ErrNoSuchUser
}

// listUsers answers GET /api/v1/users (administrators).
func (h *Handler) listUsers(w http.ResponseWriter, r *http.Request) {
	sess, ok := h.userAdminSession(w, r, false)
	if !ok {
		return
	}
	if len(r.URL.Query()) != 0 {
		h.reject(w, categoryValidation)
		return
	}
	users, err := h.deps.Auth.ListUsers(r.Context())
	if err != nil {
		h.reject(w, categoryUnavailable)
		return
	}
	items := make([]userJSON, 0, len(users))
	for _, u := range users {
		items = append(items, toUserJSON(u, sess.Username))
	}
	writeJSON(w, http.StatusOK, struct {
		Items   []userJSON `json:"items"`
		Allowed []string   `json:"allowed_actions"`
	}{Items: items, Allowed: []string{"create"}})
}

// addUser answers POST /api/v1/users: a new user with a temporary password they must change at the next sign-in.
func (h *Handler) addUser(w http.ResponseWriter, r *http.Request) {
	sess, ok := h.userAdminSession(w, r, true)
	if !ok {
		return
	}
	var b addUserBody
	if len(r.URL.Query()) != 0 || !decodeBody(w, r, &b) || len(b.Password) > auth.MaxPasswordBytes || !utf8.ValidString(b.Username) {
		h.reject(w, categoryValidation)
		return
	}
	role, err := auth.ParseRole(b.Role)
	if err != nil {
		h.userError(w, err)
		return
	}
	if err := h.deps.Auth.AddUserWithTemporaryPassword(r.Context(), b.Username, b.Password, role); err != nil {
		h.userError(w, err)
		return
	}
	u, err := h.oneUser(r.Context(), b.Username, sess.Username)
	if err != nil {
		h.userError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, u)
}

// setUserRole answers POST /api/v1/users/{id}/role.
func (h *Handler) setUserRole(w http.ResponseWriter, r *http.Request) {
	sess, ok := h.userAdminSession(w, r, true)
	if !ok {
		return
	}
	name, ok := h.targetUser(w, r, sess, "role")
	if !ok {
		return
	}
	var b roleBody
	if !decodeBody(w, r, &b) {
		h.reject(w, categoryValidation)
		return
	}
	role, err := auth.ParseRole(b.Role)
	if err != nil {
		h.userError(w, err)
		return
	}
	if err := h.deps.Auth.SetRole(r.Context(), name, role); err != nil {
		h.userError(w, err)
		return
	}
	h.replyUser(w, r, name, sess)
}

// setUserDisabled answers POST /api/v1/users/{id}/disable and /enable.
func (h *Handler) setUserDisabled(w http.ResponseWriter, r *http.Request, disable bool) {
	sess, ok := h.userAdminSession(w, r, true)
	if !ok {
		return
	}
	suffix := "enable"
	if disable {
		suffix = "disable"
	}
	name, ok := h.targetUser(w, r, sess, suffix)
	if !ok {
		return
	}
	if r.ContentLength > 0 && !decodeBodyLimit(w, r, &struct{}{}, 64) {
		h.reject(w, categoryValidation)
		return
	}
	if err := h.deps.Auth.SetDisabled(r.Context(), name, disable); err != nil {
		h.userError(w, err)
		return
	}
	h.replyUser(w, r, name, sess)
}

// resetUserPassword answers POST /api/v1/users/{id}/password: a temporary password the user must change at the next sign-in; their sessions end.
func (h *Handler) resetUserPassword(w http.ResponseWriter, r *http.Request) {
	sess, ok := h.userAdminSession(w, r, true)
	if !ok {
		return
	}
	name, ok := h.targetUser(w, r, sess, "password")
	if !ok {
		return
	}
	var b passwordBody
	if !decodeBody(w, r, &b) || len(b.Password) > auth.MaxPasswordBytes {
		h.reject(w, categoryValidation)
		return
	}
	if err := h.deps.Auth.SetTemporaryPassword(r.Context(), name, b.Password); err != nil {
		h.userError(w, err)
		return
	}
	h.replyUser(w, r, name, sess)
}

func (h *Handler) replyUser(w http.ResponseWriter, r *http.Request, name string, sess auth.Session) {
	u, err := h.oneUser(r.Context(), name, sess.Username)
	if err != nil {
		h.userError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, u)
}

// changeOwnPassword answers POST /api/v1/auth/password (every role): the signed-in user changes their own password.
func (h *Handler) changeOwnPassword(w http.ResponseWriter, r *http.Request) {
	if h.deps.Auth == nil {
		h.reject(w, categoryUnauthenticated)
		return
	}
	sess, token, ok, failed := h.session(r)
	switch {
	case failed:
		h.reject(w, categoryUnavailable)
		return
	case !ok:
		h.reject(w, categoryUnauthenticated)
		return
	}
	if !h.sameOrigin(r) || !sess.CSRFMatches(r.Header.Get(csrfHeader)) {
		h.reject(w, categoryForbidden)
		return
	}
	var b changePasswordBody
	if len(r.URL.Query()) != 0 || !decodeBody(w, r, &b) || b.Current == "" || len(b.Current) > auth.MaxPasswordBytes || len(b.New) > auth.MaxPasswordBytes {
		h.reject(w, categoryValidation)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), signInDeadline)
	defer cancel()
	err := h.deps.Auth.ChangeOwnPassword(ctx, sess, token, b.Current, b.New, h.clientHost(r))
	var rl *auth.RateLimitedError
	switch {
	case err == nil:
	case errors.Is(err, auth.ErrWrongPassword):
		h.reject(w, categoryForbidden)
		return
	case errors.Is(err, auth.ErrPasswordPolicy), errors.Is(err, auth.ErrSamePassword):
		h.reject(w, categoryValidation)
		return
	case errors.Is(err, auth.ErrUnauthenticated):
		h.reject(w, categoryUnauthenticated)
		return
	case errors.As(err, &rl):
		secs := int(rl.RetryAfter/time.Second) + 1
		h.rejectWith(w, categoryRateLimited, func(hd http.Header) { hd.Set("Retry-After", strconv.Itoa(secs)) })
		return
	default:
		h.reject(w, categoryInternal)
		return
	}
	now, nerr := h.deps.Auth.Authenticate(r.Context(), token)
	if nerr != nil {
		h.reject(w, categoryInternal)
		return
	}
	w.Header().Set(csrfHeader, now.CSRFToken())
	writeJSON(w, http.StatusOK, fromSession(now))
}

// mustChangeGate refuses every request of a user who has a temporary password except the status, the password change, sign-out and the health check
// (DR-041 D3). It runs before any route, the console included, so a new route cannot forget it.
func (h *Handler) mustChangeGate(w http.ResponseWriter, r *http.Request) bool {
	if h.deps.Auth == nil {
		return true
	}
	switch p := r.URL.Path; {
	case p == "/healthz", p == "/api/v1/auth/session", p == "/api/v1/auth/password":
		return true
	}
	tok := cookieValue(r, sessionCookieName(h.isSecure(r)))
	if tok == "" || !h.deps.Auth.MustChangePassword(r.Context(), tok) {
		return true
	}
	h.reject(w, categoryForbidden)
	return false
}
