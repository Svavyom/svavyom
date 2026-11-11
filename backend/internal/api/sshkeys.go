package api

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"example.invalid/dedicatedcloud/backend/internal/auth"
	"example.invalid/dedicatedcloud/backend/internal/sshkeys"
)

// SSHKeyLibrary is the saved public keys (DR-040). Nil keeps the routes closed. It holds public keys only; the API never sees a private key.
type SSHKeyLibrary interface {
	List(ctx context.Context) ([]sshkeys.Key, error)
	Add(ctx context.Context, actor, name, publicKey string) (sshkeys.Key, error)
	Delete(ctx context.Context, actor string, admin bool, id string) error
}

type sshKeyJSON struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Type        string   `json:"type"`
	PublicKey   string   `json:"public_key"`
	Fingerprint string   `json:"fingerprint"`
	AddedBy     string   `json:"added_by"`
	AddedAt     string   `json:"added_at"`
	Allowed     []string `json:"allowed_actions"`
}

type sshKeyBody struct {
	Name      string `json:"name"`
	PublicKey string `json:"public_key"`
}

// maySSHKey reports whether the caller may delete k: an administrator, or the user who added it (and only an operator or administrator adds).
func maySSHKey(sess auth.Session, k sshkeys.Key) bool {
	return sess.Role.AtLeast(auth.RoleAdmin) || (sess.Role.AtLeast(auth.RoleOperator) && k.AddedBy == sess.Username)
}

func toSSHKeyJSON(sess auth.Session, k sshkeys.Key) sshKeyJSON {
	allowed := []string{}
	if maySSHKey(sess, k) {
		allowed = append(allowed, "delete")
	}
	return sshKeyJSON{ID: k.ID, Name: k.Name, Type: k.Type, PublicKey: k.PublicKey, Fingerprint: k.Fingerprint, AddedBy: k.AddedBy, AddedAt: k.AddedAt.UTC().Format(time.RFC3339), Allowed: allowed}
}

// sshKeySession resolves the session for the key routes and answers 401, 503 or 404 itself. A state-changing request also needs the same origin and the
// CSRF token.
func (h *Handler) sshKeySession(w http.ResponseWriter, r *http.Request, changes bool) (auth.Session, bool) {
	if h.deps.Auth == nil || h.deps.SSHKeys == nil {
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
	return sess, true
}

func (h *Handler) sshKeyError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, sshkeys.ErrInvalid):
		h.reject(w, categoryValidation)
	case errors.Is(err, sshkeys.ErrDuplicate), errors.Is(err, sshkeys.ErrFull):
		h.reject(w, categoryConflict)
	case errors.Is(err, sshkeys.ErrNotFound):
		h.reject(w, categoryNotFound)
	case errors.Is(err, sshkeys.ErrForbidden):
		h.reject(w, categoryForbidden)
	default:
		h.reject(w, categoryUnavailable)
	}
}

// listSSHKeys answers GET /api/v1/ssh-keys: every saved key, by name, for any signed-in role.
func (h *Handler) listSSHKeys(w http.ResponseWriter, r *http.Request) {
	sess, ok := h.sshKeySession(w, r, false)
	if !ok {
		return
	}
	if len(r.URL.Query()) != 0 {
		h.reject(w, categoryValidation)
		return
	}
	keys, err := h.deps.SSHKeys.List(r.Context())
	if err != nil {
		h.reject(w, categoryUnavailable)
		return
	}
	items := make([]sshKeyJSON, 0, len(keys))
	for _, k := range keys {
		items = append(items, toSSHKeyJSON(sess, k))
	}
	allowed := []string{}
	if sess.Role.AtLeast(auth.RoleOperator) {
		allowed = append(allowed, "add")
	}
	writeJSON(w, http.StatusOK, struct {
		Items   []sshKeyJSON `json:"items"`
		Allowed []string     `json:"allowed_actions"`
	}{Items: items, Allowed: allowed})
}

// addSSHKey answers POST /api/v1/ssh-keys: an operator or administrator saves one public key.
func (h *Handler) addSSHKey(w http.ResponseWriter, r *http.Request) {
	sess, ok := h.sshKeySession(w, r, true)
	if !ok {
		return
	}
	if !sess.Role.AtLeast(auth.RoleOperator) {
		h.reject(w, categoryForbidden)
		return
	}
	var body sshKeyBody
	if len(r.URL.Query()) != 0 || !decodeBodyLimit(w, r, &body, 8192) {
		h.reject(w, categoryValidation)
		return
	}
	k, err := h.deps.SSHKeys.Add(r.Context(), sess.Username, body.Name, body.PublicKey)
	if err != nil {
		h.sshKeyError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, toSSHKeyJSON(sess, k))
}

// deleteSSHKey answers DELETE /api/v1/ssh-keys/{id}: an administrator, or the user who added the key. It returns the key that was removed.
func (h *Handler) deleteSSHKey(w http.ResponseWriter, r *http.Request) {
	sess, ok := h.sshKeySession(w, r, true)
	if !ok {
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/api/v1/ssh-keys/")
	if len(r.URL.Query()) != 0 || !sshkeys.IDRE.MatchString(id) {
		h.reject(w, categoryValidation)
		return
	}
	keys, err := h.deps.SSHKeys.List(r.Context())
	if err != nil {
		h.reject(w, categoryUnavailable)
		return
	}
	var gone sshkeys.Key
	for _, k := range keys {
		if k.ID == id {
			gone = k
		}
	}
	if err := h.deps.SSHKeys.Delete(r.Context(), sess.Username, sess.Role.AtLeast(auth.RoleAdmin), id); err != nil {
		h.sshKeyError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, toSSHKeyJSON(sess, gone))
}
