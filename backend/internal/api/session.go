package api

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"time"
	"unicode/utf8"

	"example.invalid/dedicatedcloud/backend/internal/auth"
	"example.invalid/dedicatedcloud/backend/internal/hostinfo"
	"example.invalid/dedicatedcloud/backend/internal/hypervisor"
	"example.invalid/dedicatedcloud/backend/internal/metrics"
)

// HostSource supplies the host summary (package hostinfo).
type HostSource interface {
	Host(ctx context.Context) (hostinfo.Info, error)
}

// Deps are the collaborators of the implemented routes. A nil Auth keeps the scaffold behaviour.
type Deps struct {
	Auth  *auth.Service
	Hosts HostSource
	// VMs is the read-only view of the managed host's virtual machines (the agent client). Nil keeps the routes closed.
	VMs hypervisor.Reader
	// Now is injectable for tests; default time.Now.
	Now func() time.Time
	// TrustForwardedProto makes X-Forwarded-Proto: https count as HTTPS for the Secure cookie attribute. Enable it only
	// behind a TLS-terminating proxy that sets the header; otherwise any client could influence it.
	TrustForwardedProto bool
	// Creation wires VM creation and start (DR-016). Nil keeps every creation route closed.
	Creation *Creation
	// Console wires the serial console route family (M1-D). Nil keeps every console route closed (not_found).
	Console *Console
	// Usage supplies the sampled host and VM usage (DR-022). Nil reports every usage as unavailable with an empty history.
	Usage UsageSource
	// Firewall returns the findings of the last firewall check recorded by svavyom-ctl (DR-024 D1); nil adds none. The API never reads firewall state itself.
	Firewall func() []FirewallFinding
	// Alerts is the alert subsystem as the API sees it (DR-024 D2). Nil reports no alerts and an empty list.
	Alerts *AlertsView
	// Schedules is the backup schedule store (DR-024 D3). Nil reports every VM without a schedule and offers no schedule action.
	Schedules ScheduleSource
	// NightlyBoot returns the last nightly real guest boot recorded by svavyom-ctl (DR-024 D4), or nil when none has run. The API reads a file; it never runs one.
	NightlyBoot func() *NightlyResult
	// Bridge returns the host bridge state recorded by svavyom-ctl (DR-024 D5), or nil when there is none. The API reads a file; it can neither plan nor apply.
	Bridge func() *BridgeObserved
	// BridgeDevice reports whether the host has a bridge device of that name; nil reads sysfs.
	BridgeDevice func(name string) bool
}

// BridgeObserved is the host bridge as svavyom-ctl recorded it: a closed state, the bridge and uplink names, and the seconds left to confirm.
type BridgeObserved struct {
	State       string
	Bridge      string
	Interface   string
	SecondsLeft *int
}

// NightlyResult is the last nightly boot: when it ran, "pass", "fail" or "skipped", and how many seconds it took.
type NightlyResult struct {
	At      time.Time
	Result  string
	Seconds int
}

// FirewallFinding is one recorded firewall conflict: a closed code and the remediation text.
type FirewallFinding struct{ Code, Remediation string }

// UsageSource is the sampler as the API sees it.
type UsageSource interface {
	Host(ctx context.Context) metrics.HostUsage
	VMs(ctx context.Context) map[string]metrics.VMUsage
}

const (
	maxBodyBytes   = 4096
	signInDeadline = 15 * time.Second
	csrfHeader     = "X-CSRF-Token"
)

// isSecure reports whether the request reached us over HTTPS, which decides the Secure attribute and the __Host- prefix.
func (h *Handler) isSecure(r *http.Request) bool {
	return r.TLS != nil || (h.deps.TrustForwardedProto && r.Header.Get("X-Forwarded-Proto") == "https")
}

func sessionCookieName(secure bool) string {
	if secure {
		return "__Host-svavyom_session"
	}
	return "svavyom_session"
}

func loginCookieName(secure bool) string {
	if secure {
		return "__Host-svavyom_login"
	}
	return "svavyom_login"
}

func (h *Handler) setCookie(w http.ResponseWriter, r *http.Request, name, value string, maxAge int) {
	// Secure is set whenever the request arrived over HTTPS (TLS, or a trusted proxy header); plain HTTP is the
	// loopback development listener only, and the browser would drop a Secure cookie there (docs/AUTH.md).
	http.SetCookie(w, &http.Cookie{Name: name, Value: value, Path: "/", MaxAge: maxAge, HttpOnly: true, // #nosec G124
		Secure: h.isSecure(r), SameSite: http.SameSiteStrictMode})
}

func (h *Handler) clearCookie(w http.ResponseWriter, r *http.Request, name string) {
	h.setCookie(w, r, name, "", -1)
}

func cookieValue(r *http.Request, name string) string {
	c, err := r.Cookie(name)
	if err != nil {
		return ""
	}
	return c.Value
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	body, err := json.Marshal(v)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

// authSession is the AuthSession schema. It never carries a secret: the CSRF token travels in a response header.
type authSession struct {
	Authenticated bool    `json:"authenticated"`
	Username      *string `json:"username"`
	ExpiresAt     *string `json:"expires_at"`
	Role          *string `json:"role"`
}

func anonymous() authSession { return authSession{} }

func fromSession(s auth.Session) authSession {
	u, e, r := s.Username, s.ExpiresAt.UTC().Format(time.RFC3339), string(s.Role)
	return authSession{Authenticated: true, Username: &u, ExpiresAt: &e, Role: &r}
}

func remoteHost(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return ""
	}
	return host
}

// sameOrigin is defence in depth for state-changing requests: a browser always sends Sec-Fetch-Site and, for non-GET
// requests, Origin. Either one pointing elsewhere is refused. Clients that send neither are not browsers; they still
// need the CSRF token.
func (h *Handler) sameOrigin(r *http.Request) bool {
	if v := r.Header.Get("Sec-Fetch-Site"); v != "" && v != "same-origin" {
		return false
	}
	if o := r.Header.Get("Origin"); o != "" {
		u, err := url.Parse(o)
		scheme := "http"
		if h.isSecure(r) {
			scheme = "https"
		}
		if err != nil || u.Host == "" || u.Host != r.Host || u.Scheme != scheme || (u.Path != "" && u.Path != "/") || u.User != nil {
			return false
		}
	}
	return true
}

func (h *Handler) serveImplemented(w http.ResponseWriter, r *http.Request, route declaredRoute) {
	switch route.method + " " + route.template {
	case "GET /healthz":
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(healthBody))
	case "GET /api/v1/auth/session":
		h.authStatus(w, r)
	case "POST /api/v1/auth/session":
		h.signIn(w, r)
	case "DELETE /api/v1/auth/session":
		h.signOut(w, r)
	case "GET /api/v1/hosts":
		h.listHosts(w, r)
	case "GET /api/v1/hosts/{id}":
		h.readHost(w, r)
	case "GET /api/v1/vms":
		h.listVMs(w, r)
	case "GET /api/v1/vms/{id}":
		h.readVM(w, r)
	case "GET /api/v1/volumes":
		h.listVolumes(w, r)
	case "GET /api/v1/volumes/{id}":
		h.readVolume(w, r)
	case "GET /api/v1/virtual-networks":
		h.listNetworks(w, r)
	case "GET /api/v1/virtual-networks/{id}":
		h.readNetwork(w, r)
	case "GET /api/v1/backups":
		h.listBackups(w, r)
	case "GET /api/v1/backups/{id}":
		h.readBackup(w, r)
	case "GET /api/v1/images":
		h.listImages(w, r)
	case "GET /api/v1/images/{id}":
		h.readImage(w, r)
	case "GET /api/v1/operations":
		h.listOperations(w, r)
	case "POST /api/v1/operations":
		h.submitOperation(w, r)
	case "GET /api/v1/operations/{id}":
		h.readOperation(w, r)
	case "GET /api/v1/events":
		h.listEvents(w, r)
	case "GET /api/v1/events/{id}":
		h.readEvent(w, r)
	default:
		h.reject(w, categoryUnauthenticated)
	}
}

// session resolves the request's session cookie. ok is false for a missing, malformed, unknown, revoked or expired
// session alike; failed is true when the session store itself could not be consulted.
func (h *Handler) session(r *http.Request) (s auth.Session, token string, ok, failed bool) {
	if h.deps.Auth == nil {
		return auth.Session{}, "", false, true
	}
	token = cookieValue(r, sessionCookieName(h.isSecure(r)))
	if token == "" {
		return auth.Session{}, "", false, false
	}
	return h.sessionByToken(r.Context(), token)
}

// sessionByToken re-validates a session credential (the console re-checks it for as long as a console is open).
func (h *Handler) sessionByToken(ctx context.Context, token string) (s auth.Session, tok string, ok, failed bool) {
	if h.deps.Auth == nil {
		return auth.Session{}, "", false, true
	}
	s, err := h.deps.Auth.Authenticate(ctx, token)
	switch {
	case err == nil:
		return s, token, true, false
	case errors.Is(err, auth.ErrUnauthenticated):
		return auth.Session{}, token, false, false
	}
	return auth.Session{}, token, false, true
}

// anonymousState answers for a caller without a session: a fresh pre-sign-in nonce cookie and its CSRF token (login
// CSRF), and clears a stale session cookie.
func (h *Handler) anonymousState(w http.ResponseWriter, r *http.Request, hadSessionCookie bool) {
	nonce := cookieValue(r, loginCookieName(h.isSecure(r)))
	if !auth.ValidTokenFormat(nonce) {
		n, _, err := h.deps.Auth.NewLoginNonce()
		if err != nil {
			h.reject(w, categoryInternal)
			return
		}
		nonce = n
		h.setCookie(w, r, loginCookieName(h.isSecure(r)), nonce, 0)
	}
	if hadSessionCookie {
		h.clearCookie(w, r, sessionCookieName(h.isSecure(r)))
	}
	w.Header().Set(csrfHeader, auth.LoginCSRF(nonce))
	writeJSON(w, http.StatusOK, anonymous())
}

func (h *Handler) authStatus(w http.ResponseWriter, r *http.Request) {
	if h.deps.Auth == nil {
		h.reject(w, categoryUnavailable)
		return
	}
	s, token, ok, failed := h.session(r)
	switch {
	case failed:
		h.reject(w, categoryUnavailable)
	case ok:
		w.Header().Set(csrfHeader, s.CSRFToken())
		writeJSON(w, http.StatusOK, fromSession(s))
	default:
		h.anonymousState(w, r, token != "")
	}
}

type signInBody struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// decodeBody reads one JSON object of at most maxBodyBytes with no unknown fields and no trailing data.
func decodeBody(w http.ResponseWriter, r *http.Request, dst any) bool {
	mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mt != "application/json" {
		return false
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBodyBytes))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return false
	}
	_, err = dec.Token()
	return errors.Is(err, io.EOF)
}

func (h *Handler) signIn(w http.ResponseWriter, r *http.Request) {
	if h.deps.Auth == nil {
		h.reject(w, categoryUnavailable)
		return
	}
	secure := h.isSecure(r)
	// Login CSRF: same-origin, then the token must match the pre-sign-in cookie. One generic answer for every cause.
	nonce := cookieValue(r, loginCookieName(secure))
	if !h.sameOrigin(r) || !auth.LoginCSRFValid(nonce, r.Header.Get(csrfHeader)) {
		h.reject(w, categoryForbidden)
		return
	}
	var body signInBody
	if !decodeBody(w, r, &body) || body.Username == "" || len(body.Username) > 64 || !utf8.ValidString(body.Username) ||
		body.Password == "" || len(body.Password) > auth.MaxPasswordBytes {
		h.reject(w, categoryValidation)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), signInDeadline)
	defer cancel()
	res, err := h.deps.Auth.SignIn(ctx, body.Username, body.Password, remoteHost(r), cookieValue(r, sessionCookieName(secure)))
	var rl *auth.RateLimitedError
	switch {
	case err == nil:
	case errors.Is(err, auth.ErrInvalidCredentials):
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
	h.setCookie(w, r, sessionCookieName(secure), res.SessionToken, 0)
	h.clearCookie(w, r, loginCookieName(secure))
	w.Header().Set(csrfHeader, res.CSRFToken)
	writeJSON(w, http.StatusOK, fromSession(res.Session))
}

func (h *Handler) signOut(w http.ResponseWriter, r *http.Request) {
	if h.deps.Auth == nil {
		h.reject(w, categoryUnavailable)
		return
	}
	if !h.sameOrigin(r) {
		h.reject(w, categoryForbidden)
		return
	}
	s, token, ok, failed := h.session(r)
	if failed {
		h.reject(w, categoryUnavailable)
		return
	}
	if ok {
		if !s.CSRFMatches(r.Header.Get(csrfHeader)) {
			h.reject(w, categoryForbidden)
			return
		}
		if err := h.deps.Auth.SignOut(r.Context(), token); err != nil {
			h.reject(w, categoryInternal)
			return
		}
	}
	// Not signed in (or just signed out): the same idempotent answer, and a fresh pre-sign-in state.
	h.clearCookie(w, r, sessionCookieName(h.isSecure(r)))
	h.clearCookie(w, r, loginCookieName(h.isSecure(r)))
	nonce, tok, err := h.deps.Auth.NewLoginNonce()
	if err != nil {
		h.reject(w, categoryInternal)
		return
	}
	h.setCookie(w, r, loginCookieName(h.isSecure(r)), nonce, 0)
	w.Header().Set(csrfHeader, tok)
	writeJSON(w, http.StatusOK, anonymous())
}
