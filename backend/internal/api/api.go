// Package api is the browser-api HTTP boundary (M0-E01-S04, DR-012; DR-015 D3).
//
// Served: GET /healthz, the authentication session (GET status, POST sign-in, DELETE sign-out) and the read-only
// host summary (GET /api/v1/hosts and /{id}, session required). Every other route that contracts/openapi.yaml
// declares is rejected with the typed Error envelope before any validation of the path parameter, the query or the
// body. Anything undeclared is not_found. No response echoes the path, method, headers or body. The handler holds no
// state of its own: sessions live in the auth service, host facts come from the hostinfo provider, and nothing here
// executes a command.
package api

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"time"
)

// declaredRoute is one method and path template from contracts/openapi.yaml (see routes_gen.go).
type declaredRoute struct {
	method      string
	template    string
	implemented bool
}

// Error categories used by the handler. Status and retryable are pinned to contracts/interfaces/errors.json by a test.
const (
	categoryValidation      = "validation"
	categoryUnauthenticated = "unauthenticated"
	categoryForbidden       = "forbidden"
	categoryConflict        = "conflict"
	categoryProhibited      = "prohibited"
	categoryNotFound        = "not_found"
	categoryRateLimited     = "rate_limited"
	categoryInternal        = "internal"
	categoryUnavailable     = "unavailable"
)

type category struct {
	status    int
	retryable bool
}

var categories = map[string]category{
	categoryValidation:      {status: http.StatusBadRequest, retryable: false},
	categoryUnauthenticated: {status: http.StatusUnauthorized, retryable: false},
	categoryForbidden:       {status: http.StatusForbidden, retryable: false},
	categoryConflict:        {status: http.StatusConflict, retryable: false},
	categoryProhibited:      {status: http.StatusUnprocessableEntity, retryable: false},
	categoryNotFound:        {status: http.StatusNotFound, retryable: false},
	categoryRateLimited:     {status: http.StatusTooManyRequests, retryable: true},
	categoryInternal:        {status: http.StatusInternalServerError, retryable: false},
	categoryUnavailable:     {status: http.StatusServiceUnavailable, retryable: true},
}

// errorBody is the Error schema without field_errors, which only validation errors carry. There is no free-text
// message: server text can carry secrets or internals and the UI never shows it.
type errorBody struct {
	Category      string `json:"category"`
	Retryable     bool   `json:"retryable"`
	CorrelationID string `json:"correlation_id"`
}

const healthBody = `{"status":"scaffold"}`

// Handler serves the browser-api.
type Handler struct {
	newCorrelationID func() (string, error)
	deps             Deps

	snapMu sync.Mutex // the cached snapshot capability (storage.go)
	snapAt time.Time
	snapOK bool
}

// NewHandler returns the scaffold handler: no authentication service is attached, so the session routes answer
// `unavailable` and every other declared route is rejected as unauthenticated.
func NewHandler() *Handler {
	return &Handler{newCorrelationID: correlationID}
}

// NewHandlerWith returns the handler wired to the authentication service and the host provider.
func NewHandlerWith(d Deps) *Handler {
	return &Handler{newCorrelationID: correlationID, deps: d}
}

// correlationID is 128 random bits from crypto/rand as 32 lower-case hex digits (^[A-Za-z0-9-]{8,64}$).
func correlationID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

// ServeHTTP implements http.Handler.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if strings.HasPrefix(r.URL.Path, "/console/v1/") {
		h.serveConsole(w, r)
		return
	}
	route, found := lookup(r.Method, r.URL.Path)
	switch {
	case !found:
		h.reject(w, categoryNotFound)
	case route.implemented:
		h.serveImplemented(w, r, route)
	default:
		// Declared but not implemented: no session can exist yet (D5 = A).
		h.reject(w, categoryUnauthenticated)
	}
}

// reject writes the typed Error envelope. If no correlation id can be generated the response is a bare 500 without a
// body: the envelope requires the id, and an invalid envelope must never be sent.
func (h *Handler) reject(w http.ResponseWriter, name string) { h.rejectWith(w, name, nil) }

// rejectWith is reject plus extra response headers (Retry-After, Set-Cookie).
func (h *Handler) rejectWith(w http.ResponseWriter, name string, extra func(http.Header)) {
	id, err := h.newCorrelationID()
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	spec := categories[name]
	body, err := json.Marshal(errorBody{Category: name, Retryable: spec.retryable, CorrelationID: id})
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if extra != nil {
		extra(w.Header())
	}
	w.WriteHeader(spec.status)
	_, _ = w.Write(body)
}

// lookup returns the declared route for a method and path. Matching is exact and segment-wise: a `{id}` segment
// matches any single non-empty segment without validating it, and unclean paths (empty, `.` or `..` segments,
// trailing slash) match nothing. A method that is not declared for a path matches nothing.
func lookup(method, path string) (declaredRoute, bool) {
	if !strings.HasPrefix(path, "/") {
		return declaredRoute{}, false
	}
	segments := strings.Split(path[1:], "/")
	for _, s := range segments {
		if s == "" || s == "." || s == ".." {
			return declaredRoute{}, false
		}
	}
	for _, route := range declaredRoutes {
		if route.method == method && matches(route.template, segments) {
			return route, true
		}
	}
	return declaredRoute{}, false
}

func matches(template string, segments []string) bool {
	parts := strings.Split(template[1:], "/")
	if len(parts) != len(segments) {
		return false
	}
	for i, p := range parts {
		if p != segments[i] && !(strings.HasPrefix(p, "{") && strings.HasSuffix(p, "}")) {
			return false
		}
	}
	return true
}
