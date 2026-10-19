package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strings"
	"testing"
)

const marker = "ZZ-MARKER-7f3a"

var correlationRE = regexp.MustCompile(`^[A-Za-z0-9-]{8,64}$`)

type envelope struct {
	Category      string `json:"category"`
	Retryable     bool   `json:"retryable"`
	CorrelationID string `json:"correlation_id"`
}

func serve(t *testing.T, method, target string, body io.Reader) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, target, body)
	rec := httptest.NewRecorder()
	NewHandler().ServeHTTP(rec, req)
	return rec
}

// decodeStrict decodes the Error envelope with no unknown fields and no trailing data.
func decodeStrict(t *testing.T, rec *httptest.ResponseRecorder) envelope {
	t.Helper()
	dec := json.NewDecoder(bytes.NewReader(rec.Body.Bytes()))
	dec.DisallowUnknownFields()
	var e envelope
	if err := dec.Decode(&e); err != nil {
		t.Fatalf("body %q is not the Error envelope: %v", rec.Body.String(), err)
	}
	if dec.More() {
		t.Fatalf("trailing data in body %q", rec.Body.String())
	}
	if !correlationRE.MatchString(e.CorrelationID) {
		t.Fatalf("correlation_id %q does not match %s", e.CorrelationID, correlationRE)
	}
	return e
}

func contractCategories(t *testing.T) map[string]struct {
	HTTPStatus int  `json:"http_status"`
	Retryable  bool `json:"retryable"`
} {
	t.Helper()
	raw, err := os.ReadFile("../../../contracts/interfaces/errors.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Categories map[string]struct {
			HTTPStatus int  `json:"http_status"`
			Retryable  bool `json:"retryable"`
		} `json:"categories"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	return doc.Categories
}

// Positive: /healthz conforms to the Health schema and is unchanged (AC01).
func TestHealthzConformsToHealthSchema(t *testing.T) {
	rec := serve(t, http.MethodGet, "/healthz", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if got := rec.Header().Get("Content-Type"); got != "application/json" {
		t.Fatalf("Content-Type = %q", got)
	}
	dec := json.NewDecoder(bytes.NewReader(rec.Body.Bytes()))
	dec.DisallowUnknownFields()
	var health struct {
		Status string `json:"status"`
	}
	if err := dec.Decode(&health); err != nil || health.Status != "scaffold" || dec.More() {
		t.Fatalf("body does not conform to Health {status: scaffold}: %v %+v", err, health)
	}
	if rec.Body.String() != `{"status":"scaffold"}` {
		t.Fatalf("body = %q", rec.Body.String())
	}
}

func TestHealthzIgnoresQueryAndStaysUnchanged(t *testing.T) {
	rec := serve(t, http.MethodGet, "/healthz?x="+marker, nil)
	if rec.Code != http.StatusOK || rec.Body.String() != `{"status":"scaffold"}` {
		t.Fatalf("got %d %q", rec.Code, rec.Body.String())
	}
}

// implementedRoutes is the closed set DR-015 D3 (and DR-020 D2: the Volume and Backup reads) allows to be served; everything else stays a typed rejection.
var implementedRoutes = map[string]bool{
	"GET /healthz": true, "GET /api/v1/auth/session": true, "POST /api/v1/auth/session": true,
	"DELETE /api/v1/auth/session": true, "GET /api/v1/hosts": true, "GET /api/v1/hosts/{id}": true,
	"GET /api/v1/vms": true, "GET /api/v1/vms/{id}": true, "GET /api/v1/images": true, "GET /api/v1/images/{id}": true,
	"GET /api/v1/operations": true, "POST /api/v1/operations": true, "GET /api/v1/operations/{id}": true,
	"GET /api/v1/virtual-networks": true, "GET /api/v1/virtual-networks/{id}": true, "GET /api/v1/volumes": true, "GET /api/v1/volumes/{id}": true, "GET /api/v1/backups": true, "GET /api/v1/backups/{id}": true,
	"GET /api/v1/events": true, "GET /api/v1/events/{id}": true,
}

// The generated route table is the contract: exactly the DR-015 set is implemented.
func TestRouteTableMatchesTheContractShape(t *testing.T) {
	implemented := 0
	seen := map[string]bool{}
	for _, r := range declaredRoutes {
		key := r.method + " " + r.template
		if seen[key] {
			t.Fatalf("duplicate route %s", key)
		}
		seen[key] = true
		if r.implemented {
			implemented++
			if !implementedRoutes[key] {
				t.Fatalf("%s may not be implemented", key)
			}
		}
		if r.method != http.MethodGet && r.method != http.MethodPost && r.method != http.MethodDelete {
			t.Fatalf("unexpected method in %s", key)
		}
	}
	if implemented != len(implementedRoutes) {
		t.Fatalf("implemented routes = %d, want %d", implemented, len(implementedRoutes))
	}
	for _, want := range []string{"GET /api/v1/vms", "GET /api/v1/vms/{id}", "POST /api/v1/operations", "POST /api/v1/operations/{id}/cancel", "GET /api/v1/virtual-networks"} {
		if !seen[want] {
			t.Fatalf("route %s is not declared", want)
		}
	}
	if len(declaredRoutes) != 26 {
		t.Fatalf("declared routes = %d, want 26 (23 paths)", len(declaredRoutes))
	}
}

func TestErrorCategoriesMatchErrorsContract(t *testing.T) {
	contract := contractCategories(t)
	for name, c := range categories {
		want, ok := contract[name]
		if !ok {
			t.Fatalf("category %q is not in errors.json", name)
		}
		if want.HTTPStatus != c.status || want.Retryable != c.retryable {
			t.Errorf("%s: handler (%d, %v) differs from errors.json (%d, %v)", name, c.status, c.retryable, want.HTTPStatus, want.Retryable)
		}
	}
}

// Negative (AC02): every declared but not-implemented route gets the D5 category, whatever the path parameter, query or body.
func TestDeclaredNotImplementedRoutesAreUnauthenticated(t *testing.T) {
	contract := contractCategories(t)
	for _, r := range declaredRoutes {
		if r.implemented {
			continue
		}
		path := strings.ReplaceAll(r.template, "{id}", "vm-1")
		rec := serve(t, r.method, path, nil)
		e := decodeStrict(t, rec)
		if e.Category != "unauthenticated" || rec.Code != contract["unauthenticated"].HTTPStatus || e.Retryable {
			t.Errorf("%s %s: got %d %+v", r.method, r.template, rec.Code, e)
		}
		if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
			t.Errorf("%s %s: Content-Type %q", r.method, r.template, ct)
		}
		if rec.Header().Get("Cache-Control") != "no-store" || rec.Header().Get("X-Content-Type-Options") != "nosniff" {
			t.Errorf("%s %s: missing no-store/nosniff", r.method, r.template)
		}
	}
}

// Order of checks (review N5): rejection comes before any validation of {id}, the query or the body.
func TestRejectionPrecedesValidation(t *testing.T) {
	cases := []struct {
		method, target, body string
	}{
		{http.MethodGet, "/api/v1/vms/" + marker + "%21%21not%20a%20valid%20id%21%21", ""},
		{http.MethodGet, "/api/v1/vms/%00", ""},
		{http.MethodGet, "/api/v1/vms?limit=9999&cursor=%0a" + marker, ""},
		{http.MethodGet, "/api/v1/vms?limit=abc&limit=2&unknown=" + marker, ""},
		{http.MethodPost, "/api/v1/operations", "{not json " + marker},
		{http.MethodPost, "/api/v1/operations", `{"type":"reboot","kind":"VM","id":"` + marker + `","idempotency_key":"k"}`},
		{http.MethodPost, "/api/v1/operations", strings.Repeat("A", 1<<20)},
		{http.MethodPost, "/api/v1/operations/" + marker + "/cancel", ""},
	}
	for _, tc := range cases {
		rec := serve(t, tc.method, tc.target, strings.NewReader(tc.body))
		e := decodeStrict(t, rec)
		if e.Category != "unauthenticated" || rec.Code != http.StatusUnauthorized {
			t.Errorf("%s %.40s: got %d %+v, want 401 unauthenticated", tc.method, tc.target, rec.Code, e)
		}
	}
}

// Undeclared paths and methods are not_found, including a method not declared on /healthz (AC02).
func TestUndeclaredPathsAndMethodsAreNotFound(t *testing.T) {
	cases := []struct{ method, target string }{
		{http.MethodGet, "/"},
		{http.MethodGet, "/vms"},
		{http.MethodGet, "/api"},
		{http.MethodGet, "/api/v1"},
		{http.MethodGet, "/api/v1/"},
		{http.MethodGet, "/api/v1/vms/"},
		{http.MethodGet, "/api/v1/vms/a/b"},
		{http.MethodGet, "/api/v1/secrets"},
		{http.MethodGet, "/api/v2/vms"},
		{http.MethodGet, "/api/v1/VMS"},
		{http.MethodGet, "/api/v1/operations/a/b/cancel"},
		{http.MethodGet, "/api/v1/operations/a/cancel"},
		{http.MethodGet, "/HEALTHZ"},
		{http.MethodGet, "/healthz/"},
		{http.MethodGet, "//healthz"},
		{http.MethodGet, "/healthz/extra"},
		{http.MethodGet, "/healthz/../admin"},
		{http.MethodGet, "/api/v1/vms/%2e%2e"},
		{http.MethodGet, "/api/v1/vms/a%2Fb"},
		{http.MethodPost, "/healthz"},
		{http.MethodDelete, "/healthz"},
		{http.MethodHead, "/healthz"},
		{http.MethodOptions, "/healthz"},
		{http.MethodPut, "/api/v1/vms"},
		{http.MethodDelete, "/api/v1/vms/vm-1"},
		{http.MethodPatch, "/api/v1/vms/vm-1"},
		{http.MethodPost, "/api/v1/vms"},
		{http.MethodPost, "/api/v1/vms/vm-1"},
		{http.MethodGet, "/api/v1/operations/vm-1/cancel"},
		{http.MethodPut, "/api/v1/operations/vm-1/cancel"},
		{http.MethodOptions, "*"},
		{http.MethodConnect, "/healthz"},
	}
	for _, tc := range cases {
		req := httptest.NewRequest(tc.method, tc.target, nil)
		if tc.target == "*" {
			req.URL.Path = "*"
		}
		rec := httptest.NewRecorder()
		NewHandler().ServeHTTP(rec, req)
		e := decodeStrict(t, rec)
		if e.Category != "not_found" || rec.Code != http.StatusNotFound || e.Retryable {
			t.Errorf("%s %s: got %d %+v, want 404 not_found", tc.method, tc.target, rec.Code, e)
		}
		if loc := rec.Header().Get("Location"); loc != "" {
			t.Errorf("%s %s: unclean path must not be redirected (Location %q)", tc.method, tc.target, loc)
		}
	}
}

// No response echoes the path, method, headers, query or body (AC02, section 3).
func TestResponsesNeverEchoRequestContent(t *testing.T) {
	targets := []struct{ method, target string }{
		{http.MethodGet, "/api/v1/vms/" + marker},
		{http.MethodGet, "/api/v1/" + marker},
		{http.MethodGet, "/" + marker + "?q=" + marker},
		{http.MethodPost, "/api/v1/operations"},
		{http.MethodGet, "/healthz?x=" + marker},
		{"X" + strings.ToUpper(marker[3:9]), "/healthz"},
	}
	for _, tc := range targets {
		req := httptest.NewRequest(tc.method, tc.target, strings.NewReader(`{"id":"`+marker+`"}`))
		req.Header.Set("X-Marker", marker)
		req.Header.Set("Cookie", "ownerSession="+marker)
		req.Header.Set("Authorization", "Bearer "+marker)
		req.Host = marker + ".example.invalid"
		rec := httptest.NewRecorder()
		NewHandler().ServeHTTP(rec, req)
		res := rec.Result()
		var all strings.Builder
		all.WriteString(rec.Body.String())
		for k, v := range res.Header {
			all.WriteString(k + ":" + strings.Join(v, ",") + "\n")
		}
		if strings.Contains(all.String(), marker) || strings.Contains(strings.ToLower(all.String()), strings.ToLower(tc.method)+"\n") {
			t.Errorf("%s %s echoed request content: %q", tc.method, tc.target, all.String())
		}
		if len(res.Cookies()) != 0 || res.Header.Get("Set-Cookie") != "" {
			t.Errorf("%s %s: unexpected cookie", tc.method, tc.target)
		}
	}
}

// The handler never reads the request body (nothing is validated before authentication exists).
type failingBody struct{ read bool }

func (f *failingBody) Read([]byte) (int, error) { f.read = true; return 0, errors.New("read") }

func TestRequestBodyIsNeverRead(t *testing.T) {
	body := &failingBody{}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/operations", body)
	rec := httptest.NewRecorder()
	NewHandler().ServeHTTP(rec, req)
	if body.read {
		t.Fatal("the handler read the request body")
	}
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d", rec.Code)
	}
}

func TestCorrelationIDsAreRandomAndWellFormed(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 200; i++ {
		id := decodeStrict(t, serve(t, http.MethodGet, "/api/v1/vms", nil)).CorrelationID
		if len(id) != 32 {
			t.Fatalf("id %q: want 32 hex digits (128 bits)", id)
		}
		if seen[id] {
			t.Fatalf("duplicate correlation id %q", id)
		}
		seen[id] = true
	}
}

// If the random source fails the envelope cannot be valid, so nothing but a bare 500 is sent.
func TestCorrelationFailureNeverSendsAnInvalidEnvelope(t *testing.T) {
	h := &Handler{newCorrelationID: func() (string, error) { return "", errors.New("entropy") }}
	for _, target := range []string{"/api/v1/vms", "/nope"} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, target, nil))
		if rec.Code != http.StatusInternalServerError || rec.Body.Len() != 0 {
			t.Errorf("%s: got %d %q, want a bare 500", target, rec.Code, rec.Body.String())
		}
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("health must not depend on the random source, got %d", rec.Code)
	}
}

// The handler holds no state: repeated and concurrent requests give identical shapes.
func TestHandlerIsStatelessUnderConcurrency(t *testing.T) {
	h := NewHandler()
	done := make(chan string, 16)
	for i := 0; i < 16; i++ {
		go func() {
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/hosts/local", nil))
			var e envelope
			_ = json.Unmarshal(rec.Body.Bytes(), &e)
			done <- e.Category
		}()
	}
	for i := 0; i < 16; i++ {
		if c := <-done; c != "unauthenticated" {
			t.Fatalf("category = %q", c)
		}
	}
}
