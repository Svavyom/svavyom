package main

import (
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHealthzReturnsScaffoldStatus(t *testing.T) {
	rec := httptest.NewRecorder()
	newHandler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	if got := rec.Header().Get("Content-Type"); got != "application/json" {
		t.Fatalf("Content-Type = %q, want application/json", got)
	}
	body, _ := io.ReadAll(rec.Body)
	if string(body) != `{"status":"scaffold"}` {
		t.Fatalf("body = %q, want exact scaffold status", body)
	}
}

func TestUnsupportedRequestsAreRejected(t *testing.T) {
	cases := []struct {
		method, path string
		want         int
		category     string
	}{
		{http.MethodPost, "/healthz", http.StatusNotFound, "not_found"},
		{http.MethodDelete, "/healthz", http.StatusNotFound, "not_found"},
		{http.MethodGet, "/", http.StatusNotFound, "not_found"},
		{http.MethodGet, "/vms", http.StatusNotFound, "not_found"},
		{http.MethodGet, "/api/v1/vms", http.StatusUnauthorized, "unauthenticated"},
	}
	for _, tc := range cases {
		rec := httptest.NewRecorder()
		newHandler().ServeHTTP(rec, httptest.NewRequest(tc.method, tc.path, nil))
		var e struct {
			Category string `json:"category"`
		}
		if rec.Code != tc.want || json.Unmarshal(rec.Body.Bytes(), &e) != nil || e.Category != tc.category {
			t.Errorf("%s %s: status = %d body = %q, want %d %s", tc.method, tc.path, rec.Code, rec.Body.String(), tc.want, tc.category)
		}
	}
}

func TestUncleanPathIsNeverServedDirectly(t *testing.T) {
	rec := httptest.NewRecorder()
	newHandler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz/../admin", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "" {
		t.Fatalf("Location = %q: a redirect would echo the path", loc)
	}
}

func TestServerIsLoopbackOnlyWithHeaderTimeout(t *testing.T) {
	srv := newServer()
	if srv.Addr != "127.0.0.1:8081" {
		t.Fatalf("Addr = %q, want 127.0.0.1:8081", srv.Addr)
	}
	host, _, err := net.SplitHostPort(srv.Addr)
	if err != nil {
		t.Fatal(err)
	}
	if ip := net.ParseIP(host); ip == nil || !ip.IsLoopback() {
		t.Fatalf("listen host %q is not a loopback address", host)
	}
	if srv.ReadHeaderTimeout <= 0 {
		t.Fatal("ReadHeaderTimeout must be set")
	}
}
