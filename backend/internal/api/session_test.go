package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"example.invalid/dedicatedcloud/backend/internal/auth"
	"example.invalid/dedicatedcloud/backend/internal/hostinfo"
	"example.invalid/dedicatedcloud/backend/internal/sqlitedb"
)

const (
	adminName = "admin"
	adminPass = "correct horse battery"
)

var fastParams = auth.Params{MemoryKiB: 19 * 1024, Time: 2, Threads: 1, SaltLen: 16, KeyLen: 32}

type fakeHosts struct {
	err  error
	info hostinfo.Info
}

func (f *fakeHosts) Host(context.Context) (hostinfo.Info, error) { return f.info, f.err }

func sampleHost() hostinfo.Info {
	return hostinfo.Info{ID: "local", Name: "lab-host", AgentVersion: "1.2.3", CPUCount: 8, MemoryMiB: 16000, Verdict: "unknown",
		Hardware: hostinfo.Available, KVMDevice: hostinfo.Unavailable, LibvirtPackages: hostinfo.Unknown, QEMUPackages: hostinfo.Available,
		DistroID: "debian", DistroVersion: "13",
		Findings: []hostinfo.Finding{{Code: "CONTAINERIZED", Remediation: ""}}}
}

type now struct{ ns atomic.Int64 }

func (n *now) get() time.Time      { return time.Unix(0, n.ns.Load()).UTC() }
func (n *now) add(d time.Duration) { n.ns.Add(int64(d)) }

type env struct {
	t     *testing.T
	path  string
	clk   *now
	hosts *fakeHosts
	svc   *auth.Service
	h     *Handler
	srv   *httptest.Server
}

func newEnv(t *testing.T, bootstrap bool) *env {
	t.Helper()
	e := &env{t: t, path: filepath.Join(t.TempDir(), "svavyom.db"), clk: &now{}, hosts: &fakeHosts{info: sampleHost()}}
	e.clk.ns.Store(time.Date(2026, 10, 9, 8, 0, 0, 0, time.UTC).UnixNano())
	e.start()
	if bootstrap {
		if err := e.svc.Bootstrap(context.Background(), adminName, adminPass); err != nil {
			t.Fatal(err)
		}
	}
	return e
}

// start (re)creates the database connection, the service, the handler and the server: a process restart.
func (e *env) start() {
	e.t.Helper()
	if e.srv != nil {
		e.srv.Close()
	}
	db, err := sqlitedb.Open(e.path)
	if err != nil {
		e.t.Fatal(err)
	}
	e.t.Cleanup(func() { _ = db.Close() })
	e.svc, err = auth.New(context.Background(), db, auth.Config{Params: fastParams, Clock: e.clk.get})
	if err != nil {
		e.t.Fatal(err)
	}
	e.h = NewHandlerWith(Deps{Auth: e.svc, Hosts: e.hosts})
	e.srv = httptest.NewServer(e.h)
	e.t.Cleanup(e.srv.Close)
}

type browser struct {
	t    *testing.T
	base string
	c    *http.Client
	csrf string
}

func (e *env) browser() *browser {
	jar, _ := cookiejar.New(nil)
	return &browser{t: e.t, base: e.srv.URL, c: &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
}

type reply struct {
	status int
	header http.Header
	body   []byte
}

func (b *browser) do(method, path string, body string, hdr map[string]string) reply {
	b.t.Helper()
	req, err := http.NewRequest(method, b.base+path, strings.NewReader(body))
	if err != nil {
		b.t.Fatal(err)
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	res, err := b.c.Do(req)
	if err != nil {
		b.t.Fatal(err)
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(res.Body)
	return reply{res.StatusCode, res.Header, raw}
}

// status fetches the session state and remembers the CSRF token the way the frontend does (in memory).
func (b *browser) status() reply {
	r := b.do("GET", "/api/v1/auth/session", "", nil)
	b.csrf = r.header.Get("X-CSRF-Token")
	return r
}

func creds(user, pass string) string {
	b, _ := json.Marshal(map[string]string{"username": user, "password": pass})
	return string(b)
}

func (b *browser) signIn(user, pass string) reply {
	r := b.do("POST", "/api/v1/auth/session", creds(user, pass), map[string]string{"X-CSRF-Token": b.csrf})
	if t := r.header.Get("X-CSRF-Token"); t != "" {
		b.csrf = t
	}
	return r
}

func (b *browser) signOut() reply {
	r := b.do("DELETE", "/api/v1/auth/session", "", map[string]string{"X-CSRF-Token": b.csrf})
	if t := r.header.Get("X-CSRF-Token"); t != "" {
		b.csrf = t
	}
	return r
}

func catOf(t *testing.T, r reply) string {
	t.Helper()
	var e envelope
	if err := json.Unmarshal(r.body, &e); err != nil || e.CorrelationID == "" {
		t.Fatalf("not an Error envelope: %q (%v)", r.body, err)
	}
	return e.Category
}

func keys(t *testing.T, raw []byte) []string {
	t.Helper()
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("%q: %v", raw, err)
	}
	var out []string
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func cookieNamed(res reply, name string) *http.Cookie {
	for _, c := range (&http.Response{Header: res.header}).Cookies() {
		if c.Name == name {
			return c
		}
	}
	return nil
}

// ---- status & sign-in ----------------------------------------------------------------------------------------------

func TestAnonymousStatusIssuesLoginTokenAndNoSecretInBody(t *testing.T) {
	e := newEnv(t, true)
	b := e.browser()
	r := b.status()
	if r.status != 200 || string(r.body) != `{"authenticated":false,"username":null,"expires_at":null,"role":null}` {
		t.Fatalf("%d %s", r.status, r.body)
	}
	if !auth.ValidTokenFormat(b.csrf) {
		t.Fatalf("no login CSRF token header: %q", b.csrf)
	}
	c := cookieNamed(r, "svavyom_login")
	if c == nil || !c.HttpOnly || c.SameSite != http.SameSiteStrictMode || c.Path != "/" || c.Secure {
		t.Fatalf("pre-sign-in cookie: %+v", c)
	}
	if strings.Contains(string(r.body), b.csrf) || strings.Contains(string(r.body), c.Value) {
		t.Fatal("secret in body")
	}
	if r.header.Get("Cache-Control") != "no-store" {
		t.Fatal("status must not be cached")
	}
	// The same browser keeps its nonce: a reload gets the same token.
	first := b.csrf
	b.status()
	if b.csrf != first {
		t.Fatal("login token changed on reload")
	}
}

func TestSignInHappyPathSessionAndHosts(t *testing.T) {
	e := newEnv(t, true)
	b := e.browser()
	b.status()
	r := b.signIn(adminName, adminPass)
	if r.status != 200 {
		t.Fatalf("%d %s", r.status, r.body)
	}
	if got := strings.Join(keys(t, r.body), ","); got != "authenticated,expires_at,role,username" {
		t.Fatalf("body keys %s", got)
	}
	var body struct {
		Authenticated bool
		Username      string
		ExpiresAt     string `json:"expires_at"`
	}
	_ = json.Unmarshal(r.body, &body)
	if !body.Authenticated || body.Username != adminName {
		t.Fatalf("%s", r.body)
	}
	if _, err := time.Parse(time.RFC3339, body.ExpiresAt); err != nil {
		t.Fatal(err)
	}
	sc := cookieNamed(r, "svavyom_session")
	if sc == nil || !sc.HttpOnly || sc.SameSite != http.SameSiteStrictMode || sc.Path != "/" || sc.MaxAge != 0 || len(sc.Value) != 43 {
		t.Fatalf("session cookie: %+v", sc)
	}
	if lc := cookieNamed(r, "svavyom_login"); lc == nil || lc.MaxAge >= 0 {
		t.Fatalf("pre-sign-in cookie must be cleared: %+v", lc)
	}
	if strings.Contains(string(r.body), sc.Value) || strings.Contains(string(r.body), b.csrf) {
		t.Fatal("secret in body")
	}
	if st := b.status(); !strings.Contains(string(st.body), `"authenticated":true`) || b.csrf == "" {
		t.Fatalf("status after sign-in: %s", st.body)
	}
	if h := b.do("GET", "/api/v1/hosts", "", nil); h.status != 200 {
		t.Fatalf("hosts %d %s", h.status, h.body)
	}
}

func TestLoginCSRFIsEnforced(t *testing.T) {
	e := newEnv(t, true)
	good := func() *browser { b := e.browser(); b.status(); return b }
	other := good().csrf
	cases := map[string]func(b *browser) reply{
		"no header": func(b *browser) reply { b.csrf = ""; return b.signIn(adminName, adminPass) },
		"wrong header": func(b *browser) reply {
			b.csrf = strings.Repeat("A", 43)
			return b.signIn(adminName, adminPass)
		},
		"another browser's token": func(b *browser) reply { b.csrf = other; return b.signIn(adminName, adminPass) },
		"foreign Origin": func(b *browser) reply {
			return b.do("POST", "/api/v1/auth/session", creds(adminName, adminPass), map[string]string{"X-CSRF-Token": b.csrf, "Origin": "https://evil.example"})
		},
		"null Origin": func(b *browser) reply {
			return b.do("POST", "/api/v1/auth/session", creds(adminName, adminPass), map[string]string{"X-CSRF-Token": b.csrf, "Origin": "null"})
		},
		"cross-site fetch metadata": func(b *browser) reply {
			return b.do("POST", "/api/v1/auth/session", creds(adminName, adminPass), map[string]string{"X-CSRF-Token": b.csrf, "Sec-Fetch-Site": "cross-site"})
		},
		"same-site (sibling subdomain) fetch metadata": func(b *browser) reply {
			return b.do("POST", "/api/v1/auth/session", creds(adminName, adminPass), map[string]string{"X-CSRF-Token": b.csrf, "Sec-Fetch-Site": "same-site"})
		},
	}
	for name, run := range cases {
		b := good()
		r := run(b)
		if r.status != 403 || catOf(t, r) != "forbidden" {
			t.Errorf("%s: %d %s", name, r.status, r.body)
		}
		if cookieNamed(r, "svavyom_session") != nil {
			t.Errorf("%s: a session was created", name)
		}
	}
	// A request without the pre-sign-in cookie (a forged cross-site form post) fails even with a syntactically valid token.
	req, _ := http.NewRequest("POST", e.srv.URL+"/api/v1/auth/session", strings.NewReader(creds(adminName, adminPass)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", other)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != 403 {
		t.Fatalf("cookieless sign-in: %d", res.StatusCode)
	}
	// CSRF is checked before credentials: a forged request learns nothing about the password.
	if r := good().signIn(adminName, adminPass); r.status != 200 {
		t.Fatalf("legitimate sign-in: %d", r.status)
	}
}

func TestSessionCSRFTokenCannotBeUsedAsLoginTokenAndViceVersa(t *testing.T) {
	e := newEnv(t, true)
	a := e.browser()
	a.status()
	login := a.csrf
	if r := a.signIn(adminName, adminPass); r.status != 200 {
		t.Fatal(r.status)
	}
	sessionTok := a.csrf
	if sessionTok == login {
		t.Fatal("same token before and after sign-in")
	}
	// Sign-out with the stale login token must fail and leave the session alive.
	if r := a.do("DELETE", "/api/v1/auth/session", "", map[string]string{"X-CSRF-Token": login}); r.status != 403 {
		t.Fatalf("sign-out with login token: %d", r.status)
	}
	if r := a.do("GET", "/api/v1/hosts", "", nil); r.status != 200 {
		t.Fatalf("session was damaged: %d", r.status)
	}
	// Sign-in with a session token as login token must fail.
	b := e.browser()
	b.status()
	b.csrf = sessionTok
	if r := b.signIn(adminName, adminPass); r.status != 403 {
		t.Fatalf("sign-in with session token: %d", r.status)
	}
}

func TestBadCredentialsAreGenericAndThrottled(t *testing.T) {
	e := newEnv(t, true)
	b := e.browser()
	b.status()
	wrong := b.signIn(adminName, "wrong password here")
	unknown := b.signIn("nobody", adminPass)
	for _, r := range []reply{wrong, unknown} {
		if r.status != 401 || catOf(t, r) != "unauthenticated" {
			t.Fatalf("%d %s", r.status, r.body)
		}
		if cookieNamed(r, "svavyom_session") != nil {
			t.Fatal("session cookie on failure")
		}
	}
	if len(wrong.body) != len(unknown.body) && !strings.Contains(string(wrong.body), "correlation_id") {
		t.Fatal("responses differ in shape")
	}
	for i := 0; i < 6; i++ {
		b.signIn(adminName, "wrong password here")
	}
	r := b.signIn(adminName, adminPass)
	if r.status != 429 || catOf(t, r) != "rate_limited" || r.header.Get("Retry-After") == "" {
		t.Fatalf("throttle: %d %s %v", r.status, r.body, r.header)
	}
	e.clk.add(time.Hour)
	if r := b.signIn(adminName, adminPass); r.status != 200 {
		t.Fatalf("after backoff: %d %s", r.status, r.body)
	}
}

func TestSignInBeforeBootstrapIsGeneric401(t *testing.T) {
	e := newEnv(t, false)
	b := e.browser()
	b.status()
	if r := b.signIn(adminName, adminPass); r.status != 401 || catOf(t, r) != "unauthenticated" {
		t.Fatalf("%d %s", r.status, r.body)
	}
}

func TestSignInRequestValidation(t *testing.T) {
	e := newEnv(t, true)
	hdr := func(b *browser) map[string]string { return map[string]string{"X-CSRF-Token": b.csrf} }
	cases := map[string]struct {
		body string
		ct   string
	}{
		"not json":      {"{nope", "application/json"},
		"empty object":  {"{}", "application/json"},
		"empty user":    {creds("", "x"), "application/json"},
		"empty pass":    {creds("admin", ""), "application/json"},
		"unknown field": {`{"username":"admin","password":"x","role":"root"}`, "application/json"},
		"trailing data": {creds("admin", "x") + `{"a":1}`, "application/json"},
		"array":         {`["admin","x"]`, "application/json"},
		"wrong types":   {`{"username":1,"password":true}`, "application/json"},
		"huge body":     {creds("admin", strings.Repeat("x", 10000)), "application/json"},
		"long username": {creds(strings.Repeat("a", 65), "x"), "application/json"},
		"long password": {creds("admin", strings.Repeat("p", 129)), "application/json"},
		"form encoded":  {"username=admin&password=x", "application/x-www-form-urlencoded"},
		"text/plain":    {creds("admin", "x"), "text/plain"},
		"no content":    {"", ""},
	}
	for name, c := range cases {
		b := e.browser()
		b.status()
		h := hdr(b)
		if c.ct != "" {
			h["Content-Type"] = c.ct
		}
		r := b.do("POST", "/api/v1/auth/session", c.body, h)
		if r.status != 400 || catOf(t, r) != "validation" {
			t.Errorf("%s: %d %s", name, r.status, r.body)
		}
		if strings.Contains(string(r.body), "xxxx") {
			t.Errorf("%s: input echoed", name)
		}
	}
}

func TestSessionFixationOverHTTP(t *testing.T) {
	e := newEnv(t, true)
	victim := e.browser()
	victim.status()
	if r := victim.signIn(adminName, adminPass); r.status != 200 {
		t.Fatal(r.status)
	}
	u, _ := url.Parse(e.srv.URL)
	var planted string
	for _, c := range victim.c.Jar.Cookies(u) {
		if c.Name == "svavyom_session" {
			planted = c.Value
		}
	}
	// A second browser is made to carry the first browser's (attacker-chosen) session cookie, then signs in.
	b := e.browser()
	b.status()
	b.c.Jar.SetCookies(u, []*http.Cookie{{Name: "svavyom_session", Value: planted, Path: "/"}})
	r := b.signIn(adminName, adminPass)
	fresh := cookieNamed(r, "svavyom_session")
	if r.status != 200 || fresh == nil || fresh.Value == planted {
		t.Fatalf("session id not rotated: %+v", fresh)
	}
	if r := victim.do("GET", "/api/v1/hosts", "", nil); r.status != 401 {
		t.Fatalf("the planted session survived sign-in: %d", r.status)
	}
}

// ---- sign-out -----------------------------------------------------------------------------------------------------

func TestSignOutRevokesAndReplayFails(t *testing.T) {
	e := newEnv(t, true)
	b := e.browser()
	b.status()
	b.signIn(adminName, adminPass)
	u, _ := url.Parse(e.srv.URL)
	var stolen string
	for _, c := range b.c.Jar.Cookies(u) {
		if c.Name == "svavyom_session" {
			stolen = c.Value
		}
	}
	token := b.csrf
	r := b.signOut()
	if r.status != 200 || string(r.body) != `{"authenticated":false,"username":null,"expires_at":null,"role":null}` {
		t.Fatalf("%d %s", r.status, r.body)
	}
	if c := cookieNamed(r, "svavyom_session"); c == nil || c.MaxAge >= 0 {
		t.Fatalf("session cookie not cleared: %+v", c)
	}
	// The attacker replays the stolen cookie and even the old CSRF token.
	thief := e.browser()
	thief.c.Jar.SetCookies(u, []*http.Cookie{{Name: "svavyom_session", Value: stolen, Path: "/"}})
	if r := thief.do("GET", "/api/v1/hosts", "", nil); r.status != 401 {
		t.Fatalf("revoked session accepted: %d", r.status)
	}
	if r := thief.do("GET", "/api/v1/auth/session", "", nil); !strings.Contains(string(r.body), `"authenticated":false`) {
		t.Fatalf("status: %s", r.body)
	}
	_ = token
	// Signing out again is idempotent and still answers 200.
	if r := b.signOut(); r.status != 200 {
		t.Fatalf("second sign-out: %d", r.status)
	}
}

func TestSignOutNeedsCSRFAndSameOrigin(t *testing.T) {
	e := newEnv(t, true)
	for name, hdr := range map[string]map[string]string{
		"missing token":   {},
		"wrong token":     {"X-CSRF-Token": strings.Repeat("A", 43)},
		"malformed token": {"X-CSRF-Token": "x"},
		"foreign origin":  {"Origin": "https://evil.example"},
		"cross-site":      {"Sec-Fetch-Site": "cross-site"},
	} {
		b := e.browser()
		b.status()
		b.signIn(adminName, adminPass)
		if _, ok := hdr["Origin"]; ok || hdr["Sec-Fetch-Site"] != "" {
			hdr["X-CSRF-Token"] = b.csrf // a correct token does not rescue a foreign origin
		}
		r := b.do("DELETE", "/api/v1/auth/session", "", hdr)
		if r.status != 403 || catOf(t, r) != "forbidden" {
			t.Errorf("%s: %d %s", name, r.status, r.body)
		}
		if h := b.do("GET", "/api/v1/hosts", "", nil); h.status != 200 {
			t.Errorf("%s: the failed sign-out ended the session (%d)", name, h.status)
		}
	}
}

func TestSignOutWithoutSessionIsIdempotentButStillOriginChecked(t *testing.T) {
	e := newEnv(t, true)
	b := e.browser()
	if r := b.do("DELETE", "/api/v1/auth/session", "", nil); r.status != 200 {
		t.Fatalf("%d", r.status)
	}
	if r := b.do("DELETE", "/api/v1/auth/session", "", map[string]string{"Origin": "https://evil.example"}); r.status != 403 {
		t.Fatalf("%d", r.status)
	}
}

// ---- expiry, restart, concurrency, TLS ------------------------------------------------------------------------------

func TestExpiredSessionIsUnauthenticatedEverywhere(t *testing.T) {
	e := newEnv(t, true)
	b := e.browser()
	b.status()
	b.signIn(adminName, adminPass)
	e.clk.add(31 * time.Minute) // past the idle timeout
	if r := b.do("GET", "/api/v1/hosts", "", nil); r.status != 401 {
		t.Fatalf("hosts: %d", r.status)
	}
	r := b.status()
	if !strings.Contains(string(r.body), `"authenticated":false`) {
		t.Fatalf("status: %s", r.body)
	}
	if c := cookieNamed(r, "svavyom_session"); c == nil || c.MaxAge >= 0 {
		t.Fatal("stale session cookie was not cleared")
	}
	if r := b.signIn(adminName, adminPass); r.status != 200 {
		t.Fatalf("sign in again: %d", r.status)
	}
}

func TestSessionSurvivesProcessRestart(t *testing.T) {
	e := newEnv(t, true)
	b := e.browser()
	b.status()
	b.signIn(adminName, adminPass)
	jar := b.c.Jar
	e.start() // new database connection, service, handler and listener
	b2 := &browser{t: t, base: e.srv.URL, c: &http.Client{Jar: jar}}
	u, _ := url.Parse(e.srv.URL)
	// cookies are host-scoped (127.0.0.1) not port-scoped, so the jar still applies
	if len(jar.Cookies(u)) == 0 {
		t.Fatal("jar empty")
	}
	if r := b2.do("GET", "/api/v1/hosts", "", nil); r.status != 200 {
		t.Fatalf("session lost across restart: %d", r.status)
	}
	// The CSRF token (derived, not stored) is still accepted after the restart.
	if r := b2.do("DELETE", "/api/v1/auth/session", "", map[string]string{"X-CSRF-Token": b.csrf}); r.status != 200 {
		t.Fatalf("csrf token lost across restart: %d", r.status)
	}
}

func TestConcurrentRequestsOneSession(t *testing.T) {
	e := newEnv(t, true)
	b := e.browser()
	b.status()
	b.signIn(adminName, adminPass)
	var wg sync.WaitGroup
	var ok atomic.Int32
	for i := 0; i < 24; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if r := b.do("GET", "/api/v1/hosts", "", nil); r.status == 200 {
				ok.Add(1)
			}
		}()
	}
	wg.Wait()
	if ok.Load() != 24 {
		t.Fatalf("%d/24 succeeded", ok.Load())
	}
}

func TestHTTPSCookiesAreSecureAndHostPrefixed(t *testing.T) {
	e := newEnv(t, true)
	srv := httptest.NewTLSServer(e.h)
	defer srv.Close()
	jar, _ := cookiejar.New(nil)
	c := srv.Client()
	c.Jar = jar
	b := &browser{t: t, base: srv.URL, c: c}
	r := b.status()
	lc := cookieNamed(r, "__Host-svavyom_login")
	if lc == nil || !lc.Secure || !lc.HttpOnly || lc.SameSite != http.SameSiteStrictMode || lc.Path != "/" || lc.Domain != "" {
		t.Fatalf("login cookie over HTTPS: %+v", lc)
	}
	r = b.signIn(adminName, adminPass)
	sc := cookieNamed(r, "__Host-svavyom_session")
	if sc == nil || !sc.Secure || !sc.HttpOnly || sc.SameSite != http.SameSiteStrictMode || sc.Domain != "" || sc.Path != "/" {
		t.Fatalf("session cookie over HTTPS: %+v", sc)
	}
	// Origin must match the https origin.
	u, _ := url.Parse(srv.URL)
	hdr := map[string]string{"X-CSRF-Token": b.csrf, "Origin": "http://" + u.Host}
	if r := b.do("DELETE", "/api/v1/auth/session", "", hdr); r.status != 403 {
		t.Fatalf("downgraded origin accepted: %d", r.status)
	}
	hdr["Origin"] = srv.URL
	if r := b.do("DELETE", "/api/v1/auth/session", "", hdr); r.status != 200 {
		t.Fatalf("same origin refused: %d", r.status)
	}
}

func TestForwardedProtoIsIgnoredUnlessTrusted(t *testing.T) {
	e := newEnv(t, true)
	b := e.browser()
	r := b.do("GET", "/api/v1/auth/session", "", map[string]string{"X-Forwarded-Proto": "https"})
	if cookieNamed(r, "svavyom_login") == nil || cookieNamed(r, "__Host-svavyom_login") != nil {
		t.Fatal("an untrusted X-Forwarded-Proto changed the cookie mode")
	}
	trusted := httptest.NewServer(NewHandlerWith(Deps{Auth: e.svc, Hosts: e.hosts, TrustForwardedProto: true}))
	defer trusted.Close()
	tb := &browser{t: t, base: trusted.URL, c: &http.Client{}}
	r = tb.do("GET", "/api/v1/auth/session", "", map[string]string{"X-Forwarded-Proto": "https"})
	if c := cookieNamed(r, "__Host-svavyom_login"); c == nil || !c.Secure {
		t.Fatal("trusted proxy header ignored")
	}
}

// ---- hosts -----------------------------------------------------------------------------------------------------------

func signedIn(t *testing.T, e *env) *browser {
	b := e.browser()
	b.status()
	if r := b.signIn(adminName, adminPass); r.status != 200 {
		t.Fatalf("sign-in: %d %s", r.status, r.body)
	}
	return b
}

func TestHostsRequireASession(t *testing.T) {
	e := newEnv(t, true)
	anon := e.browser()
	for _, p := range []string{"/api/v1/hosts", "/api/v1/hosts/local", "/api/v1/hosts?limit=bogus", "/api/v1/hosts/%00"} {
		r := anon.do("GET", p, "", nil)
		if r.status != 401 || catOf(t, r) != "unauthenticated" {
			t.Errorf("%s: %d %s", p, r.status, r.body)
		}
	}
	for name, cookie := range map[string]string{"forged": strings.Repeat("A", 43), "malformed": "x", "sql": "' OR 1=1 --", "empty": ""} {
		b := e.browser()
		u, _ := url.Parse(e.srv.URL)
		b.c.Jar.SetCookies(u, []*http.Cookie{{Name: "svavyom_session", Value: cookie, Path: "/"}})
		if r := b.do("GET", "/api/v1/hosts", "", nil); r.status != 401 {
			t.Errorf("%s cookie: %d", name, r.status)
		}
	}
	// A session cookie sent under the wrong (HTTPS) name over HTTP is not a session either.
	b := e.browser()
	r := b.do("GET", "/api/v1/hosts", "", map[string]string{"Cookie": "__Host-svavyom_session=" + strings.Repeat("A", 43)})
	if r.status != 401 {
		t.Fatal(r.status)
	}
}

func TestHostListExposesExactlyTheApprovedFields(t *testing.T) {
	e := newEnv(t, true)
	b := signedIn(t, e)
	r := b.do("GET", "/api/v1/hosts", "", nil)
	if r.status != 200 || r.header.Get("Cache-Control") != "no-store" {
		t.Fatalf("%d %v", r.status, r.header)
	}
	if got := strings.Join(keys(t, r.body), ","); got != "allowed_actions,items,next_cursor" {
		t.Fatalf("list keys %s", got)
	}
	var list struct {
		Items []json.RawMessage `json:"items"`
		Next  *string           `json:"next_cursor"`
	}
	_ = json.Unmarshal(r.body, &list)
	if len(list.Items) != 1 || list.Next != nil {
		t.Fatalf("%s", r.body)
	}
	host := list.Items[0]
	if got := strings.Join(keys(t, host), ","); got != "allowed_actions,desired,generation,id,name,observed" {
		t.Fatalf("host keys %s", got)
	}
	var h struct {
		Observed map[string]json.RawMessage
	}
	_ = json.Unmarshal(host, &h)
	var obs []string
	for k := range h.Observed {
		obs = append(obs, k)
	}
	sort.Strings(obs)
	if got := strings.Join(obs, ","); got != "agent_version,alerts,bridge,capability_findings,capability_verdict,cpu_count,creation,distribution,memory_mib,nightly_boot,reachable,storage,usage,virtualization" {
		t.Fatalf("observed keys %s", got)
	}
	var full hostJSON
	dec := json.NewDecoder(bytes.NewReader(host))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&full); err != nil {
		t.Fatal(err)
	}
	o := full.Observed
	if full.ID != "local" || full.Name != "lab-host" || o.CPUCount != 8 || o.MemoryMiB != 16000 || o.AgentVersion != "1.2.3" ||
		o.CapabilityVerdict != "unknown" || o.Virtualization.Hardware != "available" || o.Virtualization.KVMDevice != "unavailable" ||
		o.Virtualization.LibvirtPackages != "unknown" || o.Distribution.ID != "debian" || len(o.CapabilityFindings) != 1 || len(full.Allowed) != 0 {
		t.Fatalf("%+v", full)
	}
	for _, leak := range []string{"/etc", "/proc", "HOME=", "PATH=", "root", "uid", "pid", "hostname"} {
		if strings.Contains(string(r.body), leak) {
			t.Errorf("response contains %q", leak)
		}
	}
}

func TestReadHostAndParameterValidation(t *testing.T) {
	e := newEnv(t, true)
	b := signedIn(t, e)
	if r := b.do("GET", "/api/v1/hosts/local", "", nil); r.status != 200 || strings.Join(keys(t, r.body), ",") != "allowed_actions,desired,generation,id,name,observed" {
		t.Fatalf("%d %s", r.status, r.body)
	}
	for p, want := range map[string]int{
		"/api/v1/hosts/other": 404, "/api/v1/hosts/local?x=1": 400, "/api/v1/hosts?cursor=abc": 400, "/api/v1/hosts?limit=0": 400,
		"/api/v1/hosts?limit=201": 400, "/api/v1/hosts?limit=5&limit=6": 400, "/api/v1/hosts?other=1": 400, "/api/v1/hosts?limit=200": 200,
	} {
		if r := b.do("GET", p, "", nil); r.status != want {
			t.Errorf("%s: %d, want %d (%s)", p, r.status, want, r.body)
		}
	}
	e.hosts.err = errors.New("kaboom /etc/shadow")
	r := b.do("GET", "/api/v1/hosts", "", nil)
	if r.status != 503 || catOf(t, r) != "unavailable" || strings.Contains(string(r.body), "shadow") {
		t.Fatalf("%d %s", r.status, r.body)
	}
}

func TestScaffoldHandlerStaysClosed(t *testing.T) {
	srv := httptest.NewServer(NewHandler())
	defer srv.Close()
	b := &browser{t: t, base: srv.URL, c: &http.Client{}}
	if r := b.do("GET", "/api/v1/hosts", "", nil); r.status != 401 {
		t.Fatal(r.status)
	}
	for _, m := range []string{"GET", "POST", "DELETE"} {
		if r := b.do(m, "/api/v1/auth/session", "{}", nil); r.status != 503 || catOf(t, r) != "unavailable" {
			t.Fatalf("%s: %d %s", m, r.status, r.body)
		}
	}
}

func TestUndeclaredMethodsOnSessionPath(t *testing.T) {
	e := newEnv(t, true)
	b := e.browser()
	for _, m := range []string{"PUT", "PATCH", "HEAD", "OPTIONS"} {
		if r := b.do(m, "/api/v1/auth/session", "", nil); r.status != 404 {
			t.Errorf("%s: %d", m, r.status)
		}
	}
}

func TestNoLoggingInAuthenticationCode(t *testing.T) {
	// Passwords, hashes, tokens and CSRF secrets must never be logged; the simplest guarantee is that the packages
	// that handle them do not log at all.
	for _, f := range []string{"session.go", "hosts.go", "api.go", "../auth/service.go", "../auth/password.go", "../auth/limiter.go"} {
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, bad := range []string{`"log"`, `"log/slog"`, "fmt.Print", "println(", "os.Stderr", "os.Stdout"} {
			if strings.Contains(string(src), bad) {
				t.Errorf("%s uses %s", f, bad)
			}
		}
	}
}

func TestResponsesCarryNoServerSecrets(t *testing.T) {
	e := newEnv(t, true)
	b := e.browser()
	b.status()
	r := b.signIn(adminName, adminPass)
	all := string(r.body)
	for k, v := range r.header {
		all += k + strings.Join(v, ",")
	}
	var phc string
	db, _ := sqlitedb.Open(e.path)
	defer db.Close()
	_ = db.QueryRow(`SELECT password_phc FROM users`).Scan(&phc)
	if phc == "" || strings.Contains(all, phc) || strings.Contains(all, "argon2") {
		t.Fatal("password hash in a response")
	}
}
