package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Behind a proxy (all connections from loopback) one visitor's failures no longer lock everyone out, and the audit trail shows the real address (DR-038).
func TestProxiedSignInIsThrottledPerClientAndAuditedWithItsAddress(t *testing.T) {
	e := newEnv(t, true)
	srv := httptest.NewServer(NewHandlerWith(Deps{Auth: e.svc, Hosts: e.hosts, ProxyAddressHeader: "X-Forwarded-For"}))
	defer srv.Close()
	cli := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	signIn := func(client, user, pass string) int {
		get, _ := http.NewRequest("GET", srv.URL+"/api/v1/auth/session", nil)
		get.Header.Set("X-Forwarded-For", client)
		gr, err := cli.Do(get)
		if err != nil {
			t.Fatal(err)
		}
		_ = gr.Body.Close()
		csrf := gr.Header.Get("X-CSRF-Token")
		var cookies []*http.Cookie
		cookies = append(cookies, gr.Cookies()...)
		body := `{"username":"` + user + `","password":"` + pass + `"}`
		post, _ := http.NewRequest("POST", srv.URL+"/api/v1/auth/session", strings.NewReader(body))
		post.Header.Set("Content-Type", "application/json")
		post.Header.Set("X-Forwarded-For", client)
		if csrf != "" {
			post.Header.Set("X-CSRF-Token", csrf)
		}
		for _, c := range cookies {
			post.AddCookie(c)
		}
		pr, err := cli.Do(post)
		if err != nil {
			t.Fatal(err)
		}
		_ = pr.Body.Close()
		return pr.StatusCode
	}
	for i := 0; i < 5; i++ {
		if st := signIn("203.0.113.9", adminName, "wrong password here"); st != 401 {
			t.Fatalf("failure %d: %d", i, st)
		}
	}
	if st := signIn("203.0.113.9", adminName, adminPass); st != 429 {
		t.Fatalf("the failing visitor must be blocked: %d", st)
	}
	if st := signIn("198.51.100.7", adminName, adminPass); st != 200 {
		t.Fatalf("another visitor behind the same proxy must get in: %d", st)
	}
	evs, err := e.svc.Audit(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	var sawStranger, sawOwner bool
	for _, ev := range evs {
		sawStranger = sawStranger || (ev.Event == "sign_in" && ev.Source == "203.0.113.9")
		sawOwner = sawOwner || (ev.Event == "sign_in" && ev.Outcome == "success" && ev.Source == "198.51.100.7")
		if ev.Source == "127.0.0.1" {
			t.Errorf("an audit event carries the proxy's address, not the client's: %+v", ev)
		}
	}
	if !sawStranger || !sawOwner {
		t.Errorf("the audit trail does not show the real addresses (stranger %v, owner %v)", sawStranger, sawOwner)
	}
}
