package tlsacme

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func freeAddr(t *testing.T) string {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	a := l.Addr().String()
	l.Close()
	return a
}

// rig makes options that point at the fake CA, with the DNS check satisfied and the validation listener on a free local port.
func rig(t *testing.T, f *fakeACME, challenge string) Options {
	addr := freeAddr(t)
	f.httpAddr, f.tlsAddr = addr, addr
	dir := t.TempDir()
	return Options{Name: "console.example.org", Email: "admin@example.org", Directory: f.dir(), Challenge: challenge, AcceptTerms: true, Store: Store{Dir: filepath.Join(dir, "tls")},
		AccountKey: filepath.Join(dir, "tls", "acme", "account.key"), Addr: addr, Wait: time.Millisecond,
		Resolve:    func(context.Context, string) ([]net.IP, error) { return []net.IP{net.ParseIP("203.0.113.7")}, nil },
		LocalAddrs: func() ([]net.IP, error) { return []net.IP{net.ParseIP("203.0.113.7")}, nil }}
}

func code(err error) string {
	var e *Error
	if errors.As(err, &e) {
		return e.Code
	}
	return "untyped: " + err.Error()
}

func TestIssueOverHTTP01InstallsACertificateAndAnAccountKey(t *testing.T) {
	f := newFakeACME(t)
	o := rig(t, f, "http-01")
	in, err := Issue(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	if in.Names[0] != "console.example.org" || in.SelfSigned || in.Source != "other" {
		t.Fatalf("%+v", in)
	}
	if _, err := Pair(mustRead(t, o.Store.CertFile()), mustRead(t, o.Store.KeyFile()), o.Name); err != nil {
		t.Fatal(err)
	}
	for p, mode := range map[string]os.FileMode{o.Store.KeyFile(): 0o640, o.Store.CertFile(): 0o644, o.AccountKey: 0o600} {
		if fi, err := os.Stat(p); err != nil || fi.Mode().Perm() != mode {
			t.Fatalf("%s: %v %v", p, fi, err)
		}
	}
	if strings.Contains(string(mustRead(t, o.Store.CertFile())), "PRIVATE") {
		t.Fatal("the certificate file never holds a key")
	}
	// the temporary listener is gone when the issuance ends
	if c, err := net.DialTimeout("tcp", o.Addr, time.Second); err == nil {
		c.Close()
		t.Fatal("the validation listener must stop")
	}
	// a second issuance reuses the account
	if _, err := Issue(context.Background(), o); err != nil || f.registered != 2 {
		t.Fatalf("%v registrations=%d", err, f.registered)
	}
}

func mustRead(t *testing.T, p string) []byte {
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestIssueOverTLSALPN01(t *testing.T) {
	f := newFakeACME(t)
	o := rig(t, f, "tls-alpn-01")
	if _, err := Issue(context.Background(), o); err != nil {
		t.Fatal(err)
	}
	if _, err := Pair(mustRead(t, o.Store.CertFile()), mustRead(t, o.Store.KeyFile()), o.Name); err != nil {
		t.Fatal(err)
	}
}

func TestEachFailureIsTypedAndLeavesTheCertificateInUseAlone(t *testing.T) {
	c0, k0, _, _ := mk(t, []string{"console.example.org"}, t0, time.Hour*24, "Svavyom Development Preview (self-signed)", nil, nil)
	cases := []struct {
		name string
		want string
		set  func(f *fakeACME, o *Options)
	}{
		{"validation rejected", CodeValidation, func(f *fakeACME, o *Options) { f.rejectAuth = true }},
		{"rate limited", CodeRateLimited, func(f *fakeACME, o *Options) { f.rateLimit = true }},
		{"account registration fails", CodeAccount, func(f *fakeACME, o *Options) { f.failRegister = true }},
		{"terms not accepted", CodeTermsNotAccepted, func(f *fakeACME, o *Options) { o.AcceptTerms = false }},
		{"bad e-mail", CodeBadInput, func(f *fakeACME, o *Options) { o.Email = "nobody" }},
		{"a wildcard", CodeBadInput, func(f *fakeACME, o *Options) { o.Name = "*.example.org" }},
		{"an IP address", CodeBadInput, func(f *fakeACME, o *Options) { o.Name = "203.0.113.7" }},
		{"dns points elsewhere", CodeDNSMismatch, func(f *fakeACME, o *Options) {
			o.LocalAddrs = func() ([]net.IP, error) { return []net.IP{net.ParseIP("198.51.100.1")}, nil }
		}},
		{"dns does not resolve", CodeDNSMismatch, func(f *fakeACME, o *Options) {
			o.Resolve = func(context.Context, string) ([]net.IP, error) { return nil, errors.New("nxdomain") }
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newFakeACME(t)
			o := rig(t, f, "http-01")
			if err := o.Store.Install(c0, k0, ""); err != nil {
				t.Fatal(err)
			}
			c.set(f, &o)
			_, err := Issue(context.Background(), o)
			if code(err) != c.want {
				t.Fatalf("want %s, got %v", c.want, err)
			}
			if string(mustRead(t, o.Store.CertFile())) != string(c0) {
				t.Fatal("a failed issuance leaves the certificate in use alone")
			}
		})
	}
}

func TestAPortThatIsTakenIsTypedBeforeAnythingIsAskedOfTheAuthority(t *testing.T) {
	f := newFakeACME(t)
	o := rig(t, f, "http-01")
	l, err := net.Listen("tcp", o.Addr)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	_, err = Issue(context.Background(), o)
	if code(err) != CodePortInUse || f.registered != 0 || f.orders != 0 {
		t.Fatalf("%v registrations=%d orders=%d", err, f.registered, f.orders)
	}
}

func TestTheSkipDNSCheckLetsAHostBehindNATIssue(t *testing.T) {
	f := newFakeACME(t)
	o := rig(t, f, "http-01")
	o.LocalAddrs = func() ([]net.IP, error) { return []net.IP{net.ParseIP("10.0.0.5")}, nil }
	if _, err := Issue(context.Background(), o); code(err) != CodeDNSMismatch {
		t.Fatal(err)
	}
	o.SkipDNSCheck = true
	if _, err := Issue(context.Background(), o); err != nil {
		t.Fatal(err)
	}
}

func TestTheChallengeListenerAnswersOnlyTheTokenPath(t *testing.T) {
	f := newFakeACME(t)
	o := rig(t, f, "http-01")
	var got []string
	noFollow := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }, Timeout: 5 * time.Second}
	f.probe = func(addr string) {
		for _, c := range []struct{ method, path string }{{"GET", "/"}, {"GET", "/.well-known/acme-challenge/other"}, {"GET", "/.well-known/"}, {"POST", "/.well-known/acme-challenge/" + f.token}, {"GET", "/api/v1/hosts"}} {
			req, _ := http.NewRequest(c.method, "http://"+addr+c.path, nil)
			res, err := noFollow.Do(req)
			if err != nil {
				got = append(got, "error: "+err.Error())
				continue
			}
			b, _ := io.ReadAll(res.Body)
			res.Body.Close()
			got = append(got, fmt.Sprintf("%s %s -> %d %q", c.method, c.path, res.StatusCode, res.Header.Get("Location")))
			if strings.Contains(string(b), "acme") && res.StatusCode == 200 {
				got = append(got, "leaked the response")
			}
		}
	}
	if _, err := Issue(context.Background(), o); err != nil {
		t.Fatal(err)
	}
	if len(got) != 5 {
		t.Fatalf("%v", got)
	}
	for _, g := range got {
		if !strings.Contains(g, "-> 404 \"\"") {
			t.Fatalf("anything but the token path is a plain 404 with no redirect: %s", g)
		}
	}
}

func TestStateRoundTripsAndHoldsNoSecret(t *testing.T) {
	s := Store{Dir: t.TempDir()}
	if _, ok := s.ReadState(); ok {
		t.Fatal("no state yet")
	}
	st := State{Name: "console.example.org", Staging: true, Challenge: "http-01", LastAttempt: t0, LastResult: "ok"}
	if err := s.WriteState(st); err != nil {
		t.Fatal(err)
	}
	got, ok := s.ReadState()
	if !ok || got != st {
		t.Fatalf("%+v", got)
	}
	if b := mustRead(t, filepath.Join(s.Dir, "state.json")); strings.Contains(string(b), "@") || strings.Contains(string(b), "PRIVATE") {
		t.Fatal("the state holds no e-mail address and no key")
	}
}

func TestADryRunDoesTheWholeOrderAndInstallsNothing(t *testing.T) {
	f := newFakeACME(t)
	o := rig(t, f, "http-01")
	o.DryRun = true
	in, err := Issue(context.Background(), o)
	if err != nil || in.Names[0] != o.Name {
		t.Fatalf("%+v %v", in, err)
	}
	if _, err := os.Stat(o.Store.CertFile()); err == nil {
		t.Fatal("a rehearsal installs no certificate")
	}
	if f.orders != 1 {
		t.Fatal("it did ask the authority")
	}
}

func TestRenewHappensOnlyWhenAThirdOfTheLifetimeIsLeft(t *testing.T) {
	f := newFakeACME(t)
	o := rig(t, f, "http-01")
	first, err := Issue(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	day := 24 * time.Hour
	for _, c := range []struct {
		after time.Duration
		due   bool
	}{{59 * day, false}, {61 * day, true}} {
		o.Now = func() time.Time { return first.NotBefore.Add(c.after) }
		before := f.orders
		renewed, in, err := Renew(context.Background(), o)
		if err != nil || renewed != c.due || (f.orders > before) != c.due {
			t.Fatalf("after %v: renewed=%v err=%v orders=%d", c.after, renewed, err, f.orders)
		}
		_ = in
	}
	if _, err := os.Stat(filepath.Join(o.Store.Dir, "previous", "cert.pem")); err != nil {
		t.Fatal("the replaced certificate is kept for one renewal")
	}
}

func TestARateLimitedRenewalIsNotAskedAgainForTwelveHours(t *testing.T) {
	f := newFakeACME(t)
	o := rig(t, f, "http-01")
	first, err := Issue(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	now := first.NotBefore.Add(70 * 24 * time.Hour)
	o.Now = func() time.Time { return now }
	f.rateLimit = true
	_, _, err = Renew(context.Background(), o)
	if code(err) != CodeRateLimited {
		t.Fatal(err)
	}
	if err := o.Store.WriteState(State{Name: o.Name, LastAttempt: now, LastResult: CodeRateLimited}); err != nil {
		t.Fatal(err)
	}
	f.rateLimit = false
	orders := f.orders
	now = now.Add(2 * time.Hour)
	if _, _, err = Renew(context.Background(), o); code(err) != CodeRateLimited || f.orders != orders {
		t.Fatalf("not asked again within twelve hours: %v", err)
	}
	now = now.Add(11 * time.Hour)
	if renewed, _, err := Renew(context.Background(), o); err != nil || !renewed {
		t.Fatalf("asked again afterwards: %v", err)
	}
}

func TestTheRenewalSettingsAreRootOnly(t *testing.T) {
	s := Store{Dir: t.TempDir()}
	if _, ok := s.ReadConfig(); ok {
		t.Fatal("none yet")
	}
	if err := s.WriteConfig(Config{Name: "console.example.org", Email: "admin@example.org", Challenge: "http-01"}); err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(s.configPath()); fi.Mode().Perm() != 0o600 {
		t.Fatalf("%v", fi.Mode())
	}
	if c, ok := s.ReadConfig(); !ok || c.Email != "admin@example.org" {
		t.Fatalf("%+v", c)
	}
	if err := s.RemoveConfig(); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.ReadConfig(); ok {
		t.Fatal("removed")
	}
}
