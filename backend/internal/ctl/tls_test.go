package ctl

import (
	"bytes"
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"example.invalid/dedicatedcloud/backend/internal/tlsacme"
	"example.invalid/dedicatedcloud/backend/internal/tlsacme/acmetest"
)

func acmeRig(t *testing.T) (*testHost, *acmetest.Server, ACMEDeps) {
	h := newHost(t)
	return acmeRigOn(h)
}

func acmeRigOn(h *testHost) (*testHost, *acmetest.Server, ACMEDeps) {
	t := h.t
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	l.Close()
	f := acmetest.New(t)
	f.HTTPAddr, f.TLSAddr = addr, addr
	d := ACMEDeps{Directory: func(bool) string { return f.Dir() }, Addr: addr,
		Resolve:    func(context.Context, string) ([]net.IP, error) { return []net.IP{net.ParseIP("203.0.113.7")}, nil },
		LocalAddrs: func() ([]net.IP, error) { return []net.IP{net.ParseIP("203.0.113.7")}, nil }}
	return h, f, d
}

func issueOpts() ACMEOptions {
	return ACMEOptions{Name: "console.example.org", Email: "admin@example.org", AcceptTerms: true}
}

func tlsFile(h *testHost, name string) string {
	b, _ := os.ReadFile(filepath.Join(h.root, "etc/svavyom/tls", name))
	return string(b)
}

func TestProductionIsRefusedBeforeAStagingRehearsalAndThenAllowed(t *testing.T) {
	h, f, d := acmeRig(t)
	var out bytes.Buffer
	err := h.env.ACMEIssue(context.Background(), issueOpts(), d, &out)
	var te *tlsacme.Error
	if !errors.As(err, &te) || te.Code != tlsacme.CodeStagingFirst || f.Orders != 0 {
		t.Fatalf("%v orders=%d", err, f.Orders)
	}
	st := issueOpts()
	st.Staging = true
	if err := h.env.ACMEIssue(context.Background(), st, d, &out); err != nil {
		t.Fatal(err)
	}
	if tlsFile(h, "cert.pem") != "" {
		t.Fatal("a rehearsal installs nothing")
	}
	if !strings.Contains(out.String(), "Nothing was installed") {
		t.Fatal(out.String())
	}
	out.Reset()
	if err := h.env.ACMEIssue(context.Background(), issueOpts(), d, &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(tlsFile(h, "cert.pem"), "BEGIN CERTIFICATE") || !strings.Contains(tlsFile(h, "key.pem"), "PRIVATE KEY") {
		t.Fatal("the certificate and key are installed")
	}
	for _, u := range []string{TLSRenewService, TLSRenewTimer} {
		if b, err := os.ReadFile(h.env.P(UnitDir + "/" + u)); err != nil || len(b) == 0 {
			t.Fatalf("%s: %v", u, err)
		}
	}
	svc, _ := os.ReadFile(h.env.P(UnitDir + "/" + TLSRenewService))
	for _, want := range []string{"ExecStart=" + LibexecDir + "/svavyom-ctl tls acme-renew", "ProtectSystem=strict", "ReadWritePaths=" + ConfigDir + "/tls", "NoNewPrivileges=true"} {
		if !strings.Contains(string(svc), want) {
			t.Fatalf("the renewal service lacks %q", want)
		}
	}
	if !contains(h.run.calls, "systemctl enable --now -- "+TLSRenewTimer) {
		t.Fatalf("%v", h.run.calls)
	}
	if c, ok := (tlsacme.Store{Dir: h.env.P(ConfigDir + "/tls")}).ReadConfig(); !ok || c.Email != "admin@example.org" {
		t.Fatalf("%+v", c)
	}
	if fi, _ := os.Stat(filepath.Join(h.root, "etc/svavyom/tls/acme/account.key")); fi == nil || fi.Mode().Perm() != 0o600 {
		t.Fatal("the account key is 0600")
	}
	if strings.Contains(out.String(), "PRIVATE") || strings.Contains(tlsFile(h, "state.json"), "admin@example.org") {
		t.Fatal("neither the output nor the state shows a key or an address")
	}
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func TestAStagingRehearsalOfAnotherNameDoesNotOpenProduction(t *testing.T) {
	h, _, d := acmeRig(t)
	st := issueOpts()
	st.Staging = true
	st.Name = "other.example.org"
	var out bytes.Buffer
	if err := h.env.ACMEIssue(context.Background(), st, d, &out); err != nil {
		t.Fatal(err)
	}
	if err := h.env.ACMEIssue(context.Background(), issueOpts(), d, &out); err == nil {
		t.Fatal("production needs a rehearsal of this name")
	}
}

func TestRenewalDoesNothingUntilDueThenRenewsAndRecordsIt(t *testing.T) {
	h, f, d := acmeRig(t)
	o := issueOpts()
	o.NoStagingFirst = true
	var out bytes.Buffer
	if err := h.env.ACMEIssue(context.Background(), o, d, &out); err != nil {
		t.Fatal(err)
	}
	h.now = time.Now()
	orders := f.Orders
	out.Reset()
	if err := h.env.ACMERenew(context.Background(), d, &out); err != nil || f.Orders != orders || !strings.Contains(out.String(), "not due") {
		t.Fatalf("%v %q", err, out.String())
	}
	h.now = time.Now().Add(61 * 24 * time.Hour)
	out.Reset()
	if err := h.env.ACMERenew(context.Background(), d, &out); err != nil || f.Orders != orders+1 || !strings.Contains(out.String(), "renewed") {
		t.Fatalf("%v %q", err, out.String())
	}
	if _, err := os.Stat(filepath.Join(h.root, "etc/svavyom/tls/previous/cert.pem")); err != nil {
		t.Fatal("the replaced certificate is kept")
	}
	// a failure is recorded with its closed code and leaves the certificate alone
	before := tlsFile(h, "cert.pem")
	f.RejectAuth = true
	h.now = h.now.Add(time.Hour)
	err := h.env.ACMERenew(context.Background(), d, &out)
	var te *tlsacme.Error
	if !errors.As(err, &te) || te.Code != tlsacme.CodeValidation || tlsFile(h, "cert.pem") != before {
		t.Fatalf("%v", err)
	}
	if s, _ := (tlsacme.Store{Dir: h.env.P(ConfigDir + "/tls")}).ReadState(); s.LastResult != tlsacme.CodeValidation {
		t.Fatalf("%+v", s)
	}
}

func TestRenewalOfACertificateThisToolDidNotIssueIsANoOp(t *testing.T) {
	h, f, d := acmeRig(t)
	var out bytes.Buffer
	if err := h.env.ACMERenew(context.Background(), d, &out); err != nil || f.Orders != 0 || !strings.Contains(out.String(), "nothing to renew") {
		t.Fatalf("%v %q", err, out.String())
	}
}

func TestUseSelfSignedReplacesTheCertificateKeepsTheOldAndStopsRenewal(t *testing.T) {
	h, _, d := acmeRig(t)
	o := issueOpts()
	o.NoStagingFirst = true
	var out bytes.Buffer
	if err := h.env.ACMEIssue(context.Background(), o, d, &out); err != nil {
		t.Fatal(err)
	}
	le := tlsFile(h, "cert.pem")
	if err := h.env.UseSelfSigned(context.Background(), "console.example.org", &out); err != nil {
		t.Fatal(err)
	}
	if tlsFile(h, "cert.pem") == le {
		t.Fatal("replaced")
	}
	in, err := tlsacme.Inspect([]byte(tlsFile(h, "cert.pem")))
	if err != nil || !in.SelfSigned {
		t.Fatalf("%+v %v", in, err)
	}
	if b, _ := os.ReadFile(filepath.Join(h.root, "etc/svavyom/tls/previous/cert.pem")); string(b) != le {
		t.Fatal("the Let's Encrypt certificate is kept for one renewal")
	}
	if _, err := os.Stat(h.env.P(UnitDir + "/" + TLSRenewTimer)); err == nil {
		t.Fatal("the renewal timer is removed")
	}
	if _, ok := (tlsacme.Store{Dir: h.env.P(ConfigDir + "/tls")}).ReadConfig(); ok {
		t.Fatal("the renewal settings are forgotten")
	}
	if err := h.env.UseSelfSigned(context.Background(), "not a name!", &out); err == nil {
		t.Fatal("a bad name is refused")
	}
}
