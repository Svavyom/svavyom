package tlsacme

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func pemKey(t *testing.T, k *ecdsa.PrivateKey) []byte {
	t.Helper()
	der, err := x509.MarshalECPrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
}

// mk makes a certificate for names, valid for the given window, signed by parent (nil: self-signed). It returns the certificate and key PEM.
func mk(t *testing.T, names []string, from time.Time, life time.Duration, issuerOrg string, parent *x509.Certificate, parentKey *ecdsa.PrivateKey) (certPEM, keyPEM []byte, cert *x509.Certificate, key *ecdsa.PrivateKey) {
	t.Helper()
	key, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	tpl := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: names[0], Organization: []string{issuerOrg}}, DNSNames: names, NotBefore: from, NotAfter: from.Add(life), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, IsCA: parent == nil, BasicConstraintsValid: true}
	if parent == nil {
		parent, parentKey = tpl, key
	} else {
		tpl.Subject = pkix.Name{CommonName: names[0]}
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, parent, &key.PublicKey, parentKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ = x509.ParseCertificate(der)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pemKey(t, key), cert, key
}

var t0 = time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC)

func TestInspectSaysWhereACertificateCameFrom(t *testing.T) {
	c, _, _, _ := mk(t, []string{"console.example.org"}, t0, 90*24*time.Hour, "Svavyom Development Preview (self-signed)", nil, nil)
	in, err := Inspect(c)
	if err != nil || !in.SelfSigned || in.Source != "self_signed" || in.Names[0] != "console.example.org" {
		t.Fatalf("%+v %v", in, err)
	}
	for org, want := range map[string]string{"Let's Encrypt": "lets_encrypt", "(STAGING) Let's Encrypt": "lets_encrypt_staging", "Some Other CA": "other"} {
		_, _, ca, cak := mk(t, []string{"ca"}, t0, 24*time.Hour, org, nil, nil)
		leafPEM, _, _, _ := mk(t, []string{"console.example.org"}, t0, 90*24*time.Hour, "", ca, cak)
		in, _ := Inspect(leafPEM)
		if in.SelfSigned || in.Source != want {
			t.Fatalf("%s: %+v", org, in)
		}
	}
	if _, err := Inspect([]byte("not a certificate")); err == nil {
		t.Fatal("garbage is refused")
	}
}

func TestRenewalIsAThirdOfTheLifetime(t *testing.T) {
	for _, days := range []int{90, 64, 45, 6} {
		from := t0
		na := from.Add(time.Duration(days) * 24 * time.Hour)
		at := RenewAt(from, na)
		if left := na.Sub(at); left != time.Duration(days)*24*time.Hour/3 {
			t.Fatalf("%d days: %v left at renewal", days, left)
		}
		in := Info{NotBefore: from, NotAfter: na}
		if in.Due(at.Add(-time.Second)) || !in.Due(at) {
			t.Fatalf("%d days: due exactly at %v", days, at)
		}
	}
	if (Info{NotBefore: t0, NotAfter: t0.Add(24 * time.Hour)}).DaysLeft(t0.Add(48*time.Hour)) >= 0 {
		t.Fatal("an expired certificate has negative days left")
	}
}

func TestPairRefusesAMismatchAGarbageFileAndAWrongName(t *testing.T) {
	c1, k1, _, _ := mk(t, []string{"a.example.org"}, t0, time.Hour*24, "x", nil, nil)
	_, k2, _, _ := mk(t, []string{"b.example.org"}, t0, time.Hour*24, "x", nil, nil)
	if _, err := Pair(c1, k1, "a.example.org"); err != nil {
		t.Fatal(err)
	}
	if _, err := Pair(c1, k2, ""); err == nil {
		t.Fatal("a certificate with another certificate's key is refused")
	}
	if _, err := Pair(c1, k1[:len(k1)/2], ""); err == nil {
		t.Fatal("a truncated key is refused")
	}
	if _, err := Pair(c1, k1, "other.example.org"); err == nil || !strings.Contains(err.Error(), "does not name") {
		t.Fatalf("a certificate for another name is refused: %v", err)
	}
}

func TestInstallWritesModesKeepsThePreviousPairAndRefusesABadOne(t *testing.T) {
	dir := t.TempDir()
	s := Store{Dir: dir}
	c1, k1, _, _ := mk(t, []string{"a.example.org"}, t0, time.Hour*24, "x", nil, nil)
	c2, k2, _, _ := mk(t, []string{"a.example.org"}, t0, time.Hour*48, "x", nil, nil)
	if err := s.Install(c1, k1, "a.example.org"); err != nil {
		t.Fatal(err)
	}
	if err := s.Install(c2, k2, "a.example.org"); err != nil {
		t.Fatal(err)
	}
	for f, mode := range map[string]os.FileMode{"cert.pem": 0o644, "key.pem": 0o640, "previous/cert.pem": 0o644, "previous/key.pem": 0o600} {
		fi, err := os.Stat(filepath.Join(dir, f))
		if err != nil || fi.Mode().Perm() != mode {
			t.Fatalf("%s: %v %v", f, fi, err)
		}
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "previous", "cert.pem")); string(b) != string(c1) {
		t.Fatal("the replaced certificate is kept")
	}
	if err := s.Install(c1, k2, "a.example.org"); err == nil {
		t.Fatal("a mismatched pair is refused")
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "cert.pem")); string(b) != string(c2) {
		t.Fatal("a refused install leaves the certificate in use alone")
	}
	if m, _ := filepath.Glob(filepath.Join(dir, ".*")); len(m) != 0 {
		t.Fatalf("temporary files left: %v", m)
	}
}

func TestReloaderPicksUpANewPairAtMostOncePerMinuteAndKeepsTheOldOneOnABadPair(t *testing.T) {
	dir := t.TempDir()
	s := Store{Dir: dir}
	c1, k1, _, _ := mk(t, []string{"a.example.org"}, t0, time.Hour*24, "x", nil, nil)
	c2, k2, _, _ := mk(t, []string{"a.example.org"}, t0, time.Hour*48, "x", nil, nil)
	if err := s.Install(c1, k1, ""); err != nil {
		t.Fatal(err)
	}
	now := t0
	var logs []string
	r := &Reloader{CertFile: s.CertFile(), KeyFile: s.KeyFile(), Now: func() time.Time { return now }, Log: func(code, _ string) { logs = append(logs, code) }}
	if _, err := r.GetCertificate(nil); err == nil {
		t.Fatal("before Load there is no certificate")
	}
	if err := r.Load(); err != nil {
		t.Fatal(err)
	}
	first, _ := r.GetCertificate(nil)
	serial := func() string { c, _ := x509.ParseCertificate(first.Certificate[0]); return c.SerialNumber.String() }
	old := serial()
	if err := s.Install(c2, k2, ""); err != nil {
		t.Fatal(err)
	}
	future := t0.Add(time.Hour)
	os.Chtimes(s.CertFile(), future, future)
	os.Chtimes(s.KeyFile(), future, future)
	now = t0.Add(30 * time.Second)
	if got, _ := r.GetCertificate(nil); got != first {
		t.Fatal("a change is not looked for more than once a minute")
	}
	now = t0.Add(61 * time.Second)
	got, _ := r.GetCertificate(nil)
	if got == first || len(logs) != 1 || logs[0] != "certificate_reloaded" {
		t.Fatalf("the new pair is in use after a minute: %v", logs)
	}
	first = got
	_ = old
	// a truncated file: the old certificate stays, and it is logged once
	os.WriteFile(s.KeyFile(), k2[:20], 0o640)
	later := future.Add(time.Hour)
	os.Chtimes(s.KeyFile(), later, later)
	for i := 0; i < 3; i++ {
		now = now.Add(2 * time.Minute)
		if got, _ := r.GetCertificate(nil); got != first {
			t.Fatal("a bad pair never replaces the one in use")
		}
	}
	if len(logs) != 2 || logs[1] != "certificate_reload_failed" {
		t.Fatalf("a bad pair is logged once, not every minute: %v", logs)
	}
}

func TestAServerUsingTheReloaderServesTheRenewedCertificateWithoutARestart(t *testing.T) {
	dir := t.TempDir()
	s := Store{Dir: dir}
	c1, k1, x1, _ := mk(t, []string{"a.example.org"}, t0, time.Hour*24, "x", nil, nil)
	c2, k2, x2, _ := mk(t, []string{"a.example.org"}, t0, time.Hour*48, "x", nil, nil)
	if err := s.Install(c1, k1, ""); err != nil {
		t.Fatal(err)
	}
	now := t0
	r := &Reloader{CertFile: s.CertFile(), KeyFile: s.KeyFile(), Now: func() time.Time { return now }}
	if err := r.Load(); err != nil {
		t.Fatal(err)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{GetCertificate: r.GetCertificate, MinVersion: tls.VersionTLS12})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { _ = c.(*tls.Conn).Handshake(); c.Close() }()
		}
	}()
	serial := func() string {
		c, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{InsecureSkipVerify: true, ServerName: "a.example.org"}) //nolint:gosec // reading which certificate is served
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		return c.ConnectionState().PeerCertificates[0].SerialNumber.String()
	}
	if serial() != x1.SerialNumber.String() {
		t.Fatal("the first certificate is served")
	}
	if err := s.Install(c2, k2, ""); err != nil {
		t.Fatal(err)
	}
	future := t0.Add(time.Hour)
	os.Chtimes(s.CertFile(), future, future)
	os.Chtimes(s.KeyFile(), future, future)
	now = t0.Add(2 * time.Minute)
	if serial() != x2.SerialNumber.String() {
		t.Fatal("the renewed certificate is served on the next handshake")
	}
}
