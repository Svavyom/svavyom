package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"example.invalid/dedicatedcloud/backend/internal/tlsacme"
)

func TestTheCertificateViewShowsTheFileAndWhatTheLastRenewalRecorded(t *testing.T) {
	dir := t.TempDir()
	cert := filepath.Join(dir, "cert.pem")
	v := certificateView(cert, time.Now)
	if v() != nil {
		t.Fatal("no certificate file: nothing to show (a proxy in front)")
	}
	os.WriteFile(cert, []byte("garbage"), 0o644)
	if v() != nil {
		t.Fatal("an unreadable file shows nothing rather than guessing")
	}
}

func TestTheViewOfAManagedCertificateCarriesTheRecord(t *testing.T) {
	dir := t.TempDir()
	st := tlsacme.Store{Dir: dir}
	now := time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC)
	certPEM, keyPEM := selfSigned(t, "console.example.org", now.Add(-24*time.Hour), 90*24*time.Hour)
	if err := st.Install(certPEM, keyPEM, "console.example.org"); err != nil {
		t.Fatal(err)
	}
	got := certificateView(st.CertFile(), func() time.Time { return now })()
	if got == nil || got.Source != "self_signed" || got.Managed || got.DaysLeft != 89 || got.LastResult != nil || got.Names[0] != "console.example.org" {
		t.Fatalf("%+v", got)
	}
	if err := st.WriteState(tlsacme.State{Name: "console.example.org", LastAttempt: now, LastResult: "validation_failed", LastDetail: "no"}); err != nil {
		t.Fatal(err)
	}
	got = certificateView(st.CertFile(), func() time.Time { return now })()
	if got.LastResult == nil || *got.LastResult != "validation_failed" || got.LastDetail == nil || got.LastAttempt == nil {
		t.Fatalf("%+v", got)
	}
}

func selfSigned(t *testing.T, name string, from time.Time, life time.Duration) (certPEM, keyPEM []byte) {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: name}, DNSNames: []string{name}, NotBefore: from, NotAfter: from.Add(life)}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	kd, _ := x509.MarshalECPrivateKey(k)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kd})
}
