// Package tlsacme is the certificate handling of the web console (DR-034): reading the certificate in use, deciding when it is due for renewal, reloading it
// without a restart, writing it atomically, and getting one from an ACME service (Let's Encrypt) over HTTP-01 or TLS-ALPN-01.
package tlsacme

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"strings"
	"time"
)

// Info is what the console shows about the certificate in use. It holds nothing secret.
type Info struct {
	Names      []string  `json:"names"`
	Issuer     string    `json:"issuer"`
	NotBefore  time.Time `json:"not_before"`
	NotAfter   time.Time `json:"not_after"`
	SelfSigned bool      `json:"self_signed"`
	// Source is "self_signed", "lets_encrypt", "lets_encrypt_staging" or "other".
	Source string `json:"source"`
}

// leaf returns the first certificate of a PEM bundle.
func leaf(certPEM []byte) (*x509.Certificate, error) {
	for {
		var blk *pem.Block
		blk, certPEM = pem.Decode(certPEM)
		if blk == nil {
			return nil, errors.New("no certificate in the file")
		}
		if blk.Type == "CERTIFICATE" {
			return x509.ParseCertificate(blk.Bytes)
		}
	}
}

// Inspect describes the first certificate of a PEM bundle.
func Inspect(certPEM []byte) (Info, error) {
	c, err := leaf(certPEM)
	if err != nil {
		return Info{}, err
	}
	names := append([]string{}, c.DNSNames...)
	for _, ip := range c.IPAddresses {
		names = append(names, ip.String())
	}
	if len(names) == 0 && c.Subject.CommonName != "" {
		names = []string{c.Subject.CommonName}
	}
	self := bytes.Equal(c.RawIssuer, c.RawSubject) && c.CheckSignature(c.SignatureAlgorithm, c.RawTBSCertificate, c.Signature) == nil
	issuer := strings.Join(append(append([]string{}, c.Issuer.Organization...), c.Issuer.CommonName), " ")
	in := Info{Names: names, Issuer: strings.TrimSpace(issuer), NotBefore: c.NotBefore.UTC(), NotAfter: c.NotAfter.UTC(), SelfSigned: self, Source: "other"}
	switch {
	case self:
		in.Source = "self_signed"
	case strings.Contains(issuer, "STAGING"):
		in.Source = "lets_encrypt_staging"
	case strings.Contains(issuer, "Let's Encrypt"):
		in.Source = "lets_encrypt"
	}
	return in, nil
}

// RenewAt is when a certificate is due for renewal: when a third of its lifetime is left (30 days of 90, 15 of 45, 2 of 6). Lifetimes are changing
// (Let's Encrypt moves from 90 to 64 and then 45 days), so the rule is a fraction, not a number of days.
func RenewAt(notBefore, notAfter time.Time) time.Time {
	return notAfter.Add(-notAfter.Sub(notBefore) / 3)
}

// Due reports whether the certificate should be renewed now.
func (i Info) Due(now time.Time) bool { return !now.Before(RenewAt(i.NotBefore, i.NotAfter)) }

// DaysLeft is the whole days until the certificate expires (negative when it has).
func (i Info) DaysLeft(now time.Time) int { return int(i.NotAfter.Sub(now).Hours() / 24) }

// Pair parses a certificate and key and checks that they belong together. A non-empty name must be one of the certificate's names.
func Pair(certPEM, keyPEM []byte, name string) (*tls.Certificate, error) {
	c, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, errors.New("the certificate and key do not parse or do not match")
	}
	in, err := Inspect(certPEM)
	if err != nil {
		return nil, err
	}
	if name != "" {
		ok := false
		for _, n := range in.Names {
			if strings.EqualFold(n, name) {
				ok = true
			}
		}
		if !ok {
			return nil, errors.New("the certificate does not name " + name)
		}
	}
	return &c, nil
}
