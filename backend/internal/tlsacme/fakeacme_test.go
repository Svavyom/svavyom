package tlsacme

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/acme"
)

// fakeACME is a small ACME server (RFC 8555) for the tests: accounts, one order at a time, HTTP-01 and TLS-ALPN-01 validation against the listeners the
// test names, and a certificate signed by its own CA. It does not verify request signatures: it exists to exercise this client's side of the protocol.
type fakeACME struct {
	t        *testing.T
	srv      *httptest.Server
	ca       *x509.Certificate
	caKey    *ecdsa.PrivateKey
	mu       sync.Mutex
	nonce    int
	jwk      *ecdsa.PublicKey
	names    []string
	token    string
	status   map[string]string // authz and order status
	chType   string
	lifetime time.Duration

	// knobs
	httpAddr, tlsAddr string // where validation connects
	rejectAuth        bool   // validation always fails
	rateLimit         bool   // new-order answers 429 rateLimited
	failRegister      bool
	registered        int
	orders            int
	issuerOrg         string
	// probe runs just before validation, with the listener's address
	probe func(addr string)
}

func newFakeACME(t *testing.T) *fakeACME {
	f := &fakeACME{t: t, status: map[string]string{}, lifetime: 90 * 24 * time.Hour, issuerOrg: "Fake Test CA"}
	f.caKey, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "fake ca", Organization: []string{f.issuerOrg}}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(10 * 365 * 24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, _ := x509.CreateCertificate(rand.Reader, tpl, tpl, &f.caKey.PublicKey, f.caKey)
	f.ca, _ = x509.ParseCertificate(der)
	f.srv = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeACME) dir() string { return f.srv.URL + "/directory" }

func (f *fakeACME) problem(w http.ResponseWriter, code int, typ, detail string) {
	w.Header().Set("Content-Type", "application/problem+json")
	if code == 429 {
		w.Header().Set("Retry-After", "3600")
	}
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"type": "urn:ietf:params:acme:error:" + typ, "detail": detail})
}

func b64(s string) []byte { b, _ := base64.RawURLEncoding.DecodeString(s); return b }

// jws returns the protected header and payload of a request.
func (f *fakeACME) jws(r *http.Request) (map[string]any, []byte) {
	var env struct{ Protected, Payload string }
	b, _ := io.ReadAll(r.Body)
	_ = json.Unmarshal(b, &env)
	var hdr map[string]any
	_ = json.Unmarshal(b64(env.Protected), &hdr)
	return hdr, b64(env.Payload)
}

func (f *fakeACME) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.nonce++
	w.Header().Set("Replay-Nonce", fmt.Sprintf("n%d", f.nonce))
	base := f.srv.URL
	reply := func(code int, v any) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		_ = json.NewEncoder(w).Encode(v)
	}
	switch {
	case r.URL.Path == "/directory":
		reply(200, map[string]any{"newNonce": base + "/nonce", "newAccount": base + "/acct", "newOrder": base + "/order", "revokeCert": base + "/revoke", "keyChange": base + "/kc", "meta": map[string]string{"termsOfService": base + "/tos"}})
	case r.URL.Path == "/nonce":
		w.WriteHeader(200)
	case r.URL.Path == "/acct":
		hdr, _ := f.jws(r)
		if f.failRegister {
			f.problem(w, 400, "serverInternal", "registration is down")
			return
		}
		jwk, _ := json.Marshal(hdr["jwk"])
		var k struct{ X, Y string }
		_ = json.Unmarshal(jwk, &k)
		f.jwk = &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(b64(k.X)), Y: new(big.Int).SetBytes(b64(k.Y))}
		f.registered++
		w.Header().Set("Location", base+"/acct/1")
		reply(201, map[string]any{"status": "valid"})
	case r.URL.Path == "/order":
		if f.rateLimit {
			f.problem(w, 429, "rateLimited", "too many certificates already issued")
			return
		}
		_, p := f.jws(r)
		var req struct {
			Identifiers []struct{ Type, Value string }
		}
		_ = json.Unmarshal(p, &req)
		f.names = nil
		for _, id := range req.Identifiers {
			f.names = append(f.names, id.Value)
		}
		f.orders++
		f.token = fmt.Sprintf("tok%d", f.orders)
		f.status["authz"], f.status["order"] = "pending", "pending"
		w.Header().Set("Location", base+"/o/1")
		reply(201, f.order())
	case r.URL.Path == "/o/1":
		reply(200, f.order())
	case r.URL.Path == "/authz/1":
		reply(200, map[string]any{"status": f.status["authz"], "identifier": map[string]string{"type": "dns", "value": f.names[0]}, "challenges": []map[string]any{
			{"type": "http-01", "url": base + "/chal/http-01", "token": f.token, "status": "pending"},
			{"type": "tls-alpn-01", "url": base + "/chal/tls-alpn-01", "token": f.token, "status": "pending"}}})
	case strings.HasPrefix(r.URL.Path, "/chal/"):
		f.chType = strings.TrimPrefix(r.URL.Path, "/chal/")
		if f.validate() {
			f.status["authz"], f.status["order"] = "valid", "ready"
		} else {
			f.status["authz"], f.status["order"] = "invalid", "invalid"
		}
		reply(200, map[string]any{"type": f.chType, "url": base + r.URL.Path, "token": f.token, "status": f.status["authz"]})
	case r.URL.Path == "/finalize/1":
		_, p := f.jws(r)
		var req struct{ CSR string }
		_ = json.Unmarshal(p, &req)
		csr, err := x509.ParseCertificateRequest(b64(req.CSR))
		if err != nil || csr.CheckSignature() != nil {
			f.problem(w, 400, "badCSR", "bad csr")
			return
		}
		serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
		tpl := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: csr.DNSNames[0]}, DNSNames: csr.DNSNames, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(f.lifetime), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
		der, _ := x509.CreateCertificate(rand.Reader, tpl, f.ca, csr.PublicKey, f.caKey)
		f.status["order"] = "valid"
		f.status["cert"] = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})) + string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.ca.Raw}))
		reply(200, f.order())
	case r.URL.Path == "/cert/1":
		w.Header().Set("Content-Type", "application/pem-certificate-chain")
		_, _ = w.Write([]byte(f.status["cert"]))
	default:
		http.NotFound(w, r)
	}
}

func (f *fakeACME) order() map[string]any {
	o := map[string]any{"status": f.status["order"], "identifiers": []map[string]string{{"type": "dns", "value": f.names[0]}}, "authorizations": []string{f.srv.URL + "/authz/1"}, "finalize": f.srv.URL + "/finalize/1"}
	if f.status["order"] == "valid" {
		o["certificate"] = f.srv.URL + "/cert/1"
	}
	return o
}

// validate does what a certificate authority does: connect to the name's host and look for the key authorisation.
func (f *fakeACME) validate() bool {
	if f.rejectAuth || f.jwk == nil {
		return false
	}
	tp, _ := acme.JWKThumbprint(f.jwk)
	keyAuth := f.token + "." + tp
	switch f.chType {
	case "http-01":
		if f.probe != nil {
			f.probe(f.httpAddr)
		}
		res, err := http.Get("http://" + f.httpAddr + "/.well-known/acme-challenge/" + f.token)
		if err != nil {
			return false
		}
		defer res.Body.Close()
		b, _ := io.ReadAll(res.Body)
		return res.StatusCode == 200 && string(b) == keyAuth
	case "tls-alpn-01":
		c, err := tls.Dial("tcp", f.tlsAddr, &tls.Config{ServerName: f.names[0], NextProtos: []string{"acme-tls/1"}, InsecureSkipVerify: true}) //nolint:gosec // a test CA validating a challenge certificate
		if err != nil {
			return false
		}
		defer c.Close()
		certs := c.ConnectionState().PeerCertificates
		sum := sha256.Sum256([]byte(keyAuth))
		want, _ := asn1.Marshal(sum[:])
		for _, e := range certs[0].Extensions {
			if e.Id.String() == "1.3.6.1.5.5.7.1.31" {
				return string(e.Value) == string(want) && c.ConnectionState().NegotiatedProtocol == "acme-tls/1"
			}
		}
	}
	return false
}
