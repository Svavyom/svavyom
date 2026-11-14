package tlsacme

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/mail"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"golang.org/x/crypto/acme"
)

// The two directories are fixed in code (DR-034 security considerations); a custom one is a later, explicit option.
const (
	LetsEncrypt        = "https://acme-v02.api.letsencrypt.org/directory"
	LetsEncryptStaging = "https://acme-staging-v02.api.letsencrypt.org/directory"
)

// Closed codes of a failed issuance (DR-034 D4).
const (
	CodeTermsNotAccepted = "terms_not_accepted"
	CodeBadInput         = "bad_input"
	CodeDNSMismatch      = "dns_mismatch"
	CodePortInUse        = "port_in_use"
	CodeAccount          = "account_registration_failed"
	CodeRateLimited      = "rate_limited"
	CodeValidation       = "validation_failed"
	CodeIssue            = "issue_failed"
	CodeStagingFirst     = "staging_first"
)

// Error is a typed failure. Detail never holds a key.
type Error struct{ Code, Detail string }

func (e *Error) Error() string { return e.Code + ": " + e.Detail }

func fail(code, format string, a ...any) *Error {
	return &Error{Code: code, Detail: fmt.Sprintf(format, a...)}
}

// Options of one issuance.
type Options struct {
	Name  string
	Email string
	// Directory is the ACME directory URL (LetsEncrypt or LetsEncryptStaging).
	Directory string
	// Challenge is "http-01" (port 80) or "tls-alpn-01" (port 443).
	Challenge   string
	AcceptTerms bool
	Store       Store
	// AccountKey is the file of the account key (created 0600 when missing).
	AccountKey string
	// Addr is where the temporary validation listener binds (":80" or ":443" by default).
	Addr string
	// Resolve and LocalAddrs back the DNS check; SkipDNSCheck turns it off (NAT, a proxy in front).
	Resolve      func(ctx context.Context, name string) ([]net.IP, error)
	LocalAddrs   func() ([]net.IP, error)
	SkipDNSCheck bool
	HTTPClient   *http.Client
	Now          func() time.Time
	// Poll is how long to wait between looking at an order (a test shortens it).
	Wait time.Duration
	// DryRun does the whole order and installs nothing: the staging rehearsal, whose certificate no browser trusts.
	DryRun bool
}

var nameRE = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$`)

// CheckInput validates the name, the e-mail and the consent; it is the part of the preflight that needs no network.
func CheckInput(name, email string, accept bool) error {
	if !nameRE.MatchString(name) {
		return fail(CodeBadInput, "the name must be a public DNS name (letters, digits, hyphens and dots); a wildcard or an IP address needs another method")
	}
	if a, err := mail.ParseAddress(email); err != nil || a.Address != email {
		return fail(CodeBadInput, "the contact e-mail address is not valid")
	}
	if !accept {
		return fail(CodeTermsNotAccepted, "the certificate authority's terms of service must be accepted (--accept-terms)")
	}
	return nil
}

func defaults(o *Options) {
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Challenge == "" {
		o.Challenge = "http-01"
	}
	if o.Addr == "" {
		o.Addr = map[string]string{"http-01": ":80", "tls-alpn-01": ":443"}[o.Challenge]
	}
	if o.Resolve == nil {
		o.Resolve = func(ctx context.Context, n string) ([]net.IP, error) {
			a, err := net.DefaultResolver.LookupIPAddr(ctx, n)
			var ips []net.IP
			for _, x := range a {
				ips = append(ips, x.IP)
			}
			return ips, err
		}
	}
	if o.LocalAddrs == nil {
		o.LocalAddrs = localIPs
	}
	if o.Wait == 0 {
		o.Wait = 2 * time.Second
	}
}

func localIPs() ([]net.IP, error) {
	a, err := net.InterfaceAddrs()
	var ips []net.IP
	for _, x := range a {
		if n, ok := x.(*net.IPNet); ok {
			ips = append(ips, n.IP)
		}
	}
	return ips, err
}

// CheckDNS compares what the name resolves to with this host's own addresses. A host behind NAT does not have its public address, so a mismatch is
// refused with the addresses named, and the administrator can skip the check knowingly.
func CheckDNS(ctx context.Context, o Options) error {
	defaults(&o)
	got, err := o.Resolve(ctx, o.Name)
	if err != nil || len(got) == 0 {
		return fail(CodeDNSMismatch, "%s does not resolve to any address", o.Name)
	}
	mine, _ := o.LocalAddrs()
	for _, g := range got {
		for _, m := range mine {
			if g.Equal(m) {
				return nil
			}
		}
	}
	var s []string
	for _, g := range got {
		s = append(s, g.String())
	}
	return fail(CodeDNSMismatch, "%s resolves to %s, none of which is an address of this host (behind NAT or a proxy? then use --skip-dns-check, or DNS-01)", o.Name, strings.Join(s, ", "))
}

func accountKey(path string) (crypto.Signer, error) {
	if b, err := os.ReadFile(path); err == nil {
		blk, _ := pem.Decode(b)
		if blk == nil {
			return nil, errors.New("the account key file is damaged")
		}
		return x509.ParseECPrivateKey(blk.Bytes)
	}
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	der, _ := x509.MarshalECPrivateKey(k)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	return k, writeAtomic(path, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), 0o600)
}

// solver serves one challenge on a pre-bound listener, for as long as the issuance runs.
type solver struct {
	ln   net.Listener
	srv  *http.Server
	done chan struct{}
}

func (s *solver) stop() {
	if s.srv != nil {
		_ = s.srv.Close()
	}
	_ = s.ln.Close()
}

// Issue gets a certificate for o.Name and installs it. The key (ECDSA P-256) is made here and never leaves the host. Nothing is installed unless the whole
// order succeeds, so a failure leaves the certificate in use alone.
func Issue(ctx context.Context, o Options) (Info, error) {
	defaults(&o)
	if err := CheckInput(o.Name, o.Email, o.AcceptTerms); err != nil {
		return Info{}, err
	}
	if o.Challenge != "http-01" && o.Challenge != "tls-alpn-01" {
		return Info{}, fail(CodeBadInput, "the challenge is http-01 or tls-alpn-01")
	}
	if !o.SkipDNSCheck {
		if err := CheckDNS(ctx, o); err != nil {
			return Info{}, err
		}
	}
	// Bind first: a port that is taken is a typed failure before any account or order is made.
	ln, err := net.Listen("tcp", o.Addr)
	if err != nil {
		return Info{}, fail(CodePortInUse, "cannot listen on %s: %v", o.Addr, err)
	}
	sv := &solver{ln: ln, done: make(chan struct{})}
	defer sv.stop()

	akey, err := accountKey(o.AccountKey)
	if err != nil {
		return Info{}, fail(CodeAccount, "%v", err)
	}
	// A rate limit is answered, not waited out: the library retries a 429 until its context ends, and a limit lasts hours. The whole issuance is bounded.
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	hc := &http.Client{Timeout: 60 * time.Second}
	if o.HTTPClient != nil {
		hc = o.HTTPClient
	}
	limited := *hc
	limited.Transport = noRetry429{hc.Transport}
	cl := &acme.Client{Key: akey, DirectoryURL: o.Directory, HTTPClient: &limited, UserAgent: "svavyom-ctl"}
	if _, err := cl.Register(ctx, &acme.Account{Contact: []string{"mailto:" + o.Email}}, func(string) bool { return o.AcceptTerms }); err != nil && !errors.Is(err, acme.ErrAccountAlreadyExists) {
		return Info{}, classify(err, CodeAccount)
	}
	order, err := cl.AuthorizeOrder(ctx, acme.DomainIDs(o.Name))
	if err != nil {
		return Info{}, classify(err, CodeIssue)
	}
	for _, u := range order.AuthzURLs {
		if err := solve(ctx, cl, sv, u, o); err != nil {
			return Info{}, err
		}
	}
	if order, err = cl.WaitOrder(ctx, order.URI); err != nil {
		return Info{}, classify(err, CodeValidation)
	}
	ckey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return Info{}, fail(CodeIssue, "%v", err)
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: o.Name}, DNSNames: []string{o.Name}}, ckey)
	if err != nil {
		return Info{}, fail(CodeIssue, "%v", err)
	}
	der, _, err := cl.CreateOrderCert(ctx, order.FinalizeURL, csr, true)
	if err != nil {
		return Info{}, classify(err, CodeIssue)
	}
	var chain []byte
	for _, d := range der {
		chain = append(chain, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: d})...)
	}
	kder, _ := x509.MarshalECPrivateKey(ckey)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kder})
	if o.DryRun {
		return Inspect(chain)
	}
	if err := o.Store.Install(chain, keyPEM, o.Name); err != nil {
		return Info{}, fail(CodeIssue, "the certificate was issued but could not be installed: %v", err)
	}
	return Inspect(chain)
}

// classify maps an ACME error to a typed one.
func classify(err error, def string) *Error {
	var oe *acme.OrderError
	var ae *acme.AuthorizationError
	if _, limited := acme.RateLimit(err); limited {
		return fail(CodeRateLimited, "the certificate authority's rate limit is reached; try again later (staging has higher limits)")
	}
	var ce *acme.Error
	if errors.As(err, &ce) && strings.HasSuffix(ce.ProblemType, ":rateLimited") {
		return fail(CodeRateLimited, "the certificate authority's rate limit is reached; try again later (staging has higher limits)")
	}
	if errors.As(err, &ae) || errors.As(err, &oe) {
		return fail(CodeValidation, "the certificate authority could not validate the name: %v", err)
	}
	return fail(def, "%v", err)
}

func solve(ctx context.Context, cl *acme.Client, sv *solver, authzURL string, o Options) error {
	az, err := cl.GetAuthorization(ctx, authzURL)
	if err != nil {
		return classify(err, CodeValidation)
	}
	if az.Status == acme.StatusValid {
		return nil
	}
	var ch *acme.Challenge
	for _, c := range az.Challenges {
		if c.Type == o.Challenge {
			ch = c
		}
	}
	if ch == nil {
		return fail(CodeValidation, "the certificate authority does not offer %s for this name", o.Challenge)
	}
	switch o.Challenge {
	case "http-01":
		resp, err := cl.HTTP01ChallengeResponse(ch.Token)
		if err != nil {
			return fail(CodeIssue, "%v", err)
		}
		path := cl.HTTP01ChallengePath(ch.Token)
		sv.srv = &http.Server{ReadHeaderTimeout: 10 * time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Only the token's path is answered; anything else is 404 and nothing redirects.
			if r.URL.Path != path || r.Method != http.MethodGet {
				http.NotFound(w, r)
				return
			}
			w.Header().Set("Content-Type", "text/plain")
			_, _ = w.Write([]byte(resp))
		})}
		go func() { _ = sv.srv.Serve(sv.ln) }()
	case "tls-alpn-01":
		cert, err := cl.TLSALPN01ChallengeCert(ch.Token, o.Name)
		if err != nil {
			return fail(CodeIssue, "%v", err)
		}
		cfg := &tls.Config{NextProtos: []string{"acme-tls/1"}, MinVersion: tls.VersionTLS12, GetCertificate: func(h *tls.ClientHelloInfo) (*tls.Certificate, error) {
			if len(h.SupportedProtos) == 1 && h.SupportedProtos[0] == "acme-tls/1" {
				return &cert, nil
			}
			return nil, errors.New("only the validation handshake is served")
		}}
		tl := tls.NewListener(sv.ln, cfg)
		sv.srv = &http.Server{ReadHeaderTimeout: 10 * time.Second, Handler: http.NotFoundHandler(), TLSConfig: cfg}
		go func() { _ = sv.srv.Serve(tl) }()
	}
	if _, err := cl.Accept(ctx, ch); err != nil {
		return classify(err, CodeValidation)
	}
	if _, err := cl.WaitAuthorization(ctx, authzURL); err != nil {
		return classify(err, CodeValidation)
	}
	return nil
}

// State is what the last issuance or renewal left for the console to show; it holds no key and no e-mail address.
type State struct {
	Name        string    `json:"name"`
	Staging     bool      `json:"staging"`
	Challenge   string    `json:"challenge"`
	LastAttempt time.Time `json:"last_attempt"`
	LastResult  string    `json:"last_result"`
	LastDetail  string    `json:"last_detail,omitempty"`
	// StagingOKName and StagingOKAt record the last successful rehearsal against the staging service: production is only tried for a name that passed it.
	StagingOKName string    `json:"staging_ok_name,omitempty"`
	StagingOKAt   time.Time `json:"staging_ok_at,omitempty"`
}

func (s Store) statePath() string { return filepath.Join(s.Dir, "state.json") }

// WriteState records an attempt.
func (s Store) WriteState(st State) error {
	b, _ := json.MarshalIndent(st, "", "  ")
	return writeAtomic(s.statePath(), append(b, '\n'), 0o644)
}

// ReadState returns the last recorded attempt; ok is false when there has been none.
func (s Store) ReadState() (st State, ok bool) {
	b, err := os.ReadFile(s.statePath())
	if err != nil || json.Unmarshal(b, &st) != nil {
		return State{}, false
	}
	return st, true
}

// noRetry429 turns a 429 into a 400 with the same body, so the client reports the problem (urn:ietf:params:acme:error:rateLimited) instead of retrying.
type noRetry429 struct{ next http.RoundTripper }

func (t noRetry429) RoundTrip(r *http.Request) (*http.Response, error) {
	next := t.next
	if next == nil {
		next = http.DefaultTransport
	}
	res, err := next.RoundTrip(r)
	if err == nil && res.StatusCode == http.StatusTooManyRequests {
		res.StatusCode, res.Status = http.StatusBadRequest, "400 Bad Request"
	}
	return res, err
}
