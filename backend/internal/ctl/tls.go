package ctl

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"time"

	"example.invalid/dedicatedcloud/backend/internal/tlsacme"
)

// Certificates from Let's Encrypt (DR-034). Issuance and renewal run here, as root, from a command and a daily timer: the API cannot bind port 80 or 443 and
// cannot write /etc/svavyom/tls, and no new daemon is added.
const (
	TLSRenewService = "svavyom-tls-renew.service"
	TLSRenewTimer   = "svavyom-tls-renew.timer"
	// stagingValid is how long a successful rehearsal allows the production service to be asked.
	stagingValid = 30 * 24 * time.Hour
)

func tlsRenewService() string {
	return `# Written by svavyom-ctl tls acme-issue. Development Preview.
[Unit]
Description=Renew the Svavyom console certificate when it is due
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=` + LibexecDir + `/svavyom-ctl tls acme-renew
User=root
TimeoutStartSec=10min
Nice=10
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
ProtectSystem=strict
ReadWritePaths=` + ConfigDir + `/tls
`
}

func tlsRenewTimer() string {
	return `# Written by svavyom-ctl tls acme-issue.
[Unit]
Description=Look daily whether the Svavyom console certificate is due for renewal

[Timer]
OnCalendar=daily
RandomizedDelaySec=1h
Persistent=true

[Install]
WantedBy=timers.target
`
}

// ACMEOptions of `tls acme-issue`.
type ACMEOptions struct {
	Name, Email    string
	Staging        bool
	AcceptTerms    bool
	Challenge      string
	SkipDNSCheck   bool
	NoStagingFirst bool
}

// ACMEDeps replaces the outside world in tests. The directory URLs are fixed in code: the zero value is the real thing.
type ACMEDeps struct {
	Directory  func(staging bool) string
	Resolve    func(ctx context.Context, name string) ([]net.IP, error)
	LocalAddrs func() ([]net.IP, error)
	Addr       string
}

func (d ACMEDeps) directory(staging bool) string {
	if d.Directory != nil {
		return d.Directory(staging)
	}
	if staging {
		return tlsacme.LetsEncryptStaging
	}
	return tlsacme.LetsEncrypt
}

func (e *Env) tlsStore() (tlsacme.Store, error) {
	_, apiG, err := e.Getpw("svavyom-api")
	if err != nil {
		return tlsacme.Store{}, errors.New("the account svavyom-api does not exist")
	}
	dir := e.P(ConfigDir + "/tls")
	if err := e.ensureDir(dir, 0o750, 0, apiG); err != nil {
		return tlsacme.Store{}, err
	}
	return tlsacme.Store{Dir: dir, Chown: func(p string) error { return e.Chown(p, 0, apiG) }}, nil
}

func (e *Env) acmeOptions(st tlsacme.Store, name, email, challenge string, skip bool, d ACMEDeps) tlsacme.Options {
	return tlsacme.Options{Name: name, Email: email, Challenge: challenge, AcceptTerms: true, Store: st, AccountKey: st.AccountKeyFile(), Addr: d.Addr,
		Resolve: d.Resolve, LocalAddrs: d.LocalAddrs, SkipDNSCheck: skip, Now: e.Now}
}

// record writes the outcome of an attempt for the console, keeping the rehearsal record.
func record(st tlsacme.Store, now time.Time, name string, staging bool, challenge string, err error) {
	s, _ := st.ReadState()
	s.Name, s.Staging, s.Challenge, s.LastAttempt, s.LastResult, s.LastDetail = name, staging, challenge, now.UTC(), "ok", ""
	if err != nil {
		var te *tlsacme.Error
		s.LastResult = tlsacme.CodeIssue
		if errors.As(err, &te) {
			s.LastResult, s.LastDetail = te.Code, te.Detail
		}
	} else if staging {
		s.StagingOKName, s.StagingOKAt = name, now.UTC()
	}
	_ = st.WriteState(s)
}

// ACMEIssue gets a certificate. With Staging it only rehearses against the staging service (nothing is installed); the production service is asked only for
// a name that passed the rehearsal in the last 30 days, because production has rate limits that a mistake can use up.
func (e *Env) ACMEIssue(ctx context.Context, o ACMEOptions, d ACMEDeps, w io.Writer) error {
	if o.Challenge == "" {
		o.Challenge = "http-01"
	}
	if err := tlsacme.CheckInput(o.Name, o.Email, o.AcceptTerms); err != nil {
		return err
	}
	st, err := e.tlsStore()
	if err != nil {
		return err
	}
	if !o.Staging && !o.NoStagingFirst {
		if s, ok := st.ReadState(); !ok || s.StagingOKName != o.Name || e.Now().Sub(s.StagingOKAt) > stagingValid {
			return &tlsacme.Error{Code: tlsacme.CodeStagingFirst, Detail: "run it once with --staging first (a rehearsal that installs nothing); production has rate limits"}
		}
	}
	opt := e.acmeOptions(st, o.Name, o.Email, o.Challenge, o.SkipDNSCheck, d)
	opt.Directory, opt.DryRun = d.directory(o.Staging), o.Staging
	_, _ = fmt.Fprintf(w, "asking %s for a certificate for %s (%s, port %s)\n", map[bool]string{true: "the Let's Encrypt STAGING service", false: "Let's Encrypt"}[o.Staging], o.Name, o.Challenge, map[string]string{"http-01": "80", "tls-alpn-01": "443"}[o.Challenge])
	in, err := tlsacme.Issue(ctx, opt)
	record(st, e.Now(), o.Name, o.Staging, o.Challenge, err)
	if err != nil {
		return err
	}
	if o.Staging {
		_, _ = fmt.Fprintf(w, "OK the staging service issued a certificate for %s (valid until %s). Nothing was installed. Run again without --staging.\n", o.Name, in.NotAfter.Format("2006-01-02"))
		return nil
	}
	if err := st.WriteConfig(tlsacme.Config{Name: o.Name, Email: o.Email, Challenge: o.Challenge, SkipDNSCheck: o.SkipDNSCheck}); err != nil {
		return err
	}
	if err := e.enableRenewTimer(ctx); err != nil {
		return err
	}
	_, _ = fmt.Fprintf(w, "OK the certificate for %s is installed (valid until %s, renewal from %s). The console picks it up within a minute, no restart.\n", o.Name, in.NotAfter.Format("2006-01-02"), tlsacme.RenewAt(in.NotBefore, in.NotAfter).Format("2006-01-02"))
	return nil
}

func (e *Env) enableRenewTimer(ctx context.Context) error {
	if err := e.ensureDir(e.P(UnitDir), 0o755, 0, 0); err != nil {
		return err
	}
	if _, err := e.writeAtomic(e.P(UnitDir+"/"+TLSRenewService), []byte(tlsRenewService()), 0o644, 0, 0); err != nil {
		return err
	}
	if _, err := e.writeAtomic(e.P(UnitDir+"/"+TLSRenewTimer), []byte(tlsRenewTimer()), 0o644, 0, 0); err != nil {
		return err
	}
	if out, err := e.Run.Run(ctx, "systemctl", "daemon-reload"); err != nil {
		return fmt.Errorf("systemctl daemon-reload: %s", clean(out))
	}
	if out, err := e.Run.Run(ctx, "systemctl", "enable", "--now", "--", TLSRenewTimer); err != nil {
		return fmt.Errorf("systemctl enable %s: %s", TLSRenewTimer, clean(out))
	}
	return nil
}

// ACMERenew is what the timer runs: renew when due, say so either way. A certificate that was not issued by this tool is left alone.
func (e *Env) ACMERenew(ctx context.Context, d ACMEDeps, w io.Writer) error {
	st, err := e.tlsStore()
	if err != nil {
		return err
	}
	cfg, ok := st.ReadConfig()
	if !ok {
		_, _ = fmt.Fprintln(w, "no Let's Encrypt certificate is managed here; nothing to renew")
		return nil
	}
	opt := e.acmeOptions(st, cfg.Name, cfg.Email, cfg.Challenge, cfg.SkipDNSCheck, d)
	opt.Directory = d.directory(false)
	renewed, in, err := tlsacme.Renew(ctx, opt)
	if err != nil {
		record(st, e.Now(), cfg.Name, false, cfg.Challenge, err)
		return err
	}
	if !renewed {
		_, _ = fmt.Fprintf(w, "the certificate for %s is valid until %s and not due for renewal until %s\n", cfg.Name, in.NotAfter.Format("2006-01-02"), tlsacme.RenewAt(in.NotBefore, in.NotAfter).Format("2006-01-02"))
		return nil
	}
	record(st, e.Now(), cfg.Name, false, cfg.Challenge, nil)
	_, _ = fmt.Fprintf(w, "OK renewed the certificate for %s (valid until %s)\n", cfg.Name, in.NotAfter.Format("2006-01-02"))
	return nil
}

// UseSelfSigned replaces the certificate with a new self-signed one, keeps the replaced pair in previous/, and stops the renewal timer.
func (e *Env) UseSelfSigned(ctx context.Context, host string, w io.Writer) error {
	if !hostNameRE.MatchString(host) && net.ParseIP(host) == nil {
		return errors.New("--name needs a host name or an address")
	}
	st, err := e.tlsStore()
	if err != nil {
		return err
	}
	certPEM, keyPEM, err := e.selfSignedPair(host)
	if err != nil {
		return err
	}
	if err := st.Install(certPEM, keyPEM, host); err != nil {
		return err
	}
	_ = st.RemoveConfig()
	if _, err := os.Lstat(e.P(UnitDir + "/" + TLSRenewTimer)); err == nil {
		_, _ = e.Run.Run(ctx, "systemctl", "disable", "--now", "--", TLSRenewTimer)
	}
	for _, u := range []string{TLSRenewTimer, TLSRenewService} {
		if err := removeIfExists(e.P(UnitDir + "/" + u)); err != nil {
			return err
		}
	}
	_, _ = e.Run.Run(ctx, "systemctl", "daemon-reload")
	record(st, e.Now(), host, false, "", nil)
	_, _ = fmt.Fprintf(w, "OK the console now uses a new self-signed certificate for %s; the previous one is in %s/tls/previous and the renewal timer is off. Browsers warn about a self-signed certificate.\n", host, ConfigDir)
	return nil
}
