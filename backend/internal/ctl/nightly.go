package ctl

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"syscall"
	"time"

	"example.invalid/dedicatedcloud/backend/internal/nightly"
)

// The nightly real guest boot (DR-024 D4). svavyom-ctl runs it as root from a systemd timer; it goes through the API with a service account of the
// operator role, so everything it does is an ordinary, audited request, and the API never gains a way to start it.
const (
	NightlyStatusFile = LibDir + "/nightly-boot.json"
	NightlyCredFile   = ConfigDir + "/nightly-credential"
	NightlyUser       = "svavyom-nightly"
	NightlyService    = "svavyom-nightly-boot.service"
	NightlyTimer      = "svavyom-nightly-boot.timer"
	nightlyLock       = LibDir + "/nightly-boot.lock"
	apiDB             = LibDir + "/api/svavyom.db"
)

var hhmmRE = regexp.MustCompile(`^([01][0-9]|2[0-3]):[0-5][0-9]$`)

func nightlyService() string {
	return `# Written by svavyom-ctl install --enable-nightly-boot. Development Preview.
[Unit]
Description=Svavyom nightly real guest boot check (Development Preview)
After=svavyom-api.service libvirtd.service
Wants=svavyom-api.service

[Service]
Type=oneshot
ExecStart=` + LibexecDir + `/svavyom-ctl nightly-boot
User=root
TimeoutStartSec=45min
Nice=10
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
ProtectSystem=strict
ReadWritePaths=` + LibDir + `
`
}

func nightlyTimer(hhmm string) string {
	return `# Written by svavyom-ctl install --enable-nightly-boot.
[Unit]
Description=Run the Svavyom nightly guest boot check at ` + hhmm + `

[Timer]
OnCalendar=*-*-* ` + hhmm + `:00
Persistent=false
AccuracySec=1min

[Install]
WantedBy=timers.target
`
}

func randomPassword() (string, error) {
	var b [24]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

// StdinRunner is implemented by a Runner that can feed a command's standard input (the password of the service account travels that way, never on a command line).
type StdinRunner interface {
	RunStdin(ctx context.Context, stdin, name string, args ...string) (string, error)
}

func (r execRunner) RunStdin(ctx context.Context, stdin, name string, args ...string) (string, error) {
	cctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()
	cmd := exec.CommandContext(cctx, name, args...) // #nosec G204 -- fixed command names and arguments chosen by the callers in this file; no shell
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C"}
	cmd.Stdin = strings.NewReader(stdin)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// EnableNightlyBoot creates the service account and its credential if they do not exist, installs the service and the timer for hhmm, and starts the timer.
// Creating the account needs the API stopped for a moment (it owns the database); it is started again before this returns.
func (e *Env) EnableNightlyBoot(ctx context.Context, hhmm string, w io.Writer) error {
	if !hhmmRE.MatchString(hhmm) {
		return errors.New("--enable-nightly-boot needs a time of day written HH:MM, for example 02:30")
	}
	if _, err := e.ReadFile(e.P(NightlyCredFile)); err != nil {
		if err := e.createNightlyAccount(ctx, w); err != nil {
			return err
		}
	}
	if err := e.ensureDir(e.P(UnitDir), 0o755, 0, 0); err != nil {
		return err
	}
	if _, err := e.writeAtomic(e.P(UnitDir+"/"+NightlyService), []byte(nightlyService()), 0o644, 0, 0); err != nil {
		return err
	}
	if _, err := e.writeAtomic(e.P(UnitDir+"/"+NightlyTimer), []byte(nightlyTimer(hhmm)), 0o644, 0, 0); err != nil {
		return err
	}
	if out, err := e.Run.Run(ctx, "systemctl", "daemon-reload"); err != nil {
		return fmt.Errorf("systemctl daemon-reload: %s", clean(out))
	}
	if out, err := e.Run.Run(ctx, "systemctl", "enable", "--now", "--", NightlyTimer); err != nil {
		return fmt.Errorf("systemctl enable %s: %s", NightlyTimer, clean(out))
	}
	_, _ = fmt.Fprintf(w, "      the nightly boot check runs every day at %s (host time)\n", hhmm)
	return nil
}

// DisableNightlyBoot stops the timer and removes the two units. The service account and its credential stay (they are removed by a purge).
func (e *Env) DisableNightlyBoot(ctx context.Context) error {
	if _, err := os.Lstat(e.P(UnitDir + "/" + NightlyTimer)); err == nil {
		_, _ = e.Run.Run(ctx, "systemctl", "disable", "--now", "--", NightlyTimer)
	}
	for _, u := range []string{NightlyTimer, NightlyService} {
		if err := removeIfExists(e.P(UnitDir + "/" + u)); err != nil {
			return err
		}
	}
	_, _ = e.Run.Run(ctx, "systemctl", "daemon-reload")
	return nil
}

func (e *Env) createNightlyAccount(ctx context.Context, w io.Writer) (err error) {
	sr, ok := e.Run.(StdinRunner)
	if !ok {
		return errors.New("this runner cannot pass the password on standard input")
	}
	pw, err := randomPassword()
	if err != nil {
		return err
	}
	out, _ := e.Run.Run(ctx, "systemctl", "is-active", "--", "svavyom-api.service")
	wasActive := strings.TrimSpace(out) == "active"
	if wasActive {
		if out, err := e.Run.Run(ctx, "systemctl", "stop", "--", "svavyom-api.service"); err != nil {
			return fmt.Errorf("systemctl stop svavyom-api.service: %s", clean(out))
		}
		defer func() {
			if out, serr := e.Run.Run(ctx, "systemctl", "start", "--", "svavyom-api.service"); serr != nil && err == nil {
				err = fmt.Errorf("systemctl start svavyom-api.service: %s", clean(out))
			}
		}()
	}
	run := func(cmd string) error {
		_, err := sr.RunStdin(ctx, pw+"\n", "runuser", "-u", "svavyom-api", "--", e.P(LibexecDir+"/api"), cmd, "--db", e.P(apiDB), "--username", NightlyUser, "--role", "operator")
		return err
	}
	if run("user-add") != nil {
		// The account exists from an earlier install but its credential is gone: give it a new password and make sure it is an operator.
		if _, perr := sr.RunStdin(ctx, pw+"\n", "runuser", "-u", "svavyom-api", "--", e.P(LibexecDir+"/api"), "user-passwd", "--db", e.P(apiDB), "--username", NightlyUser); perr != nil {
			return errors.New("the nightly service account could not be created or updated (is the database initialised? run: api bootstrap-admin first)")
		}
		_, _ = e.Run.Run(ctx, "runuser", "-u", "svavyom-api", "--", e.P(LibexecDir+"/api"), "user-role", "--db", e.P(apiDB), "--username", NightlyUser, "--role", "operator")
	}
	if err := e.ensureDir(e.P(ConfigDir), 0o755, 0, 0); err != nil {
		return err
	}
	if _, err := e.writeAtomic(e.P(NightlyCredFile), []byte(NightlyUser+"\n"+pw+"\n"), 0o600, 0, 0); err != nil {
		return err
	}
	_, _ = fmt.Fprintf(w, "      created the operator account %s; its credential is in %s (root only)\n", NightlyUser, NightlyCredFile)
	return nil
}

// localAPI returns the loopback address of the installed API and, for https, the trust and server name of the installed certificate.
func (e *Env) localAPI() (base string, pool *x509.CertPool, serverName string, err error) {
	unit, rerr := e.ReadFile(e.P(UnitDir + "/svavyom-api.service"))
	if rerr != nil {
		return "", nil, "", errors.New("the API unit is not installed")
	}
	m := flagRE("listen").FindStringSubmatch(string(unit))
	if m == nil {
		return "", nil, "", errors.New("the API unit has no --listen")
	}
	_, port, perr := net.SplitHostPort(m[1])
	if perr != nil {
		return "", nil, "", errors.New("the API unit has an unusable --listen")
	}
	if !flagRE("tls-cert").MatchString(string(unit)) {
		return "http://127.0.0.1:" + port, nil, "", nil
	}
	pemBytes, rerr := e.ReadFile(e.P(ConfigDir + "/tls/cert.pem"))
	if rerr != nil {
		return "", nil, "", errors.New("the installed certificate could not be read")
	}
	blk, _ := pem.Decode(pemBytes)
	if blk == nil {
		return "", nil, "", errors.New("the installed certificate is not valid")
	}
	c, cerr := x509.ParseCertificate(blk.Bytes)
	if cerr != nil {
		return "", nil, "", errors.New("the installed certificate is not valid")
	}
	pool = x509.NewCertPool()
	pool.AddCert(c)
	switch {
	case len(c.DNSNames) > 0:
		serverName = c.DNSNames[0]
	case len(c.IPAddresses) > 0:
		serverName = c.IPAddresses[0].String()
	default:
		return "", nil, "", errors.New("the installed certificate names no host")
	}
	return "https://127.0.0.1:" + port, pool, serverName, nil
}

// NightlyDeps are replaceable in tests.
type NightlyDeps struct {
	// Runner overrides the real API client and prober.
	Runner *nightly.Runner
}

// NightlyBoot performs one night and records it. It returns the result; the caller turns a failed night into a non-zero exit status.
func NightlyBoot(ctx context.Context, e *Env, w io.Writer, d NightlyDeps) (nightly.Result, error) {
	if e.Euid() != 0 {
		return nightly.Result{}, errors.New("nightly-boot needs root (it is started by the systemd timer, or run it with sudo)")
	}
	if err := e.ensureDir(e.P(LibDir), 0o755, 0, 0); err != nil {
		return nightly.Result{}, err
	}
	lock, err := os.OpenFile(e.P(nightlyLock), os.O_CREATE|os.O_RDWR, 0o600) // #nosec G304 -- a fixed root-owned path
	if err != nil {
		return nightly.Result{}, err
	}
	defer func() { _ = lock.Close() }()
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil { // #nosec G115 -- fd fits int
		return nightly.Result{}, errors.New("another nightly boot check is running")
	}
	r := d.Runner
	if r == nil {
		cred, err := e.ReadFile(e.P(NightlyCredFile))
		if err != nil {
			return nightly.Result{}, errors.New("no credential for the nightly check: run svavyom-ctl install --enable-nightly-boot HH:MM")
		}
		lines := strings.Fields(string(cred))
		if len(lines) != 2 {
			return nightly.Result{}, errors.New("the nightly credential file is malformed")
		}
		base, pool, name, err := e.localAPI()
		if err != nil {
			return nightly.Result{}, err
		}
		c := &nightly.Client{Base: base, User: lines[0], Password: lines[1], RootCAs: pool, ServerName: name}
		r = &nightly.Runner{API: c, Prober: nightly.DialProber{}, Log: func(s string) { _, _ = fmt.Fprintln(w, "      "+s) }}
	}
	res := r.Run(ctx)
	hist, _ := nightly.Read(e.ReadFile, e.P(NightlyStatusFile)) // a damaged history starts over; it is evidence, not state
	hist.Add(res)
	if err := nightly.Write(e.P(NightlyStatusFile), hist); err != nil {
		return res, fmt.Errorf("the result could not be recorded: %w", err)
	}
	line := strings.ToUpper(res.Result) + " nightly boot"
	if res.Reason != "" {
		line += " (" + res.Reason + ")"
	}
	_, _ = fmt.Fprintf(w, "%s: %d seconds, %s\n", line, res.Seconds, res.At.Format(time.RFC3339))
	return res, nil
}
