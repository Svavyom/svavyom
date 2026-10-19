package ctl

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// StatusOptions are the inputs of the service health report.
type StatusOptions struct {
	// URL overrides the API health URL; by default it is derived from the installed API unit's --listen (the local address).
	URL string
}

// Status reports the health and readiness of an installation: the four units (active, enabled), the three internal sockets and the API's own /healthz.
// A unit that is not installed is INFO, one that is installed but inactive is NOT_READY, one that failed is FAIL. Read-only.
func Status(ctx context.Context, e *Env, o StatusOptions) Report {
	var list []Finding
	add := func(id, status, code, detail, remedy string) {
		list = append(list, Finding{ID: id, Status: status, Required: true, Code: code, Detail: clean(detail), Remediation: remedy})
	}
	installed := 0
	for _, u := range Units {
		if _, err := e.ReadFile(e.P(UnitDir + "/" + u)); err != nil {
			list = append(list, Finding{ID: u, Status: Info, Code: "UNIT_NOT_INSTALLED", Detail: "not installed"})
			continue
		}
		installed++
		out, _ := e.Run.Run(ctx, "systemctl", "is-active", "--", u)
		state := strings.TrimSpace(out)
		enabled, _ := e.Run.Run(ctx, "systemctl", "is-enabled", "--", u)
		en := strings.TrimSpace(enabled)
		switch state {
		case "active":
			add(u, Pass, "", "active, "+en, "")
		case "failed":
			add(u, Fail, "UNIT_FAILED", "failed; see: journalctl -u "+u+" -n 100 --no-pager", "Fix the cause shown in the journal (a trust-layout violation makes a service refuse to start), then systemctl restart "+u)
		default:
			add(u, NotReady, "UNIT_INACTIVE", state+", "+en, "systemctl start "+u)
		}
	}
	if installed == 0 {
		return NewReport("status", append(list, Finding{ID: "installation", Status: NotReady, Required: true, Code: "NOT_INSTALLED", Detail: "no Svavyom unit is installed", Remediation: "Run svavyom-ctl install."}))
	}
	for _, s := range []struct{ id, path string }{{"agent-socket", "/run/svavyom/agent/agent.sock"}, {"mutation-socket", "/run/svavyom/mutation/mutation.sock"}, {"console-socket", "/run/svavyom/console/console.sock"}, {"offsite-socket", "/run/svavyom/offsite/offsite.sock"}} {
		if _, err := e.ReadFile(e.P(UnitDir + "/" + map[string]string{"agent-socket": "svavyom-agent.service", "mutation-socket": "svavyom-mutation.service", "console-socket": "svavyom-console.service", "offsite-socket": "svavyom-offsite.service"}[s.id])); err != nil {
			continue
		}
		if err := e.Dial(e.P(s.path)); err != nil {
			// A socket is gated by its peer allowlist, so a refused connection by another user is expected: only a missing socket is a finding.
			if _, serr := e.Lstat(e.P(s.path)); serr != nil {
				add(s.id, NotReady, "SOCKET_MISSING", s.path+" does not exist", "systemctl start the owning unit.")
				continue
			}
		}
		add(s.id, Pass, "", s.path+" present", "")
	}
	// The API itself.
	base := o.URL
	if unit, err := e.ReadFile(e.P(UnitDir + "/svavyom-api.service")); err == nil && base == "" {
		if m := flagRE("listen").FindStringSubmatch(string(unit)); m != nil {
			if _, port, perr := net.SplitHostPort(m[1]); perr == nil {
				scheme := "http"
				if flagRE("tls-cert").MatchString(string(unit)) {
					scheme = "https"
				}
				base = fmt.Sprintf("%s://127.0.0.1:%s", scheme, port)
			}
		}
	}
	if base != "" {
		if code, detail := healthz(ctx, e, base); code == "" {
			add("api-health", Pass, "", detail, "")
		} else {
			add("api-health", NotReady, code, detail, "Check journalctl -u svavyom-api.")
		}
	}
	return NewReport("status", list)
}

// healthz asks GET /healthz. For https it trusts exactly the installed certificate (no verification bypass): the connection goes to the local address and
// the certificate's own first name is the server name.
func healthz(ctx context.Context, e *Env, base string) (code, detail string) {
	u, err := url.Parse(base)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
		return "HEALTH_URL", "unusable health URL"
	}
	tr := &http.Transport{DisableKeepAlives: true}
	if u.Scheme == "https" {
		pool := x509.NewCertPool()
		name := ""
		if pemBytes, rerr := e.ReadFile(e.P(ConfigDir + "/tls/cert.pem")); rerr == nil {
			if blk, _ := pem.Decode(pemBytes); blk != nil {
				if c, cerr := x509.ParseCertificate(blk.Bytes); cerr == nil {
					pool.AddCert(c)
					switch {
					case len(c.DNSNames) > 0:
						name = c.DNSNames[0]
					case len(c.IPAddresses) > 0:
						name = c.IPAddresses[0].String()
					}
				}
			}
		}
		tr.TLSClientConfig = &tls.Config{RootCAs: pool, ServerName: name, MinVersion: tls.VersionTLS12}
		addr := u.Host
		tr.DialContext = func(c context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(c, network, addr)
		}
		u.Host = net.JoinHostPort(name, u.Port())
		if name == "" {
			return "HEALTH_TLS", "the installed certificate could not be read"
		}
	}
	cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(cctx, http.MethodGet, u.String()+"/healthz", nil)
	if err != nil {
		return "HEALTH_URL", "unusable health URL"
	}
	res, err := (&http.Client{Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}).Do(req)
	if err != nil {
		return "API_UNREACHABLE", "the API does not answer on " + base
	}
	defer res.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(res.Body, 1<<16))
	if res.StatusCode != http.StatusOK {
		return "API_UNHEALTHY", fmt.Sprintf("/healthz returned %d", res.StatusCode)
	}
	return "", "GET /healthz = 200 on " + base
}
