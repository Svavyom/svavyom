package ctl

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const goodConfig = `{"catalog_dir":"/var/lib/svavyom/images","pool":"svavyom","network":"default","domain_type":"kvm","libvirt_uri":"qemu:///system","state_dir":"/var/lib/svavyom/state",
"trust":{"deploy_uid":0,"runtime_identities":[{"name":"api","uid":987,"gids":[987]},{"name":"agent","uid":986,"gids":[986]},{"name":"mutation","uid":985,"gids":[985,113]},{"name":"console","uid":984,"gids":[984,113]}]}}`

// installedHost is a host with a valid configuration and the directories it names, all under the temp root (the configuration names virtual paths; Env.P maps them).
func installedHost(t *testing.T, cfg string) *testHost {
	t.Helper()
	h := newHost(t)
	h.write("/etc/svavyom/provision.json", cfg)
	for _, d := range []string{"/var/lib/svavyom/images", "/var/lib/svavyom/state"} {
		if err := os.MkdirAll(h.root+d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	return h
}

func TestValidateConfigAcceptsAGoodInstallation(t *testing.T) {
	h := installedHost(t, goodConfig)
	r := ValidateConfig(context.Background(), h.env, ValidateOptions{})
	if r.Verdict != Pass {
		var b strings.Builder
		r.Text(&b)
		t.Fatalf("%s", b.String())
	}
	for _, id := range []string{"config-syntax", "catalog-dir", "state-dir", "service-ids"} {
		if find(r, id).Status != Pass {
			t.Errorf("%+v", find(r, id))
		}
	}
	if f := find(r, "image-catalog"); f.Status != Info || f.Code != "CATALOG_EMPTY" {
		t.Errorf("an empty catalog is information: %+v", f)
	}
}

func TestValidateConfigTypedFailures(t *testing.T) {
	cases := map[string]struct {
		cfg    string
		mut    func(h *testHost)
		id     string
		code   string
		status string
	}{
		"missing file":      {"", func(h *testHost) { _ = os.Remove(h.root + "/etc/svavyom/provision.json") }, "config-file", "CONFIG_MISSING", Fail},
		"not json":          {"{nope", nil, "config-syntax", "CONFIG_SYNTAX", Fail},
		"unknown key":       {strings.Replace(goodConfig, `"pool"`, `"extra":1,"pool"`, 1), nil, "config-syntax", "CONFIG_SYNTAX", Fail},
		"relative dir":      {strings.Replace(goodConfig, `"/var/lib/svavyom/images"`, `"images"`, 1), nil, "config-syntax", "CONFIG_INVALID", Fail},
		"no trust":          {`{"catalog_dir":"/var/lib/svavyom/images","pool":"p","network":"n","domain_type":"test","libvirt_uri":"test:///default","state_dir":"/var/lib/svavyom/state"}`, nil, "trust-declaration", "TRUST_MISSING", Fail},
		"state dir missing": {goodConfig, func(h *testHost) { _ = os.RemoveAll(h.root + "/var/lib/svavyom/state") }, "state-dir", "PATH_MISSING", Fail},
		"catalog is a file": {goodConfig, func(h *testHost) {
			_ = os.RemoveAll(h.root + "/var/lib/svavyom/images")
			h.write("/var/lib/svavyom/images", "x")
		}, "catalog-dir", "PATH_NOT_DIR", Fail},
		"catalog unreadable": {goodConfig, func(h *testHost) { h.write("/var/lib/svavyom/images/catalog.json", "{broken") }, "image-catalog", "CATALOG_INVALID", Fail},
		"backup dir missing": {strings.Replace(goodConfig, `"state_dir"`, `"backup_dir":"/var/lib/svavyom/bk","state_dir"`, 1), nil, "backup-dir", "BACKUP_DIR_MISSING", Fail},
	}
	for name, c := range cases {
		h := installedHost(t, goodConfig)
		if c.cfg != "" {
			h.write("/etc/svavyom/provision.json", c.cfg)
		}
		if c.mut != nil {
			c.mut(h)
		}
		r := ValidateConfig(context.Background(), h.env, ValidateOptions{})
		if f := find(r, c.id); f.Status != c.status || f.Code != c.code {
			t.Errorf("%s: %+v", name, f)
		}
		if r.Verdict != Fail || r.ExitCode() != 10 {
			t.Errorf("%s: verdict %s", name, r.Verdict)
		}
	}
}

func TestValidateConfigChecksTheServiceIdentities(t *testing.T) {
	h := installedHost(t, goodConfig)
	real := h.env.Getpw
	h.env.Getpw = func(n string) (int, int, error) {
		if n == "svavyom-mut" {
			return 0, 0, os.ErrNotExist
		}
		return real(n)
	}
	if f := find(ValidateConfig(context.Background(), h.env, ValidateOptions{}), "service-mutation"); f.Code != "SERVICE_USER_MISSING" || !strings.Contains(f.Remediation, "sysusers") {
		t.Fatalf("%+v", f)
	}
	h.env.Getpw = func(n string) (int, int, error) {
		if n == "svavyom-api" {
			return 999, 987, nil
		}
		return real(n)
	}
	if f := find(ValidateConfig(context.Background(), h.env, ValidateOptions{}), "service-api"); f.Code != "SERVICE_ID_MISMATCH" {
		t.Fatalf("a stale uid must be reported: %+v", f)
	}
	h.env.Getpw = func(n string) (int, int, error) {
		if n == "svavyom-ro" {
			return 0, 0, nil
		}
		return real(n)
	}
	if f := find(ValidateConfig(context.Background(), h.env, ValidateOptions{}), "service-agent"); f.Code != "SERVICE_USER_ROOT" {
		t.Fatalf("a service resolving to root must be refused: %+v", f)
	}
}

func TestValidateConfigListenerAndTLS(t *testing.T) {
	unit := func(listen string, tls bool) string {
		s := "[Service]\nExecStart=/usr/libexec/svavyom/api serve \\\n    --db /x \\\n    --listen " + listen + " \\\n"
		if tls {
			s += "    --tls-cert /etc/svavyom/tls/cert.pem --tls-key /etc/svavyom/tls/key.pem \\\n"
		}
		return s + "    --static-dir /usr/share/svavyom/web\n"
	}
	h := installedHost(t, goodConfig)
	h.write(UnitDir+"/svavyom-api.service", unit("127.0.0.1:8443", false))
	if f := find(ValidateConfig(context.Background(), h.env, ValidateOptions{}), "api-listener"); f.Status != Pass {
		t.Fatalf("a loopback listener needs no TLS: %+v", f)
	}
	h.write(UnitDir+"/svavyom-api.service", unit("0.0.0.0:8443", false))
	if f := find(ValidateConfig(context.Background(), h.env, ValidateOptions{}), "api-listener"); f.Code != "TLS_REQUIRED" || f.Status != Fail {
		t.Fatalf("a non-loopback listener without TLS must fail: %+v", f)
	}
	h.write(UnitDir+"/svavyom-api.service", unit("0.0.0.0:8443", true))
	if f := find(ValidateConfig(context.Background(), h.env, ValidateOptions{}), "api-tls"); f.Code != "TLS_FILE_MISSING" {
		t.Fatalf("missing files: %+v", f)
	}
	h.write("/etc/svavyom/tls/cert.pem", "c")
	h.write("/etc/svavyom/tls/key.pem", "k")
	if f := find(ValidateConfig(context.Background(), h.env, ValidateOptions{}), "api-listener"); f.Status != Pass {
		t.Fatalf("%+v", f)
	}
	h.write(UnitDir+"/svavyom-api.service", unit("nonsense", true))
	if f := find(ValidateConfig(context.Background(), h.env, ValidateOptions{}), "api-listener"); f.Code != "LISTEN_INVALID" {
		t.Fatalf("%+v", f)
	}
	// the validation output never contains the TLS key bytes
	h.write(UnitDir+"/svavyom-api.service", unit("0.0.0.0:8443", true))
	var b strings.Builder
	ValidateConfig(context.Background(), h.env, ValidateOptions{}).Text(&b)
	if strings.Contains(b.String(), "BEGIN") {
		t.Fatal("key material in the output")
	}
}

func TestValidateConfigOnlineAsksTheReadOnlyClients(t *testing.T) {
	h := installedHost(t, goodConfig)
	if r := ValidateConfig(context.Background(), h.env, ValidateOptions{Online: true}); find(r, "libvirt-network").Status != Pass || find(r, "libvirt-pool").Status != Pass || find(r, "agent-socket").Status != Pass {
		t.Fatal("online checks should pass on a healthy host")
	}
	h.run.reply["virsh -r -c qemu:///system pool-info"] = "Active: no\n"
	h.dialErr = os.ErrNotExist
	r := ValidateConfig(context.Background(), h.env, ValidateOptions{Online: true})
	if find(r, "libvirt-pool").Status != NotReady || find(r, "agent-socket").Code != "AGENT_UNREACHABLE" {
		t.Fatal("inactive pool and unreachable agent must be NOT_READY")
	}
	for _, c := range h.run.calls {
		if !strings.HasPrefix(c, "virsh -r ") {
			t.Errorf("validate-config ran %q", c)
		}
	}
}

func TestStatusReportsUnitsSocketsAndTheAPI(t *testing.T) {
	h := installedHost(t, goodConfig)
	if r := Status(context.Background(), h.env, StatusOptions{}); r.Verdict != NotReady || find(r, "installation").Code != "NOT_INSTALLED" {
		t.Fatalf("%+v", r)
	}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/healthz" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(`{"status":"scaffold"}`))
	}))
	defer ts.Close()
	_, port, _ := net.SplitHostPort(strings.TrimPrefix(ts.URL, "http://"))
	for _, u := range Units {
		body := "[Service]\nExecStart=/x\n"
		if u == "svavyom-api.service" {
			body = "[Service]\nExecStart=/usr/libexec/svavyom/api serve --listen 127.0.0.1:" + port + "\n"
		}
		h.write(UnitDir+"/"+u, body)
	}
	for _, s := range []string{"agent/agent.sock", "mutation/mutation.sock", "console/console.sock"} {
		h.write("/run/svavyom/"+s, "")
	}
	r := Status(context.Background(), h.env, StatusOptions{})
	if r.Verdict != Pass || find(r, "api-health").Status != Pass {
		var b strings.Builder
		r.Text(&b)
		t.Fatalf("%s", b.String())
	}
	h.run.reply["systemctl is-active -- svavyom-mutation.service"] = "failed\n"
	h.run.reply["systemctl is-active -- svavyom-console.service"] = "inactive\n"
	r = Status(context.Background(), h.env, StatusOptions{})
	if find(r, "svavyom-mutation.service").Code != "UNIT_FAILED" || find(r, "svavyom-console.service").Code != "UNIT_INACTIVE" || r.Verdict != Fail {
		t.Fatalf("%+v", r.Findings)
	}
	if f := find(r, "svavyom-mutation.service"); !strings.Contains(f.Remediation, "trust-layout") {
		t.Fatalf("a failed unit points at the journal and the likely cause: %+v", f)
	}
	ts.Close()
	r = Status(context.Background(), h.env, StatusOptions{})
	if find(r, "api-health").Code != "API_UNREACHABLE" {
		t.Fatalf("%+v", find(r, "api-health"))
	}
	_ = filepath.Join
}
