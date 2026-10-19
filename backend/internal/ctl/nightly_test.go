package ctl

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"example.invalid/dedicatedcloud/backend/internal/nightly"
)

// fixedRunner is a nightly.Runner whose API is a script, so the glue (credential, status file, lock, exit status) is tested on its own.
type scriptAPI struct{ ready bool }

func (s scriptAPI) Host(context.Context) (nightly.HostState, error) {
	return nightly.HostState{CreationReady: s.ready, VCPUOptions: []int{1}, MemoryOptions: []int{512}, DiskOptions: []int{10}}, nil
}
func (scriptAPI) Images(context.Context) ([]nightly.Image, error) { return nil, nil }
func (scriptAPI) VMs(context.Context) ([]nightly.VM, error)       { return nil, nil }
func (scriptAPI) ActiveOperations(context.Context) (int, error)   { return 0, nil }
func (scriptAPI) Submit(context.Context, string, string, *nightly.CreateRequest) (string, error) {
	return "", os.ErrInvalid
}
func (scriptAPI) Wait(context.Context, string, time.Duration) (string, error) {
	return "", os.ErrInvalid
}

func TestEnableNightlyBootWritesTheUnitsTheAccountAndTheCredential(t *testing.T) {
	h := newHost(t)
	var w strings.Builder
	h.run.reply["systemctl is-active -- svavyom-api.service"] = "active\n"
	if err := h.env.EnableNightlyBoot(context.Background(), "02:30", &w); err != nil {
		t.Fatal(err)
	}
	timer, ok := h.read(UnitDir + "/" + NightlyTimer)
	if !ok || !strings.Contains(timer, "OnCalendar=*-*-* 02:30:00") || !strings.Contains(timer, "Persistent=false") || !strings.Contains(timer, "WantedBy=timers.target") {
		t.Fatalf("timer:\n%s", timer)
	}
	svc, ok := h.read(UnitDir + "/" + NightlyService)
	if !ok || !strings.Contains(svc, "ExecStart="+LibexecDir+"/svavyom-ctl nightly-boot") || !strings.Contains(svc, "Type=oneshot") || !strings.Contains(svc, "NoNewPrivileges=true") || strings.Contains(svc, "@") {
		t.Fatalf("service:\n%s", svc)
	}
	cred, ok := h.read(NightlyCredFile)
	f := strings.Fields(cred)
	if !ok || len(f) != 2 || f[0] != NightlyUser || len(f[1]) < 32 {
		t.Fatalf("credential %q", cred)
	}
	if fi, _ := os.Stat(filepath.Join(h.root, NightlyCredFile)); fi.Mode().Perm() != 0o600 {
		t.Fatalf("the credential is root-only: %v", fi.Mode())
	}
	if len(h.run.stdins) != 1 || strings.TrimSpace(h.run.stdins[0]) != f[1] {
		t.Fatalf("the password goes on standard input only: %v", h.run.stdins)
	}
	for _, c := range h.run.calls {
		if strings.Contains(c, f[1]) {
			t.Fatalf("the password appeared on a command line: %s", c)
		}
	}
	for _, want := range []string{"systemctl stop -- svavyom-api.service", "runuser -u svavyom-api -- ", "user-add", "--role operator", "systemctl start -- svavyom-api.service", "systemctl daemon-reload", "systemctl enable --now -- " + NightlyTimer} {
		if !strings.Contains(strings.Join(h.run.calls, "\n"), want) {
			t.Errorf("missing %q in\n%s", want, strings.Join(h.run.calls, "\n"))
		}
	}
	if strings.Index(strings.Join(h.run.calls, "\n"), "systemctl stop") > strings.Index(strings.Join(h.run.calls, "\n"), "user-add") ||
		strings.Index(strings.Join(h.run.calls, "\n"), "user-add") > strings.Index(strings.Join(h.run.calls, "\n"), "systemctl start -- svavyom-api") {
		t.Fatalf("the API is stopped while the account is made and started afterwards:\n%s", strings.Join(h.run.calls, "\n"))
	}
	// Idempotent: a second run keeps the credential and does not touch the database again.
	before := cred
	h.run.calls = nil
	if err := h.env.EnableNightlyBoot(context.Background(), "03:15", &w); err != nil {
		t.Fatal(err)
	}
	if after, _ := h.read(NightlyCredFile); after != before {
		t.Fatal("the credential must not change on a second run")
	}
	if strings.Contains(strings.Join(h.run.calls, "\n"), "user-add") || strings.Contains(strings.Join(h.run.calls, "\n"), "svavyom-api.service") {
		t.Fatalf("no account work the second time:\n%s", strings.Join(h.run.calls, "\n"))
	}
	if timer, _ := h.read(UnitDir + "/" + NightlyTimer); !strings.Contains(timer, "03:15:00") {
		t.Fatal("the time is updated")
	}
}

func TestEnableNightlyBootRefusesABadTimeAndKeepsAnExistingAccountWhenTheUserAddFails(t *testing.T) {
	h := newHost(t)
	var w strings.Builder
	for _, bad := range []string{"", "2:30", "24:00", "02:60", "02:30:00", "noon", "02:30; rm"} {
		if err := h.env.EnableNightlyBoot(context.Background(), bad, &w); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	if h.exists(UnitDir + "/" + NightlyTimer) {
		t.Fatal("nothing may be written for a bad time")
	}
	// user-add fails (the account exists): the password is set again and the role is made sure of.
	h.run.fail["runuser -u svavyom-api -- "+h.env.P(LibexecDir+"/api")+" user-add"] = true
	if err := h.env.EnableNightlyBoot(context.Background(), "02:30", &w); err != nil {
		t.Fatal(err)
	}
	calls := strings.Join(h.run.calls, "\n")
	if !strings.Contains(calls, "user-passwd") || !strings.Contains(calls, "user-role") {
		t.Fatalf("%s", calls)
	}
	// both fail: an honest error and no credential file that would not work
	h2 := newHost(t)
	h2.run.fail["runuser"] = true
	if err := h2.env.EnableNightlyBoot(context.Background(), "02:30", &w); err == nil || h2.exists(NightlyCredFile) {
		t.Fatalf("err %v, credential written %v", err, h2.exists(NightlyCredFile))
	}
}

func TestInstallValidatesTheNightlyOptions(t *testing.T) {
	for o, ok := range map[InstallOptions]bool{
		{}: true, {EnableNightlyBoot: "02:30"}: true, {DisableNightlyBoot: true}: true,
		{EnableNightlyBoot: "25:00"}: false, {EnableNightlyBoot: "02:30", DisableNightlyBoot: true}: false,
	} {
		o.defaults()
		if err := o.validate(); (err == nil) != ok {
			t.Errorf("%+v: %v", o, err)
		}
	}
}

func TestDisableNightlyBootRemovesTheUnitsButKeepsTheAccount(t *testing.T) {
	h := newHost(t)
	var w strings.Builder
	if err := h.env.EnableNightlyBoot(context.Background(), "02:30", &w); err != nil {
		t.Fatal(err)
	}
	if err := h.env.DisableNightlyBoot(context.Background()); err != nil {
		t.Fatal(err)
	}
	if h.exists(UnitDir+"/"+NightlyTimer) || h.exists(UnitDir+"/"+NightlyService) || !h.exists(NightlyCredFile) {
		t.Fatal("units gone, credential kept")
	}
	if h.run.called("systemctl disable --now -- "+NightlyTimer) != 1 {
		t.Fatal("the timer is stopped first")
	}
	if err := h.env.DisableNightlyBoot(context.Background()); err != nil {
		t.Fatalf("disabling twice is success: %v", err)
	}
}

func TestNightlyBootRecordsEveryNightAndNeedsRoot(t *testing.T) {
	h := newHost(t)
	var w strings.Builder
	r := &nightly.Runner{API: scriptAPI{ready: false}, Prober: nightly.DialProber{}, Now: func() time.Time { return h.now }}
	res, err := NightlyBoot(context.Background(), h.env, &w, NightlyDeps{Runner: r})
	if err != nil || res.Result != nightly.Skipped || res.Reason != nightly.ReasonNotReady {
		t.Fatalf("%+v %v", res, err)
	}
	for i := 0; i < 35; i++ {
		h.now = h.now.Add(24 * time.Hour)
		if _, err := NightlyBoot(context.Background(), h.env, &w, NightlyDeps{Runner: r}); err != nil {
			t.Fatal(err)
		}
	}
	hist, ok := nightly.Read(os.ReadFile, filepath.Join(h.root, NightlyStatusFile))
	if !ok || len(hist.Runs) != nightly.MaxHistory {
		t.Fatalf("history %d ok %v", len(hist.Runs), ok)
	}
	if !strings.Contains(w.String(), "SKIPPED nightly boot (creation_not_ready)") {
		t.Fatalf("%s", w.String())
	}
	failing := &nightly.Runner{API: scriptAPI{ready: true}, Prober: nightly.DialProber{}, Now: func() time.Time { return h.now }}
	res, err = NightlyBoot(context.Background(), h.env, &w, NightlyDeps{Runner: failing})
	if err != nil || res.Result != nightly.Skipped { // no qualified image in the script: skipped, not failed
		t.Fatalf("%+v %v", res, err)
	}
	h.env.Euid = func() int { return 1000 }
	if _, err := NightlyBoot(context.Background(), h.env, &w, NightlyDeps{Runner: r}); err == nil {
		t.Fatal("not root")
	}
	h.env.Euid = func() int { return 0 }
	if _, err := NightlyBoot(context.Background(), h.env, &w, NightlyDeps{}); err == nil || !strings.Contains(err.Error(), "enable-nightly-boot") {
		t.Fatalf("no credential: %v", err)
	}
}

func TestLocalAPIDerivesLoopbackFromTheInstalledUnit(t *testing.T) {
	h := newHost(t)
	h.write(UnitDir+"/svavyom-api.service", "[Service]\nExecStart=/usr/libexec/svavyom/api serve --listen 127.0.0.1:8443 --db x\n")
	base, pool, name, err := h.env.localAPI()
	if err != nil || base != "http://127.0.0.1:8443" || pool != nil || name != "" {
		t.Fatalf("%q %v %q %v", base, pool, name, err)
	}
	h.write(UnitDir+"/svavyom-api.service", "[Service]\nExecStart=/usr/libexec/svavyom/api serve --listen 0.0.0.0:9443 --tls-cert /etc/svavyom/tls/cert.pem --tls-key /etc/svavyom/tls/key.pem\n")
	if _, _, _, err := h.env.localAPI(); err == nil {
		t.Fatal("https without a readable certificate must be an error, not a bypass")
	}
	if err := h.env.selfSignedTLS("svavyom.lab"); err != nil {
		t.Fatal(err)
	}
	base, pool, name, err = h.env.localAPI()
	if err != nil || base != "https://127.0.0.1:9443" || pool == nil || name != "svavyom.lab" {
		t.Fatalf("%q %v %q %v", base, pool, name, err)
	}
	os.Remove(filepath.Join(h.root, UnitDir, "svavyom-api.service"))
	if _, _, _, err := h.env.localAPI(); err == nil {
		t.Fatal("no unit")
	}
}
