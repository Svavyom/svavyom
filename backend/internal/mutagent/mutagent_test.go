package mutagent

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"example.invalid/dedicatedcloud/backend/internal/hypervisor"
	"example.invalid/dedicatedcloud/backend/internal/provision"
	"example.invalid/dedicatedcloud/backend/internal/provision/provtest"
	"example.invalid/dedicatedcloud/backend/internal/simhost"
)

var (
	buildOnce sync.Once
	helperBin string
	buildErr  error
)

// simHelper builds the TEST-ONLY simulated helper once per test binary.
func simHelper(t *testing.T) string {
	t.Helper()
	buildOnce.Do(func() {
		dir, err := os.MkdirTemp("", "mutagent-helper")
		if err != nil {
			buildErr = err
			return
		}
		helperBin = filepath.Join(dir, "mutation-helper-sim")
		out, err := exec.Command("go", "build", "-o", helperBin, "example.invalid/dedicatedcloud/backend/cmd/mutation-helper-sim").CombinedOutput() // #nosec G204
		if err != nil {
			buildErr = &buildFailure{string(out)}
		}
	})
	if buildErr != nil {
		t.Fatalf("cannot build the simulated helper: %v", buildErr)
	}
	return helperBin
}

type buildFailure struct{ out string }

func (b *buildFailure) Error() string { return b.out }

type rig struct {
	t       *testing.T
	cfg     provision.Config
	cfgPath string
	sim     *simhost.Host
	sup     *Supervisor
	sock    string
	client  *Client
	spec    provision.Spec
	done    chan error
}

func newRig(t *testing.T, deadline time.Duration, helper string) *rig {
	t.Helper()
	root, err := os.MkdirTemp("", "mt")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	catDir, state := filepath.Join(root, "images"), filepath.Join(root, "state")
	for _, d := range []string{catDir, state} {
		_ = os.MkdirAll(d, 0o750)
	}
	src := filepath.Join(root, "debian.qcow2")
	_ = os.WriteFile(src, provtest.Qcow2("image body"), 0o640)
	im, err := provision.Register(provision.DevPolicy(), catDir, provision.RegisterRequest{ID: "debian-13", DisplayName: "Debian 13", Distribution: "Debian", Version: "13", Source: src, LoginUser: "debian", MinDiskGiB: 3, CloudInit: true})
	if err != nil {
		t.Fatal(err)
	}
	cfg := provision.Config{CatalogDir: catDir, Pool: "svavyom", Network: "svavyom-nat", DomainType: "test", LibvirtURI: "test:///default", StateDir: state}
	cb, _ := json.Marshal(cfg)
	cfgPath := filepath.Join(root, "provision.json")
	_ = os.WriteFile(cfgPath, cb, 0o600)
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	sp, _ := ssh.NewPublicKey(pub)
	key, _ := provision.NormalizeSSHKey(string(ssh.MarshalAuthorizedKey(sp)))
	sim, _ := simhost.New(filepath.Join(state, "sim"))
	if helper == "" {
		helper = simHelper(t)
	}
	sock := filepath.Join(root, "m.sock")
	sup, err := Listen(SupervisorConfig{Trust: provision.DevPolicy(), Socket: sock, AllowUIDs: []uint32{uint32(os.Getuid())}, HelperPath: helper, // #nosec G115
		HelperArgs: []string{"--config", cfgPath, "--insecure-dev-single-identity"}, TrustedFiles: []string{cfgPath}, Env: []string{"SVAVYOM_SIM_HOST=1", "LANG=C"}, Deadline: deadline})
	if err != nil {
		t.Fatal(err)
	}
	r := &rig{t: t, cfg: cfg, cfgPath: cfgPath, sim: sim, sup: sup, sock: sock, done: make(chan error, 1),
		spec: provision.Spec{Name: "web-1", UUID: "1a1a1a1a-2222-4333-8444-5555555555ab", Fingerprint: strings.Repeat("ab", 32), VCPUs: 2, MemoryMiB: 1024,
			ImageID: "debian-13", ImageSHA256: im.SHA256, DiskGiB: 20, SSHPublicKey: key.Authorized, Network: "svavyom-nat"}}
	go func() { r.done <- sup.Serve() }()
	t.Cleanup(func() { r.sup.Close(); <-r.done })
	r.client, _ = NewClient(sock, deadline+10*time.Second)
	return r
}

func (r *rig) fault(f string) {
	if err := os.WriteFile(filepath.Join(r.cfg.StateDir, "sim-fault.json"), []byte(f), 0o600); err != nil {
		r.t.Fatal(err)
	}
}

func cat(err error) hypervisor.Category { return hypervisor.CategoryOf(err) }

func TestPreflightProvisionAndStartThroughTheSupervisor(t *testing.T) {
	r := newRig(t, 20*time.Second, "")
	ctx := context.Background()
	rd, err := r.client.Preflight(ctx)
	if err != nil || rd.Network != "available" || rd.Pool != "available" {
		t.Fatalf("%+v %v", rd, err)
	}
	if err := r.client.Provision(ctx, r.spec); err != nil {
		t.Fatal(err)
	}
	if d := r.sim.Load().Domains["web-1"]; !d.Managed || d.Running {
		t.Fatalf("%+v", d)
	}
	if err := r.client.Start(ctx, "web-1"); err != nil {
		t.Fatal(err)
	}
	if d := r.sim.Load().Domains["web-1"]; !d.Running || d.IP == "" {
		t.Fatalf("%+v", d)
	}
	// Failures come back as categories only.
	other := r.spec
	other.UUID = "2a1a1a1a-2222-4333-8444-5555555555ab"
	other.Fingerprint = strings.Repeat("cd", 32)
	if err := r.client.Provision(ctx, other); cat(err) != hypervisor.Conflict {
		t.Fatalf("same-name foreign create: %v", err)
	}
	if err := r.client.Start(ctx, "ghost"); cat(err) != hypervisor.NotFound {
		t.Fatalf("%v", err)
	}
	st := r.sim.Load()
	st.NetworkDown = true
	_ = r.sim.Save(st)
	if rd, _ := r.client.Preflight(ctx); rd.Network != "unavailable" {
		t.Fatalf("%+v", rd)
	}
}

func TestHostAdapterOffersOnlyCreateAndStart(t *testing.T) {
	r := newRig(t, 20*time.Second, "")
	h := &Host{Reader: simhost.Reader{H: r.sim}, Mut: r.client}
	ctx := context.Background()
	ds := hypervisor.DomainSpec{Name: r.spec.Name, VCPUs: r.spec.VCPUs, MemoryMiB: r.spec.MemoryMiB, UUID: r.spec.UUID, Fingerprint: r.spec.Fingerprint,
		ImageID: r.spec.ImageID, ImageSHA256: r.spec.ImageSHA256, DiskGiB: r.spec.DiskGiB, SSHPublicKey: r.spec.SSHPublicKey, Network: r.spec.Network}
	d, err := h.Define(ctx, ds)
	if err != nil || d.State != hypervisor.StateShutoff || !d.Managed {
		t.Fatalf("%+v %v", d, err)
	}
	if got, err := h.Lookup(ctx, "web-1"); err != nil || got.UUID != r.spec.UUID || got.Fingerprint != r.spec.Fingerprint || !got.Managed {
		t.Fatalf("%+v %v", got, err)
	}
	if err := h.Start(ctx, "web-1"); err != nil {
		t.Fatal(err)
	}
	if err := h.Undefine(ctx, "web-1"); cat(err) != hypervisor.Conflict {
		t.Fatalf("delete of a running VM must be a conflict: %v", err)
	}
	if !r.sim.Load().Domains["web-1"].Running || len(r.sim.Load().Domains) != 1 || len(r.sim.Load().Volumes) != 2 {
		t.Fatal("a refused delete changed the host")
	}
	if err := h.Reboot(ctx, "web-1"); err != nil || r.sim.Load().Domains["web-1"].Reboots != 1 {
		t.Fatalf("reboot: %v", err)
	}
	if err := h.Stop(ctx, "web-1"); err != nil || r.sim.Load().Domains["web-1"].Running {
		t.Fatalf("stop: %v", err)
	}
	if err := h.Reboot(ctx, "web-1"); cat(err) != hypervisor.Conflict {
		t.Fatalf("reboot of a stopped VM: %v", err)
	}
	if err := h.Destroy(ctx, "web-1"); err != nil {
		t.Fatalf("force off of a stopped VM is a no-op: %v", err)
	}
	if err := h.Undefine(ctx, "web-1"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if st := r.sim.Load(); len(st.Domains) != 0 || len(st.Volumes) != 0 {
		t.Fatalf("delete must remove the domain and exactly its two volumes: %+v", st)
	}
	if _, err := h.Define(ctx, hypervisor.DomainSpec{Name: "vm-x", VCPUs: 1, MemoryMiB: 512}); cat(err) != hypervisor.Validation {
		t.Fatalf("the minimal simulation definition must be refused: %v", err)
	}
}

func TestHelperKilledAfterEachStepIsAnUnknownOutcomeAndTheRetryResumes(t *testing.T) {
	for _, step := range []string{"begin", "image-verified", "preflight", "root-volume", "seed-volume", "domain-defined"} {
		t.Run(step, func(t *testing.T) {
			r := newRig(t, 20*time.Second, "")
			r.fault(`{"kill_after":"` + step + `"}`)
			err := r.client.Provision(context.Background(), r.spec)
			if cat(err) != hypervisor.Timeout {
				t.Fatalf("a killed helper proves nothing: want timeout (unknown), got %v", err)
			}
			if err := r.client.Provision(context.Background(), r.spec); err != nil { // reconciliation would observe; the retry must also be safe
				t.Fatalf("resume: %v", err)
			}
			st := r.sim.Load()
			if len(st.Domains) != 1 || len(st.Volumes) != 2 || !st.Domains["web-1"].Managed {
				t.Fatalf("%d domains %d volumes", len(st.Domains), len(st.Volumes))
			}
		})
	}
}

func TestHelperKilledAfterStartIsUnknownButTheVMIsRunning(t *testing.T) {
	r := newRig(t, 20*time.Second, "")
	if err := r.client.Provision(context.Background(), r.spec); err != nil {
		t.Fatal(err)
	}
	r.fault(`{"kill_after":"started"}`)
	if err := r.client.Start(context.Background(), "web-1"); cat(err) != hypervisor.Timeout {
		t.Fatalf("%v", err)
	}
	if !r.sim.Load().Domains["web-1"].Running {
		t.Fatal("the action had been applied: only observation can tell")
	}
	if err := r.client.Start(context.Background(), "web-1"); err != nil {
		t.Fatalf("start is idempotent: %v", err)
	}
}

func helperAlive(path string) bool {
	entries, _ := os.ReadDir("/proc")
	for _, e := range entries {
		b, err := os.ReadFile("/proc/" + e.Name() + "/cmdline")
		if err == nil && strings.HasPrefix(string(b), path) {
			return true
		}
	}
	return false
}

func TestAHungHelperIsKilledAndReapedAtTheDeadline(t *testing.T) {
	r := newRig(t, 2*time.Second, "")
	r.fault(`{"hang_after":"root-volume"}`)
	start := time.Now()
	err := r.client.Provision(context.Background(), r.spec)
	took := time.Since(start)
	if cat(err) != hypervisor.Timeout || took < 2*time.Second || took > 8*time.Second {
		t.Fatalf("%v after %v", err, took)
	}
	time.Sleep(200 * time.Millisecond)
	if helperAlive(simHelper(t)) {
		t.Fatal("the hung helper is still running")
	}
	if err := r.client.Provision(context.Background(), r.spec); err != nil {
		t.Fatalf("after the kill the next request must work: %v", err)
	}
}

func TestUnreachableSupervisorIsUnavailableNotUnknown(t *testing.T) {
	c, _ := NewClient(filepath.Join(os.TempDir(), "no-such-supervisor.sock"), time.Second)
	if err := c.Start(context.Background(), "web-1"); cat(err) != hypervisor.Unavailable {
		t.Fatalf("%v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r := newRig(t, 5*time.Second, "")
	if err := r.client.Start(ctx, "web-1"); cat(err) != hypervisor.Unavailable {
		t.Fatalf("a request cancelled before sending was not delivered: %v", err)
	}
}

func frame(body string) []byte {
	b := make([]byte, 4+len(body))
	binary.BigEndian.PutUint32(b, uint32(len(body)))
	copy(b[4:], body)
	return b
}

func TestMalformedAndForbiddenRequestsNeverReachAHelper(t *testing.T) {
	r := newRig(t, 5*time.Second, "")
	good, _ := json.Marshal(Request{V: 1, Op: OpProvision, Provision: &r.spec})
	badSpec := r.spec
	badSpec.Name = "a'/><x"
	bad, _ := json.Marshal(Request{V: 1, Op: OpProvision, Provision: &badSpec})
	cases := map[string][]byte{
		"not json": frame("{nope"), "empty": frame("{}"), "version": frame(`{"v":2,"op":"preflight"}`),
		"stop bad name": frame(`{"v":1,"op":"stop","name":"../x"}`), "stop with provision": frame(`{"v":1,"op":"stop","name":"web-1","provision":{}}`), "destroy": frame(`{"v":1,"op":"destroy","name":"web-1"}`),
		"undefine": frame(`{"v":1,"op":"undefine","name":"web-1"}`), "define raw xml": frame(`{"v":1,"op":"define","xml":"<domain/>"}`),
		"reboot no name": frame(`{"v":1,"op":"reboot"}`), "delete bad name": frame(`{"v":1,"op":"delete","name":"a/b"}`),
		"force_off bad name": frame(`{"v":1,"op":"force_off","name":"X"}`), "restart": frame(`{"v":1,"op":"restart","name":"web-1"}`),
		"unknown field": frame(`{"v":1,"op":"preflight","path":"/etc/passwd"}`), "preflight with name": frame(`{"v":1,"op":"preflight","name":"x"}`),
		"start bad name": frame(`{"v":1,"op":"start","name":"../x"}`), "start with provision": frame(`{"v":1,"op":"start","name":"web-1","provision":{}}`),
		"provision bad spec": frame(string(bad)), "provision with name": frame(strings.Replace(string(good), `"op":"provision"`, `"op":"provision","name":"web-1"`, 1)),
		"trailing data": frame(`{"v":1,"op":"preflight"}{"v":1,"op":"preflight"}`), "zero length": {0, 0, 0, 0}, "oversize": append([]byte{0, 0, 0xff, 0xff}, make([]byte, 64)...),
	}
	for name, b := range cases {
		c, err := net.Dial("unix", r.sock)
		if err != nil {
			t.Fatal(err)
		}
		_ = c.SetDeadline(time.Now().Add(3 * time.Second))
		_, _ = c.Write(b)
		var rep Reply
		if err := readFrame(c, &rep, MaxReplyBytes); err == nil && (rep.OK || rep.Category != string(hypervisor.Validation)) {
			t.Errorf("%s: reply %+v", name, rep)
		}
		_ = c.Close()
	}
	st := r.sim.Load()
	if len(st.Domains) != 0 || len(st.Volumes) != 0 {
		t.Fatalf("a refused request changed the host: %+v", st)
	}
}

func TestSocketIsUnixOnlyAndPeerUIDAllowlistIsEnforced(t *testing.T) {
	r := newRig(t, 5*time.Second, "")
	if r.sup.ln.Addr().Network() != "unix" {
		t.Fatalf("network %q", r.sup.ln.Addr().Network())
	}
	fi, err := os.Stat(r.sock)
	if err != nil || fi.Mode().Perm() != 0o660 || fi.Mode()&os.ModeSocket == 0 {
		t.Fatalf("%v %v", fi.Mode(), err)
	}
	other := newRigWithUID(t, uint32(os.Getuid())+4242) // #nosec G115
	if err := other.client.Start(context.Background(), "web-1"); cat(err) != hypervisor.Timeout && cat(err) != hypervisor.Unavailable {
		t.Fatalf("a peer outside the allowlist was served: %v", err)
	}
	if other.sim.Load().Domains["web-1"].Running {
		t.Fatal("unauthorised start executed")
	}
}

func newRigWithUID(t *testing.T, uid uint32) *rig {
	r := newRig(t, 5*time.Second, "")
	r.sup.Close()
	<-r.done
	sup, err := Listen(SupervisorConfig{Trust: provision.DevPolicy(), Socket: r.sock, AllowUIDs: []uint32{uid}, HelperPath: simHelper(t), HelperArgs: []string{"--config", r.cfgPath, "--insecure-dev-single-identity"},
		Env: []string{"SVAVYOM_SIM_HOST=1"}, Deadline: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	r.sup = sup
	r.done = make(chan error, 1)
	go func() { r.done <- sup.Serve() }()
	return r
}

func TestListenRefusesUnsafeConfiguration(t *testing.T) {
	dir := t.TempDir()
	helper := simHelper(t)
	ok := SupervisorConfig{Trust: provision.DevPolicy(), Socket: filepath.Join(dir, "s.sock"), AllowUIDs: []uint32{1000}, HelperPath: helper}
	notExec := filepath.Join(dir, "plain")
	_ = os.WriteFile(notExec, []byte("x"), 0o644)
	worldWritable := filepath.Join(dir, "ww")
	_ = os.WriteFile(worldWritable, []byte("#!/bin/sh\n"), 0o777)
	_ = os.Chmod(worldWritable, 0o777)
	file := filepath.Join(dir, "afile")
	_ = os.WriteFile(file, []byte("precious"), 0o600)
	for name, mut := range map[string]func(*SupervisorConfig){
		"relative socket": func(c *SupervisorConfig) { c.Socket = "s.sock" }, "unclean socket": func(c *SupervisorConfig) { c.Socket = dir + "//s.sock" },
		"long socket": func(c *SupervisorConfig) { c.Socket = "/" + strings.Repeat("a", 101) }, "no uids": func(c *SupervisorConfig) { c.AllowUIDs = nil },
		"relative helper": func(c *SupervisorConfig) { c.HelperPath = "mutation-helper-sim" }, "helper missing": func(c *SupervisorConfig) { c.HelperPath = filepath.Join(dir, "none") },
		"helper not executable": func(c *SupervisorConfig) { c.HelperPath = notExec }, "helper world writable": func(c *SupervisorConfig) { c.HelperPath = worldWritable },
		"helper is a directory": func(c *SupervisorConfig) { c.HelperPath = dir }, "socket over a file": func(c *SupervisorConfig) { c.Socket = file },
	} {
		c := ok
		mut(&c)
		if s, err := Listen(c); err == nil {
			s.Close()
			t.Errorf("%s accepted", name)
		}
	}
	if b, _ := os.ReadFile(file); string(b) != "precious" {
		t.Fatal("a regular file was replaced")
	}
	live, err := Listen(ok)
	if err != nil {
		t.Fatal(err)
	}
	defer live.Close()
	if s, err := Listen(ok); err == nil {
		s.Close()
		t.Fatal("a second supervisor displaced a live one")
	}
}

// A scripted helper stands in for arbitrary helper behaviour: what it receives and what it may do to the verdict.
func scriptHelper(t *testing.T, body string) string {
	p := filepath.Join(t.TempDir(), "helper.sh")
	if err := os.WriteFile(p, []byte("#!/bin/sh\n"+body), 0o755); err != nil { // #nosec G306
		t.Fatal(err)
	}
	return p
}

func TestHelperIsExecWithFixedArgvEnvAndRequestOnStdinOnly(t *testing.T) {
	out := filepath.Join(t.TempDir(), "seen")
	h := scriptHelper(t, `{ echo "ARGV:$*"; env | sort | grep -v '^_=' | grep -v '^PWD=' | grep -v '^SHLVL='; echo "STDIN:$(cat)"; } > `+out+`
echo '{"v":1,"ok":true}'
`)
	t.Setenv("SVAVYOM_SECRET_FROM_SUPERVISOR", "hunter2")
	r := newRig(t, 10*time.Second, h)
	if err := r.client.Start(context.Background(), "web-1"); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(out)
	seen := string(b)
	if !strings.Contains(seen, "ARGV:--config "+r.cfgPath+" --insecure-dev-single-identity\n") {
		t.Fatalf("argv is not the fixed operator arguments:\n%s", seen)
	}
	if strings.Contains(seen, "web-1\n") && strings.Contains(strings.SplitN(seen, "STDIN:", 2)[0], "web-1") {
		t.Fatal("request data reached argv or the environment")
	}
	if !strings.Contains(seen, `STDIN:{"v":1,"op":"start","name":"web-1"}`) {
		t.Fatalf("request not on stdin:\n%s", seen)
	}
	if strings.Contains(seen, "hunter2") || strings.Contains(seen, "SVAVYOM_SECRET") {
		t.Fatal("the supervisor's own environment leaked into the helper")
	}
	if !strings.Contains(seen, "SVAVYOM_SIM_HOST=1") || !strings.Contains(seen, "LANG=C") {
		t.Fatalf("configured environment missing:\n%s", seen)
	}
}

func TestOnlyAWellFormedReplyFromACleanExitIsBelieved(t *testing.T) {
	for name, c := range map[string]struct {
		script string
		want   hypervisor.Category
	}{
		"clean success":                 {`echo '{"v":1,"ok":true}'`, ""},
		"typed failure":                 {`echo '{"v":1,"ok":false,"category":"conflict"}'`, hypervisor.Conflict},
		"valid reply but exit 1":        {`echo '{"v":1,"ok":true}'; exit 1`, hypervisor.Timeout},
		"crash without reply":           {`kill -9 $$`, hypervisor.Timeout},
		"exit 0 without reply":          {`exit 0`, hypervisor.Timeout},
		"garbage":                       {`echo 'not json'`, hypervisor.Timeout},
		"unknown field":                 {`echo '{"v":1,"ok":true,"xml":"<a/>"}'`, hypervisor.Timeout},
		"wrong version":                 {`echo '{"v":9,"ok":true}'`, hypervisor.Timeout},
		"two replies":                   {`echo '{"v":1,"ok":true}{"v":1,"ok":true}'`, hypervisor.Timeout},
		"flood of output":               {`head -c 200000 /dev/zero | tr '\0' 'a'; echo '{"v":1,"ok":true}'`, hypervisor.Timeout},
		"secret in an error is dropped": {`echo '{"v":1,"ok":false,"category":"host_error","detail":"password=hunter2"}'`, hypervisor.Timeout},
		"cannot even start":             {``, ""},
	} {
		t.Run(name, func(t *testing.T) {
			helper := scriptHelper(t, c.script+"\n")
			if name == "cannot even start" {
				helper = scriptHelper(t, "exit 0\n")
			}
			r := newRig(t, 10*time.Second, helper)
			err := r.client.Start(context.Background(), "web-1")
			if name == "cannot even start" {
				return
			}
			if cat(err) != c.want {
				t.Fatalf("got %v, want category %q", err, c.want)
			}
			if err != nil && strings.Contains(err.Error(), "hunter2") {
				t.Fatal("helper text crossed the boundary")
			}
		})
	}
}

func TestConcurrencyIsBounded(t *testing.T) {
	counter := filepath.Join(t.TempDir(), "n")
	_ = os.WriteFile(counter, nil, 0o600)
	h := scriptHelper(t, `echo x >> `+counter+`; sleep 1; echo '{"v":1,"ok":true}'
`)
	r := newRig(t, 10*time.Second, h)
	var wg sync.WaitGroup
	results := make(chan error, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results <- r.client.Start(context.Background(), "web-1")
		}()
	}
	wg.Wait()
	close(results)
	ok, refused := 0, 0
	for err := range results {
		switch {
		case err == nil:
			ok++
		default:
			refused++
		}
	}
	if ok == 0 || ok > 8 {
		t.Fatalf("ok=%d refused=%d", ok, refused)
	}
	b, _ := os.ReadFile(counter)
	if n := strings.Count(string(b), "x"); n != ok {
		t.Fatalf("helpers started %d times for %d successful requests", n, ok)
	}
}

func TestRunHelperRefusesBadInputWithoutAReply(t *testing.T) {
	r := newRig(t, 5*time.Second, "")
	for name, in := range map[string]string{"empty": "", "garbage": "{", "unknown op": `{"v":1,"op":"restart","name":"web-1"}`,
		"huge": `{"v":1,"op":"preflight","pad":"` + strings.Repeat("a", MaxRequestBytes) + `"}`} {
		var out strings.Builder
		if code := RunHelper(context.Background(), strings.NewReader(in), &out, r.sim, r.cfg, provision.DevPolicy(), nil); code != 2 || out.Len() != 0 {
			t.Errorf("%s: code %d output %q", name, code, out.String())
		}
	}
	bad := r.cfg
	bad.Pool = "x'/>"
	var out strings.Builder
	if code := RunHelper(context.Background(), strings.NewReader(`{"v":1,"op":"preflight"}`), &out, r.sim, bad, provision.DevPolicy(), nil); code != 2 {
		t.Errorf("invalid configuration: %d", code)
	}
}

// R2 (V5 review): the helper and its configuration are trust anchors. A symlink, a foreign-writable file or a swappable parent
// directory is refused at start, and again before EVERY helper start (so a swap after start executes nothing).
func TestTrustAnchorsAreRefusedAtStartAndBeforeEveryHelperStart(t *testing.T) {
	root := t.TempDir()
	good := scriptHelper(t, "cat >/dev/null; echo '{\"v\":1,\"ok\":true,\"preflight\":{\"network\":\"available\",\"pool\":\"available\"}}'\n")
	cfgPath := filepath.Join(root, "provision.json")
	_ = os.WriteFile(cfgPath, []byte("{}"), 0o600)
	base := func(name string) SupervisorConfig {
		return SupervisorConfig{Trust: provision.DevPolicy(), Socket: filepath.Join(root, name+".sock"), AllowUIDs: []uint32{uint32(os.Getuid())}, HelperPath: good, TrustedFiles: []string{cfgPath}} // #nosec G115
	}
	mustRefuse := func(name string, c SupervisorConfig) {
		t.Helper()
		if s, err := Listen(c); err == nil {
			s.Close()
			t.Errorf("%s: accepted", name)
		}
	}

	link := filepath.Join(root, "helper-link")
	if err := os.Symlink(good, link); err != nil {
		t.Fatal(err)
	}
	c := base("a")
	c.HelperPath = link
	mustRefuse("helper is a symlink", c)

	gw := scriptHelper(t, "exit 0\n")
	_ = os.Chmod(gw, 0o775)
	c = base("b")
	c.HelperPath = gw
	mustRefuse("helper group-writable", c)

	swappable := filepath.Join(root, "swappable")
	_ = os.Mkdir(swappable, 0o755)
	_ = os.Chmod(swappable, 0o777) // others could rename the helper away and put their own in its place
	inSwappable := filepath.Join(swappable, "helper.sh")
	_ = os.WriteFile(inSwappable, []byte("#!/bin/sh\nexit 0\n"), 0o755) // #nosec G306
	c = base("c")
	c.HelperPath = inSwappable
	mustRefuse("helper in a directory others can write", c)

	cfgLink := filepath.Join(root, "cfg-link.json")
	_ = os.Symlink(cfgPath, cfgLink)
	c = base("d")
	c.TrustedFiles = []string{cfgLink}
	mustRefuse("config is a symlink", c)

	cfgGW := filepath.Join(root, "cfg-gw.json")
	_ = os.WriteFile(cfgGW, []byte("{}"), 0o600)
	_ = os.Chmod(cfgGW, 0o664)
	c = base("e")
	c.TrustedFiles = []string{cfgGW}
	mustRefuse("config group-writable", c)

	c = base("f")
	c.TrustedFiles = []string{filepath.Join(swappable, "provision.json")}
	_ = os.WriteFile(c.TrustedFiles[0], []byte("{}"), 0o600)
	mustRefuse("config in a directory others can write", c)

	c = base("g")
	c.TrustedFiles = []string{filepath.Join(root, "missing.json")}
	mustRefuse("config missing", c)

	// A swap after start: the next request must not start anything, and must say "unavailable" (no effect), not "unknown".
	marker := filepath.Join(root, "ran")
	h := scriptHelper(t, "touch "+marker+"; cat >/dev/null; echo '{\"v\":1,\"ok\":true,\"preflight\":{\"network\":\"available\",\"pool\":\"available\"}}'\n")
	live := base("live")
	live.HelperPath = h
	sup, err := Listen(live)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- sup.Serve() }()
	defer func() { sup.Close(); <-done }()
	cl, _ := NewClient(live.Socket, 10*time.Second)
	if _, err := cl.Preflight(context.Background()); err != nil {
		t.Fatalf("a trusted helper must run: %v", err)
	}
	_ = os.Remove(marker)
	_ = os.Chmod(h, 0o777) // now writable by anyone
	if _, err := cl.Preflight(context.Background()); cat(err) != hypervisor.Unavailable {
		t.Fatalf("a helper that became writable must be refused as unavailable: %v", err)
	}
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("a helper that failed the trust check was executed")
	}
	_ = os.Chmod(h, 0o755) // #nosec G302
	_ = os.Remove(cfgPath)
	if _, err := cl.Preflight(context.Background()); cat(err) != hypervisor.Unavailable {
		t.Fatalf("a missing configuration must be refused as unavailable: %v", err)
	}
}

// DR-017 D3 (amended): the strict production policy is the zero value, so a supervisor configured without an explicit policy
// refuses a helper that is owned by the mutation service identity itself, and the catalog/store/image check (Deployment) is
// enforced at start and before every helper run.
func TestSupervisorDefaultsToTheStrictProductionPolicyAndChecksTheDeployment(t *testing.T) {
	root := t.TempDir()
	h := scriptHelper(t, "cat >/dev/null; echo '{\"v\":1,\"ok\":true,\"preflight\":{\"network\":\"available\",\"pool\":\"available\"}}'\n")
	cfgPath := filepath.Join(root, "provision.json")
	_ = os.WriteFile(cfgPath, []byte("{}"), 0o600)
	cfg := SupervisorConfig{Socket: filepath.Join(root, "a.sock"), AllowUIDs: []uint32{uint32(os.Getuid())}, HelperPath: h, TrustedFiles: []string{cfgPath}} // #nosec G115
	if s, err := Listen(cfg); err == nil {
		s.Close()
		t.Fatal("a helper owned by the mutation service identity (no root-owned anchors) was accepted by the default policy")
	}

	bad := []string{}
	live := SupervisorConfig{Trust: provision.DevPolicy(), Socket: filepath.Join(root, "b.sock"), AllowUIDs: []uint32{uint32(os.Getuid())}, HelperPath: h, TrustedFiles: []string{cfgPath}, // #nosec G115
		Deployment: func() []string { return bad }}
	sup, err := Listen(live)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- sup.Serve() }()
	defer func() { sup.Close(); <-done }()
	cl, _ := NewClient(live.Socket, 10*time.Second)
	if _, err := cl.Preflight(context.Background()); err != nil {
		t.Fatalf("a compliant deployment must run: %v", err)
	}
	bad = []string{"published image"} // an image became replaceable after start
	if _, err := cl.Preflight(context.Background()); cat(err) != hypervisor.Unavailable {
		t.Fatalf("a deployment that stopped being operator-owned must be refused as unavailable: %v", err)
	}
	if s, err := Listen(SupervisorConfig{Trust: provision.DevPolicy(), Socket: filepath.Join(root, "c.sock"), AllowUIDs: []uint32{1}, HelperPath: h, TrustedFiles: []string{cfgPath},
		Deployment: func() []string { return bad }}); err == nil {
		s.Close()
		t.Fatal("start accepted a non-compliant deployment")
	}
}
