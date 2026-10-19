package api

import (
	"cmp"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"example.invalid/dedicatedcloud/backend/internal/alerts"
	"example.invalid/dedicatedcloud/backend/internal/backupstore"
	"example.invalid/dedicatedcloud/backend/internal/hypervisor"
	"example.invalid/dedicatedcloud/backend/internal/offsite"
	"example.invalid/dedicatedcloud/backend/internal/operation"
	"example.invalid/dedicatedcloud/backend/internal/provision"
	"example.invalid/dedicatedcloud/backend/internal/provision/provtest"
	"example.invalid/dedicatedcloud/backend/internal/schedule"
	"example.invalid/dedicatedcloud/backend/internal/simhost"
	"example.invalid/dedicatedcloud/backend/internal/sqlitedb"
)

// directHost drives the simulated host through the same provisioning code the helper runs, in process: operation manager,
// worker, API and provisioning are the real ones; only the process boundary and libvirt are absent (they have their own tests).
type directHost struct {
	sim      *simhost.Host
	cfg      provision.Config
	cat      func() (*provision.Catalog, error)
	mu       sync.Mutex
	timeoutN int // make the next N provision calls apply and then report a timeout (unknown outcome)
	defines  int
	bak      *backupstore.Store
	avoid    []netip.Prefix // what the (simulated) host reports about its own subnets and routes
	exp      *offsite.Exporter
}

func (d *directHost) Define(ctx context.Context, s hypervisor.DomainSpec) (hypervisor.Domain, error) {
	c, err := d.cat()
	if err != nil {
		return hypervisor.Domain{}, hypervisor.NewError(hypervisor.HostError, "define", "", "catalog")
	}
	ps := provision.Spec{Name: s.Name, UUID: s.UUID, Fingerprint: s.Fingerprint, VCPUs: s.VCPUs, MemoryMiB: s.MemoryMiB, ImageID: s.ImageID, ImageSHA256: s.ImageSHA256,
		DiskGiB: s.DiskGiB, SSHPublicKey: s.SSHPublicKey, Network: s.Network}
	d.mu.Lock()
	d.defines++
	lose := d.timeoutN > 0
	if lose {
		d.timeoutN--
	}
	d.mu.Unlock()
	if err := provision.Provision(ctx, d.sim, d.cfg, c, ps, d.cfg.StateDir, nil); err != nil {
		return hypervisor.Domain{}, err
	}
	if lose {
		return hypervisor.Domain{}, hypervisor.NewError(hypervisor.Timeout, "define", "", "lost reply")
	}
	return hypervisor.Domain{Name: s.Name, State: hypervisor.StateShutoff}, nil
}
func (d *directHost) Start(ctx context.Context, n string) error {
	return provision.Start(ctx, d.sim, n, nil)
}
func (d *directHost) Stop(ctx context.Context, n string) error {
	return provision.Stop(ctx, d.sim, n, nil)
}
func (d *directHost) Reboot(ctx context.Context, n string) error {
	return provision.Reboot(ctx, d.sim, n, nil)
}
func (d *directHost) Destroy(ctx context.Context, n string) error {
	return provision.ForceOff(ctx, d.sim, n, nil)
}
func (d *directHost) Undefine(ctx context.Context, n string) error {
	return provision.Delete(ctx, d.sim, d.cfg, n, nil)
}
func (d *directHost) Lookup(ctx context.Context, n string) (hypervisor.Domain, error) {
	return simhost.Reader{H: d.sim}.Lookup(ctx, n)
}
func (d *directHost) List(ctx context.Context) ([]hypervisor.Domain, error) {
	return simhost.Reader{H: d.sim}.List(ctx)
}
func (d *directHost) Calls() []hypervisor.CallRecord { return nil }

type crig struct {
	*env
	host    *directHost
	sim     *simhost.Host
	cat     *provision.Catalog
	catDir  string
	mgr     *operation.Manager
	worker  *operation.Worker
	enabled bool
	// poolType overrides the simulated pool's type ("" keeps the simulation's own, which supports snapshots).
	poolType string
	key      string
	stop     func()
	cons     *Console
	usage    UsageSource
	astore   *alerts.SQLiteStore
	engine   *alerts.Engine
	sched    *schedule.Scheduler
	sstore   *schedule.Store
}

func newCRig(t *testing.T, enabled bool) *crig {
	t.Helper()
	e := newEnv(t, true)
	root := t.TempDir()
	catDir, state := filepath.Join(root, "images"), filepath.Join(root, "state")
	for _, d := range []string{catDir, state} {
		_ = os.MkdirAll(d, 0o750)
	}
	srcs := map[string]string{}
	for name, body := range map[string]string{"debian.qcow2": "debian body", "other.qcow2": "other body", "raw.qcow2": "raw body"} {
		srcs[name] = filepath.Join(root, name)
		_ = os.WriteFile(srcs[name], provtest.Qcow2(body), 0o640)
	}
	if _, err := provision.Register(provision.DevPolicy(), catDir, provision.RegisterRequest{ID: "debian-13", DisplayName: "Debian 13", Distribution: "Debian", Version: "13", Source: srcs["debian.qcow2"], LoginUser: "debian", MinDiskGiB: 3, CloudInit: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := provision.Register(provision.DevPolicy(), catDir, provision.RegisterRequest{ID: "big-os", DisplayName: "Big OS", Distribution: "Big", Version: "1", Source: srcs["other.qcow2"], LoginUser: "admin", MinDiskGiB: 40, CloudInit: true}); err != nil {
		t.Fatal(err)
	}
	cat, _ := provision.LoadTrustedCatalog(provision.DevPolicy(), catDir)
	cfg := provision.Config{CatalogDir: catDir, Pool: "svavyom", Network: "svavyom-nat", DomainType: "test", LibvirtURI: "test:///default", StateDir: state}
	sim, _ := simhost.New(filepath.Join(root, "sim"))
	catFn := func() (*provision.Catalog, error) { return provision.LoadTrustedCatalog(provision.DevPolicy(), catDir) }
	bakDir := filepath.Join(root, "backups")
	_ = os.MkdirAll(bakDir, 0o700)
	cfg.BackupDir = bakDir
	bak, err := backupstore.Open(bakDir)
	if err != nil {
		t.Fatal(err)
	}
	host := &directHost{sim: sim, cfg: cfg, cat: catFn, bak: bak}
	db, err := sqlitedb.Open(e.path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	store, err := operation.OpenSQLite(context.Background(), db)
	if err != nil {
		t.Fatal(err)
	}
	astore, err := alerts.OpenSQLite(context.Background(), db)
	if err != nil {
		t.Fatal(err)
	}
	engine := &alerts.Engine{Store: astore}
	sstore, err := schedule.OpenSQLite(context.Background(), db)
	if err != nil {
		t.Fatal(err)
	}
	sched := &schedule.Scheduler{Store: sstore, Loc: time.UTC}
	info := sampleHost()
	prep := NewCreatePreparer(catFn, "svavyom-nat", func() (int, int) { return info.CPUCount, int(info.MemoryMiB) })
	mgr := operation.NewManager(store, host, Authorizer(), nil, operation.Config{PrepareCreate: prep, PrepareParams: NewParamsPreparer(catFn), MaxAttempts: 3, Local: ackOnly{engine, sched}})
	worker := operation.NewWorker(mgr, operation.WorkerConfig{Concurrency: 2, Poll: 10 * time.Millisecond, BackoffBase: 10 * time.Millisecond, BackoffMax: 40 * time.Millisecond,
		OpTimeout: 10 * time.Second, RecoverRetry: 10 * time.Millisecond, ObserveEvery: 50 * time.Millisecond})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = worker.Run(ctx); close(done) }()
	r := &crig{env: e, host: host, sim: sim, cat: cat, catDir: catDir, mgr: mgr, worker: worker, enabled: enabled, astore: astore, engine: engine, sched: sched, sstore: sstore}
	sched.World = testWorld{r}
	sched.Ops = mgr
	r.stop = func() { cancel(); <-done }
	t.Cleanup(r.stop)
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	sp, _ := ssh.NewPublicKey(pub)
	r.key = strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sp))) + " admin@laptop"
	r.wire()
	return r
}

// ackOnly is the Local implementation of these tests: alert acknowledgement and the schedule operations.
type ackOnly struct {
	e *alerts.Engine
	s *schedule.Scheduler
}

func (a ackOnly) AlertAcknowledge(ctx context.Context, id, _ string) error {
	return a.e.Acknowledge(ctx, id)
}
func (a ackOnly) ScheduleSet(ctx context.Context, vm string, p operation.Params, by string) error {
	err := a.s.Set(ctx, vm, schedule.Spec{EveryHours: p.EveryHours, At: p.At, KeepLocal: p.KeepLocal, KeepOffsite: p.KeepOffsite, TargetID: p.TargetID}, by)
	switch {
	case err == nil:
		return nil
	case errors.Is(err, schedule.ErrNoVM):
		return hypervisor.NewError(hypervisor.NotFound, "schedule_set", "", "no vm")
	case errors.Is(err, schedule.ErrNotOurs):
		return hypervisor.NewError(hypervisor.Prohibited, "schedule_set", "", "not ours")
	}
	return hypervisor.NewError(hypervisor.Validation, "schedule_set", "", "invalid")
}
func (a ackOnly) ScheduleClear(ctx context.Context, vm string) error {
	if err := a.s.Clear(ctx, vm); err != nil {
		return hypervisor.NewError(hypervisor.Unavailable, "schedule_clear", "", "store")
	}
	return nil
}

// testWorld lets the scheduler see the simulated host.
type testWorld struct{ r *crig }

func (w testWorld) VM(ctx context.Context, n string) (schedule.VMState, error) {
	d, err := simhost.Reader{H: w.r.sim}.Lookup(ctx, n)
	if hypervisor.CategoryOf(err) == hypervisor.NotFound {
		return schedule.VMState{}, nil
	}
	if err != nil {
		return schedule.VMState{}, err
	}
	st := "other"
	switch d.State {
	case hypervisor.StateRunning:
		st = "running"
	case hypervisor.StateShutoff:
		st = "shutoff"
	}
	return schedule.VMState{Found: true, Managed: d.Managed, State: st}, nil
}
func (testWorld) Backups(context.Context) ([]schedule.BackupInfo, error) { return nil, nil }
func (testWorld) Copies(context.Context) (map[string][]string, error)    { return nil, nil }
func (testWorld) Prune(context.Context, string, string) error            { return nil }

func (r *crig) wire() {
	r.srv.Close()
	cr := &Creation{Enabled: r.enabled, Ops: r.mgr, Notify: r.worker.Notify, Catalog: r.host.cat, Network: "svavyom-nat",
		Preflight: func(ctx context.Context) (provision.Readiness, error) {
			return provision.Preflight(ctx, r.sim, r.host.cfg), nil
		},
		HostPrefixes: func() ([]netip.Prefix, error) { return r.host.avoid, nil },
		ListBackups: func(context.Context) ([]BackupInfo, error) {
			l, err := r.host.bak.List()
			var out []BackupInfo
			for _, b := range l {
				out = append(out, BackupInfo{ID: b.Manifest.BackupID, VM: b.Manifest.VM.Name, CreatedAt: b.Manifest.CreatedAt, SizeBytes: b.Manifest.Root.Size, DiskGiB: b.Manifest.VM.DiskGiB, ImageID: b.Manifest.VM.ImageID, Valid: b.Valid})
			}
			return out, err
		},
		Targets: func() func(context.Context) ([]TargetInfo, error) {
			if r.host.exp == nil {
				return nil
			}
			return func(context.Context) ([]TargetInfo, error) {
				var out []TargetInfo
				for _, t := range r.host.exp.States() {
					out = append(out, TargetInfo{ID: t.ID, Kind: t.Kind, State: t.State})
				}
				return out, nil
			}
		}(),
		Copies: func() func(context.Context) (map[string][]string, error) {
			if r.host.exp == nil {
				return nil
			}
			return func(context.Context) (map[string][]string, error) {
				l, err := r.host.exp.Copies()
				m := map[string][]string{}
				for _, c := range l {
					m[c.Backup] = c.Targets
				}
				return m, err
			}
		}(),
		Stats: func(ctx context.Context) (StorageStats, error) {
			ps, err := r.sim.PoolStats(ctx, r.host.cfg.Pool)
			return StorageStats{PoolCapacity: ps.CapacityBytes, PoolAvailable: ps.AvailableBytes, PoolAllocation: ps.AllocationBytes, BackupsKnown: true, BackupBytes: r.host.bak.UsageBytes(), Snapshots: provision.SnapshotSupport(cmp.Or(r.poolType, ps.Type))}, err
		}}
	r.h = NewHandlerWith(Deps{Auth: r.svc, Hosts: r.hosts, VMs: simhost.Reader{H: r.sim}, Creation: cr, Alerts: &AlertsView{Source: r.astore}, Schedules: r.sstore, Console: r.cons, Usage: r.usage, Now: func() time.Time { return time.Date(2026, 10, 10, 9, 0, 0, 0, time.UTC) }})
	r.srv = httptest.NewServer(r.h)
	r.t.Cleanup(r.srv.Close)
}

func (r *crig) createBody(name, key string, mut func(map[string]any)) string {
	c := map[string]any{"vcpus": 2, "memory_mib": 1024, "image_id": "debian-13", "disk_gib": 20, "ssh_public_key": key}
	if mut != nil {
		mut(c)
	}
	b, _ := json.Marshal(map[string]any{"type": "create", "kind": "VM", "id": name, "idempotency_key": "key-" + name, "create": c})
	return string(b)
}

func (r *crig) post(b *browser, body string) reply {
	return b.do("POST", "/api/v1/operations", body, map[string]string{"X-CSRF-Token": b.csrf})
}

func (r *crig) await(b *browser, id, want string) map[string]any {
	r.t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		rep := b.do("GET", "/api/v1/operations/"+id, "", nil)
		var m map[string]any
		_ = json.Unmarshal(rep.body, &m)
		if m["status"] == want {
			return m
		}
		if time.Now().After(deadline) {
			r.t.Fatalf("operation %s: want %s, last %s", id, want, rep.body)
		}
		time.Sleep(15 * time.Millisecond)
	}
}

func opID(t *testing.T, rep reply) string {
	t.Helper()
	var m struct{ ID string }
	if rep.status != 202 || json.Unmarshal(rep.body, &m) != nil || m.ID == "" {
		t.Fatalf("submit: %d %s", rep.status, rep.body)
	}
	return m.ID
}

func TestCreateThenStartWholeJourneyThroughTheAPI(t *testing.T) {
	r := newCRig(t, true)
	b := signedIn(t, r.env)
	// readiness and choices
	h := b.do("GET", "/api/v1/hosts/local", "", nil)
	var host hostJSON
	_ = json.Unmarshal(h.body, &host)
	c := host.Observed.Creation
	if !c.Enabled || c.Network != "available" || c.Storage != "available" || len(c.VCPUOptions) == 0 || len(c.MemoryMiBOptions) == 0 || len(c.DiskGiBOptions) == 0 {
		t.Fatalf("%+v", c)
	}
	// images: the catalog is visible, the files are not
	imgs := b.do("GET", "/api/v1/images", "", nil)
	if imgs.status != 200 || !strings.Contains(string(imgs.body), `"login_user":"debian"`) || !strings.Contains(string(imgs.body), `"source_digest":"sha256:`) || strings.Contains(string(imgs.body), ".qcow2") || strings.Contains(string(imgs.body), r.catDir) {
		t.Fatalf("%d %s", imgs.status, imgs.body)
	}
	// create
	rep := r.post(b, r.createBody("web-1", r.key, nil))
	id := opID(t, rep)
	if strings.Contains(string(rep.body), "ssh-ed25519") || strings.Contains(string(rep.body), "key-web-1") || strings.Join(keys(t, rep.body), ",") !=
		"allowed_actions,attempts,created_at,error_category,generation,id,project_id,requested_by,resource_id,resource_kind,status,type,updated_at" {
		t.Fatalf("operation body: %s", rep.body)
	}
	op := r.await(b, id, "succeeded")
	if op["requested_by"] != adminName || op["type"] != "create" || op["resource_id"] != "web-1" {
		t.Fatalf("%v", op)
	}
	// the VM is there, stopped, managed, with the image's login user and no IP yet; Start is offered
	vm := b.do("GET", "/api/v1/vms/web-1", "", nil)
	var v vmJSON
	_ = json.Unmarshal(vm.body, &v)
	if v.Observed.Power != "stopped" || !v.Observed.Managed || v.Observed.IPAddress != nil || v.Observed.LoginUser == nil || *v.Observed.LoginUser != "debian" || strings.Join(v.Allowed, ",") != "start,delete,resize,reinstall,snapshot,backup,iso_attach,rescue,compute,set_schedule" || v.Observed.DiskGiB == nil || *v.Observed.DiskGiB != 20 || len(v.Observed.Snapshots) != 0 {
		t.Fatalf("%s", vm.body)
	}
	// the host holds what the spec said, and the seed carries the normalised key without its comment
	st := r.sim.Load()
	if len(st.Domains) != 1 || len(st.Volumes) != 2 || !st.Domains["web-1"].Managed {
		t.Fatalf("%+v", st)
	}
	// start
	sid := opID(t, r.post(b, `{"type":"start","kind":"VM","id":"web-1","idempotency_key":"start-web-1"}`))
	r.await(b, sid, "succeeded")
	vm = b.do("GET", "/api/v1/vms/web-1", "", nil)
	v = vmJSON{}
	_ = json.Unmarshal(vm.body, &v)
	if v.Observed.Power != "running" || v.Observed.IPAddress == nil || !provision.IsIPv4(*v.Observed.IPAddress) || strings.Join(v.Allowed, ",") != "stop,reboot,force_off,set_schedule" {
		t.Fatalf("%s", vm.body)
	}
	// sign out ends it all
	if so := b.signOut(); so.status != 200 {
		t.Fatal(so.status)
	}
	if rep := b.do("GET", "/api/v1/operations/"+id, "", nil); rep.status != 401 {
		t.Fatalf("%d", rep.status)
	}
}

func TestMutationIsClosedUnlessTheOperatorEnabledIt(t *testing.T) {
	r := newCRig(t, false)
	b := signedIn(t, r.env)
	rep := r.post(b, r.createBody("web-1", r.key, nil))
	if rep.status != 422 || catOf(t, rep) != "prohibited" {
		t.Fatalf("%d %s", rep.status, rep.body)
	}
	if st := r.sim.Load(); len(st.Domains) != 0 || len(st.Volumes) != 0 {
		t.Fatal("something was created")
	}
	if ops, _ := r.mgr.Get(operation.Actor{ID: "x"}, "op-none"); ops.ID != "" {
		t.Fatal("unexpected operation")
	}
	var host hostJSON
	_ = json.Unmarshal(b.do("GET", "/api/v1/hosts/local", "", nil).body, &host)
	if c := host.Observed.Creation; c.Enabled || len(c.VCPUOptions) != 0 || c.Network != "unknown" {
		t.Fatalf("%+v", c)
	}
	// no Start offered either
	_ = r.sim.DefineManaged("web-1")
	if vm := b.do("GET", "/api/v1/vms/web-1", "", nil); strings.Contains(string(vm.body), `"allowed_actions":["start"]`) {
		t.Fatalf("start offered while mutation is closed: %s", vm.body)
	}
	if rep := r.post(b, `{"type":"start","kind":"VM","id":"web-1","idempotency_key":"k"}`); rep.status != 422 {
		t.Fatalf("%d", rep.status)
	}
}

func TestSubmitRequiresSessionCSRFAndSameOrigin(t *testing.T) {
	r := newCRig(t, true)
	anon := r.env.browser()
	if rep := anon.do("POST", "/api/v1/operations", r.createBody("web-1", r.key, nil), nil); rep.status != 401 {
		t.Fatalf("%d", rep.status)
	}
	b := signedIn(t, r.env)
	body := r.createBody("web-1", r.key, nil)
	for name, h := range map[string]map[string]string{
		"no csrf": {}, "wrong csrf": {"X-CSRF-Token": strings.Repeat("A", 43)}, "malformed": {"X-CSRF-Token": "x"},
		"foreign origin": {"X-CSRF-Token": b.csrf, "Origin": "https://evil.example"}, "cross-site": {"X-CSRF-Token": b.csrf, "Sec-Fetch-Site": "cross-site"},
	} {
		if rep := b.do("POST", "/api/v1/operations", body, h); rep.status != 403 {
			t.Errorf("%s: %d %s", name, rep.status, rep.body)
		}
	}
	if st := r.sim.Load(); len(st.Domains)+len(st.Volumes) != 0 {
		t.Fatal("a refused request created something")
	}
	if rep := b.do("GET", "/api/v1/operations/op-abc", "", nil); rep.status != 404 {
		t.Fatalf("%d", rep.status)
	}
}

func TestSubmitValidation(t *testing.T) {
	r := newCRig(t, true)
	b := signedIn(t, r.env)
	ok := func(mut func(map[string]any)) string { return r.createBody("web-1", r.key, mut) }
	priv, _ := json.Marshal("-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----")
	cases := map[string]string{
		"not json": "{nope", "empty": "{}", "unknown top field": `{"type":"start","kind":"VM","id":"web-1","idempotency_key":"k","path":"/etc/passwd"}`,
		"unknown create field": ok(func(c map[string]any) { c["network"] = "bridge0" }), "xml in create": ok(func(c map[string]any) { c["domain_xml"] = "<domain/>" }),
		"missing create": `{"type":"create","kind":"VM","id":"web-1","idempotency_key":"k"}`, "create on start": `{"type":"start","kind":"VM","id":"web-1","idempotency_key":"k","create":{}}`,
		"name upper": strings.Replace(ok(nil), `"id":"web-1"`, `"id":"Web-1"`, 1), "name dot": strings.Replace(ok(nil), `"id":"web-1"`, `"id":"a.b"`, 1),
		"bad idempotency key": strings.Replace(ok(nil), `"key-web-1"`, `"bad key!"`, 1), "vcpus 3": ok(func(c map[string]any) { c["vcpus"] = 3 }),
		"vcpus too many": ok(func(c map[string]any) { c["vcpus"] = 64 }), "memory odd": ok(func(c map[string]any) { c["memory_mib"] = 1000 }),
		"memory over host": ok(func(c map[string]any) { c["memory_mib"] = 8192 * 2 }), "disk odd": ok(func(c map[string]any) { c["disk_gib"] = 7 }),
		"disk below image minimum": ok(func(c map[string]any) { c["image_id"] = "big-os"; c["disk_gib"] = 20 }), "unknown image": ok(func(c map[string]any) { c["image_id"] = "nope" }),
		"image path": ok(func(c map[string]any) { c["image_id"] = "../../etc/passwd" }), "image url": ok(func(c map[string]any) { c["image_id"] = "https://evil.example/x.qcow2" }),
		"string vcpus": ok(func(c map[string]any) { c["vcpus"] = "2" }), "key private": ok(func(c map[string]any) { c["ssh_public_key"] = json.RawMessage(priv) }),
		"key empty": ok(func(c map[string]any) { c["ssh_public_key"] = "" }), "key two": ok(func(c map[string]any) { c["ssh_public_key"] = r.key + "\n" + r.key }),
		"key options": ok(func(c map[string]any) { c["ssh_public_key"] = `command="id" ` + r.key }), "key garbage": ok(func(c map[string]any) { c["ssh_public_key"] = "ssh-ed25519 AAAA" }),
		"key huge": ok(func(c map[string]any) { c["ssh_public_key"] = strings.Repeat("a", 3000) }), "huge body": ok(func(c map[string]any) { c["ssh_public_key"] = strings.Repeat("a", 20000) }),
	}
	for name, body := range cases {
		rep := r.post(b, body)
		if rep.status != 400 || catOf(t, rep) != "validation" {
			t.Errorf("%s: %d %s", name, rep.status, rep.body)
		}
		if strings.Contains(string(rep.body), "BEGIN") || strings.Contains(string(rep.body), "ssh-") {
			t.Errorf("%s: input echoed", name)
		}
	}
	for name, body := range map[string]string{
		"restart": `{"type":"restart","kind":"VM","id":"web-1","idempotency_key":"k"}`, "destroy": `{"type":"destroy","kind":"VM","id":"web-1","idempotency_key":"k"}`,
		"undefine": `{"type":"undefine","kind":"VM","id":"web-1","idempotency_key":"k"}`, "volume kind": `{"type":"create","kind":"Volume","id":"v1","idempotency_key":"k"}`,
	} {
		if rep := r.post(b, body); rep.status != 422 && rep.status != 400 {
			t.Errorf("%s: %d", name, rep.status)
		} else if rep.status != 422 {
			t.Errorf("%s should be prohibited, got %d", name, rep.status)
		}
	}
	if st := r.sim.Load(); len(st.Domains)+len(st.Volumes) != 0 {
		t.Fatal("a rejected request created something")
	}
}

func TestIdempotencyReplaySameNameAndMissingNetwork(t *testing.T) {
	r := newCRig(t, true)
	b := signedIn(t, r.env)
	first := opID(t, r.post(b, r.createBody("web-1", r.key, nil)))
	if again := opID(t, r.post(b, r.createBody("web-1", r.key, nil))); again != first {
		t.Fatalf("replay created %s, want %s", again, first)
	}
	r.await(b, first, "succeeded")
	if rep := r.post(b, r.createBody("web-1", r.key, func(c map[string]any) { c["disk_gib"] = 40 })); rep.status != 409 {
		t.Fatalf("same key, different spec: %d %s", rep.status, rep.body)
	}
	// another key, same name: a VM of that name exists
	other := strings.Replace(r.createBody("web-1", r.key, nil), `"key-web-1"`, `"key-other"`, 1)
	if rep := r.post(b, other); rep.status != 409 || catOf(t, rep) != "conflict" {
		t.Fatalf("%d %s", rep.status, rep.body)
	}
	// network down: refused before anything is stored or created
	st := r.sim.Load()
	st.NetworkDown = true
	_ = r.sim.Save(st)
	if rep := r.post(b, r.createBody("web-2", r.key, nil)); rep.status != 503 || catOf(t, rep) != "unavailable" {
		t.Fatalf("%d %s", rep.status, rep.body)
	}
	var host hostJSON
	_ = json.Unmarshal(b.do("GET", "/api/v1/hosts/local", "", nil).body, &host)
	if host.Observed.Creation.Network != "unavailable" {
		t.Fatalf("%+v", host.Observed.Creation)
	}
	if len(r.sim.Load().Domains) != 1 {
		t.Fatal("a VM was created while the network was missing")
	}
}

func TestStartPrechecks(t *testing.T) {
	r := newCRig(t, true)
	b := signedIn(t, r.env)
	start := func(name string) reply {
		return r.post(b, `{"type":"start","kind":"VM","id":"`+name+`","idempotency_key":"s-`+name+`"}`)
	}
	if rep := start("ghost"); rep.status != 404 {
		t.Fatalf("absent: %d", rep.status)
	}
	st := r.sim.Load()
	st.Domains["foreign"] = simhost.Domain{UUID: "x"}
	_ = r.sim.Save(st)
	if rep := start("foreign"); rep.status != 422 {
		t.Fatalf("unmanaged: %d %s", rep.status, rep.body)
	}
	id := opID(t, r.post(b, r.createBody("web-1", r.key, nil)))
	r.await(b, id, "succeeded")
	r.await(b, opID(t, start("web-1")), "succeeded")
	if rep := start("web-1"); rep.status != 409 {
		t.Fatalf("already running: %d", rep.status)
	}
	if r.sim.Load().Domains["foreign"].Running {
		t.Fatal("a foreign VM was started")
	}
}

func TestTimeoutAfterTheHostActedResolvesToOneVM(t *testing.T) {
	r := newCRig(t, true)
	r.host.timeoutN = 1 // the first provisioning applies and then reports a timeout
	b := signedIn(t, r.env)
	id := opID(t, r.post(b, r.createBody("web-1", r.key, nil)))
	op := r.await(b, id, "succeeded")
	if op["attempts"].(float64) != 1 {
		t.Fatalf("a retry was sent although the VM was observed: %v", op)
	}
	if r.host.defines != 1 || len(r.sim.Load().Domains) != 1 {
		t.Fatalf("defines=%d domains=%d", r.host.defines, len(r.sim.Load().Domains))
	}
}

func TestOperationsAreNotLeakedAndImagesAreReadOnly(t *testing.T) {
	r := newCRig(t, true)
	b := signedIn(t, r.env)
	id := opID(t, r.post(b, r.createBody("web-1", r.key, nil)))
	rep := b.do("GET", "/api/v1/operations/"+id, "", nil)
	for _, leak := range []string{"ssh", "uuid", "fingerprint", "SHA256", "key-web-1", ".qcow2", r.catDir, "svavyom-nat", "password"} {
		if strings.Contains(string(rep.body), leak) {
			t.Errorf("operation body leaks %q: %s", leak, rep.body)
		}
	}
	for _, p := range []string{"/api/v1/operations/%00", "/api/v1/operations/a%20b", "/api/v1/operations/x?y=1"} {
		if rep := b.do("GET", p, "", nil); rep.status != 400 && rep.status != 404 {
			t.Errorf("%s: %d", p, rep.status)
		}
	}
	if rep := b.do("GET", "/api/v1/images/debian-13", "", nil); rep.status != 200 {
		t.Fatalf("%d", rep.status)
	}
	for p, want := range map[string]int{"/api/v1/images/nope": 404, "/api/v1/images/..": 404, "/api/v1/images?cursor=x": 400, "/api/v1/images/debian-13?x=1": 400} {
		if rep := b.do("GET", p, "", nil); rep.status != want {
			t.Errorf("%s: %d want %d", p, rep.status, want)
		}
	}
	for _, m := range []string{"POST", "PUT", "DELETE", "PATCH"} {
		if rep := b.do(m, "/api/v1/images", "{}", map[string]string{"X-CSRF-Token": b.csrf}); rep.status == 200 || rep.status == 202 {
			t.Errorf("%s /images succeeded", m)
		}
	}
	// disabled images are neither listed nor readable
	st, _ := provision.LoadCatalog(r.catDir)
	for _, im := range st.Images {
		if _, err := provision.SetState(provision.DevPolicy(), r.catDir, im.ID, provision.StateDisabled, ""); err != nil {
			t.Fatal(err)
		}
	}
	if rep := b.do("GET", "/api/v1/images", "", nil); !strings.Contains(string(rep.body), `"items":[]`) {
		t.Fatalf("%s", rep.body)
	}
	if rep := b.do("GET", "/api/v1/images/debian-13", "", nil); rep.status != 404 {
		t.Fatalf("%d", rep.status)
	}
	if rep := r.post(b, r.createBody("web-9", r.key, nil)); rep.status != 400 {
		t.Fatalf("a disabled image was accepted: %d", rep.status)
	}
}

// Typed readiness (DR-017): the host summary says WHY creation is or is not available, in closed codes only.
func TestCreationReadinessReasonsAreTypedAndBlockingOnlyWhenCreateWouldFail(t *testing.T) {
	read := func(b *browser) (ready bool, reasons []string) {
		t.Helper()
		var host struct {
			Observed struct {
				Creation struct {
					Ready   bool     `json:"ready"`
					Reasons []string `json:"reasons"`
				} `json:"creation"`
			} `json:"observed"`
		}
		if err := json.Unmarshal(b.do("GET", "/api/v1/hosts/local", "", nil).body, &host); err != nil {
			t.Fatal(err)
		}
		return host.Observed.Creation.Ready, host.Observed.Creation.Reasons
	}
	has := func(l []string, s string) bool {
		for _, x := range l {
			if x == s {
				return true
			}
		}
		return false
	}
	t.Run("closed switch", func(t *testing.T) {
		r := newCRig(t, false)
		ready, reasons := read(signedIn(t, r.env))
		if ready || len(reasons) != 1 || reasons[0] != "mutation_disabled" {
			t.Fatalf("%v %v", ready, reasons)
		}
	})
	t.Run("enabled with a verified image is ready, with notices", func(t *testing.T) {
		r := newCRig(t, true)
		ready, reasons := read(signedIn(t, r.env))
		if !ready || has(reasons, "no_usable_image") || !has(reasons, "image_unqualified") {
			t.Fatalf("%v %v", ready, reasons)
		}
	})
	t.Run("no usable image blocks", func(t *testing.T) {
		r := newCRig(t, true)
		for _, im := range []string{"debian-13", "big-os"} {
			if _, err := provision.SetState(provision.DevPolicy(), r.catDir, im, provision.StateRegistered, ""); err != nil {
				t.Fatal(err)
			}
		}
		ready, reasons := read(signedIn(t, r.env))
		if ready || !has(reasons, "no_usable_image") {
			t.Fatalf("%v %v", ready, reasons)
		}
	})
	t.Run("a qualified image removes the image notice", func(t *testing.T) {
		r := newCRig(t, true)
		if _, err := provision.SetState(provision.DevPolicy(), r.catDir, "debian-13", provision.StateQualified, "QUAL-TEST"); err != nil {
			t.Fatal(err)
		}
		ready, reasons := read(signedIn(t, r.env))
		if !ready || has(reasons, "image_unqualified") {
			t.Fatalf("%v %v", ready, reasons)
		}
	})
}

func TestSessionExpiryEndsCreationAccess(t *testing.T) {
	r := newCRig(t, true)
	b := signedIn(t, r.env)
	r.clk.add(31 * time.Minute)
	if rep := r.post(b, r.createBody("web-1", r.key, nil)); rep.status != 401 {
		t.Fatalf("%d", rep.status)
	}
	if st := r.sim.Load(); len(st.Domains) != 0 {
		t.Fatal("created without a session")
	}
}

// TestLifecycleThroughTheAPI drives Reboot, Stop, Start, Force Off and Delete of a real (simulated) managed VM through the browser API:
// each is a durable operation, each only in the state it applies to, and Delete removes exactly the VM's own resources.
func TestLifecycleThroughTheAPI(t *testing.T) {
	r := newCRig(t, true)
	b := signedIn(t, r.env)
	id := opID(t, r.post(b, r.createBody("web-1", r.key, nil)))
	r.await(b, id, "succeeded")
	submit := func(typ string) reply {
		return r.post(b, `{"type":"`+typ+`","kind":"VM","id":"web-1","idempotency_key":"`+typ+`-`+strings.ReplaceAll(time.Now().Format("150405.000000000"), ".", "")+`"}`)
	}
	do := func(typ string) {
		t.Helper()
		rep := submit(typ)
		if rep.status != 202 {
			t.Fatalf("%s: %d %s", typ, rep.status, rep.body)
		}
		r.await(b, opID(t, rep), "succeeded")
	}
	refuse := func(typ string, status int) {
		t.Helper()
		if rep := submit(typ); rep.status != status {
			t.Fatalf("%s should be refused with %d: %d %s", typ, status, rep.status, rep.body)
		}
	}
	// a stopped VM can neither be stopped, rebooted nor forced off, and a running one can not be deleted
	refuse("stop", 409)
	refuse("reboot", 409)
	refuse("force_off", 409)
	do("start")
	refuse("start", 409)
	refuse("delete", 409)
	do("reboot")
	if r.sim.Load().Domains["web-1"].Reboots != 1 {
		t.Fatal("reboot did not reach the host")
	}
	do("stop")
	if r.sim.Load().Domains["web-1"].Running {
		t.Fatal("stop did not power the VM off")
	}
	do("start")
	do("force_off")
	if r.sim.Load().Domains["web-1"].Running {
		t.Fatal("force off did not power the VM off")
	}
	do("delete")
	if st := r.sim.Load(); len(st.Domains) != 0 || len(st.Volumes) != 0 {
		t.Fatalf("delete must remove the VM and its two volumes: %+v", st)
	}
	if rep := b.do("GET", "/api/v1/vms/web-1", "", nil); rep.status != 404 {
		t.Fatalf("%d", rep.status)
	}
	// foreign or unmanaged VMs are never acted on
	if err := r.sim.Add("foreign", simhost.Domain{UUID: "9a9a9a9a-2222-4333-8444-5555555555ab", Running: true, VCPUs: 1, MemoryMiB: 64}); err != nil {
		t.Fatal(err)
	}
	for _, typ := range []string{"stop", "reboot", "force_off", "delete"} {
		if rep := r.post(b, `{"type":"`+typ+`","kind":"VM","id":"foreign","idempotency_key":"f-`+typ+`"}`); rep.status != 422 {
			t.Errorf("%s of a foreign VM: %d %s", typ, rep.status, rep.body)
		}
	}
	if !r.sim.Load().Domains["foreign"].Running {
		t.Fatal("a foreign VM was touched")
	}
}
