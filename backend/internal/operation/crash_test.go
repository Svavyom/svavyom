package operation

// Real process-kill restart tests (M0-E02-S07 durability gap).
//
// The "operation manager process" is this test binary re-executed in child mode (TestMain). Its state lives in a
// real SQLite file, its "host" is a file-backed hypervisor double that outlives the process, and failure points are
// injected inside the host call with SIGKILL: no deferred function, no flush, no goroutine gets to run, exactly like
// a crash. The parent then starts a fresh child on the same files, lets it reconcile, and asserts from the host's
// own command log that no host command was sent twice. This is T0/T1 simulation evidence only: it is not a KVM or a
// libvirt qualification.

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"example.invalid/dedicatedcloud/backend/internal/hypervisor"
	"example.invalid/dedicatedcloud/backend/internal/sqlitedb"
)

const childEnv = "SVAVYOM_OP_CRASH_CHILD"

func TestMain(m *testing.M) {
	if cmd := os.Getenv(childEnv); cmd != "" {
		os.Exit(runChild(cmd))
	}
	os.Exit(m.Run())
}

// ---- durable host double --------------------------------------------------------------------------------------

// durableHost is a hypervisor.Hypervisor whose domain table and command log are files, so they survive the death of
// the process that drives it. Semantics mirror package fake (idempotent start/stop/undefine).
type durableHost struct {
	dir   string
	fault string // injected failure, one-shot per test directory unless it ends in _always
}

type hostDom struct {
	State       hypervisor.State
	VCPUs       int
	MemoryMiB   int
	UUID        string
	Fingerprint string
}

type hostState map[string]hostDom

func (h *durableHost) load() hostState {
	st := hostState{}
	if b, err := os.ReadFile(filepath.Join(h.dir, "host.json")); err == nil {
		_ = json.Unmarshal(b, &st)
	}
	return st
}

func (h *durableHost) save(st hostState) {
	b, _ := json.Marshal(st)
	tmp := filepath.Join(h.dir, "host.json.tmp")
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		panic(err)
	}
	if err := os.Rename(tmp, filepath.Join(h.dir, "host.json")); err != nil {
		panic(err)
	}
}

func (h *durableHost) logCmd(op, name, outcome string) {
	f, err := os.OpenFile(filepath.Join(h.dir, "host.log"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		panic(err)
	}
	defer f.Close()
	fmt.Fprintf(f, "%s %s %s\n", op, name, outcome)
	_ = f.Sync()
}

func (h *durableHost) armed() bool {
	if strings.HasSuffix(h.fault, "_always") {
		return true
	}
	marker := filepath.Join(h.dir, "fired")
	if _, err := os.Stat(marker); err == nil {
		return false
	}
	_ = os.WriteFile(marker, nil, 0o600)
	return true
}

func die() { _ = syscall.Kill(os.Getpid(), syscall.SIGKILL); select {} }

// mutate applies fn to the table under the injected fault. fn returns the outcome word and error.
func (h *durableHost) mutate(op, name string, fn func(hostState) (string, error)) error {
	fault := ""
	if h.fault != "" && h.fault != "none" && h.armed() {
		fault = strings.TrimSuffix(h.fault, "_always")
	}
	switch fault {
	case "kill_before":
		die() // the command never reached the host
	case "timeout_not_applied":
		return hypervisor.NewError(hypervisor.Timeout, op, name, "injected")
	case "unavailable":
		return hypervisor.NewError(hypervisor.Unavailable, op, name, "injected")
	}
	st := h.load()
	outcome, err := fn(st)
	if err != nil {
		h.logCmd(op, name, "rejected")
		return err
	}
	h.save(st)
	h.logCmd(op, name, outcome)
	switch fault {
	case "kill_after":
		die() // the host acted; the manager dies before it can record the result
	case "timeout_applied":
		return hypervisor.NewError(hypervisor.Timeout, op, name, "injected")
	}
	return nil
}

func (h *durableHost) Define(_ context.Context, s hypervisor.DomainSpec) (hypervisor.Domain, error) {
	err := h.mutate("define", s.Name, func(st hostState) (string, error) {
		if _, ok := st[s.Name]; ok {
			return "", hypervisor.NewError(hypervisor.Conflict, "define", s.Name, "exists")
		}
		st[s.Name] = hostDom{State: hypervisor.StateShutoff, VCPUs: s.VCPUs, MemoryMiB: s.MemoryMiB, UUID: s.UUID, Fingerprint: s.Fingerprint}
		return "defined", nil
	})
	return hypervisor.Domain{Name: s.Name, State: hypervisor.StateShutoff}, err
}

func (h *durableHost) move(op, name string, from, to hypervisor.State) error {
	return h.mutate(op, name, func(st hostState) (string, error) {
		cur, ok := st[name]
		switch {
		case !ok:
			return "", hypervisor.NewError(hypervisor.NotFound, op, name, "absent")
		case cur.State == to:
			return "noop", nil
		case cur.State != from:
			return "", hypervisor.NewError(hypervisor.Conflict, op, name, "state")
		}
		cur.State = to
		st[name] = cur
		return string(to), nil
	})
}

func (h *durableHost) Start(_ context.Context, n string) error {
	return h.move("start", n, hypervisor.StateShutoff, hypervisor.StateRunning)
}
func (h *durableHost) Stop(_ context.Context, n string) error {
	return h.move("stop", n, hypervisor.StateRunning, hypervisor.StateShutoff)
}
func (h *durableHost) Destroy(_ context.Context, n string) error {
	return h.move("destroy", n, hypervisor.StateRunning, hypervisor.StateShutoff)
}
func (h *durableHost) Undefine(_ context.Context, n string) error {
	return h.mutate("undefine", n, func(st hostState) (string, error) {
		cur, ok := st[n]
		if !ok {
			return "noop", nil
		}
		if cur.State != hypervisor.StateShutoff {
			return "", hypervisor.NewError(hypervisor.Conflict, "undefine", n, "running")
		}
		delete(st, n)
		return "undefined", nil
	})
}
func (h *durableHost) Lookup(_ context.Context, n string) (hypervisor.Domain, error) {
	if strings.HasPrefix(h.fault, "blind") {
		return hypervisor.Domain{}, hypervisor.NewError(hypervisor.Unavailable, "lookup", n, "agent down")
	}
	st := h.load()
	s, ok := st[n]
	if !ok {
		return hypervisor.Domain{}, hypervisor.NewError(hypervisor.NotFound, "lookup", n, "absent")
	}
	return hypervisor.Domain{Name: n, State: s.State, VCPUs: s.VCPUs, MemoryMiB: s.MemoryMiB, UUID: s.UUID, Fingerprint: s.Fingerprint,
		Managed: s.UUID != "" && s.Fingerprint != ""}, nil
}
func (h *durableHost) List(context.Context) ([]hypervisor.Domain, error) { return nil, nil }
func (h *durableHost) Calls() []hypervisor.CallRecord                    { return nil }

// ---- child process --------------------------------------------------------------------------------------------

func childOpen(dir string) (*SQLiteStore, func(), error) {
	path := filepath.Join(dir, "ops.db")
	release, err := sqlitedb.LockProcess(path)
	if err != nil {
		return nil, nil, err
	}
	db, err := sqlitedb.Open(path)
	if err != nil {
		release()
		return nil, nil, err
	}
	s, err := OpenSQLite(context.Background(), db)
	if err != nil {
		release()
		return nil, nil, err
	}
	return s, func() { _ = db.Close(); release() }, nil
}

// runChild executes one command of the child protocol and prints a single JSON result line.
func runChild(cmd string) int {
	dir := os.Getenv("SVAVYOM_OP_DIR")
	args := strings.Fields(os.Getenv("SVAVYOM_OP_ARGS"))
	fault := os.Getenv("SVAVYOM_OP_FAULT")
	s, closeAll, err := childOpen(dir)
	if err != nil {
		fmt.Println(`{"error":"open"}`)
		return 0
	}
	defer closeAll()
	host := &durableHost{dir: dir, fault: fault}
	cfg := Config{MaxAttempts: 3}
	if d := strings.Fields(os.Getenv("SVAVYOM_OP_DEFAULTS")); len(d) == 2 { // process defaults differ across "restarts"
		cfg.VCPUs, _ = strconv.Atoi(d[0])
		cfg.MemoryMiB, _ = strconv.Atoi(d[1])
	}
	m := NewManager(s, host, owners{"p1": "alice"}, nil, cfg)
	out := map[string]any{}
	switch cmd {
	case "submit": // TYPE VM KEY
		op, err := m.Submit(alice, Request{ProjectID: "p1", Type: Type(args[0]), Kind: KindVM, ResourceID: args[1], IdempotencyKey: args[2]})
		out["id"], out["err"] = op.ID, errString(err)
	case "run": // ID
		op, err := m.Run(context.Background(), args[0])
		out["status"], out["err"] = op.Status, errString(err)
	case "reconcile":
		res, err := m.Reconcile(context.Background())
		out["resolved"], out["err"] = len(res), errString(err)
	case "worker":
		out["err"] = errString(runWorkerUntilIdle(m, s))
	}
	b, _ := json.Marshal(out)
	fmt.Println(string(b))
	return 0
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	if c := CategoryOf(err); c != "" {
		return c
	}
	return "other"
}

func runWorkerUntilIdle(m *Manager, s Store) error {
	w := NewWorker(m, WorkerConfig{Concurrency: 2, Poll: 10 * time.Millisecond, BackoffBase: 20 * time.Millisecond,
		BackoffMax: 50 * time.Millisecond, OpTimeout: 5 * time.Second, RecoverRetry: 10 * time.Millisecond})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- w.Run(ctx) }()
	start := time.Now()
	for quiet := 0; quiet < 5 || time.Since(start) < 400*time.Millisecond; {
		time.Sleep(30 * time.Millisecond)
		ops, err := s.NonTerminal()
		if err != nil {
			cancel()
			return err
		}
		actionable := false
		for _, op := range ops {
			if op.Status != RetryableFailure || op.Attempts < 3 {
				actionable = true
			}
		}
		if actionable {
			quiet = 0
		} else {
			quiet++
		}
		if time.Since(start) > 20*time.Second {
			cancel()
			return errors.New("timeout")
		}
	}
	cancel()
	if err := <-done; err != context.Canceled {
		return err
	}
	return nil
}

// ---- parent-side harness --------------------------------------------------------------------------------------

type child struct {
	out    map[string]any
	killed bool
}

func runProc(t *testing.T, dir, cmd, args, fault string) child {
	return runProcWith(t, dir, cmd, args, fault, "")
}

// runProcWith is runProc with the child's process-default VM size ("vcpus memory"), as after a configuration change.
func runProcWith(t *testing.T, dir, cmd, args, fault, defaults string) child {
	t.Helper()
	c := exec.Command(os.Args[0], "-test.run=^$") // #nosec G204 -- re-executes this test binary
	c.Env = append(os.Environ(), childEnv+"="+cmd, "SVAVYOM_OP_DIR="+dir, "SVAVYOM_OP_ARGS="+args, "SVAVYOM_OP_FAULT="+fault,
		"SVAVYOM_OP_DEFAULTS="+defaults)
	stdout, err := c.Output()
	res := child{out: map[string]any{}}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		if ws, ok := ee.Sys().(syscall.WaitStatus); ok && ws.Signaled() && ws.Signal() == syscall.SIGKILL {
			res.killed = true
		} else {
			t.Fatalf("child %s failed: %v\n%s", cmd, err, stdout)
		}
	} else if err != nil {
		t.Fatal(err)
	}
	sc := bufio.NewScanner(strings.NewReader(string(stdout)))
	for sc.Scan() {
		_ = json.Unmarshal(sc.Bytes(), &res.out)
	}
	return res
}

type scenario struct {
	t   *testing.T
	dir string
}

func newScenario(t *testing.T) *scenario { return &scenario{t: t, dir: t.TempDir()} }

func (s *scenario) seed(name string, st hypervisor.State) { s.seedSpec(name, st, 1, 512) }

// seedSpec puts a domain on the host without any command (it existed before, or someone else made it).
func (s *scenario) seedSpec(name string, st hypervisor.State, vcpus, mem int) {
	h := &durableHost{dir: s.dir}
	state := h.load()
	state[name] = hostDom{State: st, VCPUs: vcpus, MemoryMiB: mem}
	h.save(state)
}

func (s *scenario) submit(typ Type, vm, key string) string {
	r := runProc(s.t, s.dir, "submit", fmt.Sprintf("%s %s %s", typ, vm, key), "")
	id, _ := r.out["id"].(string)
	if id == "" {
		s.t.Fatalf("submit: %v", r.out)
	}
	return id
}

// op reads the operation from the database file the way an operator (or the next process) would.
func (s *scenario) op(id string) Operation {
	db, err := sqlitedb.Open(filepath.Join(s.dir, "ops.db"))
	if err != nil {
		s.t.Fatal(err)
	}
	defer db.Close()
	st, err := OpenSQLite(context.Background(), db)
	if err != nil {
		s.t.Fatal(err)
	}
	op, ok, err := st.Get(id)
	if err != nil || !ok {
		s.t.Fatalf("get %s: %v %v", id, ok, err)
	}
	return op
}

// sent counts host commands that reached the host and were applied (not rejected, not no-ops).
func (s *scenario) sent(op, name string) int {
	b, _ := os.ReadFile(filepath.Join(s.dir, "host.log"))
	n := 0
	for _, l := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		f := strings.Fields(l)
		if len(f) == 3 && f[0] == op && f[1] == name && f[2] != "rejected" && f[2] != "noop" {
			n++
		}
	}
	return n
}

func (s *scenario) received() int {
	b, _ := os.ReadFile(filepath.Join(s.dir, "host.log"))
	if strings.TrimSpace(string(b)) == "" {
		return 0
	}
	return len(strings.Split(strings.TrimSpace(string(b)), "\n"))
}

// seedOwn puts on the host exactly the VM that operation op would have created (its own late completion).
func (s *scenario) seedOwn(op Operation) {
	h := &durableHost{dir: s.dir}
	state := h.load()
	state[op.ResourceID] = hostDom{State: hypervisor.StateShutoff, VCPUs: op.Spec.VCPUs, MemoryMiB: op.Spec.MemoryMiB, UUID: op.Spec.UUID, Fingerprint: op.Spec.Fingerprint}
	h.save(state)
}

func (s *scenario) domain(name string) (hypervisor.State, bool) {
	st, ok := (&durableHost{dir: s.dir}).load()[name]
	return st.State, ok
}

func (s *scenario) domainSpec(name string) (int, int) {
	st := (&durableHost{dir: s.dir}).load()[name]
	return st.VCPUs, st.MemoryMiB
}

var hostOp = map[Type]string{Create: "define", Start: "start", Stop: "stop", Delete: "undefine"}

// prepare seeds the host so that typ on vm-a is a meaningful operation.
func (s *scenario) prepare(typ Type) {
	switch typ {
	case Start, Delete:
		s.seed("vm-a", hypervisor.StateShutoff)
	case Stop:
		s.seed("vm-a", hypervisor.StateRunning)
	}
}

func (s *scenario) assertApplied(typ Type) {
	st, ok := s.domain("vm-a")
	switch typ {
	case Create, Stop:
		if !ok || st != hypervisor.StateShutoff {
			s.t.Fatalf("%s: host %v %v", typ, st, ok)
		}
	case Start:
		if !ok || st != hypervisor.StateRunning {
			s.t.Fatalf("%s: host %v %v", typ, st, ok)
		}
	case Delete:
		if ok {
			s.t.Fatalf("%s: domain still present", typ)
		}
	}
}

// ---- the scenarios ----------------------------------------------------------------------------------------------

func TestCrash_BeforeHostCommand_RestartRetriesOnceWithoutDuplicate(t *testing.T) {
	for _, typ := range []Type{Create, Start, Stop, Delete} {
		t.Run(string(typ), func(t *testing.T) {
			s := newScenario(t)
			s.prepare(typ)
			id := s.submit(typ, "vm-a", "k1")
			r := runProc(t, s.dir, "run", id, "kill_before")
			if !r.killed {
				t.Fatalf("child was not killed: %v", r.out)
			}
			if got := s.op(id); got.Status != Running || got.Attempts != 1 {
				t.Fatalf("attempt must be persisted before the host is touched: %+v", got)
			}
			if s.received() != 0 {
				t.Fatal("the host saw a command although the process died before sending it")
			}
			if r := runProc(t, s.dir, "worker", "", "none"); r.out["err"] != "" {
				t.Fatalf("worker: %v", r.out)
			}
			got := s.op(id)
			if got.Status != Succeeded || got.Attempts != 2 {
				t.Fatalf("after restart: %+v", got)
			}
			if n := s.sent(hostOp[typ], "vm-a"); n != 1 {
				t.Fatalf("%s applied %d times", hostOp[typ], n)
			}
			s.assertApplied(typ)
		})
	}
}

func TestCrash_AfterHostActedBeforeResultPersisted_ReconciledNotResent(t *testing.T) {
	for _, typ := range []Type{Create, Start, Stop, Delete} {
		t.Run(string(typ), func(t *testing.T) {
			s := newScenario(t)
			s.prepare(typ)
			id := s.submit(typ, "vm-a", "k1")
			r := runProc(t, s.dir, "run", id, "kill_after")
			if !r.killed {
				t.Fatalf("child was not killed: %v", r.out)
			}
			if got := s.op(id); got.Status != Running || got.Attempts != 1 {
				t.Fatalf("crash must leave a running record: %+v", got)
			}
			before := s.received()
			if r := runProc(t, s.dir, "worker", "", "none"); r.out["err"] != "" {
				t.Fatalf("worker: %v", r.out)
			}
			if got := s.op(id); got.Status != Succeeded || got.Attempts != 1 {
				t.Fatalf("after reconcile: %+v", got)
			}
			if s.received() != before {
				t.Fatalf("recovery sent %d extra host command(s)", s.received()-before)
			}
			if n := s.sent(hostOp[typ], "vm-a"); n != 1 {
				t.Fatalf("%s applied %d times", hostOp[typ], n)
			}
			s.assertApplied(typ)
		})
	}
}

func TestCrash_TimeoutWhereActionWasApplied(t *testing.T) {
	for _, typ := range []Type{Create, Start, Stop, Delete} {
		t.Run(string(typ), func(t *testing.T) {
			s := newScenario(t)
			s.prepare(typ)
			id := s.submit(typ, "vm-a", "k1")
			r := runProc(t, s.dir, "run", id, "timeout_applied")
			if r.out["status"] != string(Running) {
				t.Fatalf("a timeout must leave the outcome unknown (running): %v", r.out)
			}
			if got := s.op(id); got.Status != Running || got.ErrorCategory != CatTimeout {
				t.Fatalf("%+v", got)
			}
			if r := runProc(t, s.dir, "worker", "", "none"); r.out["err"] != "" {
				t.Fatalf("worker: %v", r.out)
			}
			if got := s.op(id); got.Status != Succeeded || got.Attempts != 1 {
				t.Fatalf("%+v", got)
			}
			if n := s.sent(hostOp[typ], "vm-a"); n != 1 {
				t.Fatalf("%s applied %d times", hostOp[typ], n)
			}
		})
	}
}

func TestCrash_TimeoutWhereActionWasNotApplied(t *testing.T) {
	for _, typ := range []Type{Create, Start, Stop, Delete} {
		t.Run(string(typ), func(t *testing.T) {
			s := newScenario(t)
			s.prepare(typ)
			id := s.submit(typ, "vm-a", "k1")
			r := runProc(t, s.dir, "run", id, "timeout_not_applied")
			if r.out["status"] != string(Running) {
				t.Fatalf("%v", r.out)
			}
			if s.received() != 0 {
				t.Fatal("host saw the command")
			}
			if r := runProc(t, s.dir, "worker", "", "none"); r.out["err"] != "" {
				t.Fatalf("worker: %v", r.out)
			}
			got := s.op(id)
			if got.Status != Succeeded || got.Attempts != 2 {
				t.Fatalf("observed absent -> exactly one further attempt: %+v", got)
			}
			if n := s.sent(hostOp[typ], "vm-a"); n != 1 {
				t.Fatalf("%s applied %d times", hostOp[typ], n)
			}
			s.assertApplied(typ)
		})
	}
}

func TestCrash_ObservationFailure_NeverGuessesAndStaysRecoverable(t *testing.T) {
	s := newScenario(t)
	id := s.submit(Create, "vm-a", "k1")
	if r := runProc(t, s.dir, "run", id, "kill_after"); !r.killed {
		t.Fatalf("not killed: %v", r.out)
	}
	received := s.received()
	for i := 0; i < 2; i++ { // the agent is down during recovery, twice
		r := runProc(t, s.dir, "reconcile", "", "blind")
		if r.out["err"] != CatUnavailable || r.out["resolved"].(float64) != 0 {
			t.Fatalf("blind reconcile must report failure and resolve nothing: %v", r.out)
		}
		if got := s.op(id); got.Status != Running {
			t.Fatalf("state was guessed: %+v", got)
		}
	}
	if s.received() != received {
		t.Fatal("host commands were sent while the outcome was unknown")
	}
	if r := runProc(t, s.dir, "worker", "", "none"); r.out["err"] != "" {
		t.Fatal(r.out)
	}
	if got := s.op(id); got.Status != Succeeded || got.Attempts != 1 || s.sent("define", "vm-a") != 1 {
		t.Fatalf("recovery: %+v define=%d", got, s.sent("define", "vm-a"))
	}
}

func TestCrash_BoundedRetryExhaustionSurvivesRestarts(t *testing.T) {
	s := newScenario(t)
	id := s.submit(Create, "vm-a", "k1")
	runProc(t, s.dir, "run", id, "unavailable_always") // attempt 1, then the process exits
	if got := s.op(id); got.Status != RetryableFailure || got.Attempts != 1 {
		t.Fatalf("%+v", got)
	}
	runProc(t, s.dir, "worker", "", "unavailable_always") // a new process makes attempts 2 and 3
	got := s.op(id)
	if got.Status != RetryableFailure || got.Attempts != 3 || got.ErrorCategory != CatUnavailable {
		t.Fatalf("attempt count must persist across restarts and stop at the bound: %+v", got)
	}
	// The host comes back and the process restarts again: the exhausted operation is not retried automatically.
	runProc(t, s.dir, "worker", "", "none")
	if again := s.op(id); again.Attempts != 3 || again.Status != RetryableFailure {
		t.Fatalf("exhausted operation was retried: %+v", again)
	}
	if s.received() != 0 {
		t.Fatalf("host saw %d command(s) although every attempt failed before delivery", s.received())
	}
}

func TestCrash_IdempotencyKeySurvivesKillAndReplayDoesNotDuplicate(t *testing.T) {
	s := newScenario(t)
	id := s.submit(Create, "vm-a", "same-key")
	if r := runProc(t, s.dir, "run", id, "kill_after"); !r.killed {
		t.Fatal("not killed")
	}
	if replay := s.submit(Create, "vm-a", "same-key"); replay != id {
		t.Fatalf("replay after a crash created %s, want %s", replay, id)
	}
	runProc(t, s.dir, "worker", "", "none")
	if n := s.sent("define", "vm-a"); n != 1 {
		t.Fatalf("define applied %d times", n)
	}
}

func TestCrash_SecondProcessOnSameDatabaseIsRefused(t *testing.T) {
	s := newScenario(t)
	release, err := sqlitedb.LockProcess(filepath.Join(s.dir, "ops.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	r := runProc(t, s.dir, "worker", "", "none")
	if r.out["error"] != "open" {
		t.Fatalf("a second control-plane process must be refused: %v", r.out)
	}
}

// CT-PRODUCT-DELIVERY-003 s4/s5: a domain with the requested name proves nothing about who created it.
func TestCrash_PreexistingSameNameVMWithDifferentSpecDoesNotSatisfyCreate(t *testing.T) {
	for name, c := range map[string]struct {
		vcpus, mem int
		want       Status
		cat        string
	}{
		"different vcpus":               {2, 512, Failed, CatConflict},
		"different memory":              {1, 1024, Failed, CatConflict},
		"unknown spec":                  {0, 0, Failed, CatHostError},
		"foreign VM with the same size": {1, 512, Failed, CatConflict},
	} {
		t.Run(name, func(t *testing.T) {
			s := newScenario(t)
			id := s.submit(Create, "vm-a", "k1") // default definition 1 vCPU / 512 MiB, persisted now
			if r := runProc(t, s.dir, "run", id, "kill_before"); !r.killed {
				t.Fatal("not killed")
			}
			s.seedSpec("vm-a", hypervisor.StateShutoff, c.vcpus, c.mem) // someone else made a VM of that name meanwhile
			runProc(t, s.dir, "worker", "", "none")
			got := s.op(id)
			if got.Status != c.want || got.ErrorCategory != c.cat {
				t.Fatalf("%+v, want %s/%s", got, c.want, c.cat)
			}
			if s.received() != 0 {
				t.Fatalf("recovery sent %d host command(s)", s.received())
			}
			if v, m := s.domainSpec("vm-a"); v != c.vcpus || m != c.mem {
				t.Fatalf("the foreign VM was modified: %d/%d", v, m)
			}
		})
	}
}

func TestCrash_PendingCreateUsesItsPersistedSpecNotNewProcessDefaults(t *testing.T) {
	s := newScenario(t)
	r := runProcWith(t, s.dir, "submit", "create vm-a k1", "", "2 1024") // accepted under defaults 2 vCPU / 1024 MiB
	id, _ := r.out["id"].(string)
	if id == "" {
		t.Fatal(r.out)
	}
	if got := s.op(id); got.Spec.VCPUs != 2 || got.Spec.MemoryMiB != 1024 || got.Spec.UUID == "" {
		t.Fatalf("persisted spec %+v", got.Spec)
	}
	runProcWith(t, s.dir, "worker", "", "none", "8 4096") // restarted with different defaults
	if got := s.op(id); got.Status != Succeeded {
		t.Fatalf("%+v", got)
	}
	if v, m := s.domainSpec("vm-a"); v != 2 || m != 1024 {
		t.Fatalf("host VM was created with %d/%d, the persisted spec was 2/1024", v, m)
	}
}

// CT-PRODUCT-DELIVERY-004 s14: restart while retryable from an unknown create. The first attempt dies before the host sees
// it; recovery finds nothing (retryable, outcome unknown); the "late original" then appears while the process is down;
// the restarted manager must observe before it retransmits and resolve by the persisted definition, sending nothing.
func TestCrash_RestartWhileRetryableFromUnknownCreateObservesBeforeRetransmitting(t *testing.T) {
	for name, c := range map[string]struct {
		vcpus, mem int
		want       Status
		cat        string
	}{
		"late original with the persisted definition": {1, 512, Succeeded, ""},
		"a different VM appeared":                     {2, 512, Failed, CatConflict},
	} {
		t.Run(name, func(t *testing.T) {
			s := newScenario(t)
			id := s.submit(Create, "vm-a", "k1")
			if r := runProc(t, s.dir, "run", id, "kill_before"); !r.killed {
				t.Fatal("not killed")
			}
			if r := runProc(t, s.dir, "reconcile", "", "none"); r.out["err"] != "" {
				t.Fatal(r.out)
			}
			if got := s.op(id); got.Status != RetryableFailure || !got.UnknownOutcome {
				t.Fatalf("recovery must leave a retryable create marked unknown: %+v", got)
			}
			if name == "late original with the persisted definition" {
				s.seedOwn(s.op(id))
			} else {
				s.seedSpec("vm-a", hypervisor.StateShutoff, c.vcpus, c.mem)
			}
			runProc(t, s.dir, "worker", "", "none") // a fresh process
			got := s.op(id)
			if got.Status != c.want || got.ErrorCategory != c.cat {
				t.Fatalf("%+v, want %s/%s", got, c.want, c.cat)
			}
			if s.received() != 0 {
				t.Fatalf("the restarted manager sent %d host command(s) instead of observing first", s.received())
			}
		})
	}
}

func TestCrash_FirstAttemptMeetingAPreexistingSameSpecVMIsAConflict(t *testing.T) {
	s := newScenario(t)
	s.seedSpec("vm-a", hypervisor.StateShutoff, 1, 512)
	id := s.submit(Create, "vm-a", "k1")
	runProc(t, s.dir, "worker", "", "none")
	if got := s.op(id); got.Status != Failed || got.ErrorCategory != CatConflict || got.UnknownOutcome {
		t.Fatalf("%+v", got)
	}
}
