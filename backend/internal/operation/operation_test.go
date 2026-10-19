package operation

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"example.invalid/dedicatedcloud/backend/internal/hypervisor"
	"example.invalid/dedicatedcloud/backend/internal/hypervisor/fake"
)

// ---- helpers --------------------------------------------------------------------------------------------------

type owners map[string]string // project -> owner actor

func (o owners) Authorize(a Actor, project string, _ Type) error {
	if a.ID != "" && o[project] == a.ID {
		return nil
	}
	return fail(CatForbidden)
}

type sink struct {
	mu     sync.Mutex
	events []AuditEvent
}

func (s *sink) Emit(e AuditEvent) { s.mu.Lock(); s.events = append(s.events, e); s.mu.Unlock() }

type env struct {
	store *MemStore
	hv    *fake.Hypervisor
	audit *sink
	m     *Manager
}

var alice = Actor{ID: "alice"}

func newEnv(t *testing.T) *env {
	t.Helper()
	e := &env{store: NewMemStore(), hv: fake.New(), audit: &sink{}}
	e.m = e.manager(e.hv)
	return e
}

// manager builds a (re)started manager over the same store, which is how a process restart is simulated.
func (e *env) manager(hv hypervisor.Hypervisor) *Manager {
	return NewManager(e.store, hv, owners{"p1": "alice", "p2": "bob"}, e.audit, Config{
		MaxAttempts: 3,
		// Sequential ids that survive a simulated restart (the store outlives the manager).
		NewID: func() (string, error) { return fmt.Sprintf("op-%04d", len(e.store.order)+1), nil },
	})
}

func req(t Type, id, key string) Request {
	return Request{ProjectID: "p1", Type: t, Kind: KindVM, ResourceID: id, IdempotencyKey: key}
}

func mustSubmit(t *testing.T, m *Manager, r Request) Operation {
	t.Helper()
	op, err := m.Submit(alice, r)
	if err != nil {
		t.Fatalf("submit %+v: %v", r, err)
	}
	return op
}

func mustRun(t *testing.T, m *Manager, id string, want Status) Operation {
	t.Helper()
	op, err := m.Run(context.Background(), id)
	if err != nil {
		t.Fatalf("run %s: %v", id, err)
	}
	if op.Status != want {
		t.Fatalf("run %s: status %s, want %s", id, op.Status, want)
	}
	return op
}

func mutations(hv *fake.Hypervisor, op string) int {
	n := 0
	for _, c := range hv.Calls() {
		if c.Op == op && !strings.HasPrefix(c.Outcome, "fault:") && c.Outcome != "noop" && !strings.Contains(c.Outcome, "conflict") {
			n++
		}
	}
	return n
}

// lookupFails wraps a hypervisor so that Lookup (not injectable in the fake) fails with a typed category.
type lookupFails struct {
	hypervisor.Hypervisor
	cat hypervisor.Category
}

func (l lookupFails) Lookup(context.Context, string) (hypervisor.Domain, error) {
	return hypervisor.Domain{}, hypervisor.NewError(l.cat, "lookup", "x", "injected")
}

// failingStore fails the Nth Update after arming, simulating a crash between a host command and its record.
type failingStore struct {
	*MemStore
	failFrom int // fail every Update from this call number on (1-based); 0 = never
	updates  int
}

func (f *failingStore) Update(op Operation) (Operation, error) {
	f.updates++
	if f.failFrom > 0 && f.updates >= f.failFrom {
		return Operation{}, errors.New("store down")
	}
	return f.MemStore.Update(op)
}

// ---- AC01: normal path, persisted fields ------------------------------------------------------------------------

func TestNormalLifecyclePersistsStatusAndFields(t *testing.T) {
	e := newEnv(t)
	steps := []struct {
		typ   Type
		state hypervisor.State
		gone  bool
	}{{Create, hypervisor.StateShutoff, false}, {Start, hypervisor.StateRunning, false}, {Stop, hypervisor.StateShutoff, false}, {Delete, "", true}}
	for i, s := range steps {
		op := mustSubmit(t, e.m, req(s.typ, "vm-a", fmt.Sprintf("k%d", i)))
		if op.Status != Pending || op.Attempts != 0 || op.RequestedBy != "alice" || op.ProjectID != "p1" ||
			op.ResourceKind != KindVM || op.Generation != 1 || op.CreatedAt.IsZero() || op.ErrorCategory != "" {
			t.Fatalf("submitted record wrong: %+v", op)
		}
		if len(e.hv.Calls()) != i {
			t.Fatalf("Submit must not touch the host")
		}
		done := mustRun(t, e.m, op.ID, Succeeded)
		if done.Attempts != 1 || done.Generation <= op.Generation || done.ErrorCategory != "" {
			t.Fatalf("settled record wrong: %+v", done)
		}
		got, err := e.m.Get(alice, op.ID)
		if err != nil || got != done {
			t.Fatalf("persisted != returned: %+v vs %+v (%v)", got, done, err)
		}
		snap := e.hv.Snapshot()
		if st, ok := snap["vm-a"]; s.gone == ok || (ok && st != s.state) {
			t.Fatalf("host state after %s: %v", s.typ, snap)
		}
	}
	if again := mustRun(t, e.m, "op-0001", Succeeded); again.Attempts != 1 {
		t.Fatal("running a terminal operation must be a no-op")
	}
}

func TestOperationFieldsMatchTheContract(t *testing.T) {
	raw, err := os.ReadFile("../../../contracts/interfaces/resources.json")
	if err != nil {
		t.Fatal(err)
	}
	var c struct {
		Status map[string]struct{ Terminal bool } `json:"operation_status"`
		Fields []string                           `json:"operation_persisted_fields"`
	}
	if err := json.Unmarshal(raw, &c); err != nil {
		t.Fatal(err)
	}
	for _, s := range []Status{Pending, Running, Succeeded, Failed, RetryableFailure, Cancelled} {
		spec, ok := c.Status[string(s)]
		if !ok || spec.Terminal != s.Terminal() {
			t.Errorf("status %s disagrees with resources.json", s)
		}
	}
	if len(c.Status) != 6 {
		t.Errorf("resources.json has %d statuses, package has 6", len(c.Status))
	}
	want := map[string]bool{}
	for _, f := range c.Fields {
		want[f] = true
	}
	b, _ := json.Marshal(Operation{})
	var have map[string]any
	_ = json.Unmarshal(b, &have)
	snake := map[string]string{"ID": "id", "ProjectID": "project_id", "ResourceKind": "resource_kind", "ResourceID": "resource_id", "Type": "type",
		"Status": "status", "IdempotencyKey": "idempotency_key", "RequestedBy": "requested_by", "Generation": "generation",
		"Attempts": "attempts", "ErrorCategory": "error_category", "CreatedAt": "created_at", "UpdatedAt": "updated_at"}
	if len(have) != len(want) {
		t.Fatalf("Operation has %d fields, contract %d", len(have), len(want))
	}
	for k := range have {
		if !want[snake[k]] {
			t.Errorf("field %s not in operation_persisted_fields", k)
		}
	}
}

// ---- AC02: typed failures, authorization, idempotency, audit --------------------------------------------------

func TestInvalidInputIsTypedAndHasNoSideEffects(t *testing.T) {
	e := newEnv(t)
	bad := []Request{
		{ProjectID: "p1", Type: "restart", Kind: KindVM, ResourceID: "vm-a", IdempotencyKey: "k"}, // not a submit type
		{ProjectID: "p1", Type: "destroy", Kind: KindVM, ResourceID: "vm-a", IdempotencyKey: "k"},
		{ProjectID: "p1", Type: Reboot, Kind: KindVM, ResourceID: "vm-a", IdempotencyKey: "k", Spec: CreateSpec{VCPUs: 1, MemoryMiB: 512}}, // a spec on a non-create
		{ProjectID: "p1", Type: Create, Kind: "Volume", ResourceID: "v", IdempotencyKey: "k"},
		{ProjectID: "p1", Type: Create, Kind: KindVM, ResourceID: "../etc", IdempotencyKey: "k"},
		{ProjectID: "p1", Type: Create, Kind: KindVM, ResourceID: "vm-a", IdempotencyKey: ""},
		{ProjectID: "p1", Type: Create, Kind: KindVM, ResourceID: "vm-a", IdempotencyKey: strings.Repeat("k", 64)},
		{ProjectID: "p1", Type: Create, Kind: KindVM, ResourceID: "", IdempotencyKey: "k"},
	}
	for _, r := range bad {
		if _, err := e.m.Submit(alice, r); CategoryOf(err) != CatValidation {
			t.Errorf("%+v: category %q, want validation", r, CategoryOf(err))
		}
	}
	if ops, _ := e.store.NonTerminal(); len(ops) != 0 || len(e.hv.Calls()) != 0 {
		t.Fatal("invalid input created state")
	}
}

func TestAuthorizationIsDenyByDefaultAndDoesNotLeak(t *testing.T) {
	e := newEnv(t)
	op := mustSubmit(t, e.m, req(Create, "vm-a", "k1"))
	bob := Actor{ID: "bob"}
	if _, err := e.m.Submit(bob, req(Create, "vm-b", "k2")); CategoryOf(err) != CatForbidden {
		t.Errorf("bob in p1: %q", CategoryOf(err))
	}
	if _, err := e.m.Submit(Actor{}, req(Create, "vm-b", "k2")); CategoryOf(err) != CatForbidden {
		t.Errorf("anonymous: %q", CategoryOf(err))
	}
	// An invalid request from an unauthorized caller is forbidden, not validation: nothing leaks.
	if _, err := e.m.Submit(bob, Request{ProjectID: "p1", Type: "x"}); CategoryOf(err) != CatForbidden {
		t.Errorf("unauthorized + invalid: %q", CategoryOf(err))
	}
	// Existing and nonexistent operations are indistinguishable to a non-owner.
	_, errExisting := e.m.Get(bob, op.ID)
	_, errMissing := e.m.Get(bob, "op-nope")
	if CategoryOf(errExisting) != CatNotFound || CategoryOf(errMissing) != CatNotFound {
		t.Errorf("existence leak: %v / %v", errExisting, errMissing)
	}
	if _, err := e.m.Cancel(bob, op.ID); CategoryOf(err) != CatNotFound {
		t.Errorf("foreign cancel: %q", CategoryOf(err))
	}
	deny := NewManager(e.store, e.hv, nil, nil, Config{})
	if _, err := deny.Submit(alice, req(Create, "vm-c", "k3")); CategoryOf(err) != CatForbidden {
		t.Errorf("nil authorizer must deny: %q", CategoryOf(err))
	}
	if len(e.hv.Calls()) != 0 {
		t.Fatal("a denied request reached the host")
	}
}

func TestAuditNeverRecordsMalformedCallerInput(t *testing.T) {
	e := newEnv(t)
	hostile := "p1\n{\"forged\":true}" + strings.Repeat("A", 4096)
	_, _ = e.m.Submit(alice, Request{ProjectID: hostile, Type: Create, Kind: KindVM, ResourceID: "vm-a", IdempotencyKey: "k"})
	for _, ev := range e.audit.events {
		if strings.Contains(ev.ProjectID, "forged") || len(ev.ProjectID) > 63 {
			t.Fatalf("audit event carries unvalidated caller input: %q", ev.ProjectID)
		}
	}
	if len(e.audit.events) == 0 {
		t.Fatal("rejection must still be audited")
	}
}

func TestIdempotentReplayAndKeyReuseConflict(t *testing.T) {
	e := newEnv(t)
	first := mustSubmit(t, e.m, req(Create, "vm-a", "k1"))
	mustRun(t, e.m, first.ID, Succeeded)
	replay := mustSubmit(t, e.m, req(Create, "vm-a", "k1"))
	if replay.ID != first.ID || replay.Status != Succeeded {
		t.Fatalf("replay must return the existing operation: %+v", replay)
	}
	if _, err := e.m.Submit(alice, req(Delete, "vm-a", "k1")); CategoryOf(err) != CatConflict {
		t.Fatalf("same key, other payload: %q", CategoryOf(err))
	}
	if n := mutations(e.hv, "define"); n != 1 {
		t.Fatalf("define applied %d times", n)
	}
}

func TestHostFailuresMapToTypedCategories(t *testing.T) {
	e := newEnv(t)
	// start of a missing domain -> failed/not_found; create twice -> failed/conflict; injected host error -> host_error
	a := mustSubmit(t, e.m, req(Start, "ghost", "k1"))
	if op := mustRun(t, e.m, a.ID, Failed); op.ErrorCategory != CatNotFound {
		t.Errorf("start missing: %q", op.ErrorCategory)
	}
	mustRun(t, e.m, mustSubmit(t, e.m, req(Create, "vm-a", "k2")).ID, Succeeded)
	if op := mustRun(t, e.m, mustSubmit(t, e.m, req(Create, "vm-a", "k3")).ID, Failed); op.ErrorCategory != CatConflict {
		t.Errorf("create twice: %q", op.ErrorCategory)
	}
	e.hv.Inject(len(e.hv.Calls())+1, fake.FaultError, false)
	if op := mustRun(t, e.m, mustSubmit(t, e.m, req(Start, "vm-a", "k4")).ID, Failed); op.ErrorCategory != CatHostError {
		t.Errorf("host error: %q", op.ErrorCategory)
	}
	if st := e.hv.Snapshot()["vm-a"]; st != hypervisor.StateShutoff {
		t.Errorf("a failed start changed the domain: %v", st)
	}
	// Deleting a running VM is refused, not forced.
	mustRun(t, e.m, mustSubmit(t, e.m, req(Start, "vm-a", "k5")).ID, Succeeded)
	if op := mustRun(t, e.m, mustSubmit(t, e.m, req(Delete, "vm-a", "k6")).ID, Failed); op.ErrorCategory != CatConflict {
		t.Errorf("delete running: %q", op.ErrorCategory)
	}
	if _, ok := e.hv.Snapshot()["vm-a"]; !ok {
		t.Fatal("delete of a running VM destroyed it")
	}
}

func TestCancelOnlyBeforeHostWork(t *testing.T) {
	e := newEnv(t)
	op := mustSubmit(t, e.m, req(Create, "vm-a", "k1"))
	c, err := e.m.Cancel(alice, op.ID)
	if err != nil || c.Status != Cancelled {
		t.Fatalf("cancel pending: %+v %v", c, err)
	}
	if again, err := e.m.Cancel(alice, op.ID); err != nil || again.Status != Cancelled {
		t.Fatalf("cancel is idempotent: %+v %v", again, err)
	}
	if got, _ := e.m.Run(context.Background(), op.ID); got.Status != Cancelled || len(e.hv.Calls()) != 0 {
		t.Fatal("a cancelled operation ran")
	}
	done := mustSubmit(t, e.m, req(Create, "vm-b", "k2"))
	mustRun(t, e.m, done.ID, Succeeded)
	if _, err := e.m.Cancel(alice, done.ID); CategoryOf(err) != CatConflict {
		t.Fatalf("cancel terminal: %q", CategoryOf(err))
	}
}

func TestAuditHasNoSecretsAndCoversTransitions(t *testing.T) {
	e := newEnv(t)
	op := mustSubmit(t, e.m, req(Create, "vm-a", "super-secret-key"))
	mustRun(t, e.m, op.ID, Succeeded)
	_, _ = e.m.Submit(Actor{ID: "bob"}, req(Create, "vm-z", "k9"))
	blob, _ := json.Marshal(e.audit.events)
	for _, bad := range []string{"super-secret-key", "k9"} {
		if strings.Contains(string(blob), bad) {
			t.Errorf("audit leaks %q: %s", bad, blob)
		}
	}
	var seen []string
	for _, ev := range e.audit.events {
		seen = append(seen, ev.Event+":"+ev.Outcome)
	}
	for _, want := range []string{"operation.submit:accepted", "operation.status:running", "operation.status:succeeded", "operation.submit:rejected"} {
		if !strings.Contains(strings.Join(seen, " "), want) {
			t.Errorf("missing audit event %s in %v", want, seen)
		}
	}
}

// ---- AC03: fault injection, one test per failure-matrix row ------------------------------------------------------

// matrixCoverage maps every row of contracts/interfaces/failure-matrix.json to the tests that exercise it.
var matrixCoverage = map[string][]string{
	"api-restart":               {"TestFault_APIRestart_ReplayReturnsExistingOperation"},
	"operation-manager-restart": {"TestFault_OperationManagerRestart_CrashAfterHostApplied", "TestFault_OperationManagerRestart_CrashBeforeHostCommand"},
	"agent-timeout":             {"TestFault_AgentTimeout_AppliedThenReconciled", "TestFault_AgentTimeout_NotAppliedThenRetried"},
	"agent-unavailable":         {"TestFault_AgentUnavailable_BoundedRetry"},
	"host-agent-crash":          {"TestFault_HostAgentCrash_ObservationFailureNeverGuesses"},
	"libvirt-unavailable":       {"TestFault_LibvirtUnavailable_NoPartialMutation"},
}

func TestEveryFailureMatrixRowHasAFaultTest(t *testing.T) {
	raw, err := os.ReadFile("../../../contracts/interfaces/failure-matrix.json")
	if err != nil {
		t.Fatal(err)
	}
	var fm struct {
		Rows map[string]json.RawMessage `json:"rows"`
	}
	if err := json.Unmarshal(raw, &fm); err != nil {
		t.Fatal(err)
	}
	for row := range fm.Rows {
		if len(matrixCoverage[row]) == 0 {
			t.Errorf("failure-matrix row %q has no fault-injection test", row)
		}
	}
	for row := range matrixCoverage {
		if _, ok := fm.Rows[row]; !ok {
			t.Errorf("coverage names unknown row %q", row)
		}
	}
	src, _ := os.ReadFile("operation_test.go")
	for row, names := range matrixCoverage {
		for _, n := range names {
			if !strings.Contains(string(src), "func "+n+"(") {
				t.Errorf("row %q names missing test %s", row, n)
			}
		}
	}
}

func TestFault_APIRestart_ReplayReturnsExistingOperation(t *testing.T) {
	e := newEnv(t)
	first := mustSubmit(t, e.m, req(Create, "vm-a", "k1"))
	restarted := e.manager(e.hv) // the API process restarts; the client retries with the same key
	again, err := restarted.Submit(alice, req(Create, "vm-a", "k1"))
	if err != nil || again.ID != first.ID {
		t.Fatalf("replay after restart: %+v %v", again, err)
	}
	mustRun(t, restarted, again.ID, Succeeded)
	if n := mutations(e.hv, "define"); n != 1 {
		t.Fatalf("define applied %d times", n)
	}
}

func TestFault_OperationManagerRestart_CrashAfterHostApplied(t *testing.T) {
	// The host acts, then the manager dies before it can record the outcome (the store rejects the final write).
	for _, typ := range []Type{Create, Start, Stop, Delete} {
		t.Run(string(typ), func(t *testing.T) {
			e := newEnv(t)
			prepare(t, e, typ)
			fs := &failingStore{MemStore: e.store}
			m := NewManager(fs, e.hv, owners{"p1": "alice"}, e.audit, Config{})
			op := mustSubmit(t, m, req(typ, "vm-a", "crash"))
			fs.failFrom = fs.updates + 2 // allow the `running` write, fail the settle write
			if _, err := m.Run(context.Background(), op.ID); err == nil {
				t.Fatal("expected the settle write to fail")
			}
			if got, _, _ := e.store.Get(op.ID); got.Status != Running || got.Attempts != 1 {
				t.Fatalf("crash must leave a running record with its attempt: %+v", got)
			}
			before := len(e.hv.Calls())
			restarted := e.manager(e.hv)
			if _, err := restarted.Run(context.Background(), op.ID); CategoryOf(err) != CatConflict {
				t.Fatalf("running op must refuse blind re-execution: %v", err)
			}
			res, err := restarted.Reconcile(context.Background())
			if err != nil || len(res) != 1 || res[0].Status != Succeeded {
				t.Fatalf("reconcile: %+v %v", res, err)
			}
			if len(e.hv.Calls()) != before {
				t.Fatalf("reconcile re-sent a host command: %v", e.hv.Calls()[before:])
			}
			assertApplied(t, e, typ)
		})
	}
}

func TestFault_OperationManagerRestart_CrashBeforeHostCommand(t *testing.T) {
	e := newEnv(t)
	fs := &failingStore{MemStore: e.store}
	m := NewManager(fs, e.hv, owners{"p1": "alice"}, e.audit, Config{})
	op := mustSubmit(t, m, req(Create, "vm-a", "k1"))
	fs.failFrom = fs.updates + 1 // the very first write (-> running) is lost: nothing reached the host
	if _, err := m.Run(context.Background(), op.ID); err == nil {
		t.Fatal("expected failure")
	}
	if len(e.hv.Calls()) != 0 {
		t.Fatal("host command sent before the attempt was recorded")
	}
	restarted := e.manager(e.hv)
	mustRun(t, restarted, op.ID, Succeeded) // still pending: a normal run
}

func TestFault_AgentTimeout_AppliedThenReconciled(t *testing.T) {
	for _, typ := range []Type{Create, Start, Stop, Delete} {
		t.Run(string(typ), func(t *testing.T) {
			e := newEnv(t)
			prepare(t, e, typ)
			op := mustSubmit(t, e.m, req(typ, "vm-a", "t1"))
			e.hv.Inject(len(e.hv.Calls())+1, fake.FaultTimeout, true) // host acted, caller saw a timeout
			got := mustRun(t, e.m, op.ID, Running)
			if got.ErrorCategory != CatTimeout {
				t.Fatalf("unknown outcome must be marked: %+v", got)
			}
			before := len(e.hv.Calls())
			res, err := e.m.Reconcile(context.Background())
			if err != nil || len(res) != 1 || res[0].Status != Succeeded || res[0].ErrorCategory != "" {
				t.Fatalf("reconcile: %+v %v", res, err)
			}
			if len(e.hv.Calls()) != before {
				t.Fatal("reconcile re-sent a command (duplicate side effect risk)")
			}
			assertApplied(t, e, typ)
		})
	}
}

func TestFault_AgentTimeout_NotAppliedThenRetried(t *testing.T) {
	for _, typ := range []Type{Create, Start, Stop, Delete} {
		t.Run(string(typ), func(t *testing.T) {
			e := newEnv(t)
			prepare(t, e, typ)
			op := mustSubmit(t, e.m, req(typ, "vm-a", "t2"))
			e.hv.Inject(len(e.hv.Calls())+1, fake.FaultTimeout, false) // host did not act
			mustRun(t, e.m, op.ID, Running)
			res, err := e.m.Reconcile(context.Background())
			if err != nil || len(res) != 1 || res[0].Status != RetryableFailure {
				t.Fatalf("reconcile: %+v %v", res, err)
			}
			done := mustRun(t, e.m, op.ID, Succeeded)
			if done.Attempts != 2 {
				t.Fatalf("attempts %d, want 2", done.Attempts)
			}
			assertApplied(t, e, typ)
		})
	}
}

func TestFault_AgentUnavailable_BoundedRetry(t *testing.T) {
	e := newEnv(t)
	op := mustSubmit(t, e.m, req(Create, "vm-a", "u1"))
	for i := 1; i <= 3; i++ {
		e.hv.Inject(len(e.hv.Calls())+1, fake.FaultConnLoss, false)
		got := mustRun(t, e.m, op.ID, RetryableFailure)
		if got.Attempts != i || got.ErrorCategory != CatUnavailable {
			t.Fatalf("attempt %d: %+v", i, got)
		}
	}
	before := len(e.hv.Calls())
	if got, err := e.m.Run(context.Background(), op.ID); CategoryOf(err) != CatUnavailable || got.Status != RetryableFailure {
		t.Fatalf("attempt limit: %+v %v", got, err)
	}
	if len(e.hv.Calls()) != before || len(e.hv.Snapshot()) != 0 {
		t.Fatal("work happened after the attempt limit")
	}
	// The operation can still be cancelled, and nothing was created.
	if c, err := e.m.Cancel(alice, op.ID); err != nil || c.Status != Cancelled {
		t.Fatalf("cancel retryable: %+v %v", c, err)
	}
}

func TestFault_HostAgentCrash_ObservationFailureNeverGuesses(t *testing.T) {
	e := newEnv(t)
	op := mustSubmit(t, e.m, req(Create, "vm-a", "c1"))
	e.hv.Inject(len(e.hv.Calls())+1, fake.FaultTimeout, true)
	mustRun(t, e.m, op.ID, Running)
	for _, cat := range []hypervisor.Category{hypervisor.Unavailable, hypervisor.Timeout, hypervisor.HostError} {
		blind := e.manager(lookupFails{Hypervisor: e.hv, cat: cat}) // agent still down during recovery
		res, err := blind.Reconcile(context.Background())
		if err == nil || len(res) != 0 {
			t.Fatalf("%s: reconcile must report failure, resolved nothing: %+v %v", cat, res, err)
		}
		if got, _, _ := e.store.Get(op.ID); got.Status != Running {
			t.Fatalf("%s: state was guessed: %+v", cat, got)
		}
	}
	res, err := e.manager(e.hv).Reconcile(context.Background()) // agent is back
	if err != nil || len(res) != 1 || res[0].Status != Succeeded {
		t.Fatalf("recovery: %+v %v", res, err)
	}
}

func TestFault_LibvirtUnavailable_NoPartialMutation(t *testing.T) {
	e := newEnv(t)
	prepare(t, e, Start)
	before := e.hv.Snapshot()
	op := mustSubmit(t, e.m, req(Start, "vm-a", "l1"))
	e.hv.Inject(len(e.hv.Calls())+1, fake.FaultConnLoss, false)
	mustRun(t, e.m, op.ID, RetryableFailure)
	after := e.hv.Snapshot()
	if len(after) != len(before) || after["vm-a"] != before["vm-a"] {
		t.Fatalf("unavailable libvirt changed host state: %v -> %v", before, after)
	}
}

func TestRunnersCannotBothClaimAnOperation(t *testing.T) {
	e := newEnv(t)
	op := mustSubmit(t, e.m, req(Create, "vm-a", "r1"))
	var wg sync.WaitGroup
	results := make([]error, 8)
	for i := range results {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, results[i] = e.m.Run(context.Background(), op.ID)
		}()
	}
	wg.Wait()
	if n := mutations(e.hv, "define"); n != 1 {
		t.Fatalf("define applied %d times under concurrent runners", n)
	}
	got, _, _ := e.store.Get(op.ID)
	if got.Status != Succeeded || got.Attempts != 1 {
		t.Fatalf("final record: %+v", got)
	}
}

func TestClockAndUpdatedAtAdvance(t *testing.T) {
	e := newEnv(t)
	tick := time.Unix(1000, 0).UTC()
	m := NewManager(e.store, e.hv, owners{"p1": "alice"}, nil, Config{Clock: func() time.Time { tick = tick.Add(time.Second); return tick }})
	op := mustSubmit(t, m, req(Create, "vm-a", "z1"))
	done := mustRun(t, m, op.ID, Succeeded)
	if !done.UpdatedAt.After(op.UpdatedAt) || !done.CreatedAt.Equal(op.CreatedAt) {
		t.Fatalf("timestamps: %+v -> %+v", op, done)
	}
}

// ---- scenario helpers --------------------------------------------------------------------------------------------

// prepare brings the fake to the state in which typ is a meaningful operation on vm-a.
func prepare(t *testing.T, e *env, typ Type) {
	t.Helper()
	ctx := context.Background()
	if typ == Create {
		return
	}
	if _, err := e.hv.Define(ctx, hypervisor.DomainSpec{Name: "vm-a", VCPUs: 1, MemoryMiB: 512}); err != nil {
		t.Fatal(err)
	}
	if typ == Stop {
		if err := e.hv.Start(ctx, "vm-a"); err != nil {
			t.Fatal(err)
		}
	}
}

func assertApplied(t *testing.T, e *env, typ Type) {
	t.Helper()
	snap := e.hv.Snapshot()
	switch typ {
	case Create, Stop:
		if snap["vm-a"] != hypervisor.StateShutoff {
			t.Fatalf("after %s: %v", typ, snap)
		}
	case Start:
		if snap["vm-a"] != hypervisor.StateRunning {
			t.Fatalf("after %s: %v", typ, snap)
		}
	case Delete:
		if _, ok := snap["vm-a"]; ok {
			t.Fatalf("after %s: %v", typ, snap)
		}
	}
	// Exactly one effective mutation of this kind was applied, whatever the number of attempts.
	op := map[Type]string{Create: "define", Start: "start", Stop: "stop", Delete: "undefine"}[typ]
	n := 0
	for _, c := range e.hv.Calls() {
		if c.Op == op && c.Domain == "vm-a" && (c.Outcome == "defined" || c.Outcome == "running" || c.Outcome == "shutoff" || c.Outcome == "undefined" ||
			strings.HasPrefix(c.Outcome, "defined+") || strings.HasPrefix(c.Outcome, "running+") || strings.HasPrefix(c.Outcome, "shutoff+") || strings.HasPrefix(c.Outcome, "undefined+")) {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("%s applied %d times, want exactly 1: %v", typ, n, e.hv.Calls())
	}
}
