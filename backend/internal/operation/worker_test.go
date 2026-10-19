package operation

import (
	"context"
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"example.invalid/dedicatedcloud/backend/internal/hypervisor"
	"example.invalid/dedicatedcloud/backend/internal/hypervisor/fake"
)

// gate wraps a hypervisor, tracks the highest number of simultaneous host calls and can hold calls open.
type gate struct {
	hypervisor.Hypervisor
	cur, max atomic.Int32
	hold     chan struct{} // when non-nil, mutating calls block until closed
	entered  chan string
}

func (g *gate) enter(name string) func() {
	n := g.cur.Add(1)
	for {
		m := g.max.Load()
		if n <= m || g.max.CompareAndSwap(m, n) {
			break
		}
	}
	if g.entered != nil {
		g.entered <- name
	}
	if g.hold != nil {
		<-g.hold
	}
	return func() { g.cur.Add(-1) }
}
func (g *gate) Define(ctx context.Context, s hypervisor.DomainSpec) (hypervisor.Domain, error) {
	defer g.enter(s.Name)()
	return g.Hypervisor.Define(ctx, s)
}
func (g *gate) Start(ctx context.Context, n string) error {
	defer g.enter(n)()
	return g.Hypervisor.Start(ctx, n)
}

func fastCfg() WorkerConfig {
	return WorkerConfig{Concurrency: 2, Poll: 10 * time.Millisecond, BackoffBase: 10 * time.Millisecond,
		BackoffMax: 40 * time.Millisecond, OpTimeout: 5 * time.Second, RecoverRetry: 10 * time.Millisecond}
}

func startWorker(t *testing.T, w *Worker) (stop func() error) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- w.Run(ctx) }()
	return func() error { cancel(); return <-done }
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func status(s Store, id string) Status { op, _, _ := s.Get(id); return op.Status }

func TestWorker_AdvancesQueuedOperationsInOrderPerResource(t *testing.T) {
	s, _, _ := sqliteStore(t)
	hv := fake.New()
	m := NewManager(s, hv, owners{"p1": "alice"}, nil, Config{})
	// Submitted out of "dependency" luck: create, start, stop on one VM must execute strictly in order.
	ids := []string{}
	for i, typ := range []Type{Create, Start, Stop} {
		ids = append(ids, mustSubmit(t, m, req(typ, "vm-a", fmt.Sprintf("k%d", i))).ID)
	}
	w := NewWorker(m, fastCfg())
	stop := startWorker(t, w)
	for _, id := range ids {
		id := id
		waitFor(t, id, func() bool { return status(s, id) == Succeeded })
	}
	if err := stop(); err != context.Canceled {
		t.Fatalf("shutdown: %v", err)
	}
	if hv.Snapshot()["vm-a"] != hypervisor.StateShutoff {
		t.Fatalf("host: %v", hv.Snapshot())
	}
}

func TestWorker_ConcurrencyIsBoundedAndNoGoroutinePerOperation(t *testing.T) {
	s, _, _ := sqliteStore(t)
	g := &gate{Hypervisor: fake.New(), hold: make(chan struct{}), entered: make(chan string, 64)}
	m := NewManager(s, g, owners{"p1": "alice"}, nil, Config{})
	const n = 40
	for i := 0; i < n; i++ {
		mustSubmit(t, m, req(Create, fmt.Sprintf("vm-%02d", i), fmt.Sprintf("k%d", i)))
	}
	before := runtime.NumGoroutine()
	cfg := fastCfg()
	cfg.Concurrency = 3
	stop := startWorker(t, NewWorker(m, cfg))
	for i := 0; i < 3; i++ {
		<-g.entered // three executors are inside the host
	}
	time.Sleep(100 * time.Millisecond) // give a faulty worker the chance to exceed the bound
	if c := g.cur.Load(); c != 3 {
		t.Fatalf("%d simultaneous host calls, want exactly 3", c)
	}
	if grown := runtime.NumGoroutine() - before; grown > 3+4 {
		t.Fatalf("%d goroutines added for %d queued operations", grown, n)
	}
	close(g.hold)
	go func() {
		for range g.entered {
		}
	}()
	waitFor(t, "drain", func() bool { ops, _ := s.NonTerminal(); return len(ops) == 0 })
	if err := stop(); err != context.Canceled {
		t.Fatal(err)
	}
	if g.max.Load() > 3 {
		t.Fatalf("max concurrency %d", g.max.Load())
	}
}

func TestWorker_TwoWorkersOnOneStoreNeverDuplicateAHostCommand(t *testing.T) {
	// Not a supported deployment (the process lock forbids it) but the CAS claim must still hold if it happens.
	s, _, _ := sqliteStore(t)
	hv := fake.New()
	mgr := func() *Manager { return NewManager(s, hv, owners{"p1": "alice"}, nil, Config{}) }
	const n = 30
	for i := 0; i < n; i++ {
		mustSubmit(t, mgr(), req(Create, fmt.Sprintf("vm-%02d", i), fmt.Sprintf("k%d", i)))
	}
	// Skip the second worker's startup reconcile on purpose: it would otherwise legitimately observe the first
	// worker's in-flight attempts. We only assert the claim, so give it an already-recovered state.
	w1, w2 := NewWorker(mgr(), fastCfg()), NewWorker(mgr(), fastCfg())
	stop1, stop2 := startWorker(t, w1), startWorker(t, w2)
	waitFor(t, "drain", func() bool { ops, _ := s.NonTerminal(); return len(ops) == 0 })
	_ = stop1()
	_ = stop2()
	defined := map[string]int{}
	for _, c := range hv.Calls() {
		if c.Op == "define" && c.Outcome != "noop" && c.Outcome != "conflict" && len(c.Outcome) > 0 && c.Outcome[0] != 'f' {
			defined[c.Domain]++
		}
	}
	for d, c := range defined {
		if c != 1 {
			t.Errorf("%s defined %d times", d, c)
		}
	}
}

func TestWorker_RetryBackoffIsBoundedAndExhaustionStopsRetrying(t *testing.T) {
	s, _, _ := sqliteStore(t)
	hv := fake.New()
	var now atomic.Int64
	now.Store(t0.UnixNano())
	clock := func() time.Time { return time.Unix(0, now.Load()).UTC() }
	m := NewManager(s, hv, owners{"p1": "alice"}, nil, Config{MaxAttempts: 3, Clock: clock})
	op := mustSubmit(t, m, req(Create, "vm-a", "k"))
	for i := 1; i <= 10; i++ {
		hv.Inject(i, fake.FaultConnLoss, false)
	}
	cfg := fastCfg()
	cfg.BackoffBase, cfg.BackoffMax, cfg.Poll = time.Minute, 4*time.Minute, 10*time.Millisecond
	w := NewWorker(m, cfg)
	if w.Backoff(1) != time.Minute || w.Backoff(2) != 2*time.Minute || w.Backoff(3) != 4*time.Minute || w.Backoff(30) != 4*time.Minute {
		t.Fatalf("backoff curve %v %v %v %v", w.Backoff(1), w.Backoff(2), w.Backoff(3), w.Backoff(30))
	}
	stop := startWorker(t, w)
	defer func() { _ = stop() }()
	attempts := func() int { o, _, _ := s.Get(op.ID); return o.Attempts }
	waitFor(t, "attempt 1", func() bool { return attempts() == 1 })
	time.Sleep(100 * time.Millisecond)
	if attempts() != 1 {
		t.Fatalf("retried before the backoff elapsed: %d", attempts())
	}
	now.Add(int64(time.Minute)) // attempt 2 becomes due
	w.Notify()
	waitFor(t, "attempt 2", func() bool { return attempts() == 2 })
	now.Add(int64(2 * time.Minute))
	w.Notify()
	waitFor(t, "attempt 3", func() bool { return attempts() == 3 })
	now.Add(int64(time.Hour)) // far past any backoff: the attempt limit, not time, stops it
	w.Notify()
	time.Sleep(150 * time.Millisecond)
	got, _, _ := s.Get(op.ID)
	if got.Attempts != 3 || got.Status != RetryableFailure || got.ErrorCategory != CatUnavailable {
		t.Fatalf("exhausted operation: %+v", got)
	}
	if n := mutations(hv, "define"); n != 0 {
		t.Fatalf("a connection-lost attempt mutated the host %d times", n)
	}
}

func TestWorker_TimeoutAppliedIsReconciledWithoutResend(t *testing.T) {
	for _, applied := range []bool{true, false} {
		t.Run(fmt.Sprintf("applied=%v", applied), func(t *testing.T) {
			s, _, _ := sqliteStore(t)
			hv := fake.New()
			m := NewManager(s, hv, owners{"p1": "alice"}, nil, Config{})
			op := mustSubmit(t, m, req(Create, "vm-a", "k"))
			hv.Inject(1, fake.FaultTimeout, applied)
			stop := startWorker(t, NewWorker(m, fastCfg()))
			defer func() { _ = stop() }()
			waitFor(t, "terminal", func() bool { return status(s, op.ID) == Succeeded })
			got, _, _ := s.Get(op.ID)
			wantAttempts := 1
			if !applied {
				wantAttempts = 2 // not applied: observed absent, retried once
			}
			if got.Attempts != wantAttempts {
				t.Fatalf("attempts %d, want %d", got.Attempts, wantAttempts)
			}
			if n := mutations(hv, "define"); n != 1 {
				t.Fatalf("define applied %d times", n)
			}
		})
	}
}

func TestWorker_StartupReconcilesBeforeAnyNewWork(t *testing.T) {
	s, _, _ := sqliteStore(t)
	hv := fake.New()
	m := NewManager(s, hv, owners{"p1": "alice"}, nil, Config{})
	crashed := mustSubmit(t, m, req(Create, "vm-a", "k1"))
	// Simulate a crash after the host acted: running record, domain exists.
	_, _ = hv.Define(context.Background(), crashed.Spec.DomainSpec("vm-a"))
	c, _, _ := s.Get(crashed.ID)
	c.Status, c.Attempts = Running, 1
	_, _ = s.Update(c)
	calls := len(hv.Calls())
	stop := startWorker(t, NewWorker(m, fastCfg()))
	defer func() { _ = stop() }()
	waitFor(t, "reconciled", func() bool { return status(s, crashed.ID) == Succeeded })
	for _, c := range hv.Calls()[calls:] {
		if c.Op == "define" {
			t.Fatalf("recovery re-sent define: %v", c)
		}
	}
}

func TestWorker_ShutdownWaitsForInFlightAttemptAndLeavesNoRunningRecord(t *testing.T) {
	s, _, _ := sqliteStore(t)
	g := &gate{Hypervisor: fake.New(), hold: make(chan struct{}), entered: make(chan string, 4)}
	m := NewManager(s, g, owners{"p1": "alice"}, nil, Config{})
	op := mustSubmit(t, m, req(Create, "vm-a", "k"))
	stopped := make(chan error, 1)
	ctx, cancel := context.WithCancel(context.Background())
	go func() { stopped <- NewWorker(m, fastCfg()).Run(ctx) }()
	<-g.entered
	cancel()
	select {
	case <-stopped:
		t.Fatal("worker returned while a host attempt was in flight")
	case <-time.After(100 * time.Millisecond):
	}
	close(g.hold)
	if err := <-stopped; err != context.Canceled {
		t.Fatal(err)
	}
	if status(s, op.ID) != Succeeded {
		t.Fatalf("in-flight attempt was abandoned: %s", status(s, op.ID))
	}
}

func TestWorker_IdleWaitsOnTimerNotBusyLoop(t *testing.T) {
	s, _, _ := sqliteStore(t)
	var scans atomic.Int32
	cs := &countingStore{Store: s, n: &scans}
	m := NewManager(cs, fake.New(), owners{"p1": "alice"}, nil, Config{})
	cfg := fastCfg()
	cfg.Poll = 100 * time.Millisecond
	stop := startWorker(t, NewWorker(m, cfg))
	time.Sleep(550 * time.Millisecond)
	_ = stop()
	if n := scans.Load(); n > 12 { // 1 reconcile + ~6 polls
		t.Fatalf("%d store scans in 550ms idle: busy loop", n)
	}
}

type countingStore struct {
	Store
	n *atomic.Int32
}

func (c *countingStore) NonTerminal() ([]Operation, error) { c.n.Add(1); return c.Store.NonTerminal() }

func TestWorker_ConfigIsClamped(t *testing.T) {
	w := NewWorker(NewManager(NewMemStore(), fake.New(), nil, nil, Config{}), WorkerConfig{Concurrency: 10_000, Poll: time.Nanosecond, BackoffBase: -1})
	if w.cfg.Concurrency != 16 || w.cfg.Poll < 10*time.Millisecond || w.cfg.BackoffBase <= 0 || w.cfg.BackoffMax < w.cfg.BackoffBase {
		t.Fatalf("%+v", w.cfg)
	}
	_ = sync.Mutex{}
}

// ---- TD-D: observation-only reconciliation of an exhausted create with an unknown earlier outcome ----------------------

type countingHost struct {
	*fake.Hypervisor
	lookups, defines atomic.Int32
	mu               sync.Mutex
	err              error
}

func (c *countingHost) setErr(e error) { c.mu.Lock(); c.err = e; c.mu.Unlock() }

func (c *countingHost) Lookup(ctx context.Context, n string) (hypervisor.Domain, error) {
	c.lookups.Add(1)
	c.mu.Lock()
	e := c.err
	c.mu.Unlock()
	if e != nil {
		return hypervisor.Domain{}, e
	}
	return c.Hypervisor.Lookup(ctx, n)
}

func (c *countingHost) Define(ctx context.Context, s hypervisor.DomainSpec) (hypervisor.Domain, error) {
	c.defines.Add(1)
	return c.Hypervisor.Define(ctx, s)
}

// exhaustedUnknown leaves a create as retryable_failure, UnknownOutcome, attempts == MaxAttempts (1).
func exhaustedUnknown(t *testing.T, s Store) (*Manager, *countingHost, Operation) {
	t.Helper()
	h := &countingHost{Hypervisor: fake.New()}
	h.Hypervisor.Inject(1, fake.FaultTimeout, false)
	m := NewManager(s, h, owners{"p1": "alice"}, nil, Config{MaxAttempts: 1})
	op := mustSubmit(t, m, req(Create, "vm-a", "k1"))
	mustRun(t, m, op.ID, Running)
	if res, err := m.Reconcile(context.Background()); err != nil || len(res) != 1 || res[0].Status != RetryableFailure {
		t.Fatalf("%+v %v", res, err)
	}
	h.lookups.Store(0)
	h.defines.Store(0)
	got, _, _ := s.Get(op.ID)
	if got.Attempts != 1 || !got.UnknownOutcome {
		t.Fatalf("%+v", got)
	}
	return m, h, got
}

func obsCfg() WorkerConfig {
	c := fastCfg()
	c.ObserveEvery = 80 * time.Millisecond
	return c
}

func TestWorker_ExhaustedUnknownCreate_LateSuccessIsFoundWithoutAnyHostMutation(t *testing.T) {
	stores(t, func(t *testing.T, s Store) {
		m, h, op := exhaustedUnknown(t, s)
		stop := startWorker(t, NewWorker(m, obsCfg()))
		defer func() { _ = stop() }()
		waitFor(t, "first observation", func() bool { return h.lookups.Load() >= 1 })
		time.Sleep(300 * time.Millisecond) // absent: the operation stays as it is
		if got, _, _ := s.Get(op.ID); got.Status != RetryableFailure || got.Attempts != 1 {
			t.Fatalf("absent must leave it unchanged: %+v", got)
		}
		if n := h.lookups.Load(); n < 2 || n > 8 {
			t.Fatalf("%d observations in ~300ms with a 80ms interval: not bounded/periodic", n)
		}
		h.Hypervisor.Seed(identityOf(op), hypervisor.StateShutoff) // the late success
		waitFor(t, "resolved", func() bool { return status(s, op.ID) == Succeeded })
		if got, _, _ := s.Get(op.ID); got.Attempts != 1 {
			t.Fatalf("an observation burnt an attempt: %+v", got)
		}
		if h.defines.Load() != 0 {
			t.Fatalf("a Define was sent by the observation path (%d)", h.defines.Load())
		}
	})
}

func TestWorker_ExhaustedUnknownCreate_DifferentVMUnavailableAndRestart(t *testing.T) {
	stores(t, func(t *testing.T, s Store) { // a different VM appears
		m, h, op := exhaustedUnknown(t, s)
		diff := identityOf(op)
		diff.VCPUs = 4
		h.Hypervisor.Seed(diff, hypervisor.StateShutoff)
		stop := startWorker(t, NewWorker(m, obsCfg()))
		defer func() { _ = stop() }()
		waitFor(t, "conflict", func() bool { return status(s, op.ID) == Failed })
		if got, _, _ := s.Get(op.ID); got.ErrorCategory != CatConflict || h.defines.Load() != 0 {
			t.Fatalf("%+v defines=%d", got, h.defines.Load())
		}
	})
	stores(t, func(t *testing.T, s Store) { // the host is unavailable: unchanged, no mutation, still bounded
		m, h, op := exhaustedUnknown(t, s)
		h.setErr(hypervisor.NewError(hypervisor.Unavailable, "lookup", "vm-a", "down"))
		stop := startWorker(t, NewWorker(m, obsCfg()))
		time.Sleep(300 * time.Millisecond)
		_ = stop()
		got, _, _ := s.Get(op.ID)
		if got.Status != RetryableFailure || got.Attempts != 1 || got.Generation != op.Generation || h.defines.Load() != 0 {
			t.Fatalf("%+v", got)
		}
		if n := h.lookups.Load(); n > 8 {
			t.Fatalf("%d observations: busy loop", n)
		}
		// A restarted worker (new process) looks again immediately and finds the late success.
		h.setErr(nil)
		h.Hypervisor.Seed(identityOf(op), hypervisor.StateShutoff)
		stop2 := startWorker(t, NewWorker(NewManager(s, h, owners{"p1": "alice"}, nil, Config{MaxAttempts: 1}), obsCfg()))
		defer func() { _ = stop2() }()
		waitFor(t, "resolved after restart", func() bool { return status(s, op.ID) == Succeeded })
	})
}

func TestWorker_ExhaustedPlainOperationsAreStillLeftAlone(t *testing.T) {
	stores(t, func(t *testing.T, s Store) { // no unknown outcome: attempts exhausted by plain unavailability
		h := &countingHost{Hypervisor: fake.New()}
		for i := 1; i <= 3; i++ {
			h.Hypervisor.Inject(i, fake.FaultConnLoss, false)
		}
		m := NewManager(s, h, owners{"p1": "alice"}, nil, Config{MaxAttempts: 2})
		op := mustSubmit(t, m, req(Create, "vm-a", "k1"))
		for i := 0; i < 2; i++ {
			mustRun(t, m, op.ID, RetryableFailure)
		}
		h.lookups.Store(0)
		h.defines.Store(0)
		stop := startWorker(t, NewWorker(m, obsCfg()))
		time.Sleep(250 * time.Millisecond)
		_ = stop()
		if h.lookups.Load() != 0 || h.defines.Load() != 0 {
			t.Fatalf("an exhausted operation without an unknown outcome must not be touched (lookups=%d defines=%d)", h.lookups.Load(), h.defines.Load())
		}
	})
}
