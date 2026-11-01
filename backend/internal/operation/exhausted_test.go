package operation

import (
	"sync/atomic"
	"testing"
	"time"

	"example.invalid/dedicatedcloud/backend/internal/hypervisor/fake"
)

// An operation that used all its attempts blocks every later operation on the same resource until it is cancelled (M0-E01-S10, finding F-04, DR-036): the worker
// runs only the oldest open operation per resource, and an exhausted one stays the oldest. Cancelling it frees the resource, once, and says nothing ran on the host.
func TestExhaustedOperationBlocksItsSuccessorsUntilCancelled(t *testing.T) {
	s, _, _ := sqliteStore(t)
	hv := fake.New()
	var now atomic.Int64
	now.Store(t0.UnixNano())
	clock := func() time.Time { return time.Unix(0, now.Load()).UTC() }
	m := NewManager(s, hv, owners{"p1": "alice"}, nil, Config{MaxAttempts: 3, Clock: clock})
	first := mustSubmit(t, m, req(Create, "vm-a", "k1"))
	for i := 1; i <= 10; i++ {
		hv.Inject(i, fake.FaultConnLoss, false)
	}
	cfg := fastCfg()
	cfg.BackoffBase, cfg.BackoffMax = time.Minute, 4*time.Minute
	w := NewWorker(m, cfg)
	stop := startWorker(t, w)
	defer func() { _ = stop() }()
	attempts := func() int { o, _, _ := s.Get(first.ID); return o.Attempts }
	for i, step := range []time.Duration{0, time.Minute, 2 * time.Minute} {
		now.Add(int64(step))
		w.Notify()
		want := i + 1
		waitFor(t, "an attempt", func() bool { return attempts() == want })
	}
	now.Add(int64(time.Hour))
	w.Notify()
	time.Sleep(100 * time.Millisecond)
	if got, _, _ := s.Get(first.ID); got.Attempts != 3 || got.Status != RetryableFailure {
		t.Fatalf("not exhausted: %+v", got)
	}

	next := mustSubmit(t, m, req(Delete, "vm-a", "k2"))
	w.Notify()
	time.Sleep(200 * time.Millisecond)
	if got, _, _ := s.Get(next.ID); got.Status != Pending {
		t.Fatalf("the successor ran behind an exhausted operation: %s", got.Status)
	}

	c, err := m.Cancel(alice, first.ID)
	if err != nil || c.Status != Cancelled {
		t.Fatalf("cancel of the exhausted operation: %+v %v", c, err)
	}
	if again, err := m.Cancel(alice, first.ID); err != nil || again.ID != first.ID || again.Status != Cancelled {
		t.Fatalf("a second cancel is a no-op: %+v %v", again, err)
	}
	w.Notify()
	waitFor(t, "the successor to leave the queue", func() bool { got, _, _ := s.Get(next.ID); return got.Status != Pending })
	if n := mutations(hv, "define"); n != 0 {
		t.Fatalf("cancelling or the connection-lost attempts mutated the host %d times", n)
	}
}

// Only an operation that has not reached the host can be cancelled: a succeeded one, a failed one and an unknown id are refused with their own categories.
func TestCancelRefusesWhatIsNotCancellable(t *testing.T) {
	e := newEnv(t)
	done := mustSubmit(t, e.m, req(Create, "vm-a", "k1"))
	mustRun(t, e.m, done.ID, Succeeded)
	if _, err := e.m.Cancel(alice, done.ID); CategoryOf(err) != CatConflict {
		t.Fatalf("a succeeded operation: %q", CategoryOf(err))
	}
	failed := mustSubmit(t, e.m, req(Start, "ghost", "k2"))
	mustRun(t, e.m, failed.ID, Failed)
	if _, err := e.m.Cancel(alice, failed.ID); CategoryOf(err) != CatConflict {
		t.Fatalf("a failed operation: %q", CategoryOf(err))
	}
	if _, err := e.m.Cancel(alice, "op-does-not-exist"); CategoryOf(err) != CatNotFound {
		t.Fatalf("an unknown id: %q", CategoryOf(err))
	}
}

// Cancelling is audited once: who, which operation, the outcome, and nothing else (no parameter value, no key).
func TestCancelIsAuditedOnceWithoutSecrets(t *testing.T) {
	e := newEnv(t)
	op := mustSubmit(t, e.m, req(Create, "vm-a", "k1"))
	if _, err := e.m.Cancel(alice, op.ID); err != nil {
		t.Fatal(err)
	}
	var n int
	for _, ev := range e.audit.events {
		if ev.Event != "operation.cancel" {
			continue
		}
		n++
		if ev.OperationID != op.ID || ev.Actor != alice.ID || ev.Outcome != string(Cancelled) {
			t.Fatalf("the cancel event: %+v", ev)
		}
	}
	if n != 1 {
		t.Fatalf("%d cancel events, want 1", n)
	}
	if _, err := e.m.Cancel(alice, op.ID); err != nil {
		t.Fatal(err)
	}
	m := 0
	for _, ev := range e.audit.events {
		if ev.Event == "operation.cancel" {
			m++
		}
	}
	if m != 1 {
		t.Fatalf("a repeated cancel must not emit a second event: %d", m)
	}
}
