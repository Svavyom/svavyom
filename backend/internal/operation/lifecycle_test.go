package operation

import (
	"context"
	"sync"
	"testing"

	"example.invalid/dedicatedcloud/backend/internal/hypervisor"
	"example.invalid/dedicatedcloud/backend/internal/hypervisor/fake"
)

// lifeHost records the lifecycle calls and lets a test decide what each one reports. The domain it observes is whatever state says.
type lifeHost struct {
	hypervisor.Hypervisor
	mu                                     sync.Mutex
	state                                  hypervisor.State
	gone                                   bool
	stopErr, rebootErr, destroyErr, delErr error
	stops, reboots, destroys, deletes      int
}

func (h *lifeHost) Lookup(_ context.Context, name string) (hypervisor.Domain, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.gone {
		return hypervisor.Domain{}, hypervisor.NewError(hypervisor.NotFound, "lookup", name, "")
	}
	return hypervisor.Domain{Name: name, State: h.state, Managed: true}, nil
}
func (h *lifeHost) Stop(context.Context, string) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.stops++
	return h.stopErr
}
func (h *lifeHost) Reboot(context.Context, string) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.reboots++
	return h.rebootErr
}
func (h *lifeHost) Destroy(context.Context, string) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.destroys++
	if h.destroyErr == nil {
		h.state = hypervisor.StateShutoff
	}
	return h.destroyErr
}
func (h *lifeHost) Undefine(context.Context, string) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.deletes++
	return h.delErr
}

func timeoutErr(op string) error { return hypervisor.NewError(hypervisor.Timeout, op, "", "") }

func newLife(t *testing.T, st hypervisor.State) (*env, *lifeHost) {
	t.Helper()
	e := newEnv(t)
	h := &lifeHost{Hypervisor: fake.New(), state: st}
	e.m = e.manager(h)
	return e, h
}

// A stop that times out is an unknown outcome. Observation finds the VM still running, so the operation becomes retryable and is
// never turned into a force-off by the manager.
func TestStopTimeoutIsRetriedNeverForced(t *testing.T) {
	e, h := newLife(t, hypervisor.StateRunning)
	h.stopErr = timeoutErr("stop")
	op := mustSubmit(t, e.m, req(Stop, "vm-a", "k1"))
	got, err := e.m.Run(context.Background(), op.ID)
	if err != nil || got.Status != Running || got.ErrorCategory != CatTimeout {
		t.Fatalf("%+v %v", got, err)
	}
	rec, err := e.m.ReconcileOne(context.Background(), op.ID)
	if err != nil || rec.Status != RetryableFailure || !rec.UnknownOutcome {
		t.Fatalf("%+v %v", rec, err)
	}
	if h.destroys != 0 {
		t.Fatal("a stop timeout must never force the VM off")
	}
}

// A reboot whose outcome is unknown is NOT sent again and is NOT reported as done: the host observes the restart itself before it
// reports success, so a timeout means "not confirmed".
func TestRebootUnknownOutcomeIsNeverResentNorClaimed(t *testing.T) {
	for _, st := range []hypervisor.State{hypervisor.StateRunning, hypervisor.StateShutoff} {
		e, h := newLife(t, st)
		h.rebootErr = timeoutErr("reboot")
		op := mustSubmit(t, e.m, req(Reboot, "vm-a", "k1"))
		if _, err := e.m.Run(context.Background(), op.ID); err != nil {
			t.Fatal(err)
		}
		rec, err := e.m.ReconcileOne(context.Background(), op.ID)
		if err != nil || rec.Status != Failed || rec.ErrorCategory != CatTimeout || h.reboots != 1 {
			t.Fatalf("%v: %+v %v reboots=%d", st, rec, err, h.reboots)
		}
	}
}

func TestDeleteReconcilesByAbsence(t *testing.T) {
	e, h := newLife(t, hypervisor.StateShutoff)
	h.delErr = timeoutErr("undefine")
	op := mustSubmit(t, e.m, req(Delete, "vm-a", "k1"))
	_, _ = e.m.Run(context.Background(), op.ID)
	if rec, _ := e.m.ReconcileOne(context.Background(), op.ID); rec.Status != RetryableFailure {
		t.Fatalf("still present: %+v", rec)
	}
	h.mu.Lock()
	h.gone = true // the first attempt did complete after all
	h.mu.Unlock()
	if _, err := e.m.Run(context.Background(), op.ID); err != nil {
		t.Fatal(err)
	}
	if rec, _ := e.m.ReconcileOne(context.Background(), op.ID); rec.Status != Succeeded {
		t.Fatalf("an absent VM means the delete finished: %+v", rec)
	}
}

// Force Off is explicit: submitting it cancels a stuck graceful Stop of the same VM (which would otherwise hold it back) and runs.
func TestForceOffSupersedesAStuckStop(t *testing.T) {
	e, h := newLife(t, hypervisor.StateRunning)
	h.stopErr = timeoutErr("stop")
	stop := mustSubmit(t, e.m, req(Stop, "vm-a", "k1"))
	_, _ = e.m.Run(context.Background(), stop.ID)
	_, _ = e.m.ReconcileOne(context.Background(), stop.ID) // retryable_failure, unknown outcome
	force := mustSubmit(t, e.m, req(ForceOff, "vm-a", "k2"))
	if got, _, _ := e.store.Get(stop.ID); got.Status != Cancelled {
		t.Fatalf("stuck stop: %+v", got)
	}
	if got, _ := e.m.Run(context.Background(), force.ID); got.Status != Succeeded || h.destroys != 1 {
		t.Fatalf("%+v destroys=%d", got, h.destroys)
	}
	// without the explicit operation nothing was forced
	e2, h2 := newLife(t, hypervisor.StateRunning)
	h2.stopErr = timeoutErr("stop")
	s2 := mustSubmit(t, e2.m, req(Stop, "vm-a", "k1"))
	_, _ = e2.m.Run(context.Background(), s2.ID)
	_, _ = e2.m.ReconcileOne(context.Background(), s2.ID)
	if h2.destroys != 0 {
		t.Fatal("force off happened without a Force Off operation")
	}
}
