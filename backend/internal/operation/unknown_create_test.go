package operation

import (
	"context"
	"testing"

	"example.invalid/dedicatedcloud/backend/internal/hypervisor"
	"example.invalid/dedicatedcloud/backend/internal/hypervisor/fake"
)

// CT-PRODUCT-DELIVERY-004 s12-14: a create retried after an UNKNOWN outcome must look before it sends, and a Conflict
// then may be the operation's own late success. A first attempt that meets an existing VM is still a plain Conflict.

// identityOf is the definition (with the Svavyom identity) that operation op asked the host to create: what its own late
// completion would look like on the host.
func identityOf(op Operation) hypervisor.DomainSpec { return op.Spec.DomainSpec(op.ResourceID) }

// lateHost wraps the fake with the timing the scenarios need.
type lateHost struct {
	*fake.Hypervisor
	hideLookups    int   // the first N lookups report "absent" even if the domain exists
	lookupErr      error // every lookup fails with this
	lookupErrAfter error // lookups fail with this once a Define has been attempted
	appearOnDefine *hypervisor.DomainSpec
	defines        int
	defined        bool
}

func (l *lateHost) Lookup(ctx context.Context, n string) (hypervisor.Domain, error) {
	if l.lookupErr != nil {
		return hypervisor.Domain{}, l.lookupErr
	}
	if l.defined && l.lookupErrAfter != nil {
		return hypervisor.Domain{}, l.lookupErrAfter
	}
	if l.hideLookups > 0 {
		l.hideLookups--
		return hypervisor.Domain{}, hypervisor.NewError(hypervisor.NotFound, "lookup", n, "absent")
	}
	return l.Hypervisor.Lookup(ctx, n)
}

func (l *lateHost) Define(ctx context.Context, s hypervisor.DomainSpec) (hypervisor.Domain, error) {
	l.defines++
	l.defined = true
	if l.appearOnDefine != nil { // the earlier attempt completed just before this one: the VM exists now
		l.Hypervisor.Seed(*l.appearOnDefine, hypervisor.StateShutoff)
		return hypervisor.Domain{}, hypervisor.NewError(hypervisor.Conflict, "define", s.Name, "domain already defined")
	}
	return l.Hypervisor.Define(ctx, s)
}

// unknownCreate drives a create to "retryable with an unknown earlier outcome": the first Define times out and did not apply.
func unknownCreate(t *testing.T, s Store, h *lateHost) (*Manager, Operation) {
	t.Helper()
	h.Hypervisor.Inject(1, fake.FaultTimeout, false)
	m := NewManager(s, h.Hypervisor, owners{"p1": "alice"}, nil, Config{})
	m.hv = h
	op := mustSubmit(t, m, req(Create, "vm-a", "k1"))
	mustRun(t, m, op.ID, Running) // timeout: outcome unknown
	if got, _, _ := s.Get(op.ID); !got.UnknownOutcome {
		t.Fatalf("a timeout must mark the outcome unknown: %+v", got)
	}
	res, err := m.Reconcile(context.Background()) // first observation: absent
	if err != nil || len(res) != 1 || res[0].Status != RetryableFailure || !res[0].UnknownOutcome {
		t.Fatalf("%+v %v", res, err)
	}
	h.defines, h.defined = 0, false // from here on count only what the retry sends
	return m, res[0]
}

func newLate() *lateHost { return &lateHost{Hypervisor: fake.New()} }

func TestUnknownCreate_LateSuccessIsFoundBeforeTheRetryIsSent(t *testing.T) {
	stores(t, func(t *testing.T, s Store) {
		h := newLate()
		m, op := unknownCreate(t, s, h)
		h.Hypervisor.Seed(identityOf(op), hypervisor.StateShutoff) // the original host action completes late
		got := mustRun(t, m, op.ID, Succeeded)
		if h.defines != 0 {
			t.Fatalf("a Define was re-sent although the VM already existed (%d)", h.defines)
		}
		if got.Attempts != 1 {
			t.Fatalf("an observation-only resolution must not burn an attempt: %+v", got)
		}
	})
}

func TestUnknownCreate_LateSuccessInsideTheRaceWindowIsNotAFalseFailure(t *testing.T) {
	stores(t, func(t *testing.T, s Store) {
		h := newLate()
		m, op := unknownCreate(t, s, h)
		h.hideLookups = 1 // the pre-send look still sees nothing; the late completion lands right after it
		own := identityOf(op)
		h.appearOnDefine = &own
		got := mustRun(t, m, op.ID, Succeeded)
		if h.defines != 1 || got.ErrorCategory != "" {
			t.Fatalf("defines=%d %+v", h.defines, got)
		}
	})
}

func TestUnknownCreate_ADifferentVMAppearingIsAConflict(t *testing.T) {
	stores(t, func(t *testing.T, s Store) { // seen before the retry is sent
		h := newLate()
		m, op := unknownCreate(t, s, h)
		other := identityOf(op)
		other.VCPUs = 4 // the same identity but another definition
		h.Hypervisor.Seed(other, hypervisor.StateShutoff)
		got := mustRun(t, m, op.ID, Failed)
		if got.ErrorCategory != CatConflict || h.defines != 0 {
			t.Fatalf("%+v defines=%d", got, h.defines)
		}
	})
	stores(t, func(t *testing.T, s Store) { // appears inside the race window
		h := newLate()
		m, op := unknownCreate(t, s, h)
		other := hypervisor.DomainSpec{Name: "vm-a", VCPUs: 1, MemoryMiB: 512} // somebody else's VM: no Svavyom identity
		h.hideLookups, h.appearOnDefine = 1, &other
		got := mustRun(t, m, op.ID, Failed)
		if got.ErrorCategory != CatConflict {
			t.Fatalf("%+v", got)
		}
	})
}

func TestFirstCreateAttemptMeetingAnExistingSameSpecVMIsStillAConflict(t *testing.T) {
	stores(t, func(t *testing.T, s Store) {
		h := newLate()
		h.Hypervisor.Seed(hypervisor.DomainSpec{Name: "vm-a", VCPUs: 1, MemoryMiB: 512}, hypervisor.StateShutoff) // pre-existing, identical size
		m := NewManager(s, h, owners{"p1": "alice"}, nil, Config{})
		op := mustSubmit(t, m, req(Create, "vm-a", "k1"))
		got := mustRun(t, m, op.ID, Failed)
		if got.ErrorCategory != CatConflict || got.UnknownOutcome {
			t.Fatalf("a pre-existing VM must not become a successful new create: %+v", got)
		}
	})
}

func TestUnknownCreate_ObservationFailureNeverSendsAnotherDefine(t *testing.T) {
	stores(t, func(t *testing.T, s Store) {
		h := newLate()
		m, op := unknownCreate(t, s, h)
		h.lookupErr = hypervisor.NewError(hypervisor.Unavailable, "lookup", "vm-a", "agent down")
		got, err := m.Run(context.Background(), op.ID)
		if CategoryOf(err) != CatUnavailable || got.Status != RetryableFailure || got.Attempts != 1 || h.defines != 0 {
			t.Fatalf("%+v %v defines=%d", got, err, h.defines)
		}
		if stored, _, _ := s.Get(op.ID); stored.Generation != op.Generation {
			t.Fatalf("a failed observation changed the record: %+v", stored)
		}
		h.lookupErr = nil // the host is back and shows nothing: now the retry proceeds
		mustRun(t, m, op.ID, Succeeded)
		if h.defines != 1 {
			t.Fatalf("defines=%d", h.defines)
		}
	})
}

func TestUnknownCreate_ConflictWithAFailingObservationStaysUnknownNotFailed(t *testing.T) {
	stores(t, func(t *testing.T, s Store) {
		h := newLate()
		m, op := unknownCreate(t, s, h)
		own := identityOf(op)
		h.hideLookups, h.appearOnDefine = 1, &own
		h.lookupErrAfter = hypervisor.NewError(hypervisor.Timeout, "lookup", "vm-a", "slow")
		got := mustRun(t, m, op.ID, Running)
		if got.ErrorCategory != CatTimeout {
			t.Fatalf("%+v", got)
		}
		h.lookupErrAfter = nil
		res, err := m.Reconcile(context.Background())
		if err != nil || len(res) != 1 || res[0].Status != Succeeded {
			t.Fatalf("%+v %v", res, err)
		}
	})
}

func TestUnknownCreate_UnestablishableDefinitionFailsClosed(t *testing.T) {
	stores(t, func(t *testing.T, s Store) {
		h := newLate()
		m, op := unknownCreate(t, s, h)
		m.hv = zeroSpecHost{h.Hypervisor}
		h.Hypervisor.Seed(identityOf(op), hypervisor.StateShutoff)
		got := mustRun(t, m, op.ID, Failed)
		if got.ErrorCategory != CatHostError {
			t.Fatalf("%+v", got)
		}
	})
}

func TestUnknownCreate_StateSurvivesRestartAndIsObservedBeforeRetransmission(t *testing.T) {
	st, db, path := sqliteStore(t)
	h := newLate()
	_, op := unknownCreate(t, st, h)
	_ = db.Close() // process exit while retryable
	st2, db2 := reopen(t, path)
	defer db2.Close()
	got, _, _ := st2.Get(op.ID)
	if got.Status != RetryableFailure || !got.UnknownOutcome || got.Spec != op.Spec || got.Spec.UUID == "" || got.Spec.Fingerprint == "" {
		t.Fatalf("persisted state: %+v", got)
	}
	h.Hypervisor.Seed(identityOf(op), hypervisor.StateShutoff) // the late completion happened while the process was down
	m2 := NewManager(st2, h, owners{"p1": "alice"}, nil, Config{})
	mustRun(t, m2, op.ID, Succeeded)
	if h.defines != 0 {
		t.Fatalf("a restarted manager sent Define without observing first (%d)", h.defines)
	}
	if _, err := db2.Exec(`UPDATE operations SET unknown_outcome = 0`); err == nil {
		t.Log("terminal rows are already immutable")
	}
}

func TestSQLite_UnknownOutcomeMarkIsMonotonic(t *testing.T) {
	st, db, _ := sqliteStore(t)
	h := newLate()
	_, op := unknownCreate(t, st, h) // retryable_failure, non-terminal, mark set
	if _, err := db.Exec(`UPDATE operations SET unknown_outcome = 0 WHERE id = ?`, op.ID); err == nil {
		t.Fatal("the unknown-outcome mark was cleared")
	}
	op.UnknownOutcome = false
	if _, err := st.Update(op); CategoryOf(err) != CatConflict {
		t.Fatalf("clearing through the store: %v", err)
	}
}
