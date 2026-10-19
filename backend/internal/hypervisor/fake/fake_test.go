package fake

import (
	"context"
	"reflect"
	"testing"

	"example.invalid/dedicatedcloud/backend/internal/hypervisor"
	"example.invalid/dedicatedcloud/backend/internal/hypervisor/contracttest"
)

func factory(t *testing.T) (hypervisor.Hypervisor, func() map[string]hypervisor.State) {
	h := New()
	return h, h.Snapshot
}

func TestContractSuite(t *testing.T) { contracttest.Run(t, factory) }

func TestDomainXML(t *testing.T) { contracttest.DomainXMLContract(t) }

var spec = hypervisor.DomainSpec{Name: "vm1", VCPUs: 1, MemoryMiB: 128}

func TestFaultBeforeApplyLeavesStateAndIsTyped(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		fault     Fault
		category  hypervisor.Category
		retryable bool
	}{
		{FaultError, hypervisor.HostError, false},
		{FaultTimeout, hypervisor.Timeout, true},
		{FaultConnLoss, hypervisor.Unavailable, true},
	}
	for _, c := range cases {
		t.Run(string(c.fault), func(t *testing.T) {
			h := New()
			if _, err := h.Define(ctx, spec); err != nil {
				t.Fatal(err)
			}
			before := h.Snapshot()
			h.Inject(2, c.fault, false)
			err := h.Start(ctx, spec.Name)
			var he *hypervisor.Error
			if !asError(err, &he) || he.Category != c.category || he.Retryable() != c.retryable {
				t.Fatalf("got %v, want %s retryable=%v", err, c.category, c.retryable)
			}
			if !reflect.DeepEqual(before, h.Snapshot()) {
				t.Fatal("state changed although the fault happened before the call")
			}
			// The retry succeeds and applies exactly once.
			if err := h.Start(ctx, spec.Name); err != nil {
				t.Fatal(err)
			}
			if got := h.Snapshot()[spec.Name]; got != hypervisor.StateRunning {
				t.Fatalf("state = %s", got)
			}
		})
	}
}

func TestTimeoutAfterDestroyIsNotRepeated(t *testing.T) {
	ctx := context.Background()
	h := New()
	_, _ = h.Define(ctx, spec)
	_ = h.Start(ctx, spec.Name)
	h.Inject(3, FaultTimeout, true) // destroy applies, then times out
	err := h.Destroy(ctx, spec.Name)
	if hypervisor.CategoryOf(err) != hypervisor.Timeout {
		t.Fatalf("got %v, want timeout", err)
	}
	if got := h.Snapshot()[spec.Name]; got != hypervisor.StateShutoff {
		t.Fatalf("destroy should have applied before the timeout, state = %s", got)
	}
	// Retry: must be a no-op, never a second destructive action.
	if err := h.Destroy(ctx, spec.Name); err != nil {
		t.Fatal(err)
	}
	calls := h.Calls()
	last := calls[len(calls)-1]
	if last.Op != "destroy" || last.Outcome != "noop" {
		t.Fatalf("retry outcome %+v, want destroy noop", last)
	}
	applied := 0
	for _, c := range calls {
		if c.Op == "destroy" && (c.Outcome == "shutoff" || c.Outcome == "shutoff+fault:timeout") {
			applied++
		}
	}
	if applied != 1 {
		t.Fatalf("destroy applied %d times, want exactly 1: %+v", applied, calls)
	}
}

func TestTimeoutAfterUndefineRetryIsNoop(t *testing.T) {
	ctx := context.Background()
	h := New()
	_, _ = h.Define(ctx, spec)
	h.Inject(2, FaultTimeout, true)
	if err := h.Undefine(ctx, spec.Name); hypervisor.CategoryOf(err) != hypervisor.Timeout {
		t.Fatalf("got %v", err)
	}
	if err := h.Undefine(ctx, spec.Name); err != nil {
		t.Fatal(err)
	}
	if _, ok := h.Snapshot()[spec.Name]; ok {
		t.Fatal("domain still defined")
	}
	if last := h.Calls()[len(h.Calls())-1]; last.Outcome != "noop" {
		t.Fatalf("retry outcome %+v", last)
	}
}

func TestConcurrentUse(t *testing.T) {
	ctx := context.Background()
	h := New()
	done := make(chan struct{})
	for i := 0; i < 8; i++ {
		go func() {
			defer func() { done <- struct{}{} }()
			_, _ = h.Define(ctx, spec)
			_ = h.Start(ctx, spec.Name)
			_, _ = h.List(ctx)
		}()
	}
	for i := 0; i < 8; i++ {
		<-done
	}
	if len(h.Snapshot()) != 1 {
		t.Fatalf("snapshot %v", h.Snapshot())
	}
}

func asError(err error, target **hypervisor.Error) bool {
	he, ok := err.(*hypervisor.Error)
	if ok {
		*target = he
	}
	return ok
}
