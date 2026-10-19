// Package fake is a deterministic in-memory Hypervisor for T0 tests
// (story M0-E02-S03). It supports fault injection and records every call.
// It is never evidence of real virtualization behaviour.
package fake

import (
	"context"
	"sort"
	"sync"

	"example.invalid/dedicatedcloud/backend/internal/hypervisor"
)

// Fault is an injected failure.
type Fault string

// Fault kinds.
const (
	FaultError    Fault = "error"     // host error (terminal)
	FaultTimeout  Fault = "timeout"   // outcome unknown, retryable
	FaultConnLoss Fault = "conn_loss" // connection lost before the call, retryable
)

type plan struct {
	nth   int
	fault Fault
	// after applies the operation and then reports the fault (outcome unknown).
	after bool
}

// Hypervisor is the in-memory fake.
type Hypervisor struct {
	mu      sync.Mutex
	domains map[string]hypervisor.State
	specs   map[string]hypervisor.DomainSpec
	calls   []hypervisor.CallRecord
	count   int
	plans   []plan
}

// New returns an empty fake.
func New() *Hypervisor {
	return &Hypervisor{domains: map[string]hypervisor.State{}, specs: map[string]hypervisor.DomainSpec{}}
}

// Inject makes the nth call (1-based, counted across all operations) fail
// with fault. If afterApply is true the operation's effect is applied before
// the fault is reported (simulating a timeout after the host acted).
func (h *Hypervisor) Inject(nth int, fault Fault, afterApply bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.plans = append(h.plans, plan{nth: nth, fault: fault, after: afterApply})
}

// Snapshot returns a copy of the domain table for consistency checks.
func (h *Hypervisor) Snapshot() map[string]hypervisor.State {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make(map[string]hypervisor.State, len(h.domains))
	for k, v := range h.domains {
		out[k] = v
	}
	return out
}

func faultError(f Fault, op, name string) error {
	switch f {
	case FaultTimeout:
		return hypervisor.NewError(hypervisor.Timeout, op, name, "injected timeout; outcome unknown")
	case FaultConnLoss:
		return hypervisor.NewError(hypervisor.Unavailable, op, name, "injected connection loss")
	default:
		return hypervisor.NewError(hypervisor.HostError, op, name, "injected host error")
	}
}

// do runs one operation under the fault plan and records it.
func (h *Hypervisor) do(op, name string, apply func() (string, error)) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.count++
	var injected *plan
	for i := range h.plans {
		if h.plans[i].nth == h.count {
			injected = &h.plans[i]
		}
	}
	if injected != nil && !injected.after {
		err := faultError(injected.fault, op, name)
		h.calls = append(h.calls, hypervisor.CallRecord{Op: op, Domain: name, Outcome: "fault:" + string(injected.fault)})
		return err
	}
	outcome, err := apply()
	if err != nil {
		h.calls = append(h.calls, hypervisor.CallRecord{Op: op, Domain: name, Outcome: string(hypervisor.CategoryOf(err))})
		return err
	}
	if injected != nil {
		h.calls = append(h.calls, hypervisor.CallRecord{Op: op, Domain: name, Outcome: outcome + "+fault:" + string(injected.fault)})
		return faultError(injected.fault, op, name)
	}
	h.calls = append(h.calls, hypervisor.CallRecord{Op: op, Domain: name, Outcome: outcome})
	return nil
}

// Define creates a shut-off domain.
func (h *Hypervisor) Define(_ context.Context, spec hypervisor.DomainSpec) (hypervisor.Domain, error) {
	if err := spec.Validate(); err != nil {
		h.record("define", spec.Name, err)
		return hypervisor.Domain{}, err
	}
	if _, err := hypervisor.DomainXML(spec); err != nil {
		h.record("define", spec.Name, err)
		return hypervisor.Domain{}, err
	}
	err := h.do("define", spec.Name, func() (string, error) {
		if _, ok := h.domains[spec.Name]; ok {
			return "", hypervisor.NewError(hypervisor.Conflict, "define", spec.Name, "domain already defined")
		}
		h.domains[spec.Name] = hypervisor.StateShutoff
		h.specs[spec.Name] = spec
		return "defined", nil
	})
	if err != nil {
		return hypervisor.Domain{}, err
	}
	return hypervisor.Domain{Name: spec.Name, State: hypervisor.StateShutoff, VCPUs: spec.VCPUs, MemoryMiB: spec.MemoryMiB}, nil
}

func (h *Hypervisor) transition(op, name string, from, to hypervisor.State, missingOK bool) error {
	if err := hypervisor.ValidateName(op, name); err != nil {
		h.record(op, name, err)
		return err
	}
	return h.do(op, name, func() (string, error) {
		state, ok := h.domains[name]
		if !ok {
			if missingOK {
				return "noop", nil
			}
			return "", hypervisor.NewError(hypervisor.NotFound, op, name, "no such domain")
		}
		if state == to {
			return "noop", nil
		}
		if state != from {
			return "", hypervisor.NewError(hypervisor.Conflict, op, name, "invalid state "+string(state))
		}
		h.domains[name] = to
		return string(to), nil
	})
}

// Start boots a shut-off domain; starting a running domain is a no-op.
func (h *Hypervisor) Start(_ context.Context, name string) error {
	return h.transition("start", name, hypervisor.StateShutoff, hypervisor.StateRunning, false)
}

// Stop shuts down a running domain gracefully; stopping a shut-off domain is a no-op.
func (h *Hypervisor) Stop(_ context.Context, name string) error {
	return h.transition("stop", name, hypervisor.StateRunning, hypervisor.StateShutoff, false)
}

// Destroy forces a running domain off; idempotent.
func (h *Hypervisor) Destroy(_ context.Context, name string) error {
	return h.transition("destroy", name, hypervisor.StateRunning, hypervisor.StateShutoff, false)
}

// Undefine removes a shut-off domain; undefining an absent domain is a no-op.
func (h *Hypervisor) Undefine(_ context.Context, name string) error {
	if err := hypervisor.ValidateName("undefine", name); err != nil {
		h.record("undefine", name, err)
		return err
	}
	return h.do("undefine", name, func() (string, error) {
		state, ok := h.domains[name]
		if !ok {
			return "noop", nil
		}
		if state != hypervisor.StateShutoff {
			return "", hypervisor.NewError(hypervisor.Conflict, "undefine", name, "domain is running")
		}
		delete(h.domains, name)
		delete(h.specs, name)
		return "undefined", nil
	})
}

// Lookup returns a domain.
func (h *Hypervisor) Lookup(_ context.Context, name string) (hypervisor.Domain, error) {
	if err := hypervisor.ValidateName("lookup", name); err != nil {
		return hypervisor.Domain{}, err
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	state, ok := h.domains[name]
	if !ok {
		return hypervisor.Domain{}, hypervisor.NewError(hypervisor.NotFound, "lookup", name, "no such domain")
	}
	return observed(name, state, h.specs[name]), nil
}

// List returns all domains sorted by name.
func (h *Hypervisor) List(_ context.Context) ([]hypervisor.Domain, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make([]hypervisor.Domain, 0, len(h.domains))
	for name, state := range h.domains {
		out = append(out, observed(name, state, h.specs[name]))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// Calls returns a copy of the call audit log.
func (h *Hypervisor) Calls() []hypervisor.CallRecord {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]hypervisor.CallRecord(nil), h.calls...)
}

func (h *Hypervisor) record(op, name string, err error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(name) > 64 {
		name = name[:64] + "..."
	}
	h.calls = append(h.calls, hypervisor.CallRecord{Op: op, Domain: name, Outcome: string(hypervisor.CategoryOf(err))})
}

// Seed defines a domain directly, bypassing the call log and fault plan (test setup: a domain that already existed).
func (h *Hypervisor) Seed(spec hypervisor.DomainSpec, state hypervisor.State) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.domains[spec.Name] = state
	h.specs[spec.Name] = spec
}

// observed is what a read of the domain reports: the definition and, when the spec carried Svavyom identity, the ownership
// marker (Managed needs both UUID and Fingerprint, like the real metadata).
func observed(name string, state hypervisor.State, sp hypervisor.DomainSpec) hypervisor.Domain {
	return hypervisor.Domain{Name: name, State: state, VCPUs: sp.VCPUs, MemoryMiB: sp.MemoryMiB, UUID: sp.UUID,
		Fingerprint: sp.Fingerprint, Managed: sp.UUID != "" && sp.Fingerprint != "", ImageID: sp.ImageID}
}
