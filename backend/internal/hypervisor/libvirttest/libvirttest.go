//go:build libvirt_test

// Package libvirttest adapts the Hypervisor interface to libvirt's in-process
// test driver (test:///default) for T1 tests (story M0-E02-S03). It refuses
// every other URI, so it can never touch a real hypervisor. Built only with
// -tags libvirt_test (cgo, libvirt-dev); never part of a default build.
// Evidence from this adapter is "simulated" (TEST-STRATEGY).
package libvirttest

import (
	"context"
	"errors"
	"sort"
	"sync"

	libvirt "libvirt.org/go/libvirt"

	"example.invalid/dedicatedcloud/backend/internal/hypervisor"
)

// URI is the only connection URI this adapter accepts.
const URI = "test:///default"

// Hypervisor is the test-driver adapter.
type Hypervisor struct {
	mu    sync.Mutex
	conn  *libvirt.Connect
	calls []hypervisor.CallRecord
}

// Open connects to the libvirt test driver. Any other URI is Prohibited and
// no connection is attempted.
func Open(uri string) (*Hypervisor, error) {
	if uri != URI {
		return nil, hypervisor.NewError(hypervisor.Prohibited, "open", "", "only "+URI+" is allowed")
	}
	conn, err := libvirt.NewConnect(uri)
	if err != nil {
		return nil, mapErr("open", "", err)
	}
	return &Hypervisor{conn: conn}, nil
}

// Close releases the connection.
func (h *Hypervisor) Close() {
	if h.conn != nil {
		_, _ = h.conn.Close()
	}
}

// mapErr converts libvirt errors to typed hypervisor errors.
func mapErr(op, name string, err error) error {
	var lerr libvirt.Error
	if !errors.As(err, &lerr) {
		return hypervisor.NewError(hypervisor.HostError, op, name, "unexpected error")
	}
	switch lerr.Code {
	case libvirt.ERR_NO_DOMAIN:
		return hypervisor.NewError(hypervisor.NotFound, op, name, "no such domain")
	case libvirt.ERR_DOM_EXIST, libvirt.ERR_OPERATION_INVALID:
		return hypervisor.NewError(hypervisor.Conflict, op, name, "invalid state for operation")
	case libvirt.ERR_OPERATION_TIMEOUT:
		return hypervisor.NewError(hypervisor.Timeout, op, name, "libvirt timeout; outcome unknown")
	case libvirt.ERR_NO_CONNECT, libvirt.ERR_SYSTEM_ERROR, libvirt.ERR_RPC, libvirt.ERR_AGENT_UNRESPONSIVE:
		return hypervisor.NewError(hypervisor.Unavailable, op, name, "libvirt unavailable")
	case libvirt.ERR_XML_ERROR, libvirt.ERR_INVALID_ARG:
		return hypervisor.NewError(hypervisor.Validation, op, name, "rejected definition")
	default:
		return hypervisor.NewError(hypervisor.HostError, op, name, "libvirt error")
	}
}

func (h *Hypervisor) record(op, name, outcome string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(name) > 64 {
		name = name[:64] + "..."
	}
	h.calls = append(h.calls, hypervisor.CallRecord{Op: op, Domain: name, Outcome: outcome})
}

func (h *Hypervisor) fail(op, name string, err error) error {
	h.record(op, name, string(hypervisor.CategoryOf(err)))
	return err
}

func toState(s libvirt.DomainState) hypervisor.State {
	switch s {
	case libvirt.DOMAIN_RUNNING, libvirt.DOMAIN_BLOCKED, libvirt.DOMAIN_PAUSED:
		return hypervisor.StateRunning
	default:
		return hypervisor.StateShutoff
	}
}

func (h *Hypervisor) lookup(op, name string) (*libvirt.Domain, hypervisor.State, error) {
	dom, err := h.conn.LookupDomainByName(name)
	if err != nil {
		return nil, "", mapErr(op, name, err)
	}
	st, _, err := dom.GetState()
	if err != nil {
		_ = dom.Free()
		return nil, "", mapErr(op, name, err)
	}
	return dom, toState(st), nil
}

// Define creates a shut-off domain from the generated definition.
func (h *Hypervisor) Define(_ context.Context, spec hypervisor.DomainSpec) (hypervisor.Domain, error) {
	def, err := hypervisor.DomainXML(spec)
	if err != nil {
		return hypervisor.Domain{}, h.fail("define", spec.Name, err)
	}
	if dom, _, err := h.lookup("define", spec.Name); err == nil {
		_ = dom.Free()
		return hypervisor.Domain{}, h.fail("define", spec.Name,
			hypervisor.NewError(hypervisor.Conflict, "define", spec.Name, "domain already defined"))
	}
	dom, err := h.conn.DomainDefineXML(def)
	if err != nil {
		return hypervisor.Domain{}, h.fail("define", spec.Name, mapErr("define", spec.Name, err))
	}
	_ = dom.Free()
	h.record("define", spec.Name, "defined")
	return hypervisor.Domain{Name: spec.Name, State: hypervisor.StateShutoff, VCPUs: spec.VCPUs, MemoryMiB: spec.MemoryMiB}, nil
}

func (h *Hypervisor) transition(op, name string, to hypervisor.State, act func(*libvirt.Domain) error) error {
	if err := hypervisor.ValidateName(op, name); err != nil {
		return h.fail(op, name, err)
	}
	dom, st, err := h.lookup(op, name)
	if err != nil {
		return h.fail(op, name, err)
	}
	defer func() { _ = dom.Free() }()
	if st == to {
		h.record(op, name, "noop")
		return nil
	}
	if err := act(dom); err != nil {
		return h.fail(op, name, mapErr(op, name, err))
	}
	h.record(op, name, string(to))
	return nil
}

// Start boots a domain; starting a running domain is a no-op.
func (h *Hypervisor) Start(_ context.Context, name string) error {
	return h.transition("start", name, hypervisor.StateRunning, func(d *libvirt.Domain) error { return d.Create() })
}

// Stop shuts a domain down; stopping a shut-off domain is a no-op.
func (h *Hypervisor) Stop(_ context.Context, name string) error {
	return h.transition("stop", name, hypervisor.StateShutoff, func(d *libvirt.Domain) error { return d.Shutdown() })
}

// Destroy forces a domain off; idempotent.
func (h *Hypervisor) Destroy(_ context.Context, name string) error {
	return h.transition("destroy", name, hypervisor.StateShutoff, func(d *libvirt.Domain) error { return d.Destroy() })
}

// Undefine removes a shut-off domain; undefining an absent domain is a no-op.
func (h *Hypervisor) Undefine(_ context.Context, name string) error {
	if err := hypervisor.ValidateName("undefine", name); err != nil {
		return h.fail("undefine", name, err)
	}
	dom, st, err := h.lookup("undefine", name)
	if hypervisor.CategoryOf(err) == hypervisor.NotFound {
		h.record("undefine", name, "noop")
		return nil
	}
	if err != nil {
		return h.fail("undefine", name, err)
	}
	defer func() { _ = dom.Free() }()
	if st != hypervisor.StateShutoff {
		return h.fail("undefine", name, hypervisor.NewError(hypervisor.Conflict, "undefine", name, "domain is running"))
	}
	if err := dom.Undefine(); err != nil {
		return h.fail("undefine", name, mapErr("undefine", name, err))
	}
	h.record("undefine", name, "undefined")
	return nil
}

// Lookup returns a domain.
func (h *Hypervisor) Lookup(_ context.Context, name string) (hypervisor.Domain, error) {
	if err := hypervisor.ValidateName("lookup", name); err != nil {
		return hypervisor.Domain{}, err
	}
	dom, st, err := h.lookup("lookup", name)
	if err != nil {
		return hypervisor.Domain{}, err
	}
	vcpus, mem := definition(dom)
	_ = dom.Free()
	return hypervisor.Domain{Name: name, State: st, VCPUs: vcpus, MemoryMiB: mem}, nil
}

// List returns all domains known to the connection, sorted by name.
func (h *Hypervisor) List(_ context.Context) ([]hypervisor.Domain, error) {
	doms, err := h.conn.ListAllDomains(0)
	if err != nil {
		return nil, mapErr("list", "", err)
	}
	out := make([]hypervisor.Domain, 0, len(doms))
	for i := range doms {
		name, nerr := doms[i].GetName()
		st, _, serr := doms[i].GetState()
		vcpus, mem := definition(&doms[i])
		_ = doms[i].Free()
		if nerr != nil || serr != nil {
			return nil, hypervisor.NewError(hypervisor.HostError, "list", "", "cannot read domain")
		}
		out = append(out, hypervisor.Domain{Name: name, State: toState(st), VCPUs: vcpus, MemoryMiB: mem})
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

// definition reads the configured vCPU count and maximum memory (MiB); 0, 0 when libvirt does not report them.
func definition(dom *libvirt.Domain) (int, int) {
	info, err := dom.GetInfo()
	if err != nil || info == nil {
		return 0, 0
	}
	return int(info.NrVirtCpu), int(info.MaxMem / 1024) // #nosec G115 -- bounded by libvirt
}
