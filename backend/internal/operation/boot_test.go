package operation

import (
	"context"
	"fmt"
	"sync"
	"testing"

	"example.invalid/dedicatedcloud/backend/internal/hypervisor"
)

// fakeBoot records what the manager tells the intent store.
type fakeBoot struct {
	mu    sync.Mutex
	calls []string
	err   error
}

func (f *fakeBoot) rec(s string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, s)
	return f.err
}
func (f *fakeBoot) VMCreated(_ context.Context, n string, on bool, a string) error {
	return f.rec(fmt.Sprintf("created %s box=%v by=%s", n, on, a))
}
func (f *fakeBoot) VMDeleted(_ context.Context, n string) error { return f.rec("deleted " + n) }
func (f *fakeBoot) PowerIntent(_ context.Context, n string, r bool, a string) error {
	return f.rec(fmt.Sprintf("intent %s running=%v by=%s", n, r, a))
}
func (f *fakeBoot) SetStartOnBoot(_ context.Context, n string, on bool, a string) error {
	return f.rec(fmt.Sprintf("box %s %v by=%s", n, on, a))
}
func (f *fakeBoot) last() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.calls) == 0 {
		return ""
	}
	return f.calls[len(f.calls)-1]
}

// rebootingHost lets the fake hypervisor honour a reboot request.
type rebootingHost struct{ hypervisor.Hypervisor }

func (rebootingHost) Reboot(context.Context, string) error { return nil }

func bootEnv(t *testing.T) (*env, *fakeBoot) {
	t.Helper()
	e := newEnv(t)
	fb := &fakeBoot{}
	e.m = NewManager(e.store, rebootingHost{e.hv}, owners{"p1": "alice", "p2": "bob"}, e.audit, Config{MaxAttempts: 3, Boot: fb,
		NewID: func() (string, error) { return fmt.Sprintf("op-%04d", len(e.store.order)+1), nil }})
	return e, fb
}

func TestTheIntentFollowsEveryOperationThatChangesPower(t *testing.T) {
	e, fb := bootEnv(t)
	run := func(r Request, want string) {
		t.Helper()
		op := mustSubmit(t, e.m, r)
		mustRun(t, e.m, op.ID, Succeeded)
		if got := fb.last(); got != want {
			t.Errorf("%s: the intent store was told %q, want %q", r.Type, got, want)
		}
	}
	run(req(Create, "web-1", "c1"), "created web-1 box=true by=alice")
	run(req(Start, "web-1", "s1"), "intent web-1 running=true by=alice")
	run(req(Reboot, "web-1", "r1"), "intent web-1 running=true by=alice")
	run(req(Stop, "web-1", "t1"), "intent web-1 running=false by=alice")
	run(req(Start, "web-1", "s2"), "intent web-1 running=true by=alice")
	run(req(ForceOff, "web-1", "f1"), "intent web-1 running=false by=alice")
	run(req(Delete, "web-1", "d1"), "deleted web-1")
}

func TestACreateWithTheBoxUntickedSaysSo(t *testing.T) {
	e, fb := bootEnv(t)
	r := req(Create, "db-1", "c2")
	r.Spec = CreateSpec{VCPUs: 1, MemoryMiB: 512, NoStartOnBoot: true}
	op := mustSubmit(t, e.m, r)
	mustRun(t, e.m, op.ID, Succeeded)
	if got := fb.last(); got != "created db-1 box=false by=alice" {
		t.Fatalf("%q", got)
	}
}

func TestTheBoxIsAnOperationWithTypedParametersAndANotFoundVMIsRefused(t *testing.T) {
	e, fb := bootEnv(t)
	mustRun(t, e.m, mustSubmit(t, e.m, req(Create, "web-1", "c3")).ID, Succeeded)
	for name, p := range map[string]Params{"on": {Autostart: "on"}, "off": {Autostart: "off"}} {
		r := req(SetStartOnBoot, "web-1", "box-"+name)
		r.Params = p
		mustRun(t, e.m, mustSubmit(t, e.m, r).ID, Succeeded)
		if got := fb.last(); got != fmt.Sprintf("box web-1 %v by=alice", name == "on") {
			t.Errorf("%s: %q", name, got)
		}
	}
	for name, p := range map[string]Params{"empty": {}, "junk": {Autostart: "maybe"}, "extra": {Autostart: "on", VCPUs: 2}} {
		r := req(SetStartOnBoot, "web-1", "bad-"+name)
		r.Params = p
		if _, err := e.m.Submit(alice, r); err == nil {
			t.Errorf("%s must be refused", name)
		}
	}
	r := req(SetStartOnBoot, "web-1", "wrong-kind")
	r.Kind = KindNetwork
	r.Params = Params{Autostart: "on"}
	if _, err := e.m.Submit(alice, r); err == nil {
		t.Error("the type applies to a VM only")
	}
}

func TestAFailedOperationLeavesTheIntentAloneAndARecordFailureNeverChangesTheOperation(t *testing.T) {
	e, fb := bootEnv(t)
	mustRun(t, e.m, mustSubmit(t, e.m, req(Create, "web-1", "c4")).ID, Succeeded)
	before := len(fb.calls)
	// a stop of a VM that does not exist fails: nothing is recorded
	op := mustSubmit(t, e.m, req(Stop, "nope-1", "t9"))
	if got, _ := e.m.Run(context.Background(), op.ID); got.Status == Succeeded {
		t.Fatalf("a stop of a missing VM cannot succeed")
	}
	if len(fb.calls) != before {
		t.Fatalf("a failed operation told the intent store: %v", fb.calls[before:])
	}
	// the store failing does not turn a succeeded start into a failure; an audit event says so
	fb.err = fmt.Errorf("disk full")
	op = mustSubmit(t, e.m, req(Start, "web-1", "s9"))
	mustRun(t, e.m, op.ID, Succeeded)
	found := false
	for _, ev := range e.audit.events {
		if ev.Event == "operation.boot_record" && ev.Outcome == "failed" {
			found = true
		}
	}
	if !found {
		t.Fatal("no audit event for the failed record")
	}
}
