package schedule

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
	_ "time/tzdata"

	"example.invalid/dedicatedcloud/backend/internal/operation"
	"example.invalid/dedicatedcloud/backend/internal/sqlitedb"
)

// ---- timing ---------------------------------------------------------------------------------------------------------------

func at(s string) time.Time {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		panic(err)
	}
	return t
}

func TestNextAfterHoursAndDaily(t *testing.T) {
	utc := time.UTC
	if got := NextAfter(Spec{EveryHours: 6}, at("2026-10-15T10:00:00Z"), utc); !got.Equal(at("2026-10-15T16:00:00Z")) {
		t.Fatalf("hours: %v", got)
	}
	d := Spec{At: "02:30"}
	for in, want := range map[string]string{
		"2026-10-15T01:00:00Z": "2026-10-15T02:30:00Z", "2026-10-15T02:30:00Z": "2026-10-16T02:30:00Z", "2026-10-15T23:59:00Z": "2026-10-16T02:30:00Z",
	} {
		if got := NextAfter(d, at(in), utc); !got.Equal(at(want)) {
			t.Errorf("%s: got %v want %s", in, got, want)
		}
	}
}

func TestNextAfterAcrossDaylightSaving(t *testing.T) {
	ny, err := time.LoadLocation("America/New_York")
	if err != nil {
		t.Fatal(err)
	}
	d := Spec{At: "02:30"}
	// 2026-03-08: the clock jumps from 02:00 to 03:00, so 02:30 does not exist that day: it runs once, at the time Go normalises it to.
	day := time.Date(2026, 3, 8, 0, 0, 0, 0, ny)
	got := NextAfter(d, day, ny)
	if got.In(ny).Day() != 8 || got.In(ny).Hour() < 1 || got.In(ny).Hour() > 3 {
		t.Fatalf("spring forward: %v", got.In(ny)) // Go places the missing wall-clock time next to the jump; either side of it is acceptable, once
	}
	if again := NextAfter(d, got, ny); again.In(ny).Day() != 9 || again.In(ny).Hour() != 2 {
		t.Fatalf("and only once that day: %v", again.In(ny))
	}
	// 2026-11-01: 01:30 happens twice; the window runs at its first occurrence and the next one is the next day.
	one := Spec{At: "01:30"}
	first := NextAfter(one, time.Date(2026, 11, 1, 0, 0, 0, 0, ny), ny)
	if first.UTC().Hour() != 5 { // 01:30 EDT is 05:30 UTC
		t.Fatalf("fall back: %v", first.UTC())
	}
	if next := NextAfter(one, first, ny); next.In(ny).Day() != 2 {
		t.Fatalf("not twice on the same date: %v", next.In(ny))
	}
}

func TestDueMissedWindows(t *testing.T) {
	utc := time.UTC
	sched := at("2026-10-15T02:30:00Z")
	if run, next := Due(Spec{At: "02:30"}, sched, at("2026-10-15T02:31:00Z"), utc); !run || !next.Equal(at("2026-10-16T02:30:00Z")) {
		t.Fatalf("on time: %v %v", run, next)
	}
	if run, _ := Due(Spec{At: "02:30"}, sched, at("2026-10-15T08:00:00Z"), utc); !run {
		t.Fatal("5.5 hours late still runs")
	}
	if run, next := Due(Spec{At: "02:30"}, sched, at("2026-10-15T15:00:00Z"), utc); run || !next.Equal(at("2026-10-16T02:30:00Z")) {
		t.Fatalf("a daily window missed by half a day is skipped, never run in the working day: %v %v", run, next)
	}
	if run, next := Due(Spec{EveryHours: 4}, sched, at("2026-10-16T20:00:00Z"), utc); !run || !next.Equal(at("2026-10-17T00:00:00Z")) {
		t.Fatalf("an hours schedule runs once, late, and counts from now: %v %v", run, next)
	}
	if run, _ := Due(Spec{EveryHours: 4}, sched, at("2026-10-15T01:00:00Z"), utc); run {
		t.Fatal("not yet due")
	}
}

func TestSpecValidity(t *testing.T) {
	ok := []Spec{{EveryHours: 1, KeepLocal: 1}, {At: "23:59", KeepLocal: 30}, {EveryHours: 168, KeepLocal: 2, KeepOffsite: 5, TargetID: "usb-disk"}}
	bad := []Spec{{}, {KeepLocal: 3}, {EveryHours: 6, At: "02:30", KeepLocal: 3}, {EveryHours: 169, KeepLocal: 1}, {At: "24:00", KeepLocal: 1}, {At: "2:30", KeepLocal: 1},
		{EveryHours: 6, KeepLocal: 0}, {EveryHours: 6, KeepLocal: 31}, {EveryHours: 6, KeepLocal: 1, KeepOffsite: 1}, {EveryHours: 6, KeepLocal: 1, TargetID: "usb-disk"},
		{EveryHours: 6, KeepLocal: 1, KeepOffsite: 31, TargetID: "usb-disk"}, {EveryHours: 6, KeepLocal: 1, KeepOffsite: 1, TargetID: "../x"}, {EveryHours: -1, KeepLocal: 1}}
	for _, s := range ok {
		if !s.Valid() {
			t.Errorf("%+v rejected", s)
		}
	}
	for _, s := range bad {
		if s.Valid() {
			t.Errorf("%+v accepted", s)
		}
	}
}

// ---- the chain ------------------------------------------------------------------------------------------------------------

type fakeOps struct {
	mu        sync.Mutex
	byKey     map[string]*operation.Operation
	order     []string
	cancelled []string
	n         int
}

func (f *fakeOps) Submit(_ operation.Actor, req operation.Request) (operation.Operation, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.byKey == nil {
		f.byKey = map[string]*operation.Operation{}
	}
	if op, ok := f.byKey[req.IdempotencyKey]; ok {
		return *op, nil
	}
	f.n++
	op := &operation.Operation{ID: fmt.Sprintf("op-%d", f.n), ResourceKind: req.Kind, ResourceID: req.ResourceID, Type: req.Type, Status: operation.Pending, IdempotencyKey: req.IdempotencyKey, Params: req.Params}
	if req.Type == operation.Backup {
		op.Params.BackupID = fmt.Sprintf("bk-%016x", f.n)
	}
	f.byKey[req.IdempotencyKey] = op
	f.order = append(f.order, req.IdempotencyKey)
	return *op, nil
}

func (f *fakeOps) Cancel(_ operation.Actor, id string) (operation.Operation, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, op := range f.byKey {
		if op.ID == id {
			if op.Status == operation.Pending || op.Status == operation.RetryableFailure {
				op.Status = operation.Cancelled
				f.cancelled = append(f.cancelled, id)
				return *op, nil
			}
			return *op, fmt.Errorf("not cancellable")
		}
	}
	return operation.Operation{}, fmt.Errorf("unknown")
}

func (f *fakeOps) set(typ operation.Type, status operation.Status) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, op := range f.byKey {
		if op.Type == typ {
			op.Status = status
		}
	}
}

func (f *fakeOps) of(typ operation.Type) []operation.Operation {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []operation.Operation
	for _, k := range f.order {
		if op := f.byKey[k]; op.Type == typ {
			out = append(out, *op)
		}
	}
	return out
}

type fakeWorld struct {
	mu       sync.Mutex
	vms      map[string]VMState
	backups  []BackupInfo
	copies   map[string][]string
	pruned   []string
	pruneErr error
}

func (w *fakeWorld) VM(_ context.Context, n string) (VMState, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.vms[n], nil
}
func (w *fakeWorld) Backups(context.Context) ([]BackupInfo, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return append([]BackupInfo(nil), w.backups...), nil
}
func (w *fakeWorld) Copies(context.Context) (map[string][]string, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	m := map[string][]string{}
	for k, v := range w.copies {
		m[k] = v
	}
	return m, nil
}
func (w *fakeWorld) Prune(_ context.Context, b, t string) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.pruneErr != nil {
		return w.pruneErr
	}
	w.pruned = append(w.pruned, b)
	delete(w.copies, b)
	return nil
}
func (w *fakeWorld) setVM(n, state string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.vms[n] = VMState{Found: true, Managed: true, State: state}
}

type rig struct {
	t     *testing.T
	s     *Scheduler
	ops   *fakeOps
	world *fakeWorld
	store *Store
	now   time.Time
	log   []string
}

func newRig(t *testing.T) *rig {
	t.Helper()
	db, err := sqlitedb.Open(filepath.Join(t.TempDir(), "s.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	st, err := OpenSQLite(context.Background(), db)
	if err != nil {
		t.Fatal(err)
	}
	r := &rig{t: t, ops: &fakeOps{}, world: &fakeWorld{vms: map[string]VMState{"web-1": {Found: true, Managed: true, State: "running"}}, copies: map[string][]string{}}, store: st, now: at("2026-10-15T01:00:00Z")}
	r.s = &Scheduler{Store: st, World: r.world, Ops: r.ops, Now: func() time.Time { return r.now }, Loc: time.UTC, Log: func(m string) { r.log = append(r.log, m) }}
	n := 0
	r.s.NewID = func() (string, error) { n++; return fmt.Sprintf("sr-%016x", n), nil }
	return r
}

func (r *rig) set(vm string, sp Spec) {
	r.t.Helper()
	if err := r.s.Set(context.Background(), vm, sp, "admin"); err != nil {
		r.t.Fatal(err)
	}
}

func (r *rig) tick(advance time.Duration) {
	r.now = r.now.Add(advance)
	r.s.Tick(context.Background())
}

func (r *rig) last(vm string) string {
	sc, _, _ := r.store.Get(context.Background(), vm)
	return sc.LastResult
}

func (r *rig) active() []Run {
	a, err := r.store.Active(context.Background())
	if err != nil {
		r.t.Fatal(err)
	}
	return a
}

func types(ops []operation.Operation) string {
	var s []string
	for _, o := range ops {
		s = append(s, string(o.Type))
	}
	return strings.Join(s, ",")
}

func (r *rig) all() string {
	r.ops.mu.Lock()
	defer r.ops.mu.Unlock()
	var s []string
	for _, k := range r.ops.order {
		s = append(s, string(r.ops.byKey[k].Type))
	}
	return strings.Join(s, ",")
}

func TestAWindowStopsBacksUpStartsAndEndsOK(t *testing.T) {
	r := newRig(t)
	r.set("web-1", Spec{EveryHours: 6, KeepLocal: 3})
	r.tick(time.Minute) // not due
	if len(r.active()) != 0 {
		t.Fatal("nothing is due yet")
	}
	r.tick(6 * time.Hour) // due: the window opens and asks for a graceful stop
	if r.all() != "stop" || len(r.active()) != 1 {
		t.Fatalf("ops %q active %d", r.all(), len(r.active()))
	}
	r.tick(10 * time.Second)
	if r.all() != "stop" {
		t.Fatalf("waits for the guest: %q", r.all())
	}
	r.ops.set(operation.Stop, operation.Succeeded)
	r.world.setVM("web-1", "shutoff")
	r.tick(10 * time.Second)
	if r.all() != "stop,backup" {
		t.Fatalf("%q", r.all())
	}
	r.ops.set(operation.Backup, operation.Succeeded)
	r.world.backups = []BackupInfo{{ID: r.ops.of(operation.Backup)[0].Params.BackupID, VM: "web-1", Valid: true}}
	r.tick(time.Minute)
	if r.all() != "stop,backup,start" {
		t.Fatalf("the machine is started again: %q", r.all())
	}
	r.ops.set(operation.Start, operation.Succeeded)
	r.world.setVM("web-1", "running")
	r.tick(10 * time.Second)
	if len(r.active()) != 0 || r.last("web-1") != ResultOK {
		t.Fatalf("active %d, last %q, log %v", len(r.active()), r.last("web-1"), r.log)
	}
	for _, o := range r.ops.of(operation.ForceOff) {
		t.Fatalf("a force-off was submitted: %+v", o)
	}
	for _, o := range r.ops.byKey {
		if !strings.HasPrefix(o.IdempotencyKey, "sch-sr-") {
			t.Fatalf("every key names the window: %q", o.IdempotencyKey)
		}
	}
	if sc, _, _ := r.store.Get(context.Background(), "web-1"); !sc.NextRun.After(r.now) {
		t.Fatalf("the next window is in the future: %v", sc.NextRun)
	}
}

func TestAStoppedMachineStaysStopped(t *testing.T) {
	r := newRig(t)
	r.world.setVM("web-1", "shutoff")
	r.set("web-1", Spec{EveryHours: 1, KeepLocal: 1})
	r.tick(time.Hour)
	if r.all() != "backup" {
		t.Fatalf("no stop for a stopped machine: %q", r.all())
	}
	r.ops.set(operation.Backup, operation.Succeeded)
	r.world.backups = []BackupInfo{{ID: r.ops.of(operation.Backup)[0].Params.BackupID, VM: "web-1", Valid: true}}
	r.tick(time.Minute)
	if r.all() != "backup" || len(r.active()) != 0 || r.last("web-1") != ResultOK {
		t.Fatalf("a machine that was stopped is not started: %q active %d last %q", r.all(), len(r.active()), r.last("web-1"))
	}
}

func TestAGuestThatWillNotStopEndsTheWindowWithoutForcingAnything(t *testing.T) {
	r := newRig(t)
	r.set("web-1", Spec{EveryHours: 1, KeepLocal: 1})
	r.tick(time.Hour)
	r.tick(DefaultStopDeadline + time.Minute) // the stop is still queued after the deadline
	if len(r.active()) != 0 || r.last("web-1") != ResultFailed {
		t.Fatalf("active %d last %q log %v", len(r.active()), r.last("web-1"), r.log)
	}
	if got := r.all(); got != "stop" {
		t.Fatalf("no backup of a running machine, no force-off, and nothing to start: %q", got)
	}
	if len(r.ops.cancelled) != 1 {
		t.Fatalf("the stuck stop is cancelled: %v", r.ops.cancelled)
	}
}

func TestARetryingStopThatUsedItsAttemptsEndsTheWindow(t *testing.T) {
	r := newRig(t)
	r.set("web-1", Spec{EveryHours: 1, KeepLocal: 1})
	r.tick(time.Hour)
	r.ops.mu.Lock()
	for _, o := range r.ops.byKey {
		o.Status, o.Attempts = operation.RetryableFailure, 3
	}
	r.ops.mu.Unlock()
	r.tick(10 * time.Second)
	if len(r.active()) != 0 || r.last("web-1") != ResultFailed {
		t.Fatalf("active %d last %q", len(r.active()), r.last("web-1"))
	}
}

func TestAFailedBackupStartsTheMachineAgainAndDeletesNothing(t *testing.T) {
	r := newRig(t)
	r.set("web-1", Spec{EveryHours: 1, KeepLocal: 1})
	r.world.backups = []BackupInfo{{ID: "bk-00000000000000aa", VM: "web-1", Valid: true}, {ID: "bk-00000000000000bb", VM: "web-1", Valid: true}}
	_ = r.store.Made(context.Background(), "bk-00000000000000aa", "web-1", "old", r.now.Add(-2*time.Hour))
	_ = r.store.Made(context.Background(), "bk-00000000000000bb", "web-1", "old", r.now.Add(-time.Hour))
	r.tick(time.Hour)
	r.ops.set(operation.Stop, operation.Succeeded)
	r.world.setVM("web-1", "shutoff")
	r.tick(10 * time.Second)
	r.ops.set(operation.Backup, operation.Failed)
	r.tick(10 * time.Second)
	if got := r.all(); got != "stop,backup,start" {
		t.Fatalf("the machine must come back after a failed backup: %q", got)
	}
	r.ops.set(operation.Start, operation.Succeeded)
	r.world.setVM("web-1", "running")
	r.tick(10 * time.Second)
	if r.last("web-1") != ResultFailed || len(r.ops.of(operation.Delete)) != 0 {
		t.Fatalf("last %q, deletes %d: a failed window deletes nothing", r.last("web-1"), len(r.ops.of(operation.Delete)))
	}
	if f, _ := r.store.Failed(context.Background()); len(f) != 1 || f[0] != "web-1" {
		t.Fatalf("the failure is listed for the alert rule: %v", f)
	}
}

func TestACrashBetweenStepsResumesTheSameWindow(t *testing.T) {
	r := newRig(t)
	r.set("web-1", Spec{EveryHours: 1, KeepLocal: 1})
	r.tick(time.Hour)
	r.ops.set(operation.Stop, operation.Succeeded)
	r.world.setVM("web-1", "shutoff")
	// The API process dies here. A new scheduler over the same database picks the window up.
	s2 := &Scheduler{Store: r.store, World: r.world, Ops: r.ops, Now: func() time.Time { return r.now }, Loc: time.UTC}
	r.now = r.now.Add(time.Minute)
	s2.Tick(context.Background())
	if r.all() != "stop,backup" || len(r.active()) != 1 {
		t.Fatalf("resumed at the backup step, one window only: %q active %d", r.all(), len(r.active()))
	}
	s2.Tick(context.Background())
	s2.Tick(context.Background())
	if len(r.ops.of(operation.Stop)) != 1 || len(r.ops.of(operation.Backup)) != 1 {
		t.Fatalf("no step is asked for twice: %q", r.all())
	}
	// A restart after the machine was stopped but before the window recorded it: the stop is replayed by its key, not asked again.
	if len(r.ops.order) != 2 {
		t.Fatalf("%v", r.ops.order)
	}
}

func fullWindow(r *rig, vm string) string {
	r.t.Helper()
	r.tick(time.Hour)
	r.ops.set(operation.Stop, operation.Succeeded)
	r.world.setVM(vm, "shutoff")
	r.tick(10 * time.Second)
	id := ""
	for _, o := range r.ops.of(operation.Backup) {
		id = o.Params.BackupID
	}
	r.ops.set(operation.Backup, operation.Succeeded)
	r.world.mu.Lock()
	r.world.backups = append(r.world.backups, BackupInfo{ID: id, VM: vm, Valid: true})
	r.world.mu.Unlock()
	r.tick(10 * time.Second)
	r.ops.set(operation.Start, operation.Succeeded)
	r.world.setVM(vm, "running")
	return id
}

func TestRetentionDeletesOnlyTheSchedulesOwnOldestBackups(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	foreign := "bk-00000000000000ff"
	r.world.backups = []BackupInfo{{ID: foreign, VM: "web-1", Valid: true}}
	var made []string
	for i := 1; i <= 3; i++ {
		id := fmt.Sprintf("bk-%016x", i+1000)
		made = append(made, id)
		_ = r.store.Made(ctx, id, "web-1", "earlier", r.now.Add(time.Duration(i)*time.Minute-time.Hour*24))
		r.world.backups = append(r.world.backups, BackupInfo{ID: id, VM: "web-1", Valid: true})
	}
	r.set("web-1", Spec{EveryHours: 1, KeepLocal: 2})
	newest := fullWindow(r, "web-1")
	r.tick(10 * time.Second) // retention submits deletes
	dels := r.ops.of(operation.Delete)
	if len(dels) != 2 {
		t.Fatalf("four of the scheduler's own backups, two kept: %d deletes (%v)", len(dels), types(dels))
	}
	got := map[string]bool{}
	for _, d := range dels {
		got[d.ResourceID] = true
		if d.ResourceKind != operation.KindBackup {
			t.Fatalf("%+v", d)
		}
	}
	if !got[made[0]] || !got[made[1]] || got[made[2]] || got[newest] || got[foreign] {
		t.Fatalf("the two oldest of its own go; the newest two and the foreign one stay: %v", got)
	}
	if len(r.active()) != 1 {
		t.Fatal("the window waits for the deletes")
	}
	r.ops.set(operation.Delete, operation.Succeeded)
	r.tick(10 * time.Second)
	if len(r.active()) != 0 || r.last("web-1") != ResultOK {
		t.Fatalf("active %d last %q", len(r.active()), r.last("web-1"))
	}
}

func TestNeverTheNewestVerifiedCopyEvenWhenItIsDamaged(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	old := "bk-00000000000003e9"
	_ = r.store.Made(ctx, old, "web-1", "earlier", r.now.Add(-24*time.Hour))
	r.world.backups = []BackupInfo{{ID: old, VM: "web-1", Valid: true}}
	r.set("web-1", Spec{EveryHours: 1, KeepLocal: 1})
	// the new backup is reported damaged: retention must not delete the only good one
	r.tick(time.Hour)
	r.ops.set(operation.Stop, operation.Succeeded)
	r.world.setVM("web-1", "shutoff")
	r.tick(10 * time.Second)
	id := r.ops.of(operation.Backup)[0].Params.BackupID
	r.ops.set(operation.Backup, operation.Succeeded)
	r.world.backups = append(r.world.backups, BackupInfo{ID: id, VM: "web-1", Valid: false})
	r.tick(10 * time.Second)
	r.ops.set(operation.Start, operation.Succeeded)
	r.world.setVM("web-1", "running")
	r.tick(10 * time.Second)
	if n := len(r.ops.of(operation.Delete)); n != 0 {
		t.Fatalf("%d deletes: the older good copy is all there is", n)
	}
}

func TestOffsiteCopiesAreExportedAndOldOnesPruned(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	var made []string
	for i := 1; i <= 3; i++ {
		id := fmt.Sprintf("bk-%016x", i+2000)
		made = append(made, id)
		_ = r.store.Made(ctx, id, "web-1", "earlier", r.now.Add(time.Duration(i)*time.Minute-24*time.Hour))
		r.world.backups = append(r.world.backups, BackupInfo{ID: id, VM: "web-1", Valid: true})
		r.world.copies[id] = []string{"usb-disk"}
	}
	r.world.copies["bk-00000000000000ee"] = []string{"usb-disk"} // somebody else's copy on the same target
	r.set("web-1", Spec{EveryHours: 1, KeepLocal: 10, KeepOffsite: 2, TargetID: "usb-disk"})
	id := fullWindow(r, "web-1")
	r.tick(10 * time.Second)
	ex := r.ops.of(operation.BackupExport)
	if len(ex) != 1 || ex[0].ResourceID != id || ex[0].Params.TargetID != "usb-disk" || ex[0].ResourceKind != operation.KindBackup {
		t.Fatalf("the new backup is copied to the target: %+v", ex)
	}
	r.ops.set(operation.BackupExport, operation.Succeeded)
	r.world.mu.Lock()
	r.world.copies[id] = []string{"usb-disk"}
	r.world.mu.Unlock()
	r.tick(10 * time.Second)
	if len(r.world.pruned) != 2 || r.world.pruned[0] == "bk-00000000000000ee" || r.world.pruned[1] == "bk-00000000000000ee" {
		t.Fatalf("four of its own copies (three older and the new one), two kept: pruned %v", r.world.pruned)
	}
	for _, p := range r.world.pruned {
		if p == id || p == made[2] {
			t.Fatalf("the newest copies stay: pruned %v", r.world.pruned)
		}
	}
	if len(r.active()) != 0 || r.last("web-1") != ResultOK {
		t.Fatalf("active %d last %q", len(r.active()), r.last("web-1"))
	}
}

func TestAFailedExportMakesTheWindowFailAndPrunesNothingOffsite(t *testing.T) {
	r := newRig(t)
	_ = r.store.Made(context.Background(), "bk-00000000000007d1", "web-1", "earlier", r.now.Add(-24*time.Hour))
	r.world.copies["bk-00000000000007d1"] = []string{"usb-disk"}
	r.world.backups = []BackupInfo{{ID: "bk-00000000000007d1", VM: "web-1", Valid: true}}
	r.set("web-1", Spec{EveryHours: 1, KeepLocal: 5, KeepOffsite: 1, TargetID: "usb-disk"})
	fullWindow(r, "web-1")
	r.tick(10 * time.Second)
	r.ops.set(operation.BackupExport, operation.Failed)
	r.tick(10 * time.Second)
	if len(r.world.pruned) != 0 || r.last("web-1") != ResultFailed || len(r.active()) != 0 {
		t.Fatalf("pruned %v last %q active %d: with the new copy missing, the old one is all there is", r.world.pruned, r.last("web-1"), len(r.active()))
	}
}

func TestMissedDailyWindowIsSkippedAndAnHoursOneRunsOnce(t *testing.T) {
	r := newRig(t)
	r.set("web-1", Spec{At: "02:30", KeepLocal: 1})
	r.tick(14 * time.Hour) // the host was down: it is 15:00 now
	if len(r.active()) != 0 || r.last("web-1") != ResultSkipped || r.all() != "" {
		t.Fatalf("skipped, nothing submitted: active %d last %q ops %q", len(r.active()), r.last("web-1"), r.all())
	}
	r2 := newRig(t)
	r2.set("web-1", Spec{EveryHours: 4, KeepLocal: 1})
	r2.tick(40 * time.Hour)
	if r2.all() != "stop" {
		t.Fatalf("an hours schedule runs once after downtime: %q", r2.all())
	}
	r2.ops.set(operation.Stop, operation.Failed)
	r2.tick(time.Second)
	r2.tick(time.Second)
	if n := len(r2.ops.of(operation.Stop)); n != 1 {
		t.Fatalf("not once per missed interval: %d stops", n)
	}
}

func TestWindowsRunOneAtATime(t *testing.T) {
	r := newRig(t)
	r.world.vms["db-1"] = VMState{Found: true, Managed: true, State: "running"}
	r.set("web-1", Spec{EveryHours: 1, KeepLocal: 1})
	r.set("db-1", Spec{EveryHours: 1, KeepLocal: 1})
	r.tick(time.Hour)
	r.tick(time.Second)
	if len(r.active()) != 1 || len(r.ops.of(operation.Stop)) != 1 {
		t.Fatalf("active %d stops %d", len(r.active()), len(r.ops.of(operation.Stop)))
	}
}

func TestADisabledSchedulerOpensNothingButFinishesWhatIsOpen(t *testing.T) {
	r := newRig(t)
	r.set("web-1", Spec{EveryHours: 1, KeepLocal: 1})
	r.tick(time.Hour)
	r.s.Disabled = true
	r.ops.set(operation.Stop, operation.Succeeded)
	r.world.setVM("web-1", "shutoff")
	r.tick(10 * time.Second)
	if r.all() != "stop,backup" {
		t.Fatalf("an open window continues so the machine is not left stopped: %q", r.all())
	}
	r.ops.set(operation.Backup, operation.Failed)
	r.tick(10 * time.Second)
	r.ops.set(operation.Start, operation.Succeeded)
	r.world.setVM("web-1", "running")
	r.tick(10 * time.Second)
	n := len(r.ops.order)
	r.tick(48 * time.Hour)
	if len(r.ops.order) != n || len(r.active()) != 0 {
		t.Fatal("nothing new opens while the scheduler is paused")
	}
}

func TestSetAndClearGuards(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	r.world.vms["foreign"] = VMState{Found: true, Managed: false, State: "running"}
	if err := r.s.Set(ctx, "nope", Spec{EveryHours: 1, KeepLocal: 1}, "a"); err != ErrNoVM {
		t.Errorf("unknown VM: %v", err)
	}
	if err := r.s.Set(ctx, "foreign", Spec{EveryHours: 1, KeepLocal: 1}, "a"); err != ErrNotOurs {
		t.Errorf("foreign VM: %v", err)
	}
	if err := r.s.Set(ctx, "web-1", Spec{EveryHours: 0, KeepLocal: 1}, "a"); err != ErrInvalid {
		t.Errorf("invalid spec: %v", err)
	}
	if err := r.s.Set(ctx, "Bad_Name", Spec{EveryHours: 1, KeepLocal: 1}, "a"); err != ErrInvalid {
		t.Errorf("invalid name: %v", err)
	}
	if err := r.s.Set(ctx, "web-1", Spec{At: "03:00", KeepLocal: 2}, "a"); err != nil {
		t.Fatal(err)
	}
	sc, ok, _ := r.store.Get(ctx, "web-1")
	if !ok || sc.Spec.At != "03:00" || sc.SetBy != "a" || !sc.NextRun.After(r.now) {
		t.Fatalf("%+v", sc)
	}
	if err := r.s.Clear(ctx, "web-1"); err != nil {
		t.Fatal(err)
	}
	if err := r.s.Clear(ctx, "web-1"); err != nil {
		t.Fatalf("clearing twice is success: %v", err)
	}
	if _, ok, _ := r.store.Get(ctx, "web-1"); ok {
		t.Fatal("cleared")
	}
}

func TestAMachineThatIsGoneTakesItsScheduleWithIt(t *testing.T) {
	r := newRig(t)
	r.set("web-1", Spec{EveryHours: 1, KeepLocal: 1})
	r.world.mu.Lock()
	delete(r.world.vms, "web-1")
	r.world.mu.Unlock()
	r.tick(time.Hour)
	if _, ok, _ := r.store.Get(context.Background(), "web-1"); ok || r.all() != "" {
		t.Fatalf("schedule should be removed with its machine; ops %q", r.all())
	}
}

func TestAnOpenWindowFinishesEvenIfTheScheduleIsClearedMeanwhile(t *testing.T) {
	r := newRig(t)
	r.set("web-1", Spec{EveryHours: 1, KeepLocal: 1})
	r.tick(time.Hour)
	r.ops.set(operation.Stop, operation.Succeeded)
	r.world.setVM("web-1", "shutoff")
	r.tick(10 * time.Second)
	if err := r.s.Clear(context.Background(), "web-1"); err != nil {
		t.Fatal(err)
	}
	r.ops.set(operation.Backup, operation.Failed)
	r.tick(10 * time.Second)
	if r.all() != "stop,backup,start" {
		t.Fatalf("the machine still comes back: %q", r.all())
	}
}
