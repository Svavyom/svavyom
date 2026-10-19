package schedule

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"sort"
	"sync"
	"time"

	"example.invalid/dedicatedcloud/backend/internal/operation"
)

// Actor is the identity under which the scheduler submits operations; Activity shows it as the requester.
const Actor = "scheduler"

// Deadlines of a window. A graceful stop waits for the guest; the scheduler never forces it off, it gives up on the window instead and puts the
// machine back the way it found it.
const (
	DefaultStopDeadline = 15 * time.Minute
	DefaultStepDeadline = 4 * time.Hour
	DefaultTickInterval = 10 * time.Second
	DefaultMaxAttempts  = 3
	maxRunsPerTickSteps = 12
)

// VMState is what the scheduler needs to know of a VM: whether it exists, whether Svavyom manages it, and whether it is running or stopped. Any other
// power state is reported as State "other".
type VMState struct {
	Found, Managed bool
	State          string // running | shutoff | other
}

// BackupInfo is a backup in the local store.
type BackupInfo struct {
	ID        string
	VM        string
	CreatedAt string
	Valid     bool
}

// World is the read side and the off-host side the scheduler works with.
type World interface {
	VM(ctx context.Context, name string) (VMState, error)
	Backups(ctx context.Context) ([]BackupInfo, error)
	// Copies maps a backup id to the targets that hold a verified copy (nil when off-host copies are not configured).
	Copies(ctx context.Context) (map[string][]string, error)
	// Prune removes the off-host copy of backup that this host exported to target.
	Prune(ctx context.Context, backup, target string) error
}

// Ops is the operation manager as the scheduler uses it.
type Ops interface {
	Submit(actor operation.Actor, req operation.Request) (operation.Operation, error)
	Cancel(actor operation.Actor, id string) (operation.Operation, error)
}

// Scheduler opens and advances maintenance windows.
type Scheduler struct {
	Store *Store
	World World
	Ops   Ops
	// Notify wakes the operation worker after a submission.
	Notify func()
	Now    func() time.Time
	Loc    *time.Location
	// Log receives one short line per decision that a person may later ask about (never a secret, a path or host text).
	Log func(string)

	MaxAttempts  int
	StopDeadline time.Duration
	StepDeadline time.Duration
	Interval     time.Duration
	NewID        func() (string, error)
	// Disabled pauses the scheduler for the whole host (the operator's switch): schedules stay stored and nothing runs.
	Disabled bool

	mu sync.Mutex
}

func (s *Scheduler) now() time.Time {
	if s.Now != nil {
		return s.Now().UTC()
	}
	return time.Now().UTC()
}

func (s *Scheduler) loc() *time.Location {
	if s.Loc != nil {
		return s.Loc
	}
	return time.Local
}

func (s *Scheduler) logf(m string) {
	if s.Log != nil {
		s.Log(m)
	}
}

func (s *Scheduler) maxAttempts() int {
	if s.MaxAttempts > 0 {
		return s.MaxAttempts
	}
	return DefaultMaxAttempts
}

func dur(d, def time.Duration) time.Duration {
	if d > 0 {
		return d
	}
	return def
}

func (s *Scheduler) newID() (string, error) {
	if s.NewID != nil {
		return s.NewID()
	}
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return "sr-" + hex.EncodeToString(b[:]), nil
}

// Errors of Set.
var (
	ErrNoVM       = errors.New("schedule: no such VM")
	ErrNotOurs    = errors.New("schedule: the VM is not managed by Svavyom")
	ErrInvalid    = errors.New("schedule: invalid schedule")
	ErrUnreadable = errors.New("schedule: cannot read the host")
	ErrStore      = errors.New("schedule: store unavailable")
)

// Set creates or replaces the schedule of vm. The first window is the next one after now.
func (s *Scheduler) Set(ctx context.Context, vm string, sp Spec, by string) error {
	if !vmRE.MatchString(vm) || !sp.Valid() {
		return ErrInvalid
	}
	st, err := s.World.VM(ctx, vm)
	switch {
	case err != nil:
		return ErrUnreadable
	case !st.Found:
		return ErrNoVM
	case !st.Managed:
		return ErrNotOurs
	}
	now := s.now()
	if err := s.Store.Put(ctx, Schedule{VM: vm, Spec: sp, SetBy: by, CreatedAt: now, NextRun: NextAfter(sp, now, s.loc())}); err != nil {
		return ErrStore
	}
	return nil
}

// Clear removes the schedule of vm. Clearing a schedule that does not exist is success.
func (s *Scheduler) Clear(ctx context.Context, vm string) error {
	if !vmRE.MatchString(vm) {
		return ErrInvalid
	}
	if err := s.Store.Delete(ctx, vm); err != nil {
		return ErrStore
	}
	return nil
}

// Run ticks until ctx ends.
func (s *Scheduler) Run(ctx context.Context) {
	t := time.NewTicker(dur(s.Interval, DefaultTickInterval))
	defer t.Stop()
	for {
		s.Tick(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// Tick advances every open window and, when none is open, opens the next due one. Windows run one at a time: a host that stops several machines for
// backups at once is a host that is busy with the wrong thing.
func (s *Scheduler) Tick(ctx context.Context) {
	s.mu.Lock()
	defer s.mu.Unlock()
	active, err := s.Store.Active(ctx)
	if err != nil {
		s.logf("schedule: cannot read the open windows")
		return
	}
	for _, r := range active {
		s.advance(ctx, r) // an open window always finishes, even when the scheduler is paused: it is holding a machine stopped
	}
	if s.Disabled || len(active) > 0 {
		return
	}
	s.openNext(ctx)
}

func (s *Scheduler) openNext(ctx context.Context) {
	all, err := s.Store.All(ctx)
	if err != nil {
		return
	}
	now := s.now()
	for _, sc := range all {
		if sc.NextRun.After(now) {
			return // ordered by next run: nothing later is due either
		}
		run, next := Due(sc.Spec, sc.NextRun, now, s.loc())
		if err := s.Store.SetNext(ctx, sc.VM, next); err != nil {
			return
		}
		if !run {
			_ = s.Store.Record(ctx, sc.VM, ResultSkipped, now)
			s.logf("schedule: a daily window for " + sc.VM + " was missed by more than the allowed delay and is skipped")
			continue
		}
		st, err := s.World.VM(ctx, sc.VM)
		switch {
		case err != nil:
			return // cannot see the host: try again on the next tick (the next run time has already moved, so this window is lost, not repeated)
		case !st.Found:
			_ = s.Store.Delete(ctx, sc.VM) // the machine is gone: so is its schedule
			continue
		case !st.Managed, st.State == "other":
			_ = s.Store.Record(ctx, sc.VM, ResultSkipped, now)
			continue
		}
		id, err := s.newID()
		if err != nil {
			return
		}
		r := Run{ID: id, VM: sc.VM, Spec: sc.Spec, Step: StepStop, WasRunning: st.State == "running", StartedAt: now, StepSince: now}
		if !r.WasRunning {
			r.Step = StepBackup
		}
		if err := s.Store.Begin(ctx, r); err != nil {
			return
		}
		s.logf("schedule: window opened for " + sc.VM)
		s.advance(ctx, r)
		return
	}
}

func key(run Run, step string) string { return "sch-" + run.ID + "-" + step }

type verdict int

const (
	wait verdict = iota
	done
	bad
)

// classify reads an operation: done when it succeeded, bad when it failed, was cancelled or has used its attempts, wait otherwise. A step that has
// gone over its deadline while it is only queued or waiting to be retried is cancelled and reported bad; one that is executing is left to finish.
func (s *Scheduler) classify(op operation.Operation, since time.Time, deadline time.Duration) verdict {
	switch op.Status {
	case operation.Succeeded:
		return done
	case operation.Failed, operation.Cancelled:
		return bad
	case operation.RetryableFailure:
		if op.Attempts >= s.maxAttempts() {
			_, _ = s.Ops.Cancel(operation.Actor{ID: Actor}, op.ID)
			return bad
		}
	}
	if op.Status != operation.Running && s.now().Sub(since) > deadline {
		if _, err := s.Ops.Cancel(operation.Actor{ID: Actor}, op.ID); err == nil {
			return bad
		}
	}
	return wait
}

func (s *Scheduler) submit(req operation.Request) (operation.Operation, bool) {
	req.ProjectID = "default"
	op, err := s.Ops.Submit(operation.Actor{ID: Actor}, req)
	if err != nil {
		return operation.Operation{}, false
	}
	if s.Notify != nil {
		s.Notify()
	}
	return op, true
}

func (s *Scheduler) move(ctx context.Context, r *Run, step string) bool {
	r.Step, r.StepSince = step, s.now()
	return s.Store.Update(ctx, *r) == nil
}

// advance takes a window as far as it can go in this tick.
func (s *Scheduler) advance(ctx context.Context, r Run) {
	for i := 0; i < maxRunsPerTickSteps; i++ {
		switch r.Step {
		case StepStop:
			st, err := s.World.VM(ctx, r.VM)
			if err != nil {
				return
			}
			if !st.Found || !st.Managed {
				s.finish(ctx, r, ResultSkipped)
				return
			}
			if st.State == "shutoff" {
				if !s.move(ctx, &r, StepBackup) {
					return
				}
				continue
			}
			op, ok := s.submit(operation.Request{Type: operation.Stop, Kind: operation.KindVM, ResourceID: r.VM, IdempotencyKey: key(r, "stop")})
			if !ok {
				return
			}
			switch s.classify(op, r.StepSince, dur(s.StopDeadline, DefaultStopDeadline)) {
			case wait:
				return
			case bad:
				r.Failed = true
				s.logf("schedule: " + r.VM + " did not shut down in time; the window is abandoned and the machine is left as it is")
				if !s.move(ctx, &r, StepStart) {
					return
				}
			default:
				if !s.move(ctx, &r, StepBackup) {
					return
				}
			}
		case StepBackup:
			op, ok := s.submit(operation.Request{Type: operation.Backup, Kind: operation.KindVM, ResourceID: r.VM, IdempotencyKey: key(r, "backup")})
			if !ok {
				return
			}
			if r.BackupID == "" && op.Params.BackupID != "" {
				r.BackupID = op.Params.BackupID
				if s.Store.Made(ctx, r.BackupID, r.VM, r.ID, s.now()) != nil || s.Store.Update(ctx, r) != nil {
					return
				}
			}
			switch s.classify(op, r.StepSince, dur(s.StepDeadline, DefaultStepDeadline)) {
			case wait:
				return
			case bad:
				r.Failed = true
				if !s.move(ctx, &r, StepStart) {
					return
				}
			default:
				if !s.move(ctx, &r, StepStart) {
					return
				}
			}
		case StepStart:
			if r.WasRunning {
				st, err := s.World.VM(ctx, r.VM)
				if err != nil {
					return
				}
				switch {
				case !st.Found:
					s.finish(ctx, r, ResultFailed)
					return
				case st.State == "shutoff":
					op, ok := s.submit(operation.Request{Type: operation.Start, Kind: operation.KindVM, ResourceID: r.VM, IdempotencyKey: key(r, "start")})
					if !ok {
						return
					}
					switch s.classify(op, r.StepSince, dur(s.StopDeadline, DefaultStopDeadline)) {
					case wait:
						return
					case bad:
						r.Failed = true // the machine stays stopped and the alert says so
					}
				case st.State == "other":
					r.Failed = true
				}
			}
			next := StepRetention
			if !r.Failed && r.BackupID != "" && r.Spec.TargetID != "" {
				next = StepExport
			}
			if !s.move(ctx, &r, next) {
				return
			}
		case StepExport:
			op, ok := s.submit(operation.Request{Type: operation.BackupExport, Kind: operation.KindBackup, ResourceID: r.BackupID, IdempotencyKey: key(r, "export"),
				Params: operation.Params{TargetID: r.Spec.TargetID}})
			if !ok {
				return
			}
			switch s.classify(op, r.StepSince, dur(s.StepDeadline, DefaultStepDeadline)) {
			case wait:
				return
			case bad:
				r.Failed = true
			}
			if !s.move(ctx, &r, StepRetention) {
				return
			}
		case StepRetention:
			if !s.retention(ctx, r) {
				return
			}
			result := ResultOK
			if r.Failed {
				result = ResultFailed
			}
			s.finish(ctx, r, result)
			return
		default:
			s.finish(ctx, r, ResultFailed)
			return
		}
	}
}

func (s *Scheduler) finish(ctx context.Context, r Run, result string) {
	if err := s.Store.End(ctx, r.ID, s.now()); err != nil {
		return
	}
	if _, ok, _ := s.Store.Get(ctx, r.VM); ok {
		_ = s.Store.Record(ctx, r.VM, result, s.now())
	}
	s.logf("schedule: window for " + r.VM + " ended: " + result)
}

// retention removes, oldest first, the backups this scheduler made beyond the limits. It runs only when the backup this window made is in place (and,
// for the off-host limit, its copy is too): a window that failed deletes nothing. It reports whether it has nothing left to wait for.
func (s *Scheduler) retention(ctx context.Context, r Run) bool {
	made, err := s.Store.MadeBy(ctx, r.VM)
	if err != nil {
		return false
	}
	listed, err := s.World.Backups(ctx)
	if err != nil {
		return false
	}
	valid := map[string]bool{}
	present := map[string]bool{}
	for _, b := range listed {
		present[b.ID] = true
		valid[b.ID] = b.Valid
	}
	var copies map[string][]string
	if r.Spec.TargetID != "" {
		copies, err = s.World.Copies(ctx)
		if err != nil {
			copies = nil
		}
	}
	held := func(id string) bool {
		for _, t := range copies[id] {
			if t == r.Spec.TargetID {
				return true
			}
		}
		return false
	}
	finished := true
	if r.BackupID != "" && present[r.BackupID] && valid[r.BackupID] {
		var local []string
		for _, id := range made {
			if present[id] && valid[id] {
				local = append(local, id)
			}
		}
		for i, id := range local {
			if i < r.Spec.KeepLocal {
				continue
			}
			op, ok := s.submit(operation.Request{Type: operation.Delete, Kind: operation.KindBackup, ResourceID: id, IdempotencyKey: key(r, "del-"+id)})
			if !ok {
				finished = false
				continue
			}
			switch op.Status {
			case operation.Succeeded:
				present[id] = false
			case operation.Failed, operation.Cancelled:
			default:
				finished = false
			}
		}
	}
	if r.Spec.TargetID != "" && r.Spec.KeepOffsite > 0 && r.BackupID != "" && held(r.BackupID) {
		n := 0
		for _, id := range made {
			if !held(id) {
				continue
			}
			n++
			if n <= r.Spec.KeepOffsite {
				continue
			}
			if err := s.World.Prune(ctx, id, r.Spec.TargetID); err != nil {
				finished = false // try again on the next tick; the window stays open until it is settled or the deadline passes
				if s.now().Sub(r.StepSince) > dur(s.StepDeadline, DefaultStepDeadline) {
					finished = true
				}
				continue
			}
			copies[id] = nil
		}
	}
	// Records of backups that are gone from the store and hold no copy any more are dropped.
	sort.Strings(made)
	for _, id := range made {
		if !present[id] && !held(id) {
			_ = s.Store.Forget(ctx, id)
		}
	}
	return finished
}
