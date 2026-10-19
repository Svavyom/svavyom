package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	"example.invalid/dedicatedcloud/backend/internal/alerts"
	"example.invalid/dedicatedcloud/backend/internal/api"
	"example.invalid/dedicatedcloud/backend/internal/hostinfo"
	"example.invalid/dedicatedcloud/backend/internal/hypervisor"
	"example.invalid/dedicatedcloud/backend/internal/operation"
	"example.invalid/dedicatedcloud/backend/internal/provision"
	"example.invalid/dedicatedcloud/backend/internal/schedule"
)

// alertInterval is how often the rules are evaluated (DR-024 D2).
const alertInterval = 30 * time.Second

// recentOpWindow is how long after an operation that stops, removes or restarts a VM a VM that is not running is still expected.
const recentOpWindow = 10 * time.Minute

// alertSources are the facts the alert rules look at, each a function so a source that is not configured is simply absent.
type alertSources struct {
	HostID      string
	PoolFree    func(ctx context.Context) (percent int, ok bool)
	BackupFree  func(ctx context.Context) (percent int, ok bool)
	HostMemUsed func(ctx context.Context) (percent int, ok bool)
	VMs         hypervisor.Reader
	Ops         operation.Store
	MaxAttempts int
	// SchedulesFailed returns the VM names whose last scheduled backup failed; ok is false when it cannot be read.
	SchedulesFailed func(ctx context.Context) (vms []string, ok bool)
	// NightlyFailed reports whether the last nightly boot failed.
	NightlyFailed func() bool
	Now           func() time.Time
}

func (s alertSources) gather(ctx context.Context) alerts.Inputs {
	now := time.Now
	if s.Now != nil {
		now = s.Now
	}
	in := alerts.Inputs{HostID: s.HostID}
	if s.PoolFree != nil {
		if p, ok := s.PoolFree(ctx); ok {
			in.PoolFreePercent = &p
		}
	}
	if s.BackupFree != nil {
		if p, ok := s.BackupFree(ctx); ok {
			in.BackupStoreFreePercent = &p
		}
	}
	if s.HostMemUsed != nil {
		if p, ok := s.HostMemUsed(ctx); ok {
			in.HostMemoryUsedPercent = &p
		}
	}
	if s.VMs != nil {
		if ds, err := s.VMs.List(ctx); err == nil {
			in.VMsKnown = true
			for _, d := range ds {
				in.VMs = append(in.VMs, alerts.VMState{Name: d.Name, Managed: d.Managed, State: string(d.State)})
			}
		}
	}
	if s.Ops != nil {
		in.StoppedByOperation = map[string]bool{}
		if open, err := s.Ops.NonTerminal(); err == nil {
			in.ExhaustedKnown = true
			for _, o := range open {
				if o.Status == operation.RetryableFailure && o.Attempts >= s.MaxAttempts {
					in.ExhaustedOps = append(in.ExhaustedOps, alerts.ResourceRef{Kind: o.ResourceKind, ID: o.ResourceID})
				}
				if o.ResourceKind == operation.KindVM && removesFromRunning(o.Type) {
					in.StoppedByOperation[o.ResourceID] = true
				}
			}
		}
		if l, ok := s.Ops.(operation.Lister); ok {
			if page, _, err := l.Recent(100, ""); err == nil {
				for _, o := range page {
					if o.ResourceKind == operation.KindVM && removesFromRunning(o.Type) && now().Sub(o.UpdatedAt) < recentOpWindow {
						in.StoppedByOperation[o.ResourceID] = true
					}
				}
			}
		}
	}
	if s.SchedulesFailed != nil {
		if vms, ok := s.SchedulesFailed(ctx); ok {
			in.SchedulesKnown, in.ScheduleFailed = true, vms
		}
	}
	if s.NightlyFailed != nil {
		in.NightlyBootFail = s.NightlyFailed()
	}
	return in
}

// removesFromRunning is true for the operations after which a VM is expected not to be running: someone asked for it.
func removesFromRunning(t operation.Type) bool {
	switch t {
	case operation.Stop, operation.ForceOff, operation.Delete, operation.Reboot:
		return true
	}
	return false
}

// alertLoop evaluates the rules until ctx ends and hands every change to notify.
type alertLoop struct {
	Engine    *alerts.Engine
	Evaluator *alerts.Evaluator
	Sources   alertSources
	Notify    func([]alerts.Change)
	Interval  time.Duration
	Log       io.Writer
}

func (l *alertLoop) once(ctx context.Context) {
	obs, covered := l.Evaluator.Evaluate(l.Sources.gather(ctx))
	changes, err := l.Engine.Apply(ctx, obs, covered)
	if err != nil && l.Log != nil {
		_, _ = io.WriteString(l.Log, "WARNING alert evaluation failed\n")
	}
	if len(changes) > 0 && l.Notify != nil {
		l.Notify(changes)
	}
}

func (l *alertLoop) run(ctx context.Context) {
	iv := l.Interval
	if iv <= 0 {
		iv = alertInterval
	}
	t := time.NewTicker(iv)
	defer t.Stop()
	l.once(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			l.once(ctx)
		}
	}
}

// localOps runs the operations that change only the platform's own records (DR-024).
type localOps struct {
	engine *alerts.Engine
	sched  *schedule.Scheduler
}

func (l localOps) AlertAcknowledge(ctx context.Context, id, _ string) error {
	return l.engine.Acknowledge(ctx, id)
}

func scheduleError(op string, err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, schedule.ErrNoVM):
		return hypervisor.NewError(hypervisor.NotFound, op, "", "no such VM")
	case errors.Is(err, schedule.ErrNotOurs):
		return hypervisor.NewError(hypervisor.Prohibited, op, "", "not managed")
	case errors.Is(err, schedule.ErrInvalid):
		return hypervisor.NewError(hypervisor.Validation, op, "", "invalid")
	}
	return hypervisor.NewError(hypervisor.Unavailable, op, "", "unavailable")
}

func (l localOps) ScheduleSet(ctx context.Context, vm string, p operation.Params, by string) error {
	if l.sched == nil {
		return hypervisor.NewError(hypervisor.Prohibited, "schedule_set", "", "not available")
	}
	return scheduleError("schedule_set", l.sched.Set(ctx, vm, schedule.Spec{EveryHours: p.EveryHours, At: p.At, KeepLocal: p.KeepLocal, KeepOffsite: p.KeepOffsite, TargetID: p.TargetID}, by))
}

func (l localOps) ScheduleClear(ctx context.Context, vm string) error {
	if l.sched == nil {
		return hypervisor.NewError(hypervisor.Prohibited, "schedule_clear", "", "not available")
	}
	return scheduleError("schedule_clear", l.sched.Clear(ctx, vm))
}

// scheduleWorld is the scheduler's view of the host, built from the same readers the API uses.
type scheduleWorld struct {
	vms     hypervisor.Reader
	backups func(context.Context) ([]api.BackupInfo, error)
	copies  func(context.Context) (map[string][]string, error)
	prune   func(ctx context.Context, backup, target string) error
}

func (w scheduleWorld) VM(ctx context.Context, name string) (schedule.VMState, error) {
	if w.vms == nil {
		return schedule.VMState{}, errors.New("no inventory")
	}
	d, err := w.vms.Lookup(ctx, name)
	switch hypervisor.CategoryOf(err) {
	case "":
	case hypervisor.NotFound:
		return schedule.VMState{}, nil
	default:
		return schedule.VMState{}, err
	}
	st := "other"
	switch d.State {
	case hypervisor.StateRunning:
		st = "running"
	case hypervisor.StateShutoff:
		st = "shutoff"
	}
	return schedule.VMState{Found: true, Managed: d.Managed, State: st}, nil
}

func (w scheduleWorld) Backups(ctx context.Context) ([]schedule.BackupInfo, error) {
	if w.backups == nil {
		return nil, errors.New("no backup store")
	}
	l, err := w.backups(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]schedule.BackupInfo, 0, len(l))
	for _, b := range l {
		out = append(out, schedule.BackupInfo{ID: b.ID, VM: b.VM, CreatedAt: b.CreatedAt, Valid: b.Valid})
	}
	return out, nil
}

func (w scheduleWorld) Copies(ctx context.Context) (map[string][]string, error) {
	if w.copies == nil {
		return nil, nil
	}
	return w.copies(ctx)
}

func (w scheduleWorld) Prune(ctx context.Context, backup, target string) error {
	if w.prune == nil {
		return errors.New("no off-host service")
	}
	return w.prune(ctx, backup, target)
}

// startAlerts wires the alert subsystem into the API and starts its loops.
func startAlerts(ctx context.Context, stderr io.Writer, deps *api.Deps, engine *alerts.Engine, store *alerts.SQLiteStore, set *provision.AlertSettings, ops operation.Store, hosts *hostinfo.Provider, scheds *schedule.Store) {
	view := &api.AlertsView{Source: store}
	deps.Alerts = view
	th := alerts.Thresholds{}
	var notify func([]alerts.Change)
	if set != nil {
		th = alerts.Thresholds{WarnPercent: set.DiskWarnPercent, CritPercent: set.DiskCritPercent}
		if set.Webhook != nil {
			n, err := alerts.NewNotifier(alerts.Webhook{URL: set.Webhook.URL, Internal: set.Webhook.AllowInternal})
			if err != nil {
				_, _ = fmt.Fprintln(stderr, "WARNING the alert webhook is not valid; no notifications will be sent")
			} else {
				view.Webhook = true
				notify = n.Notify
				go n.Run(ctx)
			}
		}
	}
	src := alertSources{HostID: "local", Ops: ops, MaxAttempts: 3, VMs: deps.VMs}
	if info, err := hosts.Host(ctx); err == nil {
		src.HostID = info.ID
	}
	if cr := deps.Creation; cr != nil && cr.Stats != nil {
		stats := func(c context.Context) (api.StorageStats, bool) {
			c2, cancel := context.WithTimeout(c, 10*time.Second)
			defer cancel()
			st, err := cr.Stats(c2)
			return st, err == nil
		}
		src.PoolFree = func(c context.Context) (int, bool) {
			st, ok := stats(c)
			if !ok || st.PoolCapacity <= 0 {
				return 0, false
			}
			return int(st.PoolAvailable * 100 / st.PoolCapacity), true
		}
		src.BackupFree = func(c context.Context) (int, bool) {
			st, ok := stats(c)
			if !ok || !st.BackupsKnown || st.BackupTotal <= 0 {
				return 0, false
			}
			return int(st.BackupFree * 100 / st.BackupTotal), true
		}
	}
	if deps.Usage != nil {
		src.HostMemUsed = func(c context.Context) (int, bool) {
			u := deps.Usage.Host(c)
			info, err := hosts.Host(c)
			if err != nil || !u.Available || u.MemUsedMiB == nil || info.MemoryMiB <= 0 {
				return 0, false
			}
			return int(*u.MemUsedMiB * 100 / info.MemoryMiB), true
		}
	}
	if deps.NightlyBoot != nil {
		src.NightlyFailed = func() bool {
			r := deps.NightlyBoot()
			return r != nil && r.Result == "fail"
		}
	}
	if scheds != nil {
		src.SchedulesFailed = func(c context.Context) ([]string, bool) {
			vms, err := scheds.Failed(c)
			return vms, err == nil
		}
	}
	loop := &alertLoop{Engine: engine, Evaluator: &alerts.Evaluator{Thresholds: th}, Sources: src, Notify: notify, Log: stderr}
	go loop.run(ctx)
}
