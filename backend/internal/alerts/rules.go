package alerts

import "time"

// Thresholds are the operator's (provisioning configuration): free space below WarnPercent raises a warning, below CritPercent a critical alert.
type Thresholds struct{ WarnPercent, CritPercent int }

// Defaults are used when the configuration names none.
const (
	DefaultWarnPercent = 20
	DefaultCritPercent = 10
	clearMargin        = 5 // a free-space alert clears only when the free share is this many points above its threshold
)

// WithDefaults fills in the unset thresholds.
func (t Thresholds) WithDefaults() Thresholds {
	if t.WarnPercent == 0 {
		t.WarnPercent = DefaultWarnPercent
	}
	if t.CritPercent == 0 {
		t.CritPercent = DefaultCritPercent
	}
	return t
}

// Valid reports whether the thresholds are usable: 1 <= crit < warn <= 90.
func (t Thresholds) Valid() bool {
	return t.CritPercent >= 1 && t.CritPercent < t.WarnPercent && t.WarnPercent <= 90
}

// VMState is what the rules need to know of one VM.
type VMState struct {
	Name    string
	Managed bool
	State   string // running | shutoff | crashed | paused | unknown ...
}

// Inputs are the facts one evaluation looks at. A nil figure or a nil slice means "could not be read": the rules that need it are skipped, and unknown
// data never raises or resolves an alert.
type Inputs struct {
	PoolFreePercent        *int
	BackupStoreFreePercent *int
	HostMemoryUsedPercent  *int
	VMs                    []VMState // nil: the inventory could not be read
	VMsKnown               bool
	// StoppedByOperation names VMs that an operation (stop, force off, delete, reboot, create) touched recently, so a VM that is no longer running is expected.
	StoppedByOperation map[string]bool
	// ExhaustedOps are the resources of operations that used all their attempts and are still waiting.
	ExhaustedOps    []ResourceRef
	ExhaustedKnown  bool
	ScheduleFailed  []string // VM names whose last scheduled backup failed
	SchedulesKnown  bool
	NightlyBootFail bool // the last nightly boot failed
	HostID          string
}

// ResourceRef names a resource.
type ResourceRef struct{ Kind, ID string }

// Evaluator evaluates the rules. It keeps the one thing a rule cannot read from the present: which VMs were running at the last evaluation, so a VM
// that stopped by itself can be told from one somebody stopped. After a restart it knows nothing and raises nothing for that rule until it has seen a VM
// running.
type Evaluator struct {
	Thresholds Thresholds
	Now        func() time.Time

	wasRunning map[string]bool
}

func freeSpace(typ, kind, id string, free *int, th Thresholds) Obs {
	o := Obs{Type: typ, Kind: kind, ResourceID: id, Severity: Warning, Value: free}
	switch {
	case *free <= th.CritPercent:
		o.Severity, o.Active = Critical, true
	case *free <= th.WarnPercent:
		o.Active = true
	case *free >= th.WarnPercent+clearMargin:
		o.Clear = true
	}
	return o
}

// Evaluate returns the observations of one evaluation and the rule ids it judged completely.
func (ev *Evaluator) Evaluate(in Inputs) (obs []Obs, covered []string) {
	th := ev.Thresholds.WithDefaults()
	if in.HostID == "" {
		in.HostID = "host"
	}
	if in.PoolFreePercent != nil {
		obs = append(obs, freeSpace(PoolFreeLow, "Host", in.HostID, in.PoolFreePercent, th))
		covered = append(covered, PoolFreeLow)
	}
	if in.BackupStoreFreePercent != nil {
		obs = append(obs, freeSpace(BackupStoreFreeLow, "Host", in.HostID, in.BackupStoreFreePercent, th))
		covered = append(covered, BackupStoreFreeLow)
	}
	if in.HostMemoryUsedPercent != nil {
		u := *in.HostMemoryUsedPercent
		o := Obs{Type: HostMemoryHigh, Kind: "Host", ResourceID: in.HostID, Severity: Warning, Value: in.HostMemoryUsedPercent}
		switch {
		case u >= 97:
			o.Severity, o.Active = Critical, true
		case u >= 90:
			o.Active = true
		case u < 85:
			o.Clear = true
		}
		obs = append(obs, o)
		covered = append(covered, HostMemoryHigh)
	}
	if in.VMsKnown {
		running := map[string]bool{}
		for _, v := range in.VMs {
			if !v.Managed {
				continue
			}
			running[v.Name] = v.State == "running"
			obs = append(obs, Obs{Type: VMCrashed, Kind: "VM", ResourceID: v.Name, Severity: Critical, Active: v.State == "crashed", Clear: v.State != "crashed"})
			stopped := ev.wasRunning[v.Name] && v.State == "shutoff" && !in.StoppedByOperation[v.Name]
			obs = append(obs, Obs{Type: VMStoppedUnasked, Kind: "VM", ResourceID: v.Name, Severity: Warning, Active: stopped, Clear: v.State == "running"})
		}
		ev.wasRunning = running
		covered = append(covered, VMCrashed, VMStoppedUnasked)
	}
	if in.ExhaustedKnown {
		seen := map[string]bool{}
		for _, r := range in.ExhaustedOps {
			k := r.Kind + "|" + r.ID
			if seen[k] {
				continue
			}
			seen[k] = true
			obs = append(obs, Obs{Type: RetriesExhausted, Kind: r.Kind, ResourceID: r.ID, Severity: Warning, Active: true})
		}
		covered = append(covered, RetriesExhausted)
	}
	if in.SchedulesKnown {
		for _, vm := range in.ScheduleFailed {
			obs = append(obs, Obs{Type: ScheduledBackup, Kind: "VM", ResourceID: vm, Severity: Warning, Active: true})
		}
		covered = append(covered, ScheduledBackup)
	}
	nb := Obs{Type: NightlyBootFailed, Kind: "Host", ResourceID: in.HostID, Severity: Warning, Active: in.NightlyBootFail, Clear: !in.NightlyBootFail}
	obs = append(obs, nb)
	covered = append(covered, NightlyBootFailed)
	return obs, covered
}
