package provision

import (
	"context"
	"time"

	"example.invalid/dedicatedcloud/backend/internal/hypervisor"
)

// Lifecycle steps (hook names, like the provisioning steps).
const (
	StepShutdownRequested = "shutdown-requested"
	StepRebootRequested   = "reboot-requested"
	StepDestroyed         = "destroyed"
	StepSeedDeleted       = "seed-deleted"
	StepRootDeleted       = "root-deleted"
	StepUndefined         = "undefined"
)

// StopWait bounds how long Stop waits for the guest to power off after the request; PollEvery is the observation interval.
// Both are variables so tests can shorten them. A Stop that does not see the guest off within StopWait reports Timeout (an unknown
// outcome that the operation layer reconciles by observation); it NEVER escalates to a force-off.
var (
	StopWait   = 45 * time.Second
	RebootWait = 90 * time.Second
	PollEvery  = time.Second
)

// managed looks the domain up and refuses anything that does not carry a well-formed Svavyom ownership marker.
func managed(ctx context.Context, ops HostOps, name, op string) (DomainInfo, error) {
	if !VMNameRE.MatchString(name) {
		return DomainInfo{}, typed(hypervisor.Validation, op)
	}
	d, err := ops.LookupDomain(ctx, name)
	if err != nil {
		return DomainInfo{}, err
	}
	if !d.Managed || !uuidRE.MatchString(d.UUID) {
		return DomainInfo{}, typed(hypervisor.Prohibited, op)
	}
	return d, nil
}

// Stop requests a graceful guest shutdown of a Svavyom-managed domain and waits a bounded time for it to be off. A domain that is
// already off is success. Never forces anything.
func Stop(ctx context.Context, ops HostOps, name string, hook Hook) error {
	if hook == nil {
		hook = func(string) {}
	}
	d, err := managed(ctx, ops, name, "stop")
	if err != nil {
		return err
	}
	if !d.Running {
		return nil
	}
	if err := ops.ShutdownDomain(ctx, name); err != nil {
		return err
	}
	hook(StepShutdownRequested)
	deadline := time.Now().Add(StopWait)
	for {
		cur, err := ops.LookupDomain(ctx, name)
		if err == nil && !cur.Running {
			return nil
		}
		if time.Now().After(deadline) || ctx.Err() != nil {
			return typed(hypervisor.Timeout, "stop") // still running or unobservable: unknown until observed, and no force-off
		}
		select {
		case <-ctx.Done():
			return typed(hypervisor.Timeout, "stop")
		case <-time.After(PollEvery):
		}
	}
}

// Reboot asks a running, managed guest to reboot and waits a bounded time to SEE it: the hypervisor must report that the guest was
// reset. A domain that is not running is a Conflict (nothing to reboot; no implicit start). There is no destroy-and-start fallback.
// Not seeing the reset is reported as Timeout, an outcome that is unknown (the guest may reboot late, or never): the operation layer
// never sends a reboot twice.
func Reboot(ctx context.Context, ops HostOps, name string, hook Hook) error {
	if hook == nil {
		hook = func(string) {}
	}
	d, err := managed(ctx, ops, name, "reboot")
	if err != nil {
		return err
	}
	if !d.Running {
		return typed(hypervisor.Conflict, "reboot")
	}
	if err := ops.RebootDomain(ctx, name, RebootWait); err != nil {
		return err
	}
	hook(StepRebootRequested)
	return nil
}

// ForceOff powers a managed domain off immediately. Already off is success. It removes nothing.
func ForceOff(ctx context.Context, ops HostOps, name string, hook Hook) error {
	if hook == nil {
		hook = func(string) {}
	}
	d, err := managed(ctx, ops, name, "force_off")
	if err != nil {
		return err
	}
	if !d.Running {
		return nil
	}
	if err := ops.DestroyDomain(ctx, name); err != nil {
		return err
	}
	hook(StepDestroyed)
	return nil
}

// Delete removes a STOPPED Svavyom VM: its seed volume, its root volume and, last, its domain definition. Ownership is proven
// before anything is removed, and the domain is kept until the end because it is the proof: the volume names derive from the domain's
// creation UUID, the domain definition must be file-backed at exactly the paths libvirt reports for those two volumes, and both
// volumes must be plain files of the configured pool. Anything that cannot be proven is a Conflict and nothing is removed.
//
// The order makes Delete safe to run again after a crash: a volume that is already gone is skipped (the domain's own definition still
// names it, so it is still provably this VM's), and a domain that is already gone means the delete finished. The base image, the
// network, the pool and every other volume or domain are never addressed: only the two names derived from this domain's UUID are.
func Delete(ctx context.Context, ops HostOps, cfg Config, name string, hook Hook) error {
	if hook == nil {
		hook = func(string) {}
	}
	if err := cfg.Validate(); err != nil {
		return typed(hypervisor.Validation, "delete")
	}
	d, err := ops.LookupDomain(ctx, name)
	if err != nil {
		return err // NotFound means gone: the operation layer treats it as the finished state
	}
	if !VMNameRE.MatchString(name) || !d.Managed || !uuidRE.MatchString(d.UUID) {
		return typed(hypervisor.Prohibited, "delete")
	}
	if d.Running {
		return typed(hypervisor.Conflict, "delete") // Stopped only; never an implicit force-off
	}
	rootName, seedName := d.Root, d.Seed
	seedless := d.Media == MediaISO && seedName == "" // a VM created from installation media has no seed volume (DR-023 D3)
	_, _, rrev, rok := ParseVolumeName(rootName)
	_, _, srev, sok := ParseVolumeName(seedName)
	if !rok || (!seedless && (!sok || rrev != srev)) {
		return typed(hypervisor.Conflict, "delete") // the definition does not name exactly this VM's own pair of volumes
	}
	var rootSrc, seedSrc VolumeSource
	present := map[string]bool{}
	targets := []struct {
		name string
		dst  *VolumeSource
		chk  func(string, VolumeSource) error
	}{{rootName, &rootSrc, CheckDomainRootSource}}
	if !seedless {
		targets = append(targets, struct {
			name string
			dst  *VolumeSource
			chk  func(string, VolumeSource) error
		}{seedName, &seedSrc, CheckDomainSeedSource})
	}
	for _, t := range targets {
		v, err := ops.LookupVolume(ctx, cfg.Pool, t.name)
		if isNotFound(err) {
			continue // already removed by an earlier attempt of this delete
		}
		if err != nil {
			return err
		}
		src, err := ResolveVolumeSource(t.name, v)
		if err != nil || t.chk(d.XML, src) != nil {
			return typed(hypervisor.Conflict, "delete") // not provably the file the domain uses
		}
		*t.dst, present[t.name] = src, true
	}
	if present[seedName] && !seedless {
		if err := ops.DeleteVolume(ctx, cfg.Pool, seedName); err != nil && !isNotFound(err) {
			return err
		}
	}
	hook(StepSeedDeleted)
	if present[rootName] {
		if err := ops.DeleteVolume(ctx, cfg.Pool, rootName); err != nil && !isNotFound(err) {
			return err
		}
	}
	hook(StepRootDeleted)
	// Any other volume named for this UUID is a leftover of this VM too (a reinstall that was interrupted): provably its own, by name.
	if names, err := ops.ListVolumes(ctx, cfg.Pool); err != nil {
		return err
	} else {
		for _, n := range names {
			if u, _, _, ok := ParseVolumeName(n); ok && u == d.UUID {
				if err := ops.DeleteVolume(ctx, cfg.Pool, n); err != nil && !isNotFound(err) {
					return err
				}
			}
		}
	}
	// Re-prove the domain is still stopped and still ours immediately before removing it.
	cur, err := ops.LookupDomain(ctx, name)
	if isNotFound(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if !cur.Managed || cur.UUID != d.UUID || cur.Running {
		return typed(hypervisor.Conflict, "delete")
	}
	if err := ops.UndefineDomain(ctx, name); err != nil && !isNotFound(err) {
		return err
	}
	hook(StepUndefined)
	return nil
}
