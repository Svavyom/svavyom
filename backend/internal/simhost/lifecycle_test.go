package simhost_test

import (
	"context"
	"testing"
	"time"

	"example.invalid/dedicatedcloud/backend/internal/hypervisor"
	"example.invalid/dedicatedcloud/backend/internal/provision"
	"example.invalid/dedicatedcloud/backend/internal/simhost"
)

func (r *rig) running(t *testing.T) {
	t.Helper()
	if err := r.provision(nil); err != nil {
		t.Fatal(err)
	}
	if err := provision.Start(context.Background(), r.counter, "web-1", nil); err != nil {
		t.Fatal(err)
	}
}

func fastStop(t *testing.T) {
	t.Helper()
	w, rw, p := provision.StopWait, provision.RebootWait, provision.PollEvery
	provision.StopWait, provision.RebootWait, provision.PollEvery = 150*time.Millisecond, 150*time.Millisecond, 10*time.Millisecond
	t.Cleanup(func() { provision.StopWait, provision.RebootWait, provision.PollEvery = w, rw, p })
}

func TestStopIsGracefulAndNeverForces(t *testing.T) {
	fastStop(t)
	r := newRig(t)
	r.running(t)
	ctx := context.Background()
	if err := provision.Stop(ctx, r.counter, "web-1", nil); err != nil || r.host.Load().Domains["web-1"].Running {
		t.Fatalf("stop: %v", err)
	}
	if err := provision.Stop(ctx, r.counter, "web-1", nil); err != nil {
		t.Fatalf("stopping a stopped VM is a no-op: %v", err)
	}
	// A guest that ignores the power button: Stop times out (unknown outcome) and the VM is STILL running; nothing was forced.
	if err := provision.Start(ctx, r.counter, "web-1", nil); err != nil {
		t.Fatal(err)
	}
	if err := r.host.Update("web-1", func(d *simhost.Domain) { d.SlowStop = true }); err != nil {
		t.Fatal(err)
	}
	if err := provision.Stop(ctx, r.counter, "web-1", nil); cat(err) != hypervisor.Timeout {
		t.Fatalf("want timeout, got %v", err)
	}
	if !r.host.Load().Domains["web-1"].Running {
		t.Fatal("a stop timeout must not power the VM off")
	}
	if err := provision.ForceOff(ctx, r.counter, "web-1", nil); err != nil || r.host.Load().Domains["web-1"].Running {
		t.Fatalf("explicit force off: %v", err)
	}
	if len(r.host.Load().Volumes) != 2 {
		t.Fatal("force off must remove nothing")
	}
}

func TestRebootNeedsARunningManagedVM(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	if err := r.provision(nil); err != nil {
		t.Fatal(err)
	}
	if err := provision.Reboot(ctx, r.counter, "web-1", nil); cat(err) != hypervisor.Conflict {
		t.Fatalf("a stopped VM is not rebooted (and not started): %v", err)
	}
	if r.host.Load().Domains["web-1"].Running {
		t.Fatal("reboot must never start a VM")
	}
	if err := provision.Start(ctx, r.counter, "web-1", nil); err != nil {
		t.Fatal(err)
	}
	if err := provision.Reboot(ctx, r.counter, "web-1", nil); err != nil || r.host.Load().Domains["web-1"].Reboots != 1 || !r.host.Load().Domains["web-1"].Running {
		t.Fatalf("reboot: %v", err)
	}
	// A guest that ignores the request is never reported as rebooted.
	if err := r.host.Update("web-1", func(d *simhost.Domain) { d.IgnoreReboot = true }); err != nil {
		t.Fatal(err)
	}
	fastStop(t)
	if err := provision.Reboot(ctx, r.counter, "web-1", nil); cat(err) != hypervisor.Timeout {
		t.Fatalf("an unobserved restart must be a timeout: %v", err)
	}
}

func TestLifecycleRefusesForeignDomains(t *testing.T) {
	fastStop(t)
	r := newRig(t)
	ctx := context.Background()
	if err := r.host.Update("", nil); err == nil { // sanity: unknown domain
		t.Fatal("update of an unknown domain must fail")
	}
	if err := r.host.Add("foreign", simhost.Domain{UUID: "9a9a9a9a-2222-4333-8444-5555555555ab", Running: true, VCPUs: 1, MemoryMiB: 64}); err != nil {
		t.Fatal(err)
	}
	for name, err := range map[string]error{
		"stop":      provision.Stop(ctx, r.counter, "foreign", nil),
		"reboot":    provision.Reboot(ctx, r.counter, "foreign", nil),
		"force off": provision.ForceOff(ctx, r.counter, "foreign", nil),
		"delete":    provision.Delete(ctx, r.counter, r.cfg, "foreign", nil),
	} {
		if cat(err) != hypervisor.Prohibited {
			t.Errorf("%s of an unmanaged domain: %v", name, err)
		}
	}
	if d := r.host.Load().Domains["foreign"]; !d.Running {
		t.Fatal("a refused action changed a foreign domain")
	}
	if err := provision.Stop(ctx, r.counter, "nope", nil); cat(err) != hypervisor.NotFound {
		t.Fatalf("missing: %v", err)
	}
	if err := provision.Stop(ctx, r.counter, "../x", nil); cat(err) != hypervisor.Validation {
		t.Fatalf("bad name: %v", err)
	}
}

func TestDeleteRemovesOnlyTheProvenVolumesAndDomain(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	r.running(t)
	// Neighbours that must survive: another volume in the same pool, another domain.
	if err := r.host.AddVolume("svavyom", "neighbour.qcow2", simhost.Volume{Capacity: 1 << 30}); err != nil {
		t.Fatal(err)
	}
	if err := r.host.Add("other", simhost.Domain{UUID: "8a8a8a8a-2222-4333-8444-5555555555ab", VCPUs: 1, MemoryMiB: 64}); err != nil {
		t.Fatal(err)
	}
	if err := provision.Delete(ctx, r.counter, r.cfg, "web-1", nil); cat(err) != hypervisor.Conflict {
		t.Fatalf("a running VM is never deleted: %v", err)
	}
	if len(r.host.Load().Volumes) != 3 {
		t.Fatal("refused delete removed something")
	}
	if err := provision.ForceOff(ctx, r.counter, "web-1", nil); err != nil {
		t.Fatal(err)
	}
	if err := provision.Delete(ctx, r.counter, r.cfg, "web-1", nil); err != nil {
		t.Fatal(err)
	}
	st := r.host.Load()
	if _, ok := st.Domains["web-1"]; ok || len(st.Domains) != 1 {
		t.Fatalf("domains: %+v", st.Domains)
	}
	if _, ok := st.Volumes["svavyom/neighbour.qcow2"]; !ok || len(st.Volumes) != 1 {
		t.Fatalf("volumes: %+v", st.Volumes)
	}
	if err := provision.Delete(ctx, r.counter, r.cfg, "web-1", nil); cat(err) != hypervisor.NotFound {
		t.Fatalf("deleting again reports the VM as gone: %v", err)
	}
}

func TestDeleteFailsClosedWhenOwnershipIsNotProven(t *testing.T) {
	ctx := context.Background()
	t.Run("definition names a different disk", func(t *testing.T) {
		r := newRig(t)
		r.running(t)
		_ = provision.ForceOff(ctx, r.counter, "web-1", nil)
		if err := r.host.Update("web-1", func(d *simhost.Domain) { d.Root = "someone-elses.qcow2" }); err != nil {
			t.Fatal(err)
		}
		if err := provision.Delete(ctx, r.counter, r.cfg, "web-1", nil); cat(err) != hypervisor.Conflict {
			t.Fatalf("%v", err)
		}
		if len(r.host.Load().Volumes) != 2 {
			t.Fatal("something was deleted")
		}
	})
	t.Run("definition points at a different path than the volume", func(t *testing.T) {
		r := newRig(t)
		r.running(t)
		_ = provision.ForceOff(ctx, r.counter, "web-1", nil)
		if err := r.host.Update("web-1", func(d *simhost.Domain) {
			d.XML = "<domain><devices><disk type='file' device='disk'><source file='/elsewhere/" + d.Root + "'/></disk>" +
				"<disk type='file' device='cdrom'><driver type='raw'/><source file='/sim/svavyom/" + d.Seed + "'/><readonly/></disk></devices></domain>"
		}); err != nil {
			t.Fatal(err)
		}
		if err := provision.Delete(ctx, r.counter, r.cfg, "web-1", nil); cat(err) != hypervisor.Conflict {
			t.Fatalf("%v", err)
		}
		if len(r.host.Load().Volumes) != 2 || len(r.host.Load().Domains) != 1 {
			t.Fatal("something was deleted")
		}
	})
}

// TestDeleteResumesAfterACrashAtEveryStep kills the delete after each step and runs it again: it must finish, remove exactly the VM's
// own resources, and never need anything but the surviving domain definition as proof.
func TestDeleteResumesAfterACrashAtEveryStep(t *testing.T) {
	ctx := context.Background()
	for _, crash := range []string{provision.StepSeedDeleted, provision.StepRootDeleted, provision.StepUndefined} {
		t.Run(crash, func(t *testing.T) {
			r := newRig(t)
			r.running(t)
			_ = provision.ForceOff(ctx, r.counter, "web-1", nil)
			if err := r.host.AddVolume("svavyom", "neighbour.qcow2", simhost.Volume{Capacity: 1}); err != nil {
				t.Fatal(err)
			}
			func() {
				defer func() { _ = recover() }()
				_ = provision.Delete(ctx, r.counter, r.cfg, "web-1", func(step string) {
					if step == crash {
						panic("simulated process death")
					}
				})
			}()
			err := provision.Delete(ctx, r.counter, r.cfg, "web-1", nil)
			if err != nil && cat(err) != hypervisor.NotFound {
				t.Fatalf("resume: %v", err)
			}
			st := r.host.Load()
			if _, ok := st.Domains["web-1"]; ok || len(st.Volumes) != 1 {
				t.Fatalf("after resume: %+v %+v", st.Domains, st.Volumes)
			}
		})
	}
}
