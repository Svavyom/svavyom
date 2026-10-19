//go:build libvirt && libvirt_test

package libvirtmut

// REAL-HOST lifecycle qualification (docs/QUALIFICATION-LIFECYCLE.md): Reboot, Stop, Start, Force Off and the ownership-proving
// Delete of the VM the create stage left running, one STEP per invocation (SVAVYOM_QUALIFY_STEP), driven by
// tools/qualify_lifecycle.py, which also performs the guest-side checks over SSH on the host. It does nothing unless
// SVAVYOM_QUALIFY_CREATE=1. The VM is the run's own (identity derived from the run id); every step proves that before acting, and
// nothing outside that identity is touched. Evidence lines start with "QUALIFY ".

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"

	"example.invalid/dedicatedcloud/backend/internal/hypervisor"
	"example.invalid/dedicatedcloud/backend/internal/hypervisor/libvirtro"
	"example.invalid/dedicatedcloud/backend/internal/provision"
)

const inventoryFile = "lifecycle-baseline.json"

// inventory is every libvirt object that is NOT part of the run: domains, networks, pools and the volumes inside them. Only names,
// UUIDs and activity are recorded (no paths, no XML), so the file is not host-identifying.
type inventory struct {
	Domains  []string `json:"domains"`
	Networks []string `json:"networks"`
	Pools    []string `json:"pools"`
	Volumes  []string `json:"volumes"`
}

func takeInventory(o *Ops, uuid string) (inventory, error) {
	var inv inventory
	doms, err := o.conn.ListAllDomains(0)
	if err != nil {
		return inv, err
	}
	for i := range doms {
		n, _ := doms[i].GetName()
		u, _ := doms[i].GetUUIDString()
		a, _ := doms[i].IsActive()
		_ = doms[i].Free()
		if !strings.EqualFold(u, uuid) {
			inv.Domains = append(inv.Domains, fmt.Sprintf("%s %s active=%t", n, u, a))
		}
	}
	nets, err := o.conn.ListAllNetworks(0)
	if err != nil {
		return inv, err
	}
	for i := range nets {
		n, _ := nets[i].GetName()
		u, _ := nets[i].GetUUIDString()
		a, _ := nets[i].IsActive()
		_ = nets[i].Free()
		inv.Networks = append(inv.Networks, fmt.Sprintf("%s %s active=%t", n, u, a))
	}
	pools, err := o.conn.ListAllStoragePools(0)
	if err != nil {
		return inv, err
	}
	for i := range pools {
		pn, _ := pools[i].GetName()
		pa, _ := pools[i].IsActive()
		inv.Pools = append(inv.Pools, fmt.Sprintf("%s active=%t", pn, pa))
		if pa {
			vols, verr := pools[i].ListAllStorageVolumes(0)
			if verr != nil {
				_ = pools[i].Free()
				return inv, verr
			}
			for j := range vols {
				vn, _ := vols[j].GetName()
				_ = vols[j].Free()
				if !strings.Contains(vn, uuid) {
					inv.Volumes = append(inv.Volumes, pn+"/"+vn)
				}
			}
		}
		_ = pools[i].Free()
	}
	for _, s := range []*[]string{&inv.Domains, &inv.Networks, &inv.Pools, &inv.Volumes} {
		sort.Strings(*s)
	}
	return inv, nil
}

// lifecycleCtx holds what every step needs.
type lifecycleCtx struct {
	t           *testing.T
	rec         *recorder
	ops         *Ops
	cfg         provision.Config
	pol         provision.Policy
	name, uuid  string
	fp          string
	want        provision.AnchorWant
	base        provision.Anchor
	hasBaseline bool
}

func (c *lifecycleCtx) owned() provision.DomainInfo {
	c.t.Helper()
	di, err := c.ops.LookupDomain(context.Background(), c.name)
	if err != nil || !di.Managed || di.UUID != c.uuid || di.Fingerprint != c.fp {
		c.rec.fail("svavyom-owned", fmt.Sprintf("the domain is not this run's Svavyom VM (%v)", err))
		c.t.Fatal("ownership not proven")
	}
	return di
}

func (c *lifecycleCtx) counts(wantDomains, wantVolumes int, id string) {
	c.t.Helper()
	d, v, err := resourcesOf(c.ops, c.cfg.Pool, c.name, c.uuid)
	if err != nil || d != wantDomains || v != wantVolumes {
		c.rec.fail(id, fmt.Sprintf("expected %d domain(s) and %d volume(s) of this run, found %d and %d (%v)", wantDomains, wantVolumes, d, v, err))
		c.t.Fatal(id)
	}
}

func (c *lifecycleCtx) anchor(id string) {
	c.t.Helper()
	if !c.hasBaseline {
		c.rec.add(id, "NOT_RUN", "no "+anchorFile+" from the create stage")
		return
	}
	if _, line, err := checkAnchor(c.want, &c.base); err != nil {
		c.rec.fail(id, fmt.Sprintf("the base image changed: %v; %s", err, line))
		c.t.Fatal(id)
	} else {
		c.rec.pass(id, "root:root 0444 regular file, identical to the baseline; "+line)
	}
}

func TestSystemLifecycleQualification(t *testing.T) {
	cfg, pol, rec, name, uuid, fp := qualEnv(t)
	step := os.Getenv("SVAVYOM_QUALIFY_STEP")
	rec.res.Stage = "lifecycle-" + step
	defer rec.flush()
	ops, err := Open(SystemURI)
	if err != nil {
		rec.fail("real-libvirt", "cannot open qemu:///system read-write")
		t.Fatal(err)
	}
	defer ops.Close()
	if typ, terr := ops.conn.GetType(); terr != nil || typ != "QEMU" {
		rec.fail("real-libvirt", "not a real QEMU system connection")
		t.Fatal("not QEMU")
	}
	c := &lifecycleCtx{t: t, rec: rec, ops: ops, cfg: cfg, pol: pol, name: name, uuid: uuid, fp: fp}
	// The base image trust anchor, recorded by the create stage in the same output directory, is compared at every step.
	if cat, cerr := provision.LoadTrustedCatalog(pol, cfg.CatalogDir); cerr == nil {
		if raw, rerr := os.ReadFile(filepath.Join(rec.out, anchorFile)); rerr == nil && json.Unmarshal(raw, &c.base) == nil { // #nosec G304 -- fixed name in the run output dir
			for _, im := range cat.Images {
				if p, perr := cat.Path(im); perr == nil && p == c.base.Path && im.SHA256 == c.base.SHA256 {
					c.want = provision.AnchorWant{Path: p, UID: pol.Owner, GID: 0, SHA256: im.SHA256, Size: im.SizeBytes}
					c.hasBaseline = true
				}
			}
		}
	}
	ctx := context.Background()
	ro, err := libvirtro.Open(libvirtro.SystemURI)
	if err != nil {
		t.Fatal(err)
	}
	defer ro.Close()

	switch step {
	case "baseline":
		di := c.owned()
		if !di.Running {
			rec.fail("lifecycle-precondition", "the run's VM must be Running before the lifecycle stage")
			t.Fatal("not running")
		}
		c.counts(1, 2, "lifecycle-precondition")
		inv, err := takeInventory(ops, uuid)
		if err != nil {
			rec.fail("inventory-baseline", fmt.Sprint(err))
			t.Fatal(err)
		}
		b, _ := json.MarshalIndent(inv, "", "  ")
		_ = os.WriteFile(filepath.Join(rec.out, inventoryFile), append(b, '\n'), 0o644) // #nosec G306 -- names and uuids of libvirt objects, no paths
		rec.pass("inventory-baseline", fmt.Sprintf("recorded %d other domains, %d networks, %d pools, %d other volumes", len(inv.Domains), len(inv.Networks), len(inv.Pools), len(inv.Volumes)))
		rec.pass("lifecycle-precondition", "the run's VM is Running, Svavyom-owned (uuid and fingerprint), with 1 domain and 2 volumes")
		c.anchor("image-immutable-lifecycle-start")

	case "reboot":
		c.owned()
		if err := provision.Reboot(ctx, ops, name, nil); err != nil {
			rec.fail("lifecycle-reboot", fmt.Sprintf("reboot not confirmed: %v", err))
			t.Fatal(err)
		}
		c.owned()
		rec.pass("lifecycle-reboot", "guest reboot (ACPI) requested and libvirt reported the guest reset; the VM is Running")
		c.anchor("image-immutable-after-reboot")

	case "delete-refused-running":
		c.owned()
		err := provision.Delete(ctx, ops, cfg, name, nil)
		if hypervisor.CategoryOf(err) != hypervisor.Conflict {
			rec.fail("delete-refused-while-running", fmt.Sprintf("a running VM must not be deleted: %v", err))
			t.Fatal("delete of a running VM was not refused")
		}
		c.counts(1, 2, "delete-refused-while-running")
		rec.pass("delete-refused-while-running", "Delete of the Running VM was refused (conflict); the domain and both volumes are intact")

	case "stop":
		c.owned()
		if err := provision.Stop(ctx, ops, name, nil); err != nil {
			rec.fail("lifecycle-stop", fmt.Sprintf("graceful stop not completed: %v", err))
			t.Fatal(err)
		}
		d, err := ro.Lookup(ctx, name)
		if err != nil || d.State != hypervisor.StateShutoff {
			rec.fail("lifecycle-stop", fmt.Sprintf("expected Stopped: %+v %v", d, err))
			t.Fatal("not stopped")
		}
		c.counts(1, 2, "lifecycle-stop")
		rec.pass("lifecycle-stop", "graceful (ACPI) shutdown observed: Stopped; no force-off was issued; domain and both volumes intact")

	case "start":
		c.owned()
		if err := provision.Start(ctx, ops, name, nil); err != nil {
			rec.fail("lifecycle-start", fmt.Sprint(err))
			t.Fatal(err)
		}
		deadline := time.Now().Add(4 * time.Minute)
		var d hypervisor.Domain
		for time.Now().Before(deadline) {
			if d, err = ro.Lookup(ctx, name); err == nil && d.State == hypervisor.StateRunning && provision.IsIPv4(d.IPv4) {
				break
			}
			time.Sleep(5 * time.Second)
		}
		if err != nil || d.State != hypervisor.StateRunning || !provision.IsIPv4(d.IPv4) {
			rec.fail("lifecycle-start", fmt.Sprintf("not Running with an address: %+v %v", d, err))
			t.Fatal("not running")
		}
		rec.res.IPv4 = d.IPv4
		rec.pass("lifecycle-start", "Running again with a DHCP address")
		c.anchor("image-immutable-running-again")

	case "force-off":
		c.owned()
		if err := provision.ForceOff(ctx, ops, name, nil); err != nil {
			rec.fail("lifecycle-force-off", fmt.Sprint(err))
			t.Fatal(err)
		}
		d, err := ro.Lookup(ctx, name)
		if err != nil || d.State != hypervisor.StateShutoff {
			rec.fail("lifecycle-force-off", fmt.Sprintf("expected Stopped: %+v %v", d, err))
			t.Fatal("not stopped")
		}
		c.counts(1, 2, "lifecycle-force-off")
		rec.pass("lifecycle-force-off", "explicit Force Off: Stopped; nothing deleted (domain and both volumes intact)")

	case "delete-crash":
		di := c.owned()
		if di.Running {
			t.Fatal("delete requires a stopped VM")
		}
		// The unknown-outcome case: the delete is interrupted after the seed volume was removed (as a killed helper would leave it).
		crashed := make(chan struct{})
		go func() {
			defer close(crashed)
			_ = provision.Delete(ctx, ops, cfg, name, func(s string) {
				if s == provision.StepSeedDeleted {
					runtime.Goexit()
				}
			})
		}()
		<-crashed
		if _, err := ops.LookupVolume(ctx, cfg.Pool, provision.SeedVolumeName(uuid)); hypervisor.CategoryOf(err) != hypervisor.NotFound {
			rec.fail("delete-interrupted", fmt.Sprintf("the seed volume should be gone after the interrupted delete: %v", err))
			t.Fatal("seed still present")
		}
		if _, err := ops.LookupVolume(ctx, cfg.Pool, provision.RootVolumeName(uuid)); err != nil {
			rec.fail("delete-interrupted", fmt.Sprintf("the root volume should still exist: %v", err))
			t.Fatal("root gone")
		}
		c.owned() // the definition that proves ownership is still there
		rec.pass("delete-interrupted", "interrupted after the seed volume: domain and root volume remain, so ownership is still provable")

	case "delete-resume":
		c.owned()
		if err := provision.Delete(ctx, ops, cfg, name, nil); err != nil {
			rec.fail("lifecycle-delete", fmt.Sprintf("delete (resume) failed: %v", err))
			t.Fatal(err)
		}
		c.counts(0, 0, "lifecycle-delete")
		rec.pass("lifecycle-delete", "the interrupted delete was resumed to completion: domain gone, root and seed volumes gone")
		if err := provision.Delete(ctx, ops, cfg, name, nil); hypervisor.CategoryOf(err) != hypervisor.NotFound {
			rec.fail("delete-idempotent", fmt.Sprintf("deleting a deleted VM should report not found: %v", err))
		} else {
			rec.pass("delete-idempotent", "a repeated Delete reports the VM as gone and changes nothing")
		}
		c.anchor("image-immutable-after")
		raw, rerr := os.ReadFile(filepath.Join(rec.out, inventoryFile)) // #nosec G304 -- fixed name in the run output dir
		var was inventory
		now, nerr := takeInventory(ops, uuid)
		if rerr != nil || json.Unmarshal(raw, &was) != nil || nerr != nil {
			rec.add("unrelated-resources-unchanged", "NOT_RUN", "no baseline inventory to compare with")
		} else if !reflect.DeepEqual(was, now) {
			rec.fail("unrelated-resources-unchanged", "the set of other domains, networks, pools or volumes differs from the baseline")
		} else {
			rec.pass("unrelated-resources-unchanged", "every other domain, network (incl. default), pool and volume is identical to the baseline")
		}

	default:
		t.Fatalf("SVAVYOM_QUALIFY_STEP %q is not a lifecycle step", step)
	}
	if rec.failed() {
		t.Fatal("one or more criteria failed")
	}
}
