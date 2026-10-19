//go:build libvirt && libvirt_test

package libvirtmut

// REAL-HOST storage and recovery qualification (docs/QUALIFICATION-STORAGE.md): grow the root disk, stopped snapshot and restore, stopped backup,
// delete, restore to a NEW VM, reinstall from the qualified image, and ownership-proving cleanup, one STEP per invocation
// (SVAVYOM_QUALIFY_STEP), driven by tools/qualify_storage.py, which also performs the guest-side checks over SSH. Continues a run whose create stage
// left the run's VM Running. It does nothing unless SVAVYOM_QUALIFY_CREATE=1. Every VM it touches has an identity DERIVED from the run id (the
// original, and the restored one), proven before each step. Evidence lines start with "QUALIFY ".

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"example.invalid/dedicatedcloud/backend/internal/backupstore"
	"example.invalid/dedicatedcloud/backend/internal/hypervisor"
	"example.invalid/dedicatedcloud/backend/internal/hypervisor/libvirtro"
	"example.invalid/dedicatedcloud/backend/internal/provision"
)

const (
	storageSnapID   = "snap-5a5a5a5a5a5a"
	storageRev      = "5a5a5a5a"
	storageResizeTo = 12
)

// restoredIdentity derives the identity of the VM the restore step creates, the same way qualIdentity derives the original's.
func restoredIdentity(runID string) (name, uuid, fingerprint, backupID string) {
	s := sha256.Sum256([]byte("svavyom-qualify-restored-v1:" + runID))
	b := s[:16]
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	h := hex.EncodeToString(b)
	uuid = h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
	f := sha256.Sum256([]byte("svavyom-qualify-restored-fingerprint-v1:" + runID))
	bk := sha256.Sum256([]byte("svavyom-qualify-backup-v1:" + runID))
	return "svr-" + strings.TrimPrefix(runID, "qr-"), uuid, hex.EncodeToString(f[:]), "bk-" + hex.EncodeToString(bk[:8])
}

func TestSystemStorageQualification(t *testing.T) {
	cfg, pol, rec, name, uuid, fp := qualEnv(t)
	step := os.Getenv("SVAVYOM_QUALIFY_STEP")
	rec.res.Stage = "storage-" + step
	defer rec.flush()
	rname, ruuid, rfp, backupID := restoredIdentity(rec.res.RunID)
	cfg.BackupDir = os.Getenv("SVAVYOM_QUALIFY_BACKUP_DIR")
	if cfg.BackupDir == "" || cfg.Validate() != nil {
		t.Fatalf("SVAVYOM_QUALIFY_BACKUP_DIR must be a valid backup directory: %v", cfg.Validate())
	}
	store, err := backupstore.Open(cfg.BackupDir)
	if err != nil {
		rec.fail("backup-store", fmt.Sprint(err))
		t.Fatal(err)
	}
	ops, err := Open(SystemURI)
	if err != nil {
		rec.fail("real-libvirt", "cannot open qemu:///system read-write")
		t.Fatal(err)
	}
	defer ops.Close()
	ops.Diag = func(op, detail string) { t.Logf("raw libvirt %s: %s", op, detail) } // harness only; never reaches a product surface
	if typ, terr := ops.conn.GetType(); terr != nil || typ != "QEMU" {
		rec.fail("real-libvirt", "not a real QEMU system connection")
		t.Fatal("not QEMU")
	}
	ctx := context.Background()
	ro, err := libvirtro.Open(libvirtro.SystemURI)
	if err != nil {
		t.Fatal(err)
	}
	defer ro.Close()
	cat, err := provision.LoadTrustedCatalog(pol, cfg.CatalogDir)
	if err != nil {
		rec.fail("managed-image", fmt.Sprint(err))
		t.Fatal(err)
	}
	var want provision.AnchorWant
	var base provision.Anchor
	haveAnchor := false
	if raw, rerr := os.ReadFile(filepath.Join(rec.out, anchorFile)); rerr == nil && json.Unmarshal(raw, &base) == nil { // #nosec G304 -- fixed name in the run output dir
		for _, im := range cat.Images {
			if p, perr := cat.Path(im); perr == nil && p == base.Path && im.SHA256 == base.SHA256 {
				want, haveAnchor = provision.AnchorWant{Path: p, UID: pol.Owner, GID: 0, SHA256: im.SHA256, Size: im.SizeBytes}, true
			}
		}
	}
	anchor := func(id string) {
		t.Helper()
		if !haveAnchor {
			rec.add(id, "NOT_RUN", "no "+anchorFile+" from the create stage")
			return
		}
		if _, line, err := checkAnchor(want, &base); err != nil {
			rec.fail(id, fmt.Sprintf("the base image changed: %v; %s", err, line))
			t.Fatal(id)
		} else {
			rec.pass(id, "root:root 0444 regular file, identical to the baseline; "+line)
		}
	}
	owned := func(vm, wantUUID, wantFP string) provision.DomainInfo {
		t.Helper()
		di, err := ops.LookupDomain(ctx, vm)
		if err != nil || !di.Managed || di.UUID != wantUUID || di.Fingerprint != wantFP {
			rec.fail("svavyom-owned", fmt.Sprintf("%s is not provably this run's Svavyom VM (%v)", vm, err))
			t.Fatal("ownership not proven")
		}
		return di
	}
	startAndWait := func(vm string) string {
		t.Helper()
		if err := provision.Start(ctx, ops, vm, nil); err != nil {
			rec.fail("vm-start", fmt.Sprint(err))
			t.Fatal(err)
		}
		deadline := time.Now().Add(4 * time.Minute)
		var d hypervisor.Domain
		for time.Now().Before(deadline) {
			if d, err = ro.Lookup(ctx, vm); err == nil && d.State == hypervisor.StateRunning && provision.IsIPv4(d.IPv4) {
				return d.IPv4
			}
			time.Sleep(5 * time.Second)
		}
		rec.fail("vm-start", fmt.Sprintf("%s did not get an address: %+v %v", vm, d, err))
		t.Fatal("no address")
		return ""
	}
	pubKey := func() string {
		kb, err := os.ReadFile(os.Getenv("SVAVYOM_QUALIFY_SSH_PUBKEY_FILE")) // #nosec G304 -- operator-supplied PUBLIC key
		if err != nil {
			t.Fatal(err)
		}
		k, err := provision.NormalizeSSHKey(string(kb))
		if err != nil {
			t.Fatal(err)
		}
		return k.Authorized
	}
	img, err := cat.Usable(os.Getenv("SVAVYOM_QUALIFY_IMAGE_ID"))
	if err != nil {
		rec.fail("managed-image", fmt.Sprint(err))
		t.Fatal(err)
	}
	counts := func(vm, u string, wantD, wantV int, id string) {
		t.Helper()
		d, v, err := resourcesOf(ops, cfg.Pool, vm, u)
		if err != nil || d != wantD || v != wantV {
			rec.fail(id, fmt.Sprintf("expected %d domain(s) and %d volume(s) for %s, found %d and %d (%v)", wantD, wantV, vm, d, v, err))
			t.Fatal(id)
		}
	}

	switch step {
	case "baseline":
		di := owned(name, uuid, fp)
		if !di.Running {
			rec.fail("storage-precondition", "the run's VM must be Running before the storage stage")
			t.Fatal("not running")
		}
		inv, err := takeInventory(ops, uuid)
		if err != nil {
			rec.fail("inventory-baseline", fmt.Sprint(err))
			t.Fatal(err)
		}
		b, _ := json.MarshalIndent(inv, "", "  ")
		_ = os.WriteFile(filepath.Join(rec.out, inventoryFile), append(b, '\n'), 0o644) // #nosec G306 -- names and uuids, no paths
		rec.pass("inventory-baseline", fmt.Sprintf("recorded %d other domains, %d networks, %d pools, %d other volumes", len(inv.Domains), len(inv.Networks), len(inv.Pools), len(inv.Volumes)))
		ps, perr := ops.PoolStats(ctx, cfg.Pool)
		if perr != nil || ps.CapacityBytes <= 0 || ps.AvailableBytes <= 0 || ps.AvailableBytes > ps.CapacityBytes {
			rec.fail("storage-visibility", fmt.Sprintf("pool stats not usable: %+v %v", ps, perr))
			t.Fatal("pool stats")
		}
		free, ferr := store.FreeBytes()
		if ferr != nil || free <= 0 {
			rec.fail("storage-visibility", "backup store free space not readable")
			t.Fatal("backup stats")
		}
		rec.pass("storage-visibility", fmt.Sprintf("pool %.1f GiB total, %.1f GiB free; backup store %.1f GiB free; image catalog lists %s (%s) state=%s evidence=%s",
			float64(ps.CapacityBytes)/(1<<30), float64(ps.AvailableBytes)/(1<<30), float64(free)/(1<<30), img.ID, img.SHA256[:12], img.State, img.Evidence))
		if img.State != provision.StateQualified {
			rec.fail("image-qualified", "the catalog image is not real-host qualified; reinstall needs one")
		}
		anchor("image-immutable-storage-start")

	case "stop":
		owned(name, uuid, fp)
		if err := provision.Stop(ctx, ops, name, nil); err != nil {
			rec.fail("vm-stop", fmt.Sprint(err))
			t.Fatal(err)
		}
		rec.pass("vm-stop", "graceful stop observed")

	case "resize":
		owned(name, uuid, fp)
		before, _ := ops.LookupVolume(ctx, cfg.Pool, provision.RootVolumeName(uuid))
		if err := provision.Resize(ctx, ops, cfg, name, storageResizeTo, nil); err != nil {
			rec.fail("disk-grow", fmt.Sprint(err))
			t.Fatal(err)
		}
		after, _ := ops.LookupVolume(ctx, cfg.Pool, provision.RootVolumeName(uuid))
		if after.CapacityBytes != int64(storageResizeTo)<<30 || after.BackingPath != before.BackingPath {
			rec.fail("disk-grow", fmt.Sprintf("capacity %d -> %d backing %q -> %q", before.CapacityBytes, after.CapacityBytes, before.BackingPath, after.BackingPath))
			t.Fatal("resize")
		}
		if err := provision.Resize(ctx, ops, cfg, name, 5, nil); hypervisor.CategoryOf(err) != hypervisor.Validation {
			rec.fail("shrink-refused", fmt.Sprintf("a shrink must be refused: %v", err))
			t.Fatal("shrink")
		}
		rec.pass("shrink-refused", "shrinking the root volume was refused; the volume is unchanged")
		rec.pass("disk-grow", fmt.Sprintf("root volume grown %d -> %d GiB while Stopped; backing image reference unchanged", before.CapacityBytes>>30, after.CapacityBytes>>30))
		anchor("image-immutable-after-resize")

	case "snapshot":
		owned(name, uuid, fp)
		if err := provision.Snapshot(ctx, ops, name, storageSnapID, nil); err != nil {
			rec.fail("snapshot-created", fmt.Sprint(err))
			t.Fatal(err)
		}
		if err := provision.Resize(ctx, ops, cfg, name, storageResizeTo+1, nil); hypervisor.CategoryOf(err) != hypervisor.Conflict {
			rec.fail("resize-blocked-by-snapshot", fmt.Sprintf("resize with a snapshot must be refused: %v", err))
			t.Fatal("resize with snapshot")
		}
		rec.pass("resize-blocked-by-snapshot", "a grow request was refused while the VM holds a snapshot")
		rec.pass("snapshot-created", "stopped-VM snapshot "+storageSnapID+" taken and owned (name prefix + description naming the VM uuid)")

	case "start-primary":
		owned(name, uuid, fp)
		rec.res.IPv4 = startAndWait(name)
		rec.pass("vm-start", "Running with a DHCP address")

	case "restore-snapshot":
		owned(name, uuid, fp)
		if err := provision.RestoreSnapshot(ctx, ops, name, storageSnapID, nil); err != nil {
			rec.fail("snapshot-restored", fmt.Sprint(err))
			t.Fatal(err)
		}
		d := owned(name, uuid, fp)
		if d.Running {
			rec.fail("snapshot-restored", "the VM must stay Stopped after a restore")
		}
		rec.pass("snapshot-restored", "reverted to "+storageSnapID+"; VM Stopped and still owned")
		if err := provision.DeleteSnapshot(ctx, ops, name, storageSnapID, nil); err != nil {
			rec.fail("snapshot-deleted", fmt.Sprint(err))
			t.Fatal(err)
		}
		all, _ := ops.ListSnapshots(ctx, name)
		if len(all) != 0 {
			rec.fail("snapshot-deleted", fmt.Sprintf("%d snapshots remain", len(all)))
			t.Fatal("snapshot remains")
		}
		rec.pass("snapshot-deleted", "the VM's own snapshot was deleted; none remains")
		anchor("image-immutable-after-snapshot")

	case "backup":
		owned(name, uuid, fp)
		if err := provision.Backup(ctx, ops, cfg, cat, store, name, backupID, provision.BackupInput{Version: "qualification"}, nil); err != nil {
			rec.fail("backup-created", fmt.Sprint(err))
			t.Fatal(err)
		}
		b, err := store.Verify(backupID)
		if err != nil {
			rec.fail("backup-checksum", fmt.Sprint(err))
			t.Fatal(err)
		}
		m := b.Manifest
		rec.pass("backup-created", fmt.Sprintf("backup %s: %.1f MiB overlay, %d GiB virtual, base image %s", backupID, float64(m.Root.Size)/(1<<20), m.VM.DiskGiB, m.VM.ImageSHA256[:12]))
		rec.pass("backup-checksum", "manifest checksum and the root copy's SHA-256 re-verified in full")
		if err := provision.Backup(ctx, ops, cfg, cat, store, name, backupID, provision.BackupInput{}, nil); err != nil {
			rec.fail("backup-idempotent", fmt.Sprint(err))
		} else {
			rec.pass("backup-idempotent", "running the finished backup again changed nothing")
		}
		// the manifest never carries an SSH key
		if raw, _ := os.ReadFile(filepath.Join(cfg.BackupDir, backupID, backupstore.ManifestFile)); strings.Contains(string(raw), "ssh-") { // #nosec G304 -- inside the store
			rec.fail("backup-no-key", "the manifest contains an SSH key")
		} else {
			rec.pass("backup-no-key", "the manifest holds no SSH key or secret")
		}

	case "delete-source":
		owned(name, uuid, fp)
		if err := provision.Delete(ctx, ops, cfg, name, nil); err != nil {
			rec.fail("source-deleted", fmt.Sprint(err))
			t.Fatal(err)
		}
		counts(name, uuid, 0, 0, "source-deleted")
		if _, err := store.Verify(backupID); err != nil {
			rec.fail("source-deleted", "deleting the VM damaged the backup: "+err.Error())
			t.Fatal(err)
		}
		rec.pass("source-deleted", "the source VM and its volumes are gone; the backup is intact")

	case "restore":
		spec := provision.RestoreSpec{Name: rname, UUID: ruuid, Fingerprint: rfp, SSHPublicKey: pubKey()}
		// negative cases first: a damaged copy of the backup must be refused and create nothing
		if err := provision.Restore(ctx, ops, cfg, cat, store, "bk-ffffffffffffffff", spec, filepath.Join(cfg.StateDir, "scratch"), nil); hypervisor.CategoryOf(err) != hypervisor.NotFound {
			rec.fail("restore-unknown-refused", fmt.Sprintf("an unknown backup must be refused: %v", err))
			t.Fatal("unknown backup")
		}
		counts(rname, ruuid, 0, 0, "restore-unknown-refused")
		rec.pass("restore-unknown-refused", "restoring an unknown backup id was refused and created nothing")
		scratch := filepath.Join(cfg.StateDir, "scratch")
		if err := os.MkdirAll(scratch, 0o700); err != nil {
			scratch = t.TempDir()
		}
		crashed := make(chan struct{})
		go func() { // the unknown-outcome case: the restore dies right after the backed-up bytes were uploaded
			defer close(crashed)
			_ = provision.Restore(ctx, ops, cfg, cat, store, backupID, spec, scratch, func(s string) {
				if s == provision.StepRestoreUploaded {
					runtime.Goexit()
				}
			})
		}()
		<-crashed
		if d, v, _ := resourcesOf(ops, cfg.Pool, rname, ruuid); d != 0 || v != 1 {
			rec.fail("restore-interrupted", fmt.Sprintf("after the interrupted restore expected 0 domains and the 1 uploaded root volume, found %d and %d", d, v))
			t.Fatal("interrupted state")
		}
		rec.pass("restore-interrupted", "interrupted right after the upload: 0 domains and only the new root volume remain")
		if err := provision.Restore(ctx, ops, cfg, cat, store, backupID, spec, scratch, nil); err != nil {
			rec.fail("restore-completed", fmt.Sprint(err))
			t.Fatal(err)
		}
		if err := provision.Restore(ctx, ops, cfg, cat, store, backupID, spec, scratch, nil); err != nil {
			rec.fail("restore-completed", "an identical repeat failed: "+err.Error())
			t.Fatal(err)
		}
		counts(rname, ruuid, 1, 2, "restore-no-duplicates")
		owned(rname, ruuid, rfp)
		rec.pass("restore-completed", "the interrupted restore was completed; a repeat is a no-op")
		rec.pass("restore-no-duplicates", "exactly 1 domain and 2 volumes for the restored identity")
		// a collision must be refused
		other := spec
		other.UUID, other.Fingerprint = "9c9c9c9c-1111-4222-8333-444444444444", strings.Repeat("9c", 32)
		if err := provision.Restore(ctx, ops, cfg, cat, store, backupID, other, scratch, nil); hypervisor.CategoryOf(err) != hypervisor.Conflict {
			rec.fail("restore-collision-refused", fmt.Sprintf("a name already used by another VM must be a conflict: %v", err))
		} else {
			rec.pass("restore-collision-refused", "restoring under a name that is taken by another VM was refused")
		}
		anchor("image-immutable-after-restore")

	case "start-restored":
		owned(rname, ruuid, rfp)
		rec.res.IPv4 = startAndWait(rname)
		rec.res.VMName = rname
		rec.pass("restored-vm-start", "the restored VM started with a DHCP address")

	case "stop-restored":
		owned(rname, ruuid, rfp)
		if err := provision.Stop(ctx, ops, rname, nil); err != nil {
			rec.fail("vm-stop", fmt.Sprint(err))
			t.Fatal(err)
		}
		rec.pass("vm-stop", "graceful stop observed (restored VM)")

	case "reinstall":
		owned(rname, ruuid, rfp)
		// an image that is not qualified is refused: use a catalog copy where the state is lowered
		rs := provision.ReinstallSpec{ImageID: img.ID, ImageSHA256: img.SHA256, SSHPublicKey: pubKey(), Rev: storageRev}
		if err := provision.Reinstall(ctx, ops, cfg, cat, rname, provision.ReinstallSpec{ImageID: img.ID, ImageSHA256: strings.Repeat("0", 64), SSHPublicKey: rs.SSHPublicKey, Rev: storageRev}, filepath.Join(cfg.StateDir, "scratch"), nil); hypervisor.CategoryOf(err) != hypervisor.Conflict {
			rec.fail("reinstall-wrong-digest-refused", fmt.Sprintf("a digest that does not match the catalog must be refused: %v", err))
			t.Fatal("digest")
		}
		counts(rname, ruuid, 1, 2, "reinstall-wrong-digest-refused")
		rec.pass("reinstall-wrong-digest-refused", "a reinstall naming a different digest was refused; nothing was created")
		scratch := filepath.Join(cfg.StateDir, "scratch")
		if err := os.MkdirAll(scratch, 0o700); err != nil {
			scratch = t.TempDir()
		}
		old := owned(rname, ruuid, rfp)
		var steps []string
		if err := provision.Reinstall(ctx, ops, cfg, cat, rname, rs, scratch, func(s string) { steps = append(steps, s) }); err != nil {
			rec.fail("reinstall-completed", fmt.Sprint(err))
			t.Fatal(err)
		}
		now := owned(rname, ruuid, rfp)
		if now.Root == old.Root || now.Root != provision.RootVolumeNameRev(ruuid, storageRev) {
			rec.fail("reinstall-completed", fmt.Sprintf("the domain names %s (was %s)", now.Root, old.Root))
			t.Fatal("not switched")
		}
		counts(rname, ruuid, 1, 2, "reinstall-no-leftovers")
		if err := provision.Reinstall(ctx, ops, cfg, cat, rname, rs, scratch, nil); err != nil {
			rec.fail("reinstall-completed", "an identical repeat failed: "+err.Error())
		}
		rec.pass("reinstall-completed", "root and seed replaced under revision "+storageRev+" (steps "+strings.Join(steps, ",")+"); identity, size and network kept")
		rec.pass("reinstall-no-leftovers", "exactly 1 domain and the new pair of volumes remain; the old pair was removed after the commit")
		anchor("image-immutable-after-reinstall")

	case "cleanup":
		owned(rname, ruuid, rfp)
		if err := provision.Delete(ctx, ops, cfg, rname, nil); err != nil {
			rec.fail("restored-deleted", fmt.Sprint(err))
			t.Fatal(err)
		}
		counts(rname, ruuid, 0, 0, "restored-deleted")
		counts(name, uuid, 0, 0, "restored-deleted")
		rec.pass("restored-deleted", "the restored VM and its volumes are gone")
		if err := store.Delete(backupID); err != nil {
			rec.fail("backup-deleted", fmt.Sprint(err))
		} else if l, _ := store.List(); len(l) != 0 {
			rec.fail("backup-deleted", fmt.Sprintf("%d backups remain", len(l)))
		} else {
			rec.pass("backup-deleted", "the run's backup was deleted; the store is empty")
		}
		anchor("image-immutable-after")
		raw, rerr := os.ReadFile(filepath.Join(rec.out, inventoryFile)) // #nosec G304 -- fixed name in the run output dir
		var was inventory
		now, nerr := takeInventory(ops, uuid)
		switch {
		case rerr != nil || json.Unmarshal(raw, &was) != nil || nerr != nil:
			rec.add("unrelated-resources-unchanged", "NOT_RUN", "no baseline inventory to compare with")
		case !reflect.DeepEqual(was, now):
			rec.fail("unrelated-resources-unchanged", "the set of other domains, networks, pools or volumes differs from the baseline")
		default:
			rec.pass("unrelated-resources-unchanged", "every other domain, network (incl. default), pool and volume is identical to the baseline")
		}

	default:
		t.Fatalf("SVAVYOM_QUALIFY_STEP %q is not a storage step", step)
	}
	if rec.failed() {
		t.Fatal("one or more criteria failed")
	}
}
