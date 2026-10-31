package mutagent

import (
	"context"
	"io"
	"net/netip"
	"os"
	"path/filepath"

	"example.invalid/dedicatedcloud/backend/internal/backupstore"
	"example.invalid/dedicatedcloud/backend/internal/hypervisor"
	"example.invalid/dedicatedcloud/backend/internal/provision"
)

// RunHelper is the body of a helper process: read ONE request as a JSON document from in (at most MaxRequestBytes), execute it
// with ops (pol decides which catalog and image files are trusted), write ONE reply document to out. It returns the process exit code: 0 when a reply was written (success or typed
// failure), 2 when the request could not even be read or validated (no reply). It owns no state between runs.
func RunHelper(ctx context.Context, in io.Reader, out io.Writer, ops provision.HostOps, cfg provision.Config, pol provision.Policy, hook provision.Hook) int {
	raw, err := io.ReadAll(io.LimitReader(in, MaxRequestBytes+1))
	if err != nil || len(raw) == 0 || len(raw) > MaxRequestBytes {
		return 2
	}
	var q Request
	if decodeStrict(raw, &q) != nil || !q.Valid() || cfg.Validate() != nil {
		return 2
	}
	if hook != nil {
		hook("begin") // before any host action (fault injection point)
	}
	reply := Reply{V: Version, OK: true}
	var rerr error
	if isStorageOp(q.Op) {
		rerr = runStorage(ctx, q, &reply, ops, cfg, pol, hook)
		if rerr != nil {
			reply = Reply{V: Version, Category: string(categoryOf(rerr))}
		}
		if writeJSON(out, reply) != nil {
			return 2
		}
		return 0
	}
	if isNetworkOp(q.Op) {
		rerr = runNetwork(ctx, q, ops, cfg, hook)
		if rerr != nil {
			reply = Reply{V: Version, Category: string(categoryOf(rerr))}
		}
		if writeJSON(out, reply) != nil {
			return 2
		}
		return 0
	}
	switch q.Op {
	case OpPreflight:
		r := provision.Preflight(ctx, ops, cfg)
		reply.Preflight = &Preflight{Network: r.Network, Pool: r.Pool}
	case OpProvision:
		scratch := filepath.Join(cfg.StateDir, "scratch")
		if err := os.MkdirAll(scratch, 0o700); err != nil {
			rerr = hypervisor.NewError(hypervisor.HostError, "provision", "", "scratch")
			break
		}
		cat, err := provision.LoadTrustedCatalog(pol, cfg.CatalogDir)
		if err != nil {
			rerr = hypervisor.NewError(hypervisor.HostError, "provision", "", "catalog")
			break
		}
		rerr = provision.Provision(ctx, ops, cfg, cat, *q.Provision, scratch, hook)
	case OpStart:
		rerr = provision.Start(ctx, ops, q.Name, hook)
	case OpStop:
		rerr = provision.Stop(ctx, ops, q.Name, hook)
	case OpReboot:
		rerr = provision.Reboot(ctx, ops, q.Name, hook)
	case OpForceOff:
		rerr = provision.ForceOff(ctx, ops, q.Name, hook)
	case OpDelete:
		rerr = provision.Delete(ctx, ops, cfg, q.Name, hook)
	}
	if rerr != nil {
		reply = Reply{V: Version, Category: string(categoryOf(rerr))}
	}
	if writeJSON(out, reply) != nil {
		return 2
	}
	return 0
}

func categoryOf(err error) hypervisor.Category {
	switch c := hypervisor.CategoryOf(err); c {
	case hypervisor.NotFound, hypervisor.Conflict, hypervisor.Validation, hypervisor.Prohibited, hypervisor.Timeout, hypervisor.Unavailable, hypervisor.HostError:
		return c
	}
	return hypervisor.HostError
}

func isNetworkOp(op string) bool {
	switch op {
	case OpNetCreate, OpNetStart, OpNetStop, OpNetAutostart, OpNetDelete, OpCompute, OpReserveIP, OpReleaseIP:
		return true
	}
	return false
}

// runNetwork executes one M3 operation. Every value was validated by Request.Valid; the network XML is rendered here from a fixed template.
func runNetwork(ctx context.Context, q Request, ops provision.HostOps, cfg provision.Config, hook provision.Hook) error {
	switch q.Op {
	case OpNetCreate:
		var avoid []netip.Prefix
		for _, a := range q.Net.Avoid {
			p, err := provision.ParsePrefixStrict(a)
			if err != nil {
				return hypervisor.NewError(hypervisor.Validation, q.Op, "", "avoid")
			}
			avoid = append(avoid, p)
		}
		return provision.NetworkCreate(ctx, ops, cfg, provision.NetworkSpec{Name: q.Name, UUID: q.Net.UUID, Subnet: q.Net.Subnet, DHCPStart: q.Net.DHCPStart, DHCPEnd: q.Net.DHCPEnd, HostBridge: q.Net.HostBridge}, avoid, hook)
	case OpNetStart:
		return provision.NetworkStart(ctx, ops, q.Name, hook)
	case OpNetStop:
		return provision.NetworkStop(ctx, ops, q.Name, hook)
	case OpNetAutostart:
		return provision.NetworkAutostart(ctx, ops, q.Name, q.Net.Autostart == "on")
	case OpNetDelete:
		return provision.NetworkDelete(ctx, ops, q.Name, hook)
	case OpCompute:
		return provision.Compute(ctx, ops, q.Name, q.Net.VCPUs, q.Net.MemoryMiB, hook)
	case OpReserveIP:
		return provision.ReserveIP(ctx, ops, q.Name, q.Net.IP, hook)
	case OpReleaseIP:
		return provision.ReleaseIP(ctx, ops, q.Name, hook)
	}
	return hypervisor.NewError(hypervisor.Validation, q.Op, "", "unknown")
}

func isStorageOp(op string) bool {
	switch op {
	case OpResize, OpReinstall, OpSnapshot, OpRestoreSnapshot, OpDeleteSnapshot, OpBackup, OpRestore, OpDeleteBackup, OpListBackups, OpStats,
		OpVolCreate, OpVolAttach, OpVolDetach, OpVolDelete, OpEjectISO, OpGraphicsEnable, OpISOAttach, OpRescue, OpUnrescue:
		return true
	}
	return false
}

// maxListedBackups bounds the ordinary list_backups reply (newest first); maxFullListedBackups bounds the complete listing a request with Full asks for. The reply
// says when a cap cut the list (Truncated).
const (
	maxListedBackups     = 100
	maxFullListedBackups = 10000
)

// listedBackups is the reply of list_backups: the newest limit backups of l (newest first) and whether l held more.
func listedBackups(l []backupstore.Summary, limit int) ([]BackupSummary, bool) {
	var out []BackupSummary
	for _, b := range l {
		if len(out) >= limit {
			break
		}
		out = append(out, BackupSummary{ID: b.Manifest.BackupID, VM: b.Manifest.VM.Name, CreatedAt: b.Manifest.CreatedAt,
			SizeBytes: b.Manifest.Root.Size, DiskGiB: b.Manifest.VM.DiskGiB, ImageID: b.Manifest.VM.ImageID, Valid: b.Valid})
	}
	return out, len(l) > limit
}

// runStorage executes one M2 operation. The scratch directory, the trusted catalog and the backup store are opened here, per request, from the
// server-owned configuration; nothing in the request names a path.
func runStorage(ctx context.Context, q Request, reply *Reply, ops provision.HostOps, cfg provision.Config, pol provision.Policy, hook provision.Hook) error {
	typed := func(c hypervisor.Category, op string) error { return hypervisor.NewError(c, op, "", "storage") }
	var store *backupstore.Store
	if cfg.BackupDir != "" {
		s, err := backupstore.Open(cfg.BackupDir)
		if err != nil {
			return typed(hypervisor.Unavailable, q.Op)
		}
		store = s
	}
	catalog := func() (*provision.Catalog, error) {
		cat, err := provision.LoadTrustedCatalog(pol, cfg.CatalogDir)
		if err != nil {
			return nil, typed(hypervisor.HostError, q.Op)
		}
		return cat, nil
	}
	scratch := func() (string, error) {
		d := filepath.Join(cfg.StateDir, "scratch")
		if err := os.MkdirAll(d, 0o700); err != nil {
			return "", typed(hypervisor.HostError, q.Op)
		}
		return d, nil
	}
	switch q.Op {
	case OpStats:
		ps, err := ops.PoolStats(ctx, cfg.Pool)
		if err != nil {
			return err
		}
		st := &Stats{PoolCapacity: ps.CapacityBytes, PoolAvailable: ps.AvailableBytes, PoolAllocation: ps.AllocationBytes, Snapshots: provision.SnapshotSupport(ps.Type)}
		if store != nil {
			st.BackupsKnown, st.BackupBytes = true, store.UsageBytes()
			st.BackupFree, _ = store.FreeBytes()
			st.BackupTotal, _ = store.TotalBytes()
		}
		reply.Stats = st
		return nil
	case OpListBackups:
		if store == nil {
			return nil // none configured: an empty list, not an error
		}
		l, err := store.List()
		if err != nil {
			return typed(hypervisor.Unavailable, q.Op)
		}
		limit := maxListedBackups
		if q.Full {
			limit = maxFullListedBackups
		}
		reply.Backups, reply.Truncated = listedBackups(l, limit)
		return nil
	case OpDeleteBackup:
		if store == nil {
			return typed(hypervisor.Unavailable, q.Op)
		}
		if err := store.Delete(q.ID); err != nil {
			return typed(hypervisor.Conflict, q.Op)
		}
		return nil
	case OpEjectISO:
		sha := ""
		if q.Media != nil {
			sha = q.Media.ImageSHA256
		}
		return provision.EjectISO(ctx, ops, q.Name, sha, hook)
	case OpGraphicsEnable:
		return provision.GraphicsEnable(ctx, ops, q.Name, hook)
	case OpUnrescue:
		return provision.Unrescue(ctx, ops, q.Name, hook)
	case OpISOAttach:
		cat, err := catalog()
		if err != nil {
			return err
		}
		return provision.ISOAttach(ctx, ops, cat, q.Name, q.Media.ImageID, q.Media.ImageSHA256, q.Media.Boot, hook)
	case OpRescue:
		cat, err := catalog()
		if err != nil {
			return err
		}
		return provision.Rescue(ctx, ops, cat, q.Name, q.Media.ImageID, q.Media.ImageSHA256, hook)
	case OpVolCreate:
		return provision.VolumeCreate(ctx, ops, cfg, q.Name, q.DiskGiB, hook)
	case OpVolAttach:
		return provision.VolumeAttach(ctx, ops, cfg, q.Name, q.VM, hook)
	case OpVolDetach:
		return provision.VolumeDetach(ctx, ops, cfg, q.Name, hook)
	case OpVolDelete:
		return provision.VolumeDelete(ctx, ops, cfg, q.Name, hook)
	case OpResize:
		return provision.Resize(ctx, ops, cfg, q.Name, q.DiskGiB, hook)
	case OpSnapshot:
		return provision.Snapshot(ctx, ops, q.Name, q.ID, hook)
	case OpRestoreSnapshot:
		return provision.RestoreSnapshot(ctx, ops, q.Name, q.ID, hook)
	case OpDeleteSnapshot:
		return provision.DeleteSnapshot(ctx, ops, q.Name, q.ID, hook)
	case OpBackup:
		cat, err := catalog()
		if err != nil {
			return err
		}
		return provision.Backup(ctx, ops, cfg, cat, store, q.Name, q.ID, provision.BackupInput{Version: ToolVersion}, hook)
	case OpRestore:
		cat, err := catalog()
		if err != nil {
			return err
		}
		sd, err := scratch()
		if err != nil {
			return err
		}
		return provision.Restore(ctx, ops, cfg, cat, store, q.ID, provision.RestoreSpec{Name: q.Name, UUID: q.Restore.UUID, Fingerprint: q.Restore.Fingerprint, SSHPublicKey: q.Restore.SSHPublicKey}, sd, hook)
	case OpReinstall:
		cat, err := catalog()
		if err != nil {
			return err
		}
		sd, err := scratch()
		if err != nil {
			return err
		}
		r := q.Reinstall
		return provision.Reinstall(ctx, ops, cfg, cat, q.Name, provision.ReinstallSpec{ImageID: r.ImageID, ImageSHA256: r.ImageSHA256, SSHPublicKey: r.SSHPublicKey, Rev: r.Rev}, sd, hook)
	}
	return typed(hypervisor.Validation, q.Op)
}

// ToolVersion is recorded in backup manifests; the build may set it with -ldflags.
var ToolVersion = "svavyom-dev"
