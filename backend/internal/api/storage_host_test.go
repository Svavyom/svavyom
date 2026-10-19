package api

import (
	"context"
	"os"
	"path/filepath"

	"example.invalid/dedicatedcloud/backend/internal/hypervisor"
	"example.invalid/dedicatedcloud/backend/internal/offsite"
	"example.invalid/dedicatedcloud/backend/internal/operation"
	"example.invalid/dedicatedcloud/backend/internal/provision"
)

var _ operation.Storage = (*directHost)(nil)

// The storage and recovery operations run the same provisioning code as the mutation helper, in process, against the simulated host.

func (d *directHost) catalog() (*provision.Catalog, error) { return d.cat() }

func (d *directHost) scratch() string {
	p := filepath.Join(d.cfg.StateDir, "scratch")
	_ = os.MkdirAll(p, 0o700)
	return p
}

func (d *directHost) Resize(ctx context.Context, name string, gib int) error {
	return provision.Resize(ctx, d.sim, d.cfg, name, gib, nil)
}

func (d *directHost) Reinstall(ctx context.Context, name string, p operation.Params) error {
	c, err := d.catalog()
	if err != nil {
		return err
	}
	return provision.Reinstall(ctx, d.sim, d.cfg, c, name, provision.ReinstallSpec{ImageID: p.ImageID, ImageSHA256: p.ImageSHA256, SSHPublicKey: p.SSHPublicKey, Rev: p.Rev}, d.scratch(), nil)
}

func (d *directHost) BackupExport(ctx context.Context, backupID, targetID string) error {
	if d.exp == nil {
		return hypervisor.NewError(hypervisor.Prohibited, "backup_export", "", "not available")
	}
	return offsite.ToHypervisorError("backup_export", d.exp.Export(ctx, backupID, targetID))
}

func (d *directHost) EjectISO(ctx context.Context, name string) error {
	return provision.EjectISO(ctx, d.sim, name, nil)
}

func (d *directHost) GraphicsEnable(ctx context.Context, name string) error {
	return provision.GraphicsEnable(ctx, d.sim, name, nil)
}

func (d *directHost) Unrescue(ctx context.Context, name string) error {
	return provision.Unrescue(ctx, d.sim, name, nil)
}

func (d *directHost) ISOAttach(ctx context.Context, name string, p operation.Params) error {
	c, err := d.catalog()
	if err != nil {
		return err
	}
	return provision.ISOAttach(ctx, d.sim, c, name, p.ImageID, p.ImageSHA256, p.Boot, nil)
}

func (d *directHost) Rescue(ctx context.Context, name string, p operation.Params) error {
	c, err := d.catalog()
	if err != nil {
		return err
	}
	return provision.Rescue(ctx, d.sim, c, name, p.ImageID, p.ImageSHA256, nil)
}

func (d *directHost) VolumeCreate(ctx context.Context, name string, gib int) error {
	return provision.VolumeCreate(ctx, d.sim, d.cfg, name, gib, nil)
}

func (d *directHost) VolumeAttach(ctx context.Context, name, vm string) error {
	return provision.VolumeAttach(ctx, d.sim, d.cfg, name, vm, nil)
}

func (d *directHost) VolumeDetach(ctx context.Context, name string) error {
	return provision.VolumeDetach(ctx, d.sim, d.cfg, name, nil)
}

func (d *directHost) VolumeDelete(ctx context.Context, name string) error {
	return provision.VolumeDelete(ctx, d.sim, d.cfg, name, nil)
}

func (d *directHost) Snapshot(ctx context.Context, name, id string) error {
	return provision.Snapshot(ctx, d.sim, name, id, nil)
}

func (d *directHost) RestoreSnapshot(ctx context.Context, name, id string) error {
	return provision.RestoreSnapshot(ctx, d.sim, name, id, nil)
}

func (d *directHost) DeleteSnapshot(ctx context.Context, name, id string) error {
	return provision.DeleteSnapshot(ctx, d.sim, name, id, nil)
}

func (d *directHost) Backup(ctx context.Context, name, id string) error {
	c, err := d.catalog()
	if err != nil {
		return err
	}
	return provision.Backup(ctx, d.sim, d.cfg, c, d.bak, name, id, provision.BackupInput{Version: "test"}, nil)
}

func (d *directHost) Restore(ctx context.Context, backupID string, p operation.Params) error {
	c, err := d.catalog()
	if err != nil {
		return err
	}
	return provision.Restore(ctx, d.sim, d.cfg, c, d.bak, backupID, provision.RestoreSpec{Name: p.NewName, UUID: p.NewUUID, Fingerprint: p.NewFinger, SSHPublicKey: p.SSHPublicKey}, d.scratch(), nil)
}

func (d *directHost) DeleteBackup(_ context.Context, backupID string) error {
	return d.bak.Delete(backupID)
}

var _ operation.Networking = (*directHost)(nil)

func (d *directHost) NetworkCreate(ctx context.Context, name string, p operation.Params) error {
	return provision.NetworkCreate(ctx, d.sim, d.cfg, provision.NetworkSpec{Name: name, UUID: p.NewUUID, Subnet: p.Subnet, DHCPStart: p.DHCPStart, DHCPEnd: p.DHCPEnd, HostBridge: p.Bridge}, d.avoid, nil)
}
func (d *directHost) NetworkStart(ctx context.Context, name string) error {
	return provision.NetworkStart(ctx, d.sim, name, nil)
}
func (d *directHost) NetworkStop(ctx context.Context, name string) error {
	return provision.NetworkStop(ctx, d.sim, name, nil)
}
func (d *directHost) NetworkAutostart(ctx context.Context, name string, on bool) error {
	return provision.NetworkAutostart(ctx, d.sim, name, on)
}
func (d *directHost) NetworkDelete(ctx context.Context, name string) error {
	return provision.NetworkDelete(ctx, d.sim, name, nil)
}
func (d *directHost) Compute(ctx context.Context, vm string, vcpus, mem int) error {
	return provision.Compute(ctx, d.sim, vm, vcpus, mem, nil)
}
func (d *directHost) ReserveIP(ctx context.Context, vm, ip string) error {
	return provision.ReserveIP(ctx, d.sim, vm, ip, nil)
}
func (d *directHost) ReleaseIP(ctx context.Context, vm string) error {
	return provision.ReleaseIP(ctx, d.sim, vm, nil)
}
