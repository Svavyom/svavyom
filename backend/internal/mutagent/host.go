package mutagent

import (
	"context"

	"example.invalid/dedicatedcloud/backend/internal/hypervisor"
	"example.invalid/dedicatedcloud/backend/internal/offsite"
	"example.invalid/dedicatedcloud/backend/internal/operation"
	"example.invalid/dedicatedcloud/backend/internal/provision"
)

// Host is the hypervisor.Hypervisor the operation manager drives in production: observation through the read-only inventory
// agent; every mutation goes through the mutation supervisor's closed protocol, whose helper checks Svavyom ownership of the named VM
// before it acts. Nothing here reaches libvirt directly.
type Host struct {
	Reader hypervisor.Reader
	Mut    *Client
	// Offsite copies a backup to an off-host target (the separate svavyom-offsite service); nil means no target is declared.
	Offsite offsite.Exporting
	// HostPrefixes returns the host's own IPv4 subnets and routes (as CIDR strings) for a network create to avoid. The mutation helper runs in a
	// confined namespace and cannot see them; the API process, which shares the host's network namespace, reads them. An error refuses the create.
	HostPrefixes func(ctx context.Context) ([]string, error)
}

var _ hypervisor.Hypervisor = (*Host)(nil)

// Define provisions a Svavyom-owned VM. The spec must carry the full creation identity; the minimal simulation definition
// (no UUID, image or key) is refused.
func (h *Host) Define(ctx context.Context, s hypervisor.DomainSpec) (hypervisor.Domain, error) {
	ps := provision.Spec{Name: s.Name, UUID: s.UUID, Fingerprint: s.Fingerprint, VCPUs: s.VCPUs, MemoryMiB: s.MemoryMiB, ImageID: s.ImageID,
		ImageSHA256: s.ImageSHA256, DiskGiB: s.DiskGiB, SSHPublicKey: s.SSHPublicKey, Network: s.Network, Profile: s.Profile}
	if err := h.Mut.Provision(ctx, ps); err != nil {
		return hypervisor.Domain{}, err
	}
	return hypervisor.Domain{Name: s.Name, State: hypervisor.StateShutoff, VCPUs: s.VCPUs, MemoryMiB: s.MemoryMiB, UUID: s.UUID, Fingerprint: s.Fingerprint,
		Managed: true, ImageID: s.ImageID}, nil
}

// Start boots a managed VM.
func (h *Host) Start(ctx context.Context, name string) error { return h.Mut.Start(ctx, name) }

// Stop requests a graceful guest shutdown. It never escalates to a force-off.
func (h *Host) Stop(ctx context.Context, name string) error { return h.Mut.Stop(ctx, name) }

// Reboot requests a guest reboot (operation.Rebooter).
func (h *Host) Reboot(ctx context.Context, name string) error { return h.Mut.Reboot(ctx, name) }

// Destroy powers the VM off immediately (the explicit Force Off). It removes nothing.
func (h *Host) Destroy(ctx context.Context, name string) error { return h.Mut.ForceOff(ctx, name) }

// Undefine is the Delete of a stopped Svavyom VM: the helper proves ownership, removes the VM's own two volumes and then its
// definition. The name is historical (hypervisor.Hypervisor); on this host it never leaves volumes behind.
func (h *Host) Undefine(ctx context.Context, name string) error { return h.Mut.Delete(ctx, name) }

// Lookup observes through the read-only agent.
func (h *Host) Lookup(ctx context.Context, name string) (hypervisor.Domain, error) {
	return h.Reader.Lookup(ctx, name)
}

// List observes through the read-only agent.
func (h *Host) List(ctx context.Context) ([]hypervisor.Domain, error) { return h.Reader.List(ctx) }

// Calls returns nothing: the audit trail of this host is the operation record, not an in-process log.
func (h *Host) Calls() []hypervisor.CallRecord { return nil }

var _ operation.Storage = (*Host)(nil)

// Resize implements operation.Storage.
func (h *Host) Resize(ctx context.Context, name string, diskGiB int) error {
	return h.Mut.Resize(ctx, name, diskGiB)
}

// Reinstall implements operation.Storage.
func (h *Host) Reinstall(ctx context.Context, name string, p operation.Params) error {
	return h.Mut.Reinstall(ctx, name, Reinstall{ImageID: p.ImageID, ImageSHA256: p.ImageSHA256, SSHPublicKey: p.SSHPublicKey, Rev: p.Rev})
}

// Snapshot implements operation.Storage.
func (h *Host) Snapshot(ctx context.Context, name, id string) error {
	return h.Mut.Snapshot(ctx, name, id)
}

// RestoreSnapshot implements operation.Storage.
func (h *Host) RestoreSnapshot(ctx context.Context, name, id string) error {
	return h.Mut.RestoreSnapshot(ctx, name, id)
}

// DeleteSnapshot implements operation.Storage.
func (h *Host) DeleteSnapshot(ctx context.Context, name, id string) error {
	return h.Mut.DeleteSnapshot(ctx, name, id)
}

// Backup implements operation.Storage.
func (h *Host) Backup(ctx context.Context, name, id string) error { return h.Mut.Backup(ctx, name, id) }

// Restore implements operation.Storage: backupID is the operation's resource, the new VM's name and identity are in the parameters.
func (h *Host) Restore(ctx context.Context, backupID string, p operation.Params) error {
	return h.Mut.Restore(ctx, p.NewName, backupID, Restore{UUID: p.NewUUID, Fingerprint: p.NewFinger, SSHPublicKey: p.SSHPublicKey})
}

// BackupExport implements operation.Storage: the copy runs in the offsite service, which has the network the mutation unit lacks.
func (h *Host) BackupExport(ctx context.Context, backupID, targetID string) error {
	if h.Offsite == nil {
		return hypervisor.NewError(hypervisor.Prohibited, "backup_export", "", "not available")
	}
	return offsite.ToHypervisorError("backup_export", h.Offsite.Export(ctx, backupID, targetID))
}

// EjectISO implements operation.Storage.
func (h *Host) EjectISO(ctx context.Context, name string, p operation.Params) error {
	if p.ImageID == "" {
		return h.Mut.EjectISO(ctx, name, nil)
	}
	return h.Mut.EjectISO(ctx, name, &Media{ImageID: p.ImageID, ImageSHA256: p.ImageSHA256})
}

// GraphicsEnable, ISOAttach, Rescue and Unrescue implement operation.Storage (DR-026).
func (h *Host) GraphicsEnable(ctx context.Context, name string) error {
	return h.Mut.GraphicsEnable(ctx, name)
}

func (h *Host) ISOAttach(ctx context.Context, name string, p operation.Params) error {
	return h.Mut.ISOAttach(ctx, name, Media{ImageID: p.ImageID, ImageSHA256: p.ImageSHA256, Boot: p.Boot})
}

func (h *Host) Rescue(ctx context.Context, name string, p operation.Params) error {
	return h.Mut.Rescue(ctx, name, Media{ImageID: p.ImageID, ImageSHA256: p.ImageSHA256})
}

func (h *Host) Unrescue(ctx context.Context, name string) error { return h.Mut.Unrescue(ctx, name) }

// VolumeCreate implements operation.Storage.
func (h *Host) VolumeCreate(ctx context.Context, name string, diskGiB int) error {
	return h.Mut.VolumeCreate(ctx, name, diskGiB)
}

// VolumeAttach implements operation.Storage.
func (h *Host) VolumeAttach(ctx context.Context, name, vm string) error {
	return h.Mut.VolumeAttach(ctx, name, vm)
}

// VolumeDetach implements operation.Storage.
func (h *Host) VolumeDetach(ctx context.Context, name string) error {
	return h.Mut.VolumeDetach(ctx, name)
}

// VolumeDelete implements operation.Storage.
func (h *Host) VolumeDelete(ctx context.Context, name string) error {
	return h.Mut.VolumeDelete(ctx, name)
}

// DeleteBackup implements operation.Storage.
func (h *Host) DeleteBackup(ctx context.Context, backupID string) error {
	return h.Mut.DeleteBackup(ctx, backupID)
}

var _ operation.Networking = (*Host)(nil)

// NetworkCreate implements operation.Networking. Avoid holds the host prefixes the API collected when the request was accepted; it is looked up
// per call from the Host's HostPrefixes hook.
func (h *Host) NetworkCreate(ctx context.Context, name string, p operation.Params) error {
	if p.Bridge != "" { // a bridge-mode network has no subnet, so there is nothing to keep apart from the host's own prefixes
		return h.Mut.NetworkCreate(ctx, name, Net{UUID: p.NewUUID, HostBridge: p.Bridge})
	}
	var avoid []string
	if h.HostPrefixes != nil {
		a, err := h.HostPrefixes(ctx)
		if err != nil {
			return hypervisor.NewError(hypervisor.Unavailable, "network-create", "", "the host's own networks cannot be read")
		}
		avoid = a
	}
	return h.Mut.NetworkCreate(ctx, name, Net{UUID: p.NewUUID, Subnet: p.Subnet, DHCPStart: p.DHCPStart, DHCPEnd: p.DHCPEnd, Avoid: avoid})
}

// NetworkStart, NetworkStop, NetworkAutostart and NetworkDelete implement operation.Networking.
func (h *Host) NetworkStart(ctx context.Context, name string) error {
	return h.Mut.NetworkStart(ctx, name)
}
func (h *Host) NetworkStop(ctx context.Context, name string) error {
	return h.Mut.NetworkStop(ctx, name)
}
func (h *Host) NetworkDelete(ctx context.Context, name string) error {
	return h.Mut.NetworkDelete(ctx, name)
}
func (h *Host) NetworkAutostart(ctx context.Context, name string, on bool) error {
	s := "off"
	if on {
		s = "on"
	}
	return h.Mut.NetworkAutostart(ctx, name, s)
}

// Compute, ReserveIP and ReleaseIP implement operation.Networking.
func (h *Host) Compute(ctx context.Context, vm string, vcpus, memoryMiB int) error {
	return h.Mut.Compute(ctx, vm, vcpus, memoryMiB)
}
func (h *Host) ReserveIP(ctx context.Context, vm, ip string) error {
	return h.Mut.ReserveIP(ctx, vm, ip)
}
func (h *Host) ReleaseIP(ctx context.Context, vm string) error { return h.Mut.ReleaseIP(ctx, vm) }
