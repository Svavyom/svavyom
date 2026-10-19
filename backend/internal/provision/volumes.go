package provision

import (
	"context"
	"fmt"

	"example.invalid/dedicatedcloud/backend/internal/hypervisor"
)

// Standalone data volumes (M1-E02-S06, DR-023 D2). A data volume is a Svavyom-owned qcow2 file in the configured pool, named "svavyom-vol-<name>.qcow2".
// It is created empty, attached to a STOPPED Svavyom VM's persistent definition (no hot-plug), detached from it, and deleted as its own operation; a
// volume attached to a VM is never deleted, and deleting a VM never deletes a volume. Every function here is idempotent, because an operation
// whose outcome is unknown is settled by running it again.
const (
	StepVolumeCreated  = "volume-created"
	StepVolumeAttached = "volume-attached"
	StepVolumeDetached = "volume-detached"
	StepVolumeDeleted  = "volume-deleted"
)

// ownedDataVolume proves the volume is Svavyom's data volume in the configured pool and returns its resolved source.
func ownedDataVolume(ctx context.Context, ops HostOps, cfg Config, name, op string) (VolumeInfo, VolumeSource, error) {
	if !ValidDataName(name) {
		return VolumeInfo{}, VolumeSource{}, typed(hypervisor.Validation, op)
	}
	file := DataVolumeName(name)
	v, err := ops.LookupVolume(ctx, cfg.Pool, file)
	if err != nil {
		return VolumeInfo{}, VolumeSource{}, err
	}
	src, err := ResolveVolumeSource(file, v)
	if err != nil {
		return VolumeInfo{}, VolumeSource{}, typedWhy(hypervisor.Conflict, op, "the volume is not provably Svavyom's")
	}
	return v, src, nil
}

// holder returns the domain whose definition carries the data volume (and the disk target), or ok=false when no domain does.
func holder(ctx context.Context, ops HostOps, name string) (DomainInfo, DataDisk, bool, error) {
	all, err := ops.ListDomains(ctx)
	if err != nil {
		return DomainInfo{}, DataDisk{}, false, err
	}
	for _, d := range all {
		for _, dd := range d.Data {
			if dd.Volume == name {
				return d, dd, true, nil
			}
		}
	}
	return DomainInfo{}, DataDisk{}, false, nil
}

// VolumeCreate creates an empty data volume of gib GiB. An existing volume of the same name and size is success; another size is a conflict.
func VolumeCreate(ctx context.Context, ops HostOps, cfg Config, name string, gib int, hook Hook) error {
	if hook == nil {
		hook = func(string) {}
	}
	if !ValidDataName(name) || gib < 1 || gib > MaxDiskGiB {
		return typed(hypervisor.Validation, "volume_create")
	}
	if ok, err := ops.PoolActive(ctx, cfg.Pool); err != nil {
		return err
	} else if !ok {
		return typedWhy(hypervisor.Conflict, "volume_create", "the storage pool is not active")
	}
	want := int64(gib) << 30
	file := DataVolumeName(name)
	switch v, err := ops.LookupVolume(ctx, cfg.Pool, file); {
	case err == nil:
		if v.CapacityBytes != want {
			return typedWhy(hypervisor.Conflict, "volume_create", "a volume of this name exists with another size")
		}
		if _, _, perr := ownedDataVolume(ctx, ops, cfg, name, "volume_create"); perr != nil {
			return perr
		}
		return nil
	case hypervisor.CategoryOf(err) != hypervisor.NotFound:
		return err
	}
	st, err := ops.PoolStats(ctx, cfg.Pool)
	if err != nil {
		return err
	}
	if st.AvailableBytes < poolReserve {
		return typedWhy(hypervisor.Conflict, "volume_create", "the pool has no room")
	}
	if err := ops.CreateDataVolume(ctx, cfg.Pool, file, want); err != nil {
		return err
	}
	hook(StepVolumeCreated)
	v, err := ops.LookupVolume(ctx, cfg.Pool, file)
	if err != nil {
		return err
	}
	if v.CapacityBytes != want {
		return typed(hypervisor.HostError, "volume_create")
	}
	return nil
}

// VolumeAttach adds the data volume to the persistent definition of the STOPPED VM vm. Already attached to that VM is success; attached to another
// VM, a running VM or a VM with all its data targets used is a conflict.
func VolumeAttach(ctx context.Context, ops HostOps, cfg Config, name, vm string, hook Hook) error {
	if hook == nil {
		hook = func(string) {}
	}
	d, err := stopped(ctx, ops, vm, "volume_attach")
	if err != nil {
		return err
	}
	_, src, err := ownedDataVolume(ctx, ops, cfg, name, "volume_attach")
	if err != nil {
		return err
	}
	if h, _, ok, herr := holder(ctx, ops, name); herr != nil {
		return herr
	} else if ok {
		if h.UUID == d.UUID {
			return nil
		}
		return typedWhy(hypervisor.Conflict, "volume_attach", "the volume is attached to another VM")
	}
	if len(d.Data) >= MaxDataDisks {
		return typedWhy(hypervisor.Conflict, "volume_attach", "the VM has the most data volumes it can take")
	}
	used := map[string]bool{}
	for _, dd := range d.Data {
		used[dd.Dev] = true
	}
	dev := ""
	for c := 'b'; c <= 'z'; c++ {
		if t := fmt.Sprintf("vd%c", c); !used[t] {
			dev = t
			break
		}
	}
	if err := ops.AttachDataDisk(ctx, vm, name, src.Path, dev); err != nil {
		return err
	}
	hook(StepVolumeAttached)
	after, err := ops.LookupDomain(ctx, vm)
	if err != nil {
		return err
	}
	for _, dd := range after.Data {
		if dd.Volume == name {
			return nil
		}
	}
	return typed(hypervisor.HostError, "volume_attach")
}

// VolumeDetach removes the data volume from the VM that carries it. A volume no VM carries is success; the VM must be stopped. The volume itself
// and its data are untouched.
func VolumeDetach(ctx context.Context, ops HostOps, cfg Config, name string, hook Hook) error {
	if hook == nil {
		hook = func(string) {}
	}
	if !ValidDataName(name) {
		return typed(hypervisor.Validation, "volume_detach")
	}
	h, _, ok, err := holder(ctx, ops, name)
	if err != nil {
		return err
	}
	if !ok {
		return nil
	}
	if !h.Managed {
		return typed(hypervisor.Prohibited, "volume_detach")
	}
	if h.Running {
		return typedWhy(hypervisor.Conflict, "volume_detach", "the VM is not stopped")
	}
	if err := ops.DetachDataDisk(ctx, h.Name, name); err != nil {
		return err
	}
	hook(StepVolumeDetached)
	if still, _, ok, err := holder(ctx, ops, name); err != nil {
		return err
	} else if ok && still.UUID == h.UUID {
		return typed(hypervisor.HostError, "volume_detach")
	}
	return nil
}

// VolumeDelete deletes a data volume no VM carries. An absent volume is success.
func VolumeDelete(ctx context.Context, ops HostOps, cfg Config, name string, hook Hook) error {
	if hook == nil {
		hook = func(string) {}
	}
	if !ValidDataName(name) {
		return typed(hypervisor.Validation, "volume_delete")
	}
	_, _, err := ownedDataVolume(ctx, ops, cfg, name, "volume_delete")
	if hypervisor.CategoryOf(err) == hypervisor.NotFound {
		return nil
	}
	if err != nil {
		return err
	}
	if _, _, ok, herr := holder(ctx, ops, name); herr != nil {
		return herr
	} else if ok {
		return typedWhy(hypervisor.Conflict, "volume_delete", "the volume is attached to a VM")
	}
	if err := ops.DeleteVolume(ctx, cfg.Pool, DataVolumeName(name)); err != nil {
		return err
	}
	hook(StepVolumeDeleted)
	return nil
}
