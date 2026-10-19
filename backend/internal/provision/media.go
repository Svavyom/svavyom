package provision

import (
	"context"
	"errors"

	"example.invalid/dedicatedcloud/backend/internal/hypervisor"
)

// Host-side operations on the devices of a STOPPED, Svavyom-owned VM (DR-026): the graphical console, installation media and rescue mode. Each one reads
// the persistent definition, applies one transformation from devices.go, hands the result to HostOps.DefineDomain and then reads the definition back to prove
// the postcondition and that nothing else about the VM changed. Running one again after an unknown outcome finds the work done and succeeds.

// Steps reported to the hook.
const (
	StepGraphicsEnabled = "graphics-enabled"
	StepISOAttached     = "iso-attached"
	StepRescued         = "rescued"
	StepUnrescued       = "unrescued"
)

// redefine stores the transformed definition and proves the VM is still the same VM with the wanted change.
func redefine(ctx context.Context, ops HostOps, before DomainInfo, op, y string, want func(DomainInfo) bool) error {
	if y == before.XML {
		return nil
	}
	if err := ops.DefineDomain(ctx, y); err != nil {
		return err
	}
	after, err := ops.LookupDomain(ctx, before.Name)
	if err != nil {
		return err
	}
	if !after.Managed || after.UUID != before.UUID || after.Fingerprint != before.Fingerprint || after.Root != before.Root || after.Seed != before.Seed ||
		len(after.Data) != len(before.Data) || !want(after) {
		return typed(hypervisor.HostError, op)
	}
	return nil
}

func mapDeviceErr(op string, err error) error {
	switch {
	case errors.Is(err, ErrISOPresent), errors.Is(err, ErrRescued), errors.Is(err, ErrNoGraphics):
		return typedWhy(hypervisor.Conflict, op, err.Error())
	case errors.Is(err, ErrBoot), errors.Is(err, ErrBacking):
		return typed(hypervisor.Validation, op)
	}
	return typed(hypervisor.HostError, op)
}

// mediaPath returns the verified store path of the catalog ISO the request names; a changed or non-ISO image is refused.
func mediaPath(cat *Catalog, imageID, sha, op string) (string, error) {
	im, err := cat.Usable(imageID)
	if err != nil || !im.IsISO() || im.SHA256 != sha {
		return "", typed(hypervisor.Validation, op)
	}
	p, err := cat.Verify(im)
	if err != nil {
		return "", typed(hypervisor.HostError, op)
	}
	return p, nil
}

// GraphicsEnable gives a stopped VM the graphical console devices (a VM created before this release has none).
func GraphicsEnable(ctx context.Context, ops HostOps, name string, hook Hook) error {
	if hook == nil {
		hook = func(string) {}
	}
	d, err := stopped(ctx, ops, name, "graphics_enable")
	if err != nil {
		return err
	}
	y, err := AddGraphicsXML(d.XML)
	if err != nil {
		return mapDeviceErr("graphics_enable", err)
	}
	if err := redefine(ctx, ops, d, "graphics_enable", y, func(a DomainInfo) bool { return a.Graphics }); err != nil {
		return err
	}
	hook(StepGraphicsEnabled)
	return nil
}

// ISOAttach attaches catalog installation media to a stopped VM, optionally as the next boot device.
func ISOAttach(ctx context.Context, ops HostOps, cat *Catalog, name, imageID, sha, boot string, hook Hook) error {
	if hook == nil {
		hook = func(string) {}
	}
	d, err := stopped(ctx, ops, name, "iso_attach")
	if err != nil {
		return err
	}
	if d.Rescue != "" {
		return typedWhy(hypervisor.Conflict, "iso_attach", "the VM is in rescue mode")
	}
	p, err := mediaPath(cat, imageID, sha, "iso_attach")
	if err != nil {
		return err
	}
	y, err := AttachISOXML(d.XML, p, boot)
	if err != nil {
		return mapDeviceErr("iso_attach", err)
	}
	if err := redefine(ctx, ops, d, "iso_attach", y, func(a DomainInfo) bool { return a.ISO == sha }); err != nil {
		return err
	}
	hook(StepISOAttached)
	return nil
}

// EjectISO removes the installation media from the persistent definition of the STOPPED VM, so it boots from its disk. No media is success. A VM in
// rescue mode is taken out of it with Unrescue, not by ejecting.
func EjectISO(ctx context.Context, ops HostOps, name string, hook Hook) error {
	if hook == nil {
		hook = func(string) {}
	}
	d, err := stopped(ctx, ops, name, "eject_iso")
	if err != nil {
		return err
	}
	if d.Rescue != "" {
		return typedWhy(hypervisor.Conflict, "eject_iso", "the VM is in rescue mode")
	}
	y, had, err := RemoveISOXML(d.XML)
	if err != nil {
		return mapDeviceErr("eject_iso", err)
	}
	if !had {
		return nil
	}
	if err := redefine(ctx, ops, d, "eject_iso", y, func(a DomainInfo) bool { return a.ISO == "" }); err != nil {
		return err
	}
	hook(StepISOEjected)
	return nil
}

// Rescue boots the VM from rescue media next time, with its own disk untouched; Unrescue puts the definition back.
func Rescue(ctx context.Context, ops HostOps, cat *Catalog, name, imageID, sha string, hook Hook) error {
	if hook == nil {
		hook = func(string) {}
	}
	d, err := stopped(ctx, ops, name, "rescue")
	if err != nil {
		return err
	}
	if d.Rescue == sha {
		return nil // already in rescue mode with this media
	}
	p, err := mediaPath(cat, imageID, sha, "rescue")
	if err != nil {
		return err
	}
	y, err := RescueXML(d.XML, p, sha)
	if err != nil {
		return mapDeviceErr("rescue", err)
	}
	if err := redefine(ctx, ops, d, "rescue", y, func(a DomainInfo) bool { return a.Rescue == sha && a.ISO == sha }); err != nil {
		return err
	}
	hook(StepRescued)
	return nil
}

// Unrescue leaves rescue mode. A VM that is not in rescue mode is success.
func Unrescue(ctx context.Context, ops HostOps, name string, hook Hook) error {
	if hook == nil {
		hook = func(string) {}
	}
	d, err := stopped(ctx, ops, name, "unrescue")
	if err != nil {
		return err
	}
	y, changed, err := UnrescueXML(d.XML)
	if err != nil {
		return mapDeviceErr("unrescue", err)
	}
	if !changed {
		return nil
	}
	if err := redefine(ctx, ops, d, "unrescue", y, func(a DomainInfo) bool { return a.Rescue == "" && a.ISO == "" }); err != nil {
		return err
	}
	hook(StepUnrescued)
	return nil
}
