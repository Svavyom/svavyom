package provision

import (
	"context"
	"net/netip"
	"strings"

	"example.invalid/dedicatedcloud/backend/internal/hypervisor"
)

// Operation steps of the network operations (hook names, like the provisioning steps).
const (
	StepNetworkDefined = "network-defined"
	StepNetworkStarted = "network-started"
	StepNetworkRemoved = "network-removed"
	StepReserved       = "ip-reserved"
	StepReleased       = "ip-released"
	StepComputeSet     = "compute-set"
)

// Operation-level limits of a VM's compute change. The API offers the host's own choice lists; these are the hard ceilings the helper enforces.
const MinMemoryMiB = 64

func netProof(ctx context.Context, ops HostOps, name, op string) (NetworkInfo, error) {
	if !netNameRE.MatchString(name) {
		return NetworkInfo{}, typed(hypervisor.Validation, op)
	}
	n, err := ops.LookupNetwork(ctx, name)
	if err != nil {
		return NetworkInfo{}, err
	}
	if !n.Managed {
		return NetworkInfo{}, typedWhy(hypervisor.Prohibited, op, "not a Svavyom-managed network")
	}
	return n, nil
}

// attached lists the domains whose first network interface uses the network (and which of them run).
func attached(ctx context.Context, ops HostOps, network string) (all, running []string, err error) {
	ds, err := ops.ListDomains(ctx)
	if err != nil {
		return nil, nil, err
	}
	for _, d := range ds {
		pd, perr := ParseDomain(d.XML)
		if perr != nil {
			return nil, nil, typed(hypervisor.HostError, "network") // a definition we cannot read could be attached: fail closed
		}
		if pd.Network == network {
			all = append(all, pd.Name)
			if d.Running {
				running = append(running, pd.Name)
			}
		}
	}
	return all, running, nil
}

func sameNetwork(n NetworkInfo, s NetworkSpec) bool {
	if s.HostBridge != "" {
		return n.Managed && n.UUID == s.UUID && n.Mode == "bridge" && n.Bridge == s.HostBridge && !n.Subnet.IsValid()
	}
	return n.Managed && n.UUID == s.UUID && n.Subnet.String() == s.Subnet && n.DHCPStart == s.DHCPStart && n.DHCPEnd == s.DHCPEnd && n.Mode == "nat" && n.Bridge == BridgeName(s.UUID)
}

// NetworkCreate defines, starts and turns on autostart for a managed NAT network. It refuses a name or bridge that is taken, a subnet that overlaps
// ANY other libvirt network (managed or not) or any prefix in avoid (the host's own interface subnets and routes: the confined mutation helper cannot
// see them, so the API reads them and passes them as extra refusals, and fails closed when it cannot read them). An interrupted create is finished by running it again with the same specification (same name and UUID); the same specification already complete is
// success. It never edits host interfaces or routes: libvirt creates the bridge itself.
func NetworkCreate(ctx context.Context, ops HostOps, cfg Config, s NetworkSpec, avoid []netip.Prefix, hook Hook) error {
	if hook == nil {
		hook = func(string) {}
	}
	if cfg.Validate() != nil || s.Validate() != nil || s.Name == cfg.Network {
		return typed(hypervisor.Validation, "network-create")
	}
	p, _ := ParseManagedSubnet(s.Subnet)
	nets, err := ops.ListNetworks(ctx)
	if err != nil {
		return err
	}
	var existing *NetworkInfo
	for i, n := range nets {
		switch {
		case n.Name == s.Name:
			if !sameNetwork(n, s) {
				return typedWhy(hypervisor.Conflict, "network-create", "a network of that name exists")
			}
			existing = &nets[i]
		case n.UUID == s.UUID:
			return typedWhy(hypervisor.Conflict, "network-create", "identity or bridge already used")
		case s.HostBridge != "" && n.Bridge == s.HostBridge:
			return typedWhy(hypervisor.Conflict, "network-create", "another libvirt network already uses that host bridge")
		case s.HostBridge == "" && n.Bridge == BridgeName(s.UUID):
			return typedWhy(hypervisor.Conflict, "network-create", "identity or bridge already used")
		}
	}
	if s.HostBridge != "" && existing == nil {
		x, xerr := NetworkXML(s)
		if xerr != nil {
			return typed(hypervisor.Validation, "network-create")
		}
		if err := ops.DefineNetwork(ctx, x); err != nil {
			return err
		}
	}
	if existing == nil && s.HostBridge == "" {
		for _, n := range nets {
			if n.Subnet.IsValid() && Overlaps(n.Subnet, p) {
				return typedWhy(hypervisor.Conflict, "network-create", "the subnet overlaps another libvirt network")
			}
		}
		for _, h := range avoid { // the host's own subnets and routes, as the caller (the API, which sees the host's network namespace) found them
			if Overlaps(h, p) {
				return typedWhy(hypervisor.Conflict, "network-create", "the subnet overlaps a host network or route")
			}
		}
		x, xerr := NetworkXML(s)
		if xerr != nil {
			return typed(hypervisor.Validation, "network-create")
		}
		if err := ops.DefineNetwork(ctx, x); err != nil {
			return err
		}
	}
	hook(StepNetworkDefined)
	n, err := netProof(ctx, ops, s.Name, "network-create")
	if err != nil || !sameNetwork(n, s) {
		if err == nil {
			err = typed(hypervisor.Conflict, "network-create")
		}
		return err
	}
	if !n.Active {
		if err := ops.StartNetwork(ctx, s.Name); err != nil {
			return err
		}
	}
	hook(StepNetworkStarted)
	if !n.Autostart {
		if err := ops.SetNetworkAutostart(ctx, s.Name, true); err != nil {
			return err
		}
	}
	return nil
}

// NetworkStart activates a managed network (already active is success).
func NetworkStart(ctx context.Context, ops HostOps, name string, hook Hook) error {
	n, err := netProof(ctx, ops, name, "network-start")
	if err != nil {
		return err
	}
	if !n.Active {
		if err := ops.StartNetwork(ctx, name); err != nil {
			return err
		}
	}
	if hook != nil {
		hook(StepNetworkStarted)
	}
	return nil
}

// NetworkStop deactivates a managed network, refusing while any attached VM runs (stopping it would cut that VM off). Already inactive is success.
func NetworkStop(ctx context.Context, ops HostOps, name string, hook Hook) error {
	n, err := netProof(ctx, ops, name, "network-stop")
	if err != nil {
		return err
	}
	if !n.Active {
		return nil
	}
	_, running, err := attached(ctx, ops, name)
	if err != nil {
		return err
	}
	if len(running) > 0 {
		return typedWhy(hypervisor.Conflict, "network-stop", "a VM attached to the network is running")
	}
	return ops.StopNetwork(ctx, name)
}

// NetworkAutostart turns autostart of a managed network on or off.
func NetworkAutostart(ctx context.Context, ops HostOps, name string, on bool) error {
	n, err := netProof(ctx, ops, name, "network-autostart")
	if err != nil {
		return err
	}
	if n.Autostart == on {
		return nil
	}
	return ops.SetNetworkAutostart(ctx, name, on)
}

// NetworkDelete removes a Svavyom-managed network that no VM is attached to: stop if active, then undefine. A network already gone is success
// (a repeat after an interruption). The host's pre-existing and default networks are not managed and are refused with `prohibited`.
func NetworkDelete(ctx context.Context, ops HostOps, name string, hook Hook) error {
	if !netNameRE.MatchString(name) {
		return typed(hypervisor.Validation, "network-delete")
	}
	n, err := ops.LookupNetwork(ctx, name)
	if isNotFound(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if !n.Managed {
		return typedWhy(hypervisor.Prohibited, "network-delete", "not a Svavyom-managed network")
	}
	all, _, err := attached(ctx, ops, name)
	if err != nil {
		return err
	}
	if len(all) > 0 {
		return typedWhy(hypervisor.Conflict, "network-delete", "a VM is attached to the network")
	}
	if n.Active {
		if err := ops.StopNetwork(ctx, name); err != nil {
			return err
		}
	}
	if err := ops.UndefineNetwork(ctx, name); err != nil && !isNotFound(err) {
		return err
	}
	if hook != nil {
		hook(StepNetworkRemoved)
	}
	return nil
}

// vmNet resolves the managed VM and the managed network it is attached to, and its derived MAC.
func vmNet(ctx context.Context, ops HostOps, vm, op string) (DomainInfo, NetworkInfo, string, error) {
	d, err := managed(ctx, ops, vm, op)
	if err != nil {
		return DomainInfo{}, NetworkInfo{}, "", err
	}
	pd, perr := ParseDomain(d.XML)
	if perr != nil || pd.MAC != MAC(d.UUID) || pd.Network == "" {
		return DomainInfo{}, NetworkInfo{}, "", typedWhy(hypervisor.Conflict, op, "the VM's network interface is not the one Svavyom defined")
	}
	n, err := netProof(ctx, ops, pd.Network, op)
	if err != nil {
		return DomainInfo{}, NetworkInfo{}, "", err
	}
	return d, n, pd.MAC, nil
}

// ReserveIP binds a fixed address to the VM's MAC on its managed network with a static DHCP reservation (the guest still uses DHCP; nothing is
// configured inside the guest). The address must be a host address of the network (not the network, gateway or broadcast address), unused by any
// other reservation or current lease, and the VM may hold only one reservation. A guest that ALREADY holds a lease keeps that address (libvirt's DHCP
// server does not move it); the reservation governs a later allocation, after the existing lease no longer controls the guest's address.
func ReserveIP(ctx context.Context, ops HostOps, vm, ip string, hook Hook) error {
	a, err := netip.ParseAddr(ip)
	if err != nil || !a.Is4() || a.String() != ip {
		return typed(hypervisor.Validation, "reserve-ip")
	}
	_, n, mac, err := vmNet(ctx, ops, vm, "reserve-ip")
	if err != nil {
		return err
	}
	if !n.Subnet.IsValid() || !UsableHost(n.Subnet, a) {
		return typedWhy(hypervisor.Validation, "reserve-ip", "not a usable host address of the network")
	}
	for _, h := range n.Hosts {
		switch {
		case h.MAC == mac && h.IP == ip:
			return nil // already reserved
		case h.MAC == mac:
			return typedWhy(hypervisor.Conflict, "reserve-ip", "the VM already holds another reservation: release it first")
		case h.IP == ip:
			return typedWhy(hypervisor.Conflict, "reserve-ip", "the address is reserved for another VM")
		}
	}
	leases, err := ops.NetworkLeases(ctx, n.Name)
	if err != nil {
		return err
	}
	for _, l := range leases {
		if l.IP == ip && strings.ToLower(l.MAC) != mac {
			return typedWhy(hypervisor.Conflict, "reserve-ip", "the address is leased to another machine")
		}
	}
	if err := ops.AddNetworkHost(ctx, n.Name, mac, ip); err != nil {
		return err
	}
	if hook != nil {
		hook(StepReserved)
	}
	return nil
}

// ReleaseIP removes the VM's static DHCP reservation (none is success).
func ReleaseIP(ctx context.Context, ops HostOps, vm string, hook Hook) error {
	_, n, mac, err := vmNet(ctx, ops, vm, "release-ip")
	if err != nil {
		return err
	}
	for _, h := range n.Hosts {
		if h.MAC == mac {
			if err := ops.RemoveNetworkHost(ctx, n.Name, h.MAC, h.IP); err != nil {
				return err
			}
			break
		}
	}
	if hook != nil {
		hook(StepReleased)
	}
	return nil
}

// Compute sets the persistent vCPU count and memory of a STOPPED Svavyom-managed VM. Disk size is a separate operation (Resize). Hot-plug is not
// offered. Idempotent: the same values are success.
func Compute(ctx context.Context, ops HostOps, name string, vcpus, memoryMiB int, hook Hook) error {
	if vcpus < 1 || vcpus > MaxVCPUs || memoryMiB < MinMemoryMiB || memoryMiB > MaxMemoryMiB || memoryMiB%MinMemoryMiB != 0 {
		return typed(hypervisor.Validation, "compute")
	}
	d, err := stopped(ctx, ops, name, "compute")
	if err != nil {
		return err
	}
	if d.VCPUs == vcpus && d.MemoryMiB == memoryMiB {
		return nil
	}
	if err := ops.SetDomainCompute(ctx, name, vcpus, memoryMiB); err != nil {
		return err
	}
	if hook != nil {
		hook(StepComputeSet)
	}
	return nil
}
