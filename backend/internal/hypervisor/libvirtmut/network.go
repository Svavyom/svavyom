//go:build libvirt

package libvirtmut

import (
	"context"
	"strings"

	libvirt "libvirt.org/go/libvirt"

	"example.invalid/dedicatedcloud/backend/internal/hypervisor"
	"example.invalid/dedicatedcloud/backend/internal/provision"
)

func (o *Ops) network(op, name string) (*libvirt.Network, error) {
	n, err := o.conn.LookupNetworkByName(name)
	if err != nil {
		return nil, mapErr(op, err)
	}
	return n, nil
}

func describeNetwork(n *libvirt.Network) (provision.NetworkInfo, error) {
	x, err := n.GetXMLDesc(0)
	if err != nil {
		return provision.NetworkInfo{}, mapErr("network", err)
	}
	active, err := n.IsActive()
	if err != nil {
		return provision.NetworkInfo{}, mapErr("network", err)
	}
	auto, err := n.GetAutostart()
	if err != nil {
		return provision.NetworkInfo{}, mapErr("network", err)
	}
	info, perr := provision.ParseNetwork(x, active, auto)
	if perr != nil {
		return provision.NetworkInfo{}, hypervisor.NewError(hypervisor.HostError, "network", "", "unreadable definition")
	}
	return info, nil
}

// ListNetworks implements provision.HostOps.
func (o *Ops) ListNetworks(ctx context.Context) ([]provision.NetworkInfo, error) {
	if err := ctxErr(ctx, "networks"); err != nil {
		return nil, err
	}
	nets, err := o.conn.ListAllNetworks(0)
	if err != nil {
		return nil, mapErr("networks", err)
	}
	out := make([]provision.NetworkInfo, 0, len(nets))
	for i := range nets {
		info, derr := describeNetwork(&nets[i])
		_ = nets[i].Free()
		if derr != nil {
			for j := i + 1; j < len(nets); j++ {
				_ = nets[j].Free()
			}
			return nil, derr
		}
		out = append(out, info)
	}
	return out, nil
}

// LookupNetwork implements provision.HostOps.
func (o *Ops) LookupNetwork(ctx context.Context, name string) (provision.NetworkInfo, error) {
	if err := ctxErr(ctx, "network"); err != nil {
		return provision.NetworkInfo{}, err
	}
	n, err := o.network("network", name)
	if err != nil {
		return provision.NetworkInfo{}, err
	}
	defer func() { _ = n.Free() }()
	return describeNetwork(n)
}

// DefineNetwork implements provision.HostOps.
func (o *Ops) DefineNetwork(ctx context.Context, x string) error {
	if err := ctxErr(ctx, "define-network"); err != nil {
		return err
	}
	n, err := o.conn.NetworkDefineXML(x)
	if err != nil {
		o.diag("define-network", err)
		return mapErr("define-network", err)
	}
	_ = n.Free()
	return nil
}

// StartNetwork implements provision.HostOps.
func (o *Ops) StartNetwork(ctx context.Context, name string) error {
	if err := ctxErr(ctx, "start-network"); err != nil {
		return err
	}
	n, err := o.network("start-network", name)
	if err != nil {
		return err
	}
	defer func() { _ = n.Free() }()
	if err := n.Create(); err != nil {
		o.diag("start-network", err)
		return mapErr("start-network", err)
	}
	return nil
}

// StopNetwork implements provision.HostOps.
func (o *Ops) StopNetwork(ctx context.Context, name string) error {
	if err := ctxErr(ctx, "stop-network"); err != nil {
		return err
	}
	n, err := o.network("stop-network", name)
	if err != nil {
		return err
	}
	defer func() { _ = n.Free() }()
	if err := n.Destroy(); err != nil {
		return mapErr("stop-network", err)
	}
	return nil
}

// SetNetworkAutostart implements provision.HostOps.
func (o *Ops) SetNetworkAutostart(ctx context.Context, name string, on bool) error {
	if err := ctxErr(ctx, "autostart"); err != nil {
		return err
	}
	n, err := o.network("autostart", name)
	if err != nil {
		return err
	}
	defer func() { _ = n.Free() }()
	if err := n.SetAutostart(on); err != nil {
		return mapErr("autostart", err)
	}
	return nil
}

// UndefineNetwork implements provision.HostOps.
func (o *Ops) UndefineNetwork(ctx context.Context, name string) error {
	if err := ctxErr(ctx, "undefine-network"); err != nil {
		return err
	}
	n, err := o.network("undefine-network", name)
	if err != nil {
		return err
	}
	defer func() { _ = n.Free() }()
	if err := n.Undefine(); err != nil {
		return mapErr("undefine-network", err)
	}
	return nil
}

func (o *Ops) updateHost(op, network string, cmd libvirt.NetworkUpdateCommand, mac, ip string) error {
	x, err := provision.HostEntryXML(mac, ip)
	if err != nil {
		return hypervisor.NewError(hypervisor.Validation, op, "", "bad entry")
	}
	n, err := o.network(op, network)
	if err != nil {
		return err
	}
	defer func() { _ = n.Free() }()
	flags := libvirt.NETWORK_UPDATE_AFFECT_CONFIG
	if active, aerr := n.IsActive(); aerr == nil && active {
		flags |= libvirt.NETWORK_UPDATE_AFFECT_LIVE
	}
	if err := n.Update(cmd, libvirt.NETWORK_SECTION_IP_DHCP_HOST, -1, x, flags); err != nil {
		o.diag(op, err)
		return mapErr(op, err)
	}
	return nil
}

// AddNetworkHost implements provision.HostOps (a static DHCP reservation, live and persistent).
func (o *Ops) AddNetworkHost(ctx context.Context, network, mac, ip string) error {
	if err := ctxErr(ctx, "add-host"); err != nil {
		return err
	}
	return o.updateHost("add-host", network, libvirt.NETWORK_UPDATE_COMMAND_ADD_LAST, mac, ip)
}

// RemoveNetworkHost implements provision.HostOps.
func (o *Ops) RemoveNetworkHost(ctx context.Context, network, mac, ip string) error {
	if err := ctxErr(ctx, "remove-host"); err != nil {
		return err
	}
	return o.updateHost("remove-host", network, libvirt.NETWORK_UPDATE_COMMAND_DELETE, mac, ip)
}

// NetworkLeases implements provision.HostOps.
func (o *Ops) NetworkLeases(ctx context.Context, network string) ([]provision.NetLease, error) {
	if err := ctxErr(ctx, "leases"); err != nil {
		return nil, err
	}
	n, err := o.network("leases", network)
	if err != nil {
		return nil, err
	}
	defer func() { _ = n.Free() }()
	ls, err := n.GetDHCPLeases()
	if err != nil {
		return nil, mapErr("leases", err)
	}
	out := make([]provision.NetLease, 0, len(ls))
	for _, l := range ls {
		if l.Type == libvirt.IP_ADDR_TYPE_IPV4 {
			out = append(out, provision.NetLease{MAC: strings.ToLower(l.Mac), IP: l.IPaddr, Expiry: l.ExpiryTime.Unix()})
		}
	}
	return out, nil
}

// ListDomains implements provision.HostOps.
func (o *Ops) ListDomains(ctx context.Context) ([]provision.DomainInfo, error) {
	if err := ctxErr(ctx, "domains"); err != nil {
		return nil, err
	}
	doms, err := o.conn.ListAllDomains(0)
	if err != nil {
		return nil, mapErr("domains", err)
	}
	out := make([]provision.DomainInfo, 0, len(doms))
	var first error
	for i := range doms {
		if first == nil {
			x, xerr := doms[i].GetXMLDesc(0)
			active, aerr := doms[i].IsActive()
			switch {
			case xerr != nil:
				first = mapErr("domains", xerr)
			case aerr != nil:
				first = mapErr("domains", aerr)
			default:
				pd, perr := provision.ParseDomain(x)
				if perr != nil {
					first = hypervisor.NewError(hypervisor.HostError, "domains", "", "unreadable definition")
				} else {
					out = append(out, provision.DomainInfo{Name: pd.Name, Data: pd.Data, Media: pd.Media, ISO: pd.ISO, ISOs: pd.ISOs, UUID: pd.UUID, Fingerprint: pd.Fingerprint, Managed: pd.Managed, Running: active, Root: pd.Root, Seed: pd.Seed, XML: x,
						VCPUs: pd.VCPUs, MemoryMiB: pd.MemoryMiB, ImageID: pd.ImageID})
				}
			}
		}
		_ = doms[i].Free()
	}
	if first != nil {
		return nil, first
	}
	return out, nil
}

// SetDomainCompute implements provision.HostOps: the persistent definition only (a stopped domain), maximum first so current never exceeds it.
func (o *Ops) SetDomainCompute(ctx context.Context, name string, vcpus, memoryMiB int) error {
	if err := ctxErr(ctx, "compute"); err != nil {
		return err
	}
	if vcpus < 1 || memoryMiB < 1 {
		return hypervisor.NewError(hypervisor.Validation, "compute", "", "bounds")
	}
	d, err := o.domain("compute", name)
	if err != nil {
		return err
	}
	defer func() { _ = d.Free() }()
	if active, aerr := d.IsActive(); aerr != nil || active {
		return hypervisor.NewError(hypervisor.Conflict, "compute", "", "running")
	}
	kib := uint64(memoryMiB) * 1024 // #nosec G115 -- memoryMiB is positive and bounded by the caller
	steps := []func() error{
		func() error {
			return d.SetVcpusFlags(uint(vcpus), libvirt.DOMAIN_VCPU_CONFIG|libvirt.DOMAIN_VCPU_MAXIMUM)
		}, // #nosec G115 -- bounded positive
		func() error { return d.SetVcpusFlags(uint(vcpus), libvirt.DOMAIN_VCPU_CONFIG) }, // #nosec G115 -- bounded positive
		func() error { return d.SetMemoryFlags(kib, libvirt.DOMAIN_MEM_CONFIG|libvirt.DOMAIN_MEM_MAXIMUM) },
		func() error { return d.SetMemoryFlags(kib, libvirt.DOMAIN_MEM_CONFIG) },
	}
	for _, s := range steps {
		if err := s(); err != nil {
			o.diag("compute", err)
			return mapErr("compute", err)
		}
	}
	return nil
}

var _ provision.HostOps = (*Ops)(nil)
