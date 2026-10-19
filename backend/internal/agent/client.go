package agent

import (
	"context"
	"net"
	"path/filepath"
	"time"

	"example.invalid/dedicatedcloud/backend/internal/hypervisor"
)

// Client implements hypervisor.Reader over the agent's Unix socket. Each call uses a fresh connection and a deadline.
type Client struct {
	path    string
	timeout time.Duration
}

var _ hypervisor.Reader = (*Client)(nil)

// NewClient returns a client for the socket at path (clean absolute path).
func NewClient(path string, timeout time.Duration) (*Client, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || len(path) > 100 {
		return nil, hypervisor.NewError(hypervisor.Validation, "agent", "", "socket path must be a clean absolute path")
	}
	if timeout <= 0 || timeout > 30*time.Second {
		timeout = 5 * time.Second
	}
	return &Client{path: path, timeout: timeout}, nil
}

func (c *Client) call(ctx context.Context, q Request) (Reply, error) {
	if err := ctx.Err(); err != nil {
		return Reply{}, hypervisor.NewError(hypervisor.Timeout, "agent", "", "cancelled")
	}
	deadline := time.Now().Add(c.timeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	var dialer net.Dialer
	dctx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	conn, err := dialer.DialContext(dctx, "unix", c.path)
	if err != nil {
		return Reply{}, hypervisor.NewError(hypervisor.Unavailable, "agent", "", "agent unreachable")
	}
	defer conn.Close()
	_ = conn.SetDeadline(deadline)
	q.V = Version
	if err := writeFrame(conn, q, MaxRequestBytes); err != nil {
		return Reply{}, hypervisor.NewError(hypervisor.Unavailable, "agent", "", "agent unreachable")
	}
	var r Reply
	if err := readFrame(conn, &r, MaxReplyBytes); err != nil || r.V != Version {
		return Reply{}, hypervisor.NewError(hypervisor.Unavailable, "agent", "", "bad agent reply")
	}
	if !r.OK {
		switch hypervisor.Category(r.Category) {
		case hypervisor.NotFound, hypervisor.Unavailable, hypervisor.Timeout, hypervisor.Validation:
			return Reply{}, hypervisor.NewError(hypervisor.Category(r.Category), "agent", "", "agent reported a failure")
		}
		return Reply{}, hypervisor.NewError(hypervisor.HostError, "agent", "", "agent reported a failure")
	}
	return r, nil
}

func fromWire(w Domain) (hypervisor.Domain, bool) {
	if !nameRE.MatchString(w.Name) || !powers[hypervisor.State(w.Power)] || !validDetails(w) {
		return hypervisor.Domain{}, false
	}
	d := hypervisor.Domain{Name: w.Name, State: hypervisor.State(w.Power), VCPUs: w.VCPUs, MemoryMiB: w.MemoryMiB, UUID: w.UUID, Managed: w.Managed,
		Fingerprint: w.Fingerprint, ImageID: w.ImageID, IPv4: w.IP, DiskBytes: w.DiskBytes, Network: w.Network, MAC: w.MAC, CPUTimeNs: w.CPUTimeNs,
		MemUsedMiB: w.MemUsedMiB, DiskIOBytes: w.DiskIOBytes, NetIOBytes: w.NetIOBytes, DataVolumes: w.DataVolumes, Media: w.Media, ISOSHA256: w.ISOSHA256, Graphics: w.Graphics, RescueSHA256: w.RescueSHA256}
	for _, sn := range w.Snapshots {
		d.Snapshots = append(d.Snapshots, hypervisor.Snapshot{ID: sn.ID, Created: sn.Created})
	}
	return d, true
}

// Lookup implements hypervisor.Reader.
func (c *Client) Lookup(ctx context.Context, name string) (hypervisor.Domain, error) {
	if !nameRE.MatchString(name) {
		return hypervisor.Domain{}, hypervisor.NewError(hypervisor.NotFound, "lookup", "", "no such domain")
	}
	r, err := c.call(ctx, Request{Op: OpLookup, Name: name})
	if err != nil {
		return hypervisor.Domain{}, err
	}
	if len(r.Domains) != 1 || r.Domains[0].Name != name {
		return hypervisor.Domain{}, hypervisor.NewError(hypervisor.HostError, "lookup", "", "bad agent reply")
	}
	d, ok := fromWire(r.Domains[0])
	if !ok {
		return hypervisor.Domain{}, hypervisor.NewError(hypervisor.HostError, "lookup", "", "bad agent reply")
	}
	return d, nil
}

// List implements hypervisor.Reader.
func (c *Client) List(ctx context.Context) ([]hypervisor.Domain, error) {
	r, err := c.call(ctx, Request{Op: OpList})
	if err != nil {
		return nil, err
	}
	if len(r.Domains) > MaxDomains {
		return nil, hypervisor.NewError(hypervisor.HostError, "list", "", "bad agent reply")
	}
	out := make([]hypervisor.Domain, 0, len(r.Domains))
	for _, w := range r.Domains {
		d, ok := fromWire(w)
		if !ok {
			return nil, hypervisor.NewError(hypervisor.HostError, "list", "", "bad agent reply")
		}
		out = append(out, d)
	}
	return out, nil
}

var _ hypervisor.NetworkReader = (*Client)(nil)

// Networks implements hypervisor.NetworkReader.
func (c *Client) Networks(ctx context.Context) ([]hypervisor.Network, error) {
	r, err := c.call(ctx, Request{Op: OpNetworks})
	if err != nil {
		return nil, err
	}
	if len(r.Networks) > MaxNetworks {
		return nil, hypervisor.NewError(hypervisor.HostError, "networks", "", "bad agent reply")
	}
	out := make([]hypervisor.Network, 0, len(r.Networks))
	for _, w := range r.Networks {
		if !validNet(w) {
			return nil, hypervisor.NewError(hypervisor.HostError, "networks", "", "bad agent reply")
		}
		n := hypervisor.Network{Name: w.Name, UUID: w.UUID, Managed: w.Managed, Active: w.Active, Autostart: w.Autostart, Mode: w.Mode, Bridge: w.Bridge, Subnet: w.Subnet,
			Gateway: w.Gateway, DHCPStart: w.DHCPStart, DHCPEnd: w.DHCPEnd, AttachedVMs: w.Attached}
		for _, x := range w.Reservations {
			n.Reservations = append(n.Reservations, hypervisor.Reservation{MAC: x.MAC, IP: x.IP})
		}
		out = append(out, n)
	}
	return out, nil
}

var _ hypervisor.DataVolumeReader = (*Client)(nil)

// DataVolumes implements hypervisor.DataVolumeReader.
func (c *Client) DataVolumes(ctx context.Context) ([]hypervisor.DataVolume, error) {
	r, err := c.call(ctx, Request{Op: OpVolumes})
	if err != nil {
		return nil, err
	}
	if len(r.Volumes) > MaxVolumes {
		return nil, hypervisor.NewError(hypervisor.HostError, "volumes", "", "bad agent reply")
	}
	out := make([]hypervisor.DataVolume, 0, len(r.Volumes))
	for _, w := range r.Volumes {
		if !validVol(w) {
			return nil, hypervisor.NewError(hypervisor.HostError, "volumes", "", "bad agent reply")
		}
		out = append(out, hypervisor.DataVolume{Name: w.Name, CapacityBytes: w.Capacity})
	}
	return out, nil
}
