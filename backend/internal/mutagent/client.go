package mutagent

import (
	"context"
	"net"
	"path/filepath"
	"time"

	"example.invalid/dedicatedcloud/backend/internal/hypervisor"
	"example.invalid/dedicatedcloud/backend/internal/provision"
)

// Client talks to the supervisor. Error semantics matter to the operation manager:
//   - failure to connect or to send the request: category Unavailable (nothing was delivered, retry is safe);
//   - anything that goes wrong after the request was sent (broken connection, deadline, bad reply): Timeout, the outcome of the
//     host action is UNKNOWN and must be reconciled by observation, never assumed.
type Client struct {
	path    string
	timeout time.Duration
}

// NewClient returns a client for the supervisor socket. The timeout bounds a whole call and should exceed the supervisor's
// helper deadline so that the supervisor, not the client, decides on a timeout.
func NewClient(path string, timeout time.Duration) (*Client, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || len(path) > 100 {
		return nil, hypervisor.NewError(hypervisor.Validation, "mutagent", "", "socket path must be a clean absolute path")
	}
	if timeout <= 0 || timeout > MaxDeadline+30*time.Second {
		timeout = DefaultDeadline + 15*time.Second
	}
	return &Client{path: path, timeout: timeout}, nil
}

func (c *Client) call(ctx context.Context, q Request) (Reply, error) {
	if err := ctx.Err(); err != nil {
		return Reply{}, hypervisor.NewError(hypervisor.Unavailable, "mutagent", "", "cancelled before sending")
	}
	timeout := c.timeout
	if LongOp(q.Op) {
		timeout = max(timeout, MaxDeadline+15*time.Second) // the supervisor, not the client, must be the one to decide on a timeout
	}
	deadline := time.Now().Add(timeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	dctx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	var dialer net.Dialer
	conn, err := dialer.DialContext(dctx, "unix", c.path)
	if err != nil {
		return Reply{}, hypervisor.NewError(hypervisor.Unavailable, "mutagent", "", "supervisor unreachable")
	}
	defer conn.Close()
	_ = conn.SetDeadline(deadline)
	q.V = Version
	if err := writeFrame(conn, q, MaxRequestBytes); err != nil {
		return Reply{}, hypervisor.NewError(hypervisor.Unavailable, "mutagent", "", "request not delivered")
	}
	var r Reply
	if err := readFrame(conn, &r, MaxReplyBytes); err != nil || r.V != Version {
		return Reply{}, hypervisor.NewError(hypervisor.Timeout, "mutagent", "", "outcome unknown")
	}
	if !r.OK {
		switch hypervisor.Category(r.Category) {
		case hypervisor.NotFound, hypervisor.Conflict, hypervisor.Validation, hypervisor.Prohibited, hypervisor.Timeout, hypervisor.Unavailable, hypervisor.HostError:
			return Reply{}, hypervisor.NewError(hypervisor.Category(r.Category), "mutagent", "", "mutation agent reported a failure")
		}
		return Reply{}, hypervisor.NewError(hypervisor.HostError, "mutagent", "", "mutation agent reported a failure")
	}
	return r, nil
}

// Preflight asks whether the configured network and pool are ready. It mutates nothing.
func (c *Client) Preflight(ctx context.Context) (provision.Readiness, error) {
	r, err := c.call(ctx, Request{Op: OpPreflight})
	if err != nil {
		return provision.Readiness{Network: "unknown", Pool: "unknown"}, err
	}
	if r.Preflight == nil {
		return provision.Readiness{Network: "unknown", Pool: "unknown"}, hypervisor.NewError(hypervisor.HostError, "mutagent", "", "bad reply")
	}
	ok := func(s string) bool { return s == "available" || s == "unavailable" || s == "unknown" }
	if !ok(r.Preflight.Network) || !ok(r.Preflight.Pool) {
		return provision.Readiness{Network: "unknown", Pool: "unknown"}, hypervisor.NewError(hypervisor.HostError, "mutagent", "", "bad reply")
	}
	return provision.Readiness{Network: r.Preflight.Network, Pool: r.Preflight.Pool}, nil
}

// Provision defines the VM described by spec (stopped).
func (c *Client) Provision(ctx context.Context, spec provision.Spec) error {
	if err := spec.ValidateAnyMedia(); err != nil {
		return hypervisor.NewError(hypervisor.Validation, "mutagent", "", "invalid specification")
	}
	_, err := c.call(ctx, Request{Op: OpProvision, Provision: &spec})
	return err
}

// Start boots the named Svavyom-managed VM.
func (c *Client) Start(ctx context.Context, name string) error {
	if !provision.VMNameRE.MatchString(name) {
		return hypervisor.NewError(hypervisor.Validation, "mutagent", "", "invalid name")
	}
	_, err := c.call(ctx, Request{Op: OpStart, Name: name})
	return err
}

// vm sends one of the name-only VM operations.
func (c *Client) vm(ctx context.Context, op, name string) error {
	if !provision.VMNameRE.MatchString(name) {
		return hypervisor.NewError(hypervisor.Validation, "mutagent", "", "invalid name")
	}
	_, err := c.call(ctx, Request{Op: op, Name: name})
	return err
}

// Stop asks the guest of the named Svavyom-managed VM to shut down (graceful; never forced).
func (c *Client) Stop(ctx context.Context, name string) error { return c.vm(ctx, OpStop, name) }

// Reboot asks the guest of the named running VM to reboot.
func (c *Client) Reboot(ctx context.Context, name string) error { return c.vm(ctx, OpReboot, name) }

// ForceOff powers the named VM off immediately. It deletes nothing.
func (c *Client) ForceOff(ctx context.Context, name string) error { return c.vm(ctx, OpForceOff, name) }

// Delete removes the named STOPPED Svavyom VM with its two volumes, after the helper proved ownership.
func (c *Client) Delete(ctx context.Context, name string) error { return c.vm(ctx, OpDelete, name) }

// Resize grows the named stopped VM's root volume to diskGiB.
func (c *Client) Resize(ctx context.Context, name string, diskGiB int) error {
	_, err := c.call(ctx, Request{Op: OpResize, Name: name, DiskGiB: diskGiB})
	return err
}

// EjectISO removes an installation medium of the named stopped VM: the one m names, or (m nil) the only one it has (DR-031).
func (c *Client) EjectISO(ctx context.Context, name string, m *Media) error {
	if m == nil {
		return c.vm(ctx, OpEjectISO, name)
	}
	_, err := c.call(ctx, Request{Op: OpEjectISO, Name: name, Media: m})
	return err
}

// GraphicsEnable gives the named stopped VM the graphical console devices; Unrescue puts a VM in rescue mode back.
func (c *Client) GraphicsEnable(ctx context.Context, name string) error {
	return c.vm(ctx, OpGraphicsEnable, name)
}
func (c *Client) Unrescue(ctx context.Context, name string) error { return c.vm(ctx, OpUnrescue, name) }

// ISOAttach attaches the catalog ISO to the named stopped VM; Rescue boots it from rescue media with its own disk kept.
func (c *Client) ISOAttach(ctx context.Context, name string, m Media) error {
	_, err := c.call(ctx, Request{Op: OpISOAttach, Name: name, Media: &m})
	return err
}

func (c *Client) Rescue(ctx context.Context, name string, m Media) error {
	_, err := c.call(ctx, Request{Op: OpRescue, Name: name, Media: &m})
	return err
}

// VolumeCreate creates the empty data volume name of diskGiB GiB.
func (c *Client) VolumeCreate(ctx context.Context, name string, diskGiB int) error {
	_, err := c.call(ctx, Request{Op: OpVolCreate, Name: name, DiskGiB: diskGiB})
	return err
}

// VolumeAttach attaches the data volume name to the named stopped VM.
func (c *Client) VolumeAttach(ctx context.Context, name, vm string) error {
	_, err := c.call(ctx, Request{Op: OpVolAttach, Name: name, VM: vm})
	return err
}

// VolumeDetach detaches the data volume name from the VM that carries it.
func (c *Client) VolumeDetach(ctx context.Context, name string) error {
	_, err := c.call(ctx, Request{Op: OpVolDetach, Name: name})
	return err
}

// VolumeDelete deletes the data volume name when no VM carries it.
func (c *Client) VolumeDelete(ctx context.Context, name string) error {
	_, err := c.call(ctx, Request{Op: OpVolDelete, Name: name})
	return err
}

// Snapshot takes snapshot id of the named stopped VM.
func (c *Client) Snapshot(ctx context.Context, name, id string) error {
	_, err := c.call(ctx, Request{Op: OpSnapshot, Name: name, ID: id})
	return err
}

// RestoreSnapshot returns the named stopped VM to snapshot id.
func (c *Client) RestoreSnapshot(ctx context.Context, name, id string) error {
	_, err := c.call(ctx, Request{Op: OpRestoreSnapshot, Name: name, ID: id})
	return err
}

// DeleteSnapshot removes snapshot id of the named VM.
func (c *Client) DeleteSnapshot(ctx context.Context, name, id string) error {
	_, err := c.call(ctx, Request{Op: OpDeleteSnapshot, Name: name, ID: id})
	return err
}

// Backup copies the named stopped VM's root overlay into the backup store as id.
func (c *Client) Backup(ctx context.Context, name, id string) error {
	_, err := c.call(ctx, Request{Op: OpBackup, Name: name, ID: id})
	return err
}

// DeleteBackup removes backup id from the store.
func (c *Client) DeleteBackup(ctx context.Context, id string) error {
	_, err := c.call(ctx, Request{Op: OpDeleteBackup, ID: id})
	return err
}

// Reinstall replaces the named stopped VM's root disk.
func (c *Client) Reinstall(ctx context.Context, name string, r Reinstall) error {
	_, err := c.call(ctx, Request{Op: OpReinstall, Name: name, Reinstall: &r})
	return err
}

// Restore creates the VM named name from backup id.
func (c *Client) Restore(ctx context.Context, name, id string, r Restore) error {
	_, err := c.call(ctx, Request{Op: OpRestore, Name: name, ID: id, Restore: &r})
	return err
}

// ListBackups returns the backups in the store (newest first, bounded).
func (c *Client) ListBackups(ctx context.Context) ([]BackupSummary, error) {
	r, err := c.call(ctx, Request{Op: OpListBackups})
	return r.Backups, err
}

// ListBackupsComplete returns every backup in the store (newest first) and whether the store holds more than the helper's complete-listing cap (truncated).
// Anything that decides from absence (the scheduler's retention) must refuse to act on a truncated list.
func (c *Client) ListBackupsComplete(ctx context.Context) ([]BackupSummary, bool, error) {
	r, err := c.call(ctx, Request{Op: OpListBackups, Full: true})
	return r.Backups, r.Truncated, err
}

// Stats returns the pool and backup-store facts.
func (c *Client) Stats(ctx context.Context) (Stats, error) {
	r, err := c.call(ctx, Request{Op: OpStats})
	if err != nil {
		return Stats{}, err
	}
	if r.Stats == nil {
		return Stats{}, hypervisor.NewError(hypervisor.HostError, "mutagent", "", "bad reply")
	}
	switch r.Stats.Snapshots {
	case "available", "unavailable", "unknown":
	case "":
		r.Stats.Snapshots = "unknown" // an older helper does not report it
	default:
		return Stats{}, hypervisor.NewError(hypervisor.HostError, "mutagent", "", "bad reply")
	}
	return *r.Stats, nil
}

// NetworkCreate defines, starts and turns on autostart for a managed NAT network. avoid are the host's own prefixes the API found.
func (c *Client) NetworkCreate(ctx context.Context, name string, n Net) error {
	_, err := c.call(ctx, Request{Op: OpNetCreate, Name: name, Net: &n})
	return err
}

// NetworkStart, NetworkStop and NetworkDelete act on a Svavyom-managed network.
func (c *Client) NetworkStart(ctx context.Context, name string) error {
	_, err := c.call(ctx, Request{Op: OpNetStart, Name: name})
	return err
}

func (c *Client) NetworkStop(ctx context.Context, name string) error {
	_, err := c.call(ctx, Request{Op: OpNetStop, Name: name})
	return err
}

func (c *Client) NetworkDelete(ctx context.Context, name string) error {
	_, err := c.call(ctx, Request{Op: OpNetDelete, Name: name})
	return err
}

// NetworkAutostart turns autostart of a managed network on ("on") or off ("off").
func (c *Client) NetworkAutostart(ctx context.Context, name, state string) error {
	_, err := c.call(ctx, Request{Op: OpNetAutostart, Name: name, Net: &Net{Autostart: state}})
	return err
}

// Compute sets the vCPU count and memory of the named stopped VM.
func (c *Client) Compute(ctx context.Context, name string, vcpus, memoryMiB int) error {
	_, err := c.call(ctx, Request{Op: OpCompute, Name: name, Net: &Net{VCPUs: vcpus, MemoryMiB: memoryMiB}})
	return err
}

// ReserveIP binds a static DHCP reservation for the named VM; ReleaseIP removes it.
func (c *Client) ReserveIP(ctx context.Context, name, ip string) error {
	_, err := c.call(ctx, Request{Op: OpReserveIP, Name: name, Net: &Net{IP: ip}})
	return err
}

func (c *Client) ReleaseIP(ctx context.Context, name string) error {
	_, err := c.call(ctx, Request{Op: OpReleaseIP, Name: name})
	return err
}
