package offsite

import (
	"context"
	"errors"
	"net"
	"path/filepath"
	"time"
)

// Client is the API's end of the protocol.
type Client struct {
	socket string
}

// NewClient validates the socket path.
func NewClient(socket string) (*Client, error) {
	if !filepath.IsAbs(socket) || filepath.Clean(socket) != socket {
		return nil, errors.New("offsite: socket path must be a clean absolute path")
	}
	return &Client{socket: socket}, nil
}

func (c *Client) call(ctx context.Context, q Request) (Reply, error) {
	q.V = Version
	var d net.Dialer
	conn, err := d.DialContext(ctx, "unix", c.socket)
	if err != nil {
		return Reply{}, &Error{Category: "unavailable"}
	}
	defer conn.Close()
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	} else {
		_ = conn.SetDeadline(time.Now().Add(time.Minute))
	}
	// Honour cancellation while waiting for the (long) reply.
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	if err := writeFrame(conn, q); err != nil {
		return Reply{}, &Error{Category: "unavailable"}
	}
	var r Reply
	if err := readFrame(conn, &r); err != nil {
		if ctx.Err() != nil {
			return Reply{}, &Error{Category: "timeout"}
		}
		return Reply{}, &Error{Category: "unavailable"}
	}
	if r.V != Version {
		return Reply{}, &Error{Category: "host_error"}
	}
	if !r.OK {
		if !categoryOK.MatchString(r.Category) {
			return Reply{}, &Error{Category: "host_error"}
		}
		return Reply{}, &Error{Category: r.Category}
	}
	return r, nil
}

// Targets lists the declared targets and whether each is ready.
func (c *Client) Targets(ctx context.Context) ([]TargetState, error) {
	r, err := c.call(ctx, Request{Op: OpTargets})
	if err != nil {
		return nil, err
	}
	for _, t := range r.Targets {
		if t.ID == "" || (t.Kind != "ssh" && t.Kind != "path") || (t.State != "ready" && t.State != "unavailable") {
			return nil, &Error{Category: "host_error"}
		}
	}
	return r.Targets, nil
}

// Copies lists which targets hold a verified copy of which backup.
func (c *Client) Copies(ctx context.Context) (map[string][]string, error) {
	r, err := c.call(ctx, Request{Op: OpCopies})
	if err != nil {
		return nil, err
	}
	if len(r.Copies) > maxCopies {
		return nil, &Error{Category: "host_error"}
	}
	out := map[string][]string{}
	for _, cp := range r.Copies {
		out[cp.Backup] = cp.Targets
	}
	return out, nil
}

// Export copies backup to target and waits for the verified result.
func (c *Client) Export(ctx context.Context, backup, target string) error {
	_, err := c.call(ctx, Request{Op: OpExport, Backup: backup, Target: target})
	return err
}

// Prune removes the copy of backup that the service exported to target. Removing a copy that is already gone succeeds.
func (c *Client) Prune(ctx context.Context, backup, target string) error {
	_, err := c.call(ctx, Request{Op: OpPrune, Backup: backup, Target: target})
	return err
}
