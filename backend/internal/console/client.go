package console

import (
	"context"
	"errors"
	"net"
	"path/filepath"
	"sync"
	"time"
)

// Error is a failure reported by the broker (or by reaching it). Category is the closed vocabulary of Reply.Category, plus
// "unavailable" when the broker could not be reached at all.
type Error struct{ Category string }

func (e *Error) Error() string { return "console: " + e.Category }

// CategoryOf returns the category of err, or "" for other errors.
func CategoryOf(err error) string {
	var e *Error
	if errors.As(err, &e) {
		return e.Category
	}
	return ""
}

// Client talks to the broker over its Unix socket. It holds no connection between calls.
type Client struct {
	path    string
	timeout time.Duration
}

// NewClient returns a client for the broker socket.
func NewClient(path string, timeout time.Duration) (*Client, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || len(path) > 100 {
		return nil, errors.New("console: socket path must be a clean absolute path of at most 100 bytes")
	}
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	return &Client{path: path, timeout: timeout}, nil
}

func (c *Client) open(ctx context.Context, q Request) (net.Conn, Reply, error) {
	dctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	var d net.Dialer
	conn, err := d.DialContext(dctx, "unix", c.path)
	if err != nil {
		return nil, Reply{}, &Error{Category: "unavailable"}
	}
	_ = conn.SetDeadline(time.Now().Add(c.timeout))
	q.V = Version
	if err := WriteFrame(conn, q); err != nil {
		_ = conn.Close()
		return nil, Reply{}, &Error{Category: "unavailable"}
	}
	var rep Reply
	if err := ReadFrame(conn, &rep); err != nil || rep.V != Version {
		_ = conn.Close()
		return nil, Reply{}, &Error{Category: "unavailable"}
	}
	if !rep.OK {
		_ = conn.Close()
		switch rep.Category {
		case "not_found", "conflict", "prohibited", "unavailable", "validation":
			return nil, rep, &Error{Category: rep.Category}
		}
		return nil, rep, &Error{Category: "unavailable"}
	}
	_ = conn.SetDeadline(time.Time{})
	return conn, rep, nil
}

// Snapshot returns the typed console state of a VM and the tail of its serial output (at most max bytes; <= 0 selects the broker's
// maximum).
func (c *Client) Snapshot(ctx context.Context, vm string, max int) (Reply, []byte, error) {
	conn, rep, err := c.open(ctx, Request{Op: OpSnapshot, VM: vm, Max: max})
	if err != nil {
		return rep, nil, err
	}
	_ = conn.Close()
	var data []byte
	if rep.Data != "" {
		if data, err = Decode(rep.Data, MaxSnapshot); err != nil {
			return rep, nil, &Error{Category: "unavailable"}
		}
	}
	return rep, data, nil
}

// Attachment is the API's end of an interactive console connection.
type Attachment struct {
	conn net.Conn
	wmu  sync.Mutex
	once sync.Once
}

// Attach opens the (single) interactive attachment to a VM's console.
func (c *Client) Attach(ctx context.Context, vm string) (*Attachment, error) {
	conn, _, err := c.open(ctx, Request{Op: OpAttach, VM: vm})
	if err != nil {
		return nil, err
	}
	return &Attachment{conn: conn}, nil
}

// Recv returns the next frame from the broker (output or end). It blocks; Close unblocks it.
func (a *Attachment) Recv() (Frame, error) {
	var f Frame
	if err := ReadFrame(a.conn, &f); err != nil {
		return Frame{}, err
	}
	return f, nil
}

// Send forwards keystrokes (split into frames of at most MaxChunk bytes).
func (a *Attachment) Send(p []byte) error {
	a.wmu.Lock()
	defer a.wmu.Unlock()
	for len(p) > 0 {
		n := min(len(p), MaxChunk)
		_ = a.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
		if err := WriteFrame(a.conn, Frame{T: FrameIn, D: Encode(p[:n])}); err != nil {
			return err
		}
		p = p[n:]
	}
	return nil
}

// Close ends the attachment (telling the broker first, best effort).
func (a *Attachment) Close() {
	a.once.Do(func() {
		a.wmu.Lock()
		_ = a.conn.SetWriteDeadline(time.Now().Add(time.Second))
		_ = WriteFrame(a.conn, Frame{T: FrameEnd, Reason: ReasonClosed})
		a.wmu.Unlock()
		_ = a.conn.Close()
	})
}

// Graphics opens the VM's graphical console: the returned connection carries the raw RFB (VNC) stream until it is closed. The broker allows one viewer
// per VM.
func (c *Client) Graphics(ctx context.Context, vm string) (net.Conn, error) {
	conn, _, err := c.open(ctx, Request{Op: OpGraphics, VM: vm})
	if err != nil {
		return nil, err
	}
	return conn, nil
}
