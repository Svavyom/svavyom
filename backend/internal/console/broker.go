package console

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"
)

// BrokerConfig is server-owned. The broker serves two requests on a Unix socket (mode 0660, peer-uid allowlist) and nothing else.
type BrokerConfig struct {
	Socket    string
	AllowUIDs []uint32
	Source    Source
	// ScanEvery is how often running VMs are looked up so their console output is captured from (nearly) the start of the boot.
	ScanEvery time.Duration
	// IdleTimeout ends an attachment without input or output; MaxLifetime ends any attachment. Both bound a console connection.
	IdleTimeout, MaxLifetime time.Duration
	// MaxConns bounds simultaneous connections (snapshot or attach).
	MaxConns int
	// InputPerSecond bounds keystroke bytes per second per attachment (a paste is slowed down, not refused).
	InputPerSecond int
	// GraphicsInputPerSecond bounds the bytes per second a viewer may send to the VM's VNC server (pointer and key events are tiny).
	GraphicsInputPerSecond int
}

func (c *BrokerConfig) defaults() {
	if c.ScanEvery <= 0 {
		c.ScanEvery = time.Second
	}
	if c.IdleTimeout <= 0 {
		c.IdleTimeout = 10 * time.Minute
	}
	if c.MaxLifetime <= 0 {
		c.MaxLifetime = time.Hour
	}
	if c.MaxConns <= 0 || c.MaxConns > 16 {
		c.MaxConns = 8
	}
	if c.InputPerSecond <= 0 {
		c.InputPerSecond = 16 << 10
	}
	if c.GraphicsInputPerSecond <= 0 {
		c.GraphicsInputPerSecond = 256 << 10
	}
}

const maxRings = 128

// Broker is the console broker.
type Broker struct {
	cfg  BrokerConfig
	ln   net.Listener
	uids map[uint32]bool
	sem  chan struct{}

	mu        sync.Mutex
	rings     map[string]*ring     // last output per VM (kept after the VM stops, until it starts again or is gone)
	order     []string             // ring insertion order, for eviction
	followers map[string]*follower // VMs whose console stream is currently open
	attached  map[string]bool      // VMs with an interactive attachment
	viewing   map[string]bool      // VMs with a graphical viewer
	closed    bool                 // set by Close under mu: no follower may be registered afterwards

	closing chan struct{}
	wg      sync.WaitGroup
	once    sync.Once
	ctx     context.Context
	cancel  context.CancelFunc
}

// follower reads one VM's console stream into its ring and hands the bytes to the attached client, if any.
type follower struct {
	vm     string
	stream io.ReadWriteCloser
	ring   *ring
	done   chan struct{}
	mu     sync.Mutex
	out    chan []byte // the attached client's queue; nil when nobody is attached
	wmu    sync.Mutex  // serialises writes to the stream
}

// NewBroker validates the configuration and binds the socket.
func NewBroker(cfg BrokerConfig) (*Broker, error) {
	cfg.defaults()
	if cfg.Source == nil {
		return nil, errors.New("console: a source is required")
	}
	if !filepath.IsAbs(cfg.Socket) || filepath.Clean(cfg.Socket) != cfg.Socket || len(cfg.Socket) > 100 {
		return nil, errors.New("console: socket path must be a clean absolute path of at most 100 bytes")
	}
	if len(cfg.AllowUIDs) == 0 {
		return nil, errors.New("console: at least one allowed uid is required")
	}
	if err := removeStale(cfg.Socket); err != nil {
		return nil, err
	}
	old := syscall.Umask(0o117)
	ln, err := net.Listen("unix", cfg.Socket)
	syscall.Umask(old)
	if err != nil {
		return nil, fmt.Errorf("console: listen: %w", err)
	}
	if err := os.Chmod(cfg.Socket, 0o660); err != nil { // #nosec G302 -- group access for the API user is the design
		_ = ln.Close()
		return nil, fmt.Errorf("console: chmod: %w", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	b := &Broker{cfg: cfg, ln: ln, uids: map[uint32]bool{}, sem: make(chan struct{}, cfg.MaxConns), rings: map[string]*ring{},
		followers: map[string]*follower{}, attached: map[string]bool{}, viewing: map[string]bool{}, closing: make(chan struct{}), ctx: ctx, cancel: cancel}
	for _, u := range cfg.AllowUIDs {
		b.uids[u] = true
	}
	return b, nil
}

func removeStale(path string) error {
	fi, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if fi.Mode()&os.ModeSocket == 0 {
		return errors.New("console: refusing to replace a non-socket file")
	}
	if c, err := net.DialTimeout("unix", path, time.Second); err == nil {
		_ = c.Close()
		return errors.New("console: another broker is already listening")
	}
	return os.Remove(path)
}

func peerUID(conn net.Conn) (uint32, bool) {
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		return 0, false
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return 0, false
	}
	var cred *syscall.Ucred
	var cerr error
	if err := raw.Control(func(fd uintptr) {
		cred, cerr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED) // #nosec G115 -- fd fits int
	}); err != nil || cerr != nil || cred == nil {
		return 0, false
	}
	return cred.Uid, true
}

// Serve runs the scanner and accepts connections until Close.
func (b *Broker) Serve() error {
	b.wg.Add(1)
	go func() { defer b.wg.Done(); b.scan() }()
	for {
		conn, err := b.ln.Accept()
		if err != nil {
			select {
			case <-b.closing:
				b.wg.Wait()
				return nil
			default:
				return err
			}
		}
		select {
		case b.sem <- struct{}{}:
		default:
			_ = conn.Close() // at capacity: refuse rather than queue
			continue
		}
		b.wg.Add(1)
		go func() {
			defer b.wg.Done()
			defer func() { <-b.sem }()
			b.handle(conn)
		}()
	}
}

// Close stops accepting, ends every follower and attachment, and returns when they are gone.
func (b *Broker) Close() {
	b.once.Do(func() {
		close(b.closing)
		b.cancel()
		_ = b.ln.Close()
		b.mu.Lock()
		b.closed = true
		for _, f := range b.followers {
			_ = f.stream.Close()
		}
		b.mu.Unlock()
	})
}

// scan keeps a follower open for every running, managed VM with a serial console.
func (b *Broker) scan() {
	t := time.NewTicker(b.cfg.ScanEvery)
	defer t.Stop()
	for {
		b.scanOnce()
		select {
		case <-b.closing:
			return
		case <-t.C:
		}
	}
}

func (b *Broker) scanOnce() {
	ctx, cancel := context.WithTimeout(b.ctx, 10*time.Second)
	defer cancel()
	names, err := b.cfg.Source.Running(ctx)
	if err != nil {
		return
	}
	for _, n := range names {
		if ValidVM(n) {
			_, _ = b.ensure(ctx, n)
		}
	}
}

// ensure returns the VM's follower, opening its console stream if it has none. A new run of the VM starts a fresh ring.
func (b *Broker) ensure(ctx context.Context, vm string) (*follower, error) {
	b.mu.Lock()
	if f, ok := b.followers[vm]; ok {
		b.mu.Unlock()
		return f, nil
	}
	b.mu.Unlock()
	st, err := b.cfg.Source.Open(ctx, vm)
	if err != nil {
		return nil, err
	}
	b.mu.Lock()
	if b.closed { // the broker is shutting down: a follower registered now would never be closed and Serve would wait for it forever
		b.mu.Unlock()
		_ = st.Close()
		return nil, errors.New("console: broker closed")
	}
	if f, ok := b.followers[vm]; ok { // lost a race: keep the first
		b.mu.Unlock()
		_ = st.Close()
		return f, nil
	}
	r := b.ringLocked(vm)
	r.reset()
	f := &follower{vm: vm, stream: st, ring: r, done: make(chan struct{})}
	b.followers[vm] = f
	b.mu.Unlock()
	b.wg.Add(1)
	go func() { defer b.wg.Done(); b.follow(f) }()
	return f, nil
}

func (b *Broker) ringLocked(vm string) *ring {
	if r, ok := b.rings[vm]; ok {
		return r
	}
	if len(b.order) >= maxRings {
		delete(b.rings, b.order[0])
		b.order = b.order[1:]
	}
	r := newRing(MaxSnapshot)
	b.rings[vm], b.order = r, append(b.order, vm)
	return r
}

func (b *Broker) forget(vm string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.rings, vm)
	for i, n := range b.order {
		if n == vm {
			b.order = append(b.order[:i], b.order[i+1:]...)
			break
		}
	}
}

func (b *Broker) follow(f *follower) {
	defer func() {
		_ = f.stream.Close()
		b.mu.Lock()
		delete(b.followers, f.vm)
		b.mu.Unlock()
		// done is closed BEFORE the attached client's queue: a client that sees its queue closed must be able to tell "the VM's console ended"
		// (done closed) from "I was too slow and was dropped" (done still open).
		close(f.done)
		f.mu.Lock()
		if f.out != nil {
			close(f.out)
			f.out = nil
		}
		f.mu.Unlock()
	}()
	buf := make([]byte, MaxChunk)
	for {
		n, err := f.stream.Read(buf)
		if n > 0 {
			chunk := append([]byte(nil), buf[:n]...)
			f.ring.write(chunk)
			f.mu.Lock()
			if f.out != nil {
				select {
				case f.out <- chunk:
				default: // the client cannot keep up: end it rather than buffer without bound
					close(f.out)
					f.out = nil
				}
			}
			f.mu.Unlock()
		}
		if err != nil {
			return
		}
	}
}

func (b *Broker) handle(conn net.Conn) {
	defer conn.Close()
	if uid, ok := peerUID(conn); !ok || !b.uids[uid] {
		return // silent
	}
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	var q Request
	if err := ReadFrame(conn, &q); err != nil || !q.Valid() {
		b.reply(conn, Reply{V: Version, Category: "validation"})
		return
	}
	_ = conn.SetReadDeadline(time.Time{})
	switch q.Op {
	case OpSnapshot:
		b.snapshot(conn, q)
	case OpAttach:
		b.attach(conn, q)
	case OpGraphics:
		b.graphics(conn, q)
	}
}

func (b *Broker) reply(conn net.Conn, r Reply) {
	_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	_ = WriteFrame(conn, r)
	_ = conn.SetWriteDeadline(time.Time{})
}

func (b *Broker) snapshot(conn net.Conn, q Request) {
	ctx, cancel := context.WithTimeout(b.ctx, 10*time.Second)
	defer cancel()
	info, err := b.cfg.Source.Check(ctx, q.VM)
	switch {
	case IsNotFound(err):
		b.forget(q.VM)
		b.reply(conn, Reply{V: Version, Category: "not_found"})
		return
	case err != nil:
		b.reply(conn, Reply{V: Version, OK: true, State: Unavailable})
		return
	case !info.Managed || !info.Configured:
		b.reply(conn, Reply{V: Version, OK: true, State: NotConfigured, Running: false})
		return
	}
	b.mu.Lock()
	r := b.rings[q.VM]
	b.mu.Unlock()
	max := q.Max
	if max <= 0 || max > MaxSnapshot {
		max = MaxSnapshot
	}
	rep := Reply{V: Version, OK: true, State: NoOutput, Running: info.Running}
	if r != nil {
		if tail, trunc := r.tail(max); len(tail) > 0 {
			rep.State, rep.Data, rep.Truncated = Available, Encode(tail), trunc
		}
	}
	b.reply(conn, rep)
}

// takeAttachment reserves the single interactive attachment of a VM.
func (b *Broker) takeAttachment(vm string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.attached[vm] {
		return false
	}
	b.attached[vm] = true
	return true
}

func (b *Broker) releaseAttachment(vm string) {
	b.mu.Lock()
	delete(b.attached, vm)
	b.mu.Unlock()
}

func (b *Broker) attach(conn net.Conn, q Request) {
	ctx, cancel := context.WithTimeout(b.ctx, 10*time.Second)
	info, err := b.cfg.Source.Check(ctx, q.VM)
	cancel()
	switch {
	case IsNotFound(err):
		b.reply(conn, Reply{V: Version, Category: "not_found"})
		return
	case err != nil:
		b.reply(conn, Reply{V: Version, Category: "unavailable"})
		return
	case !info.Managed || !info.Configured:
		b.reply(conn, Reply{V: Version, Category: "prohibited"}) // never a console into a VM Svavyom does not own
		return
	case !info.Running:
		b.reply(conn, Reply{V: Version, Category: "conflict"})
		return
	}
	if !b.takeAttachment(q.VM) {
		b.reply(conn, Reply{V: Version, Category: "conflict"}) // one console per VM
		return
	}
	defer b.releaseAttachment(q.VM)
	octx, ocancel := context.WithTimeout(b.ctx, 10*time.Second)
	f, err := b.ensure(octx, q.VM)
	ocancel()
	if err != nil {
		b.reply(conn, Reply{V: Version, Category: "unavailable"})
		return
	}
	// Subscribe and copy the buffer under one lock: no byte is lost or shown twice between the replay and the live feed.
	out := make(chan []byte, 256)
	f.mu.Lock()
	if f.out != nil {
		f.mu.Unlock()
		b.reply(conn, Reply{V: Version, Category: "conflict"})
		return
	}
	select {
	case <-f.done:
		f.mu.Unlock()
		b.reply(conn, Reply{V: Version, Category: "conflict"})
		return
	default:
	}
	f.out = out
	replay, _ := f.ring.tail(0)
	f.mu.Unlock()
	defer func() {
		f.mu.Lock()
		if f.out == out { // detach only our own queue
			f.out = nil
		}
		f.mu.Unlock()
	}()
	b.reply(conn, Reply{V: Version, OK: true, State: Available, Running: true})
	b.pump(conn, f, out, replay)
}

// pump moves bytes between the console stream and the API connection until either side ends or a bound is reached.
func (b *Broker) pump(conn net.Conn, f *follower, out <-chan []byte, replay []byte) {
	end := func(reason string) {
		_ = conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
		_ = WriteFrame(conn, Frame{T: FrameEnd, Reason: reason})
	}
	life := time.NewTimer(b.cfg.MaxLifetime)
	defer life.Stop()
	idle := time.NewTimer(b.cfg.IdleTimeout)
	defer idle.Stop()
	touch := func() {
		if !idle.Stop() {
			select {
			case <-idle.C:
			default:
			}
		}
		idle.Reset(b.cfg.IdleTimeout)
	}
	send := func(p []byte) error {
		for len(p) > 0 {
			n := min(len(p), MaxChunk)
			_ = conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if err := WriteFrame(conn, Frame{T: FrameOut, D: Encode(p[:n])}); err != nil {
				return err
			}
			p = p[n:]
		}
		return nil
	}
	if send(replay) != nil {
		return
	}
	in := make(chan Frame)
	go func() { // client -> broker
		defer close(in)
		for {
			var fr Frame
			if err := ReadFrame(conn, &fr); err != nil {
				return
			}
			select {
			case in <- fr:
			case <-b.closing:
				return
			}
		}
	}()
	bucket := newBucket(b.cfg.InputPerSecond)
	for {
		select {
		case chunk, ok := <-out:
			if !ok {
				select {
				case <-f.done:
					end(ReasonVMEnded)
				default:
					end(ReasonError)
				}
				return
			}
			touch()
			if send(chunk) != nil {
				return
			}
		case fr, ok := <-in:
			if !ok {
				return
			}
			switch fr.T {
			case FrameEnd:
				return
			case FrameIn:
				data, err := Decode(fr.D, MaxChunk)
				if err != nil {
					end(ReasonError)
					return
				}
				touch()
				bucket.wait(len(data), b.closing)
				f.wmu.Lock()
				_, werr := f.stream.Write(data)
				f.wmu.Unlock()
				if werr != nil {
					end(ReasonVMEnded)
					return
				}
			default:
				end(ReasonError)
				return
			}
		case <-idle.C:
			end(ReasonIdle)
			return
		case <-life.C:
			end(ReasonLifetime)
			return
		case <-f.done:
			end(ReasonVMEnded)
			return
		case <-b.closing:
			end(ReasonClosed)
			return
		}
	}
}

// bucket is a small byte-rate limiter: wait blocks until n bytes may be sent at the configured rate.
type bucket struct {
	rate   float64
	tokens float64
	last   time.Time
}

func newBucket(perSecond int) *bucket {
	return &bucket{rate: float64(perSecond), tokens: float64(perSecond), last: time.Now()}
}

func (k *bucket) wait(n int, stop <-chan struct{}) {
	for {
		now := time.Now()
		k.tokens = min(k.rate, k.tokens+now.Sub(k.last).Seconds()*k.rate)
		k.last = now
		if k.tokens >= float64(n) {
			k.tokens -= float64(n)
			return
		}
		d := time.Duration((float64(n) - k.tokens) / k.rate * float64(time.Second))
		select {
		case <-time.After(max(d, time.Millisecond)):
		case <-stop:
			return
		}
	}
}
