package console

import (
	"context"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// The graphical console path (DR-026 D1). The broker asks the hypervisor for a connection to the VM's VNC server (libvirt hands over a socket pair; the
// VNC server has no port) and, after an OK reply, copies bytes between that connection and the API without looking at them. The broker enforces what
// it can without understanding RFB: one viewer per VM, a lifetime, an idle limit and a byte-rate limit on what flows towards the VM.

func (b *Broker) takeViewer(vm string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.viewing[vm] {
		return false
	}
	b.viewing[vm] = true
	return true
}

func (b *Broker) releaseViewer(vm string) {
	b.mu.Lock()
	delete(b.viewing, vm)
	b.mu.Unlock()
}

func (b *Broker) graphics(conn net.Conn, q Request) {
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
	case !info.Managed || !info.Graphics:
		b.reply(conn, Reply{V: Version, Category: "prohibited"}) // never a console into a VM Svavyom does not own, or one without the device
		return
	case !info.Running:
		b.reply(conn, Reply{V: Version, Category: "conflict"})
		return
	}
	if !b.takeViewer(q.VM) {
		b.reply(conn, Reply{V: Version, Category: "conflict"}) // one viewer per VM
		return
	}
	defer b.releaseViewer(q.VM)
	octx, ocancel := context.WithTimeout(b.ctx, 10*time.Second)
	st, err := b.cfg.Source.OpenGraphics(octx, q.VM)
	ocancel()
	if err != nil {
		b.reply(conn, Reply{V: Version, Category: "unavailable"})
		return
	}
	defer st.Close()
	b.reply(conn, Reply{V: Version, OK: true, State: Available, Running: true})
	b.pipe(conn, st)
}

// pipe joins the API connection and the VNC stream until either side ends or a bound is reached.
func (b *Broker) pipe(conn net.Conn, st io.ReadWriteCloser) {
	var last atomic.Int64
	last.Store(time.Now().UnixNano())
	touch := func() { last.Store(time.Now().UnixNano()) }
	done := make(chan struct{})
	var once sync.Once
	stop := func() {
		once.Do(func() {
			close(done)
			_ = conn.Close()
			_ = st.Close()
		})
	}
	go func() { // VM -> API
		buf := make([]byte, 32<<10)
		for {
			n, err := st.Read(buf)
			if n > 0 {
				touch()
				_ = conn.SetWriteDeadline(time.Now().Add(15 * time.Second))
				if _, werr := conn.Write(buf[:n]); werr != nil {
					stop()
					return
				}
			}
			if err != nil {
				stop()
				return
			}
		}
	}()
	go func() { // API -> VM
		bk := newBucket(b.cfg.GraphicsInputPerSecond)
		buf := make([]byte, 16<<10)
		for {
			n, err := conn.Read(buf)
			if n > 0 {
				touch()
				bk.wait(n, b.closing)
				if _, werr := st.Write(buf[:n]); werr != nil {
					stop()
					return
				}
			}
			if err != nil {
				stop()
				return
			}
		}
	}()
	life := time.NewTimer(b.cfg.MaxLifetime)
	defer life.Stop()
	tick := time.NewTicker(min(b.cfg.IdleTimeout/4, 5*time.Second) + time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-done:
			return
		case <-life.C:
			stop()
		case <-b.closing:
			stop()
		case <-tick.C:
			if time.Since(time.Unix(0, last.Load())) > b.cfg.IdleTimeout {
				stop()
			}
		}
	}
}
