package console

import "sync"

// ring keeps the last cap bytes written to it.
type ring struct {
	mu    sync.Mutex
	buf   []byte
	cap   int
	total uint64 // bytes ever written (so a reader can tell truncation)
}

func newRing(cap int) *ring { return &ring{cap: cap} }

func (r *ring) write(p []byte) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.total += uint64(len(p))
	if len(p) >= r.cap {
		r.buf = append(r.buf[:0], p[len(p)-r.cap:]...)
		return
	}
	if over := len(r.buf) + len(p) - r.cap; over > 0 {
		r.buf = append(r.buf[:0], r.buf[over:]...)
	}
	r.buf = append(r.buf, p...)
}

// tail returns a copy of at most max bytes (all of them when max <= 0) and whether older bytes were dropped.
func (r *ring) tail(max int) ([]byte, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	b := r.buf
	if max > 0 && len(b) > max {
		b = b[len(b)-max:]
	}
	return append([]byte(nil), b...), uint64(len(b)) < r.total
}

func (r *ring) reset() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.buf, r.total = nil, 0
}
