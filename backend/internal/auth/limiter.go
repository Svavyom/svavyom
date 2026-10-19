package auth

import (
	"sync"
	"time"
)

// limiter throttles failed sign-ins by source address and by claimed username (existing or not, so the behaviour
// leaks nothing about which usernames exist). After failFree failures a key is blocked for an exponentially growing
// time, capped. State is in memory and bounded: a restart clears it, which only ever helps the legitimate user.
type limiter struct {
	mu    sync.Mutex
	clock func() time.Time
	keys  map[string]*entry
}

type entry struct {
	failures int
	until    time.Time
	touched  time.Time
}

const (
	failFree   = 5
	baseBlock  = 30 * time.Second
	maxBlock   = 15 * time.Minute
	forgetAge  = time.Hour
	maxEntries = 4096
)

func newLimiter(clock func() time.Time) *limiter {
	return &limiter{clock: clock, keys: map[string]*entry{}}
}

func keyed(source, user string) []string {
	k := []string{"u:" + user}
	if source != "" {
		k = append(k, "s:"+source)
	}
	return k
}

// check returns how long the caller must wait, or 0.
func (l *limiter) check(source, user string) time.Duration {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.clock()
	var wait time.Duration
	for _, k := range keyed(source, user) {
		if e := l.keys[k]; e != nil && e.until.After(now) {
			wait = max(wait, e.until.Sub(now))
		}
	}
	return wait
}

func (l *limiter) failure(source, user string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.clock()
	for _, k := range keyed(source, user) {
		e := l.keys[k]
		if e == nil {
			if len(l.keys) >= maxEntries {
				l.evict(now)
			}
			if len(l.keys) >= maxEntries {
				continue // every entry is currently blocked: never grow without bound, never drop a block
			}
			e = &entry{}
			l.keys[k] = e
		}
		e.failures++
		e.touched = now
		if e.failures >= failFree {
			block := baseBlock
			for i := failFree; i < e.failures && block < maxBlock; i++ {
				block *= 2
			}
			e.until = now.Add(min(block, maxBlock))
		}
	}
}

func (l *limiter) success(source, user string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, k := range keyed(source, user) {
		delete(l.keys, k)
	}
}

// evict frees room: first entries idle for an hour, then (if still full) the least recently touched entry that is not
// currently blocking anyone. A block is never evicted, so flooding with fresh names cannot lift a block.
func (l *limiter) evict(now time.Time) {
	for k, e := range l.keys {
		if now.Sub(e.touched) > forgetAge && !e.until.After(now) {
			delete(l.keys, k)
		}
	}
	if len(l.keys) < maxEntries {
		return
	}
	oldest, at := "", now
	for k, e := range l.keys {
		if !e.until.After(now) && !e.touched.After(at) {
			oldest, at = k, e.touched
		}
	}
	if oldest != "" {
		delete(l.keys, oldest)
	}
}
