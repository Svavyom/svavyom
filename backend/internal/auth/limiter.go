package auth

import (
	"sync"
	"time"
)

// limiter throttles failed sign-ins (DR-038). A block is keyed on the user AND the source together ("p:user|source"), so a stranger who fails five times for a
// name locks only themselves out of it, never the person who owns it; a source that fails many times across any names is blocked on its own ("s:source", at a higher
// threshold, so one address cannot spray a list of names); and a name that failed recently, from anywhere, makes the next attempts on it wait a little ("u:user":
// a slow-down that never refuses a correct sign-in by itself). Claimed usernames count whether or not they exist, so the behaviour leaks nothing about which
// exist. After the free failures a blocked key waits an exponentially growing time, capped. State is in memory and bounded: a restart clears every block, which
// only ever helps the legitimate user.
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
	failFree   = 5  // failures of one (user, source) pair before it is blocked
	sourceFree = 20 // failures of one source, across any names, before it is blocked
	slowFree   = 5  // failures of one name, from anywhere, before attempts on it start to wait
	slowStep   = 250 * time.Millisecond
	slowMax    = 2 * time.Second
	baseBlock  = 30 * time.Second
	maxBlock   = 15 * time.Minute
	forgetAge  = time.Hour
	maxEntries = 4096
)

func newLimiter(clock func() time.Time) *limiter {
	return &limiter{clock: clock, keys: map[string]*entry{}}
}

func pairKey(source, user string) string { return "p:" + user + "|" + source }
func sourceKey(source string) string     { return "s:" + source }
func userKey(user string) string         { return "u:" + user }

// free is how many failures a key forgives before it blocks; the user key never blocks (it only slows).
func free(key string) int {
	switch key[0] {
	case 'p':
		return failFree
	case 's':
		return sourceFree
	}
	return 0
}

func blockingKeys(source, user string) []string {
	k := []string{pairKey(source, user)}
	if source != "" {
		k = append(k, sourceKey(source))
	}
	return k
}

// check returns how long this (user, source) must wait before it may try again, or 0. Only the pair and the source can refuse.
func (l *limiter) check(source, user string) time.Duration {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.clock()
	var wait time.Duration
	for _, k := range blockingKeys(source, user) {
		if e := l.keys[k]; e != nil && e.until.After(now) {
			wait = max(wait, e.until.Sub(now))
		}
	}
	return wait
}

// slow returns how long an attempt on this name should wait because the name failed recently (from any source). It never refuses: a correct password is accepted
// after the wait.
func (l *limiter) slow(user string) time.Duration {
	l.mu.Lock()
	defer l.mu.Unlock()
	e := l.keys[userKey(user)]
	if e == nil || e.failures < slowFree || l.clock().Sub(e.touched) > forgetAge {
		return 0
	}
	return min(slowStep*time.Duration(e.failures-slowFree+1), slowMax)
}

func (l *limiter) failure(source, user string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.clock()
	for _, k := range append(blockingKeys(source, user), userKey(user)) {
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
		if f := free(k); f > 0 && e.failures >= f {
			block := baseBlock
			for i := f; i < e.failures && block < maxBlock; i++ {
				block *= 2
			}
			e.until = now.Add(min(block, maxBlock))
		}
	}
}

// success forgets what this (user, source) pair and this source did wrong, and the name's slow-down: the owner got in.
func (l *limiter) success(source, user string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, k := range append(blockingKeys(source, user), userKey(user)) {
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
