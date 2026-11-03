package auth

import (
	"errors"
	"testing"
	"time"
)

// A stranger who fails for a name locks only themselves out of it (DR-038, finding F-03). The old limiter blocked the name for everyone.
func TestAStrangersFailuresDoNotLockTheOwnerOut(t *testing.T) {
	r := newRig(t)
	r.bootstrap()
	const stranger, owner = "203.0.113.9", "198.51.100.7"
	for i := 0; i < failFree; i++ {
		if _, err := r.svc.SignIn(ctx, adminName, "wrong password here", stranger, ""); !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("attempt %d: %v", i, err)
		}
	}
	var rl *RateLimitedError
	if _, err := r.svc.SignIn(ctx, adminName, adminPass, stranger, ""); !errors.As(err, &rl) {
		t.Fatalf("the stranger must be blocked as the pair (admin, stranger): %v", err)
	}
	if _, err := r.svc.SignIn(ctx, adminName, adminPass, owner, ""); err != nil {
		t.Fatalf("the owner, from another address, must get in: %v", err)
	}
	// and a repeat of the same strangers' failures a long time later is a fresh start, not a permanent lock
	r.clk.add(maxBlock + time.Minute)
	if _, err := r.svc.SignIn(ctx, adminName, adminPass, stranger, ""); err != nil {
		t.Fatalf("after the block the pair recovers: %v", err)
	}
}

// One address spraying many names is blocked on its own, at a higher threshold; unrelated names and other addresses are not affected.
func TestASourceThatSpraysManyNamesIsBlockedAlone(t *testing.T) {
	r := newRig(t)
	r.bootstrap()
	const sprayer = "203.0.113.50"
	for i := 0; i < sourceFree; i++ {
		_, _ = r.svc.SignIn(ctx, "nobody"+itoa(i), "wrong password here", sprayer, "") // 20 different names, one failure each
	}
	var rl *RateLimitedError
	if _, err := r.svc.SignIn(ctx, adminName, adminPass, sprayer, ""); !errors.As(err, &rl) {
		t.Fatalf("the spraying address must be blocked even for a correct password: %v", err)
	}
	if _, err := r.svc.SignIn(ctx, adminName, adminPass, "198.51.100.7", ""); err != nil {
		t.Fatalf("another address is not affected: %v", err)
	}
}

// Fewer failures than the source threshold never block a source on its own (the pair threshold does that for one name).
func TestASourceBelowTheThresholdIsNotBlocked(t *testing.T) {
	clk := newClock()
	l := newLimiter(clk.now)
	for i := 0; i < sourceFree-1; i++ {
		l.failure("203.0.113.50", "name"+itoa(i))
	}
	if l.check("203.0.113.50", "someone") != 0 {
		t.Fatal("blocked below the threshold")
	}
	l.failure("203.0.113.50", "last")
	if l.check("203.0.113.50", "someone") == 0 {
		t.Fatal("not blocked at the threshold")
	}
}

// A name that failed recently, from anywhere, makes the next attempts on it wait, up to a cap, and never refuses by itself; a correct sign-in ends it.
func TestARecentlyFailedNameSlowsAttemptsButNeverRefusesACorrectOne(t *testing.T) {
	r := newRig(t)
	r.bootstrap()
	for i := 0; i < slowFree; i++ {
		_, _ = r.svc.SignIn(ctx, adminName, "wrong password here", "203.0.113.1"+itoa(i), "") // five different sources, one failure each
	}
	r.slept = nil
	if _, err := r.svc.SignIn(ctx, adminName, adminPass, "198.51.100.7", ""); err != nil {
		t.Fatalf("a correct sign-in is accepted after the wait: %v", err)
	}
	if len(r.slept) != 1 || r.slept[0] != slowStep || r.slept[0] > slowMax {
		t.Fatalf("the slow-down: %v", r.slept)
	}
	r.slept = nil
	if _, err := r.svc.SignIn(ctx, adminName, adminPass, "198.51.100.7", ""); err != nil || len(r.slept) != 0 {
		t.Fatalf("a sign-in clears the slow-down: %v %v", err, r.slept)
	}
	// the wait grows with the failures and is capped
	clk := newClock()
	l := newLimiter(clk.now)
	for i := 0; i < slowFree+20; i++ {
		l.failure("203.0.113."+itoa(i), "admin")
	}
	if d := l.slow("admin"); d != slowMax {
		t.Fatalf("the slow-down must be capped at %v, got %v", slowMax, d)
	}
	if l.slow("someone-else") != 0 {
		t.Fatal("another name is not slowed")
	}
	clk.t.Add(int64(forgetAge + time.Minute))
	if l.slow("admin") != 0 {
		t.Fatal("the slow-down must fade")
	}
}
