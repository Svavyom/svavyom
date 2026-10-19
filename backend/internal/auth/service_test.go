package auth

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"example.invalid/dedicatedcloud/backend/internal/sqlitedb"
)

const (
	adminName = "admin"
	adminPass = "correct horse battery"
)

type clock struct{ t atomic.Int64 }

func newClock() *clock {
	c := &clock{}
	c.t.Store(time.Date(2026, 10, 9, 8, 0, 0, 0, time.UTC).UnixNano())
	return c
}
func (c *clock) now() time.Time      { return time.Unix(0, c.t.Load()).UTC() }
func (c *clock) add(d time.Duration) { c.t.Add(int64(d)) }

type rig struct {
	t    *testing.T
	path string
	db   *sql.DB
	clk  *clock
	svc  *Service
}

func newRig(t *testing.T) *rig {
	t.Helper()
	r := &rig{t: t, path: filepath.Join(t.TempDir(), "svavyom.db"), clk: newClock()}
	r.open()
	return r
}

// open (re)opens the database and the service, which is how a process restart is simulated.
func (r *rig) open() {
	r.t.Helper()
	if r.db != nil {
		_ = r.db.Close()
	}
	db, err := sqlitedb.Open(r.path)
	if err != nil {
		r.t.Fatal(err)
	}
	r.t.Cleanup(func() { _ = db.Close() })
	svc, err := New(context.Background(), db, Config{Params: fast, Clock: r.clk.now, IdleTimeout: 30 * time.Minute, AbsoluteTimeout: 12 * time.Hour})
	if err != nil {
		r.t.Fatal(err)
	}
	r.db, r.svc = db, svc
}

func (r *rig) bootstrap() {
	r.t.Helper()
	if err := r.svc.Bootstrap(context.Background(), adminName, adminPass); err != nil {
		r.t.Fatal(err)
	}
}

func (r *rig) signIn() SignInResult {
	r.t.Helper()
	res, err := r.svc.SignIn(context.Background(), adminName, adminPass, "198.51.100.7", "")
	if err != nil {
		r.t.Fatal(err)
	}
	return res
}

var ctx = context.Background()

// ---- bootstrap ---------------------------------------------------------------------------------------------------

func TestBootstrapOnceThenFailsSafely(t *testing.T) {
	r := newRig(t)
	if ok, _ := r.svc.Configured(ctx); ok {
		t.Fatal("configured before bootstrap")
	}
	r.bootstrap()
	if ok, _ := r.svc.Configured(ctx); !ok {
		t.Fatal("not configured after bootstrap")
	}
	if err := r.svc.Bootstrap(ctx, "other", "another long password"); !errors.Is(err, ErrAlreadyBootstrapped) {
		t.Fatalf("replay: %v", err)
	}
	// The original credential is untouched by the replay.
	if _, err := r.svc.SignIn(ctx, adminName, adminPass, "", ""); err != nil {
		t.Fatalf("original credential no longer works: %v", err)
	}
	if _, err := r.svc.SignIn(ctx, "other", "another long password", "", ""); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("replayed credential works: %v", err)
	}
}

func TestBootstrapRejectsBadInput(t *testing.T) {
	r := newRig(t)
	for _, u := range []string{"", "a", "Admin", "ad min", "1admin", strings.Repeat("a", 33), "ad;min", "admin\n"} {
		if err := r.svc.Bootstrap(ctx, u, adminPass); !errors.Is(err, ErrBadUsername) {
			t.Errorf("username %q accepted: %v", u, err)
		}
	}
	for _, p := range []string{"", "short", "aaaaaaaaaaaaaaaa", "admin"} {
		if err := r.svc.Bootstrap(ctx, adminName, p); !errors.Is(err, ErrPasswordPolicy) {
			t.Errorf("password %q accepted: %v", p, err)
		}
	}
	if ok, _ := r.svc.Configured(ctx); ok {
		t.Fatal("a rejected bootstrap created an administrator")
	}
}

func TestConcurrentBootstrapExactlyOneWinner(t *testing.T) {
	r := newRig(t)
	var wins, already atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			switch err := r.svc.Bootstrap(ctx, adminName, adminPass+strings.Repeat("x", i)); {
			case err == nil:
				wins.Add(1)
			case errors.Is(err, ErrAlreadyBootstrapped):
				already.Add(1)
			default:
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if wins.Load() != 1 || already.Load() != 7 {
		t.Fatalf("wins=%d already=%d", wins.Load(), already.Load())
	}
	var n int
	_ = r.db.QueryRow(`SELECT count(*) FROM users`).Scan(&n)
	if n != 1 {
		t.Fatalf("%d administrators", n)
	}
}

func TestBootstrapStoresOnlyAHash(t *testing.T) {
	r := newRig(t)
	r.bootstrap()
	var phc string
	_ = r.db.QueryRow(`SELECT password_phc FROM users`).Scan(&phc)
	if strings.Contains(phc, adminPass) || !strings.HasPrefix(phc, "$argon2id$") {
		t.Fatalf("stored credential: %q", phc)
	}
}

// ---- sign-in -------------------------------------------------------------------------------------------------------

func TestSignInFailuresAreIndistinguishable(t *testing.T) {
	r := newRig(t)
	r.bootstrap()
	_, errWrong := r.svc.SignIn(ctx, adminName, "wrong password here", "203.0.113.1", "")
	_, errUnknown := r.svc.SignIn(ctx, "nobody", adminPass, "203.0.113.2", "")
	_, errEmpty := r.svc.SignIn(ctx, "", "", "203.0.113.3", "")
	for name, err := range map[string]error{"wrong": errWrong, "unknown": errUnknown, "empty": errEmpty} {
		if !errors.Is(err, ErrInvalidCredentials) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if errWrong != errUnknown {
		t.Fatal("different errors for wrong password and unknown user")
	}
}

func TestSignInBeforeBootstrapIsGenericFailure(t *testing.T) {
	r := newRig(t)
	if _, err := r.svc.SignIn(ctx, adminName, adminPass, "", ""); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("got %v", err)
	}
}

func TestUnknownAndWrongPasswordCostTheSame(t *testing.T) {
	// Timing-sensitive behaviour, as far as a unit test can say it: both paths run exactly one Argon2id computation,
	// so their durations are of the same order. A path that skipped the hash would be orders of magnitude faster.
	r := newRig(t)
	r.bootstrap()
	timeit := func(user string) time.Duration {
		best := time.Hour
		for i := 0; i < 5; i++ {
			start := time.Now()
			_, _ = r.svc.SignIn(ctx, user, "wrong password here", "", "")
			best = min(best, time.Since(start))
			r.svc.lim.success("", user) // keep the throttle out of the measurement
		}
		return best
	}
	known, unknown := timeit(adminName), timeit("nobody")
	ratio := float64(known) / float64(unknown)
	t.Logf("wrong-password %v, unknown-user %v (ratio %.2f)", known, unknown, ratio)
	if ratio < 0.25 || ratio > 4 {
		t.Fatalf("timing differs too much: %v vs %v", known, unknown)
	}
	if unknown < 3*time.Millisecond {
		t.Fatalf("unknown-user path did no hashing (%v)", unknown)
	}
}

func TestOverlongPasswordIsBoundedNotRejectedByTiming(t *testing.T) {
	r := newRig(t)
	r.bootstrap()
	start := time.Now()
	_, err := r.svc.SignIn(ctx, adminName, strings.Repeat("A", 10<<20), "", "")
	if !errors.Is(err, ErrInvalidCredentials) || time.Since(start) > 2*time.Second {
		t.Fatalf("%v after %v", err, time.Since(start))
	}
}

func TestCorruptedCredentialRowFailsClosed(t *testing.T) {
	r := newRig(t)
	r.bootstrap()
	for _, bad := range []string{"", "plaintext-password", "$argon2id$v=19$m=4294967295,t=2,p=1$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"} {
		if _, err := r.db.Exec(`UPDATE users SET password_phc = ?`, bad); err != nil {
			t.Fatal(err)
		}
		start := time.Now()
		_, err := r.svc.SignIn(ctx, adminName, adminPass, "", "")
		if !errors.Is(err, ErrInvalidCredentials) {
			t.Errorf("%q: %v", bad, err)
		}
		if time.Since(start) > time.Second {
			t.Errorf("%q: took %v", bad, time.Since(start))
		}
		r.svc.lim.success("", adminName)
	}
	evs, _ := r.svc.Audit(ctx)
	found := false
	for _, e := range evs {
		found = found || e.Reason == "credential_corrupt"
	}
	if !found {
		t.Fatal("corruption is not visible in the audit log")
	}
}

func TestPasswordIsRehashedToTheCurrentBaseline(t *testing.T) {
	r := newRig(t)
	weak := Params{MemoryKiB: 19 * 1024, Time: 2, Threads: 1, SaltLen: 16, KeyLen: 32}
	phc, _ := HashPassword(adminPass, weak)
	r.bootstrap()
	_, _ = r.db.Exec(`UPDATE users SET password_phc = ?`, phc)
	stronger := Params{MemoryKiB: 20 * 1024, Time: 2, Threads: 1, SaltLen: 16, KeyLen: 32}
	svc, err := New(ctx, r.db, Config{Params: stronger, Clock: r.clk.now})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.SignIn(ctx, adminName, adminPass, "", ""); err != nil {
		t.Fatal(err)
	}
	var now string
	_ = r.db.QueryRow(`SELECT password_phc FROM users`).Scan(&now)
	if !strings.Contains(now, "m=20480,") {
		t.Fatalf("not upgraded: %s", now)
	}
}

// ---- sessions ------------------------------------------------------------------------------------------------------

func TestSessionLifecycleValidMissingMalformedForged(t *testing.T) {
	r := newRig(t)
	r.bootstrap()
	res := r.signIn()
	if !ValidTokenFormat(res.SessionToken) || !ValidTokenFormat(res.CSRFToken) || res.SessionToken == res.CSRFToken {
		t.Fatal("token format")
	}
	sess, err := r.svc.Authenticate(ctx, res.SessionToken)
	if err != nil || sess.Username != adminName {
		t.Fatalf("valid session: %+v %v", sess, err)
	}
	for name, tok := range map[string]string{
		"missing": "", "short": "abc", "long": strings.Repeat("a", 44), "bad alphabet": strings.Repeat("!", 43),
		"padding": strings.Repeat("a", 42) + "=", "null byte": strings.Repeat("a", 42) + "\x00", "sql": "' OR 1=1 --" + strings.Repeat("a", 32),
		"forged": strings.Repeat("A", 43), "csrf as session": res.CSRFToken,
	} {
		if _, err := r.svc.Authenticate(ctx, tok); !errors.Is(err, ErrUnauthenticated) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestRawTokenIsNeverStored(t *testing.T) {
	r := newRig(t)
	r.bootstrap()
	res := r.signIn()
	rows, err := r.db.Query(`SELECT id_hash FROM sessions`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var a []byte
		_ = rows.Scan(&a)
		if strings.Contains(string(a), res.SessionToken) || strings.Contains(string(a), res.CSRFToken) || len(a) != 32 {
			t.Fatal("raw token stored")
		}
	}
	var n int
	_ = r.db.QueryRow(`SELECT count(*) FROM sessions WHERE id_hash = ?`, []byte(res.SessionToken)).Scan(&n)
	if n != 0 {
		t.Fatal("session found by raw token")
	}
	cols, _ := r.db.Query(`SELECT name FROM pragma_table_info('sessions')`)
	defer cols.Close()
	for cols.Next() {
		var c string
		_ = cols.Scan(&c)
		if strings.Contains(c, "token") || strings.Contains(c, "csrf") || strings.Contains(c, "secret") {
			t.Errorf("sessions.%s looks like secret storage", c)
		}
	}
}

func TestIdleTimeout(t *testing.T) {
	r := newRig(t)
	r.bootstrap()
	res := r.signIn()
	r.clk.add(29 * time.Minute)
	if _, err := r.svc.Authenticate(ctx, res.SessionToken); err != nil {
		t.Fatalf("active within idle window: %v", err)
	}
	r.clk.add(29 * time.Minute) // activity at +29m extended the window
	if _, err := r.svc.Authenticate(ctx, res.SessionToken); err != nil {
		t.Fatalf("activity must extend the idle window: %v", err)
	}
	r.clk.add(31 * time.Minute)
	if _, err := r.svc.Authenticate(ctx, res.SessionToken); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("idle expiry: %v", err)
	}
	r.clk.add(-31 * time.Minute) // even if the clock steps back, an expired session stays dead
	if _, err := r.svc.Authenticate(ctx, res.SessionToken); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("expired session revived: %v", err)
	}
}

func TestAbsoluteTimeoutCannotBeExtendedByActivity(t *testing.T) {
	r := newRig(t)
	r.bootstrap()
	res := r.signIn()
	for i := 0; i < 24; i++ { // 11h36m of activity every 29 minutes (below the 30m idle limit)
		r.clk.add(29 * time.Minute)
		if _, err := r.svc.Authenticate(ctx, res.SessionToken); err != nil {
			t.Fatalf("step %d: %v", i, err)
		}
	}
	r.clk.add(29 * time.Minute) // 12h 7m after sign-in: absolute limit passed
	if _, err := r.svc.Authenticate(ctx, res.SessionToken); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("absolute expiry: %v", err)
	}
}

func TestExpiryReportedOnSessionMatchesTheEarlierLimit(t *testing.T) {
	r := newRig(t)
	r.bootstrap()
	res := r.signIn()
	if got := res.Session.ExpiresAt.Sub(r.clk.now()); got != 30*time.Minute {
		t.Fatalf("idle limit %v", got)
	}
}

func TestLogoutRevokesServerSideAndReplayFails(t *testing.T) {
	r := newRig(t)
	r.bootstrap()
	res := r.signIn()
	if err := r.svc.SignOut(ctx, res.SessionToken); err != nil {
		t.Fatal(err)
	}
	if _, err := r.svc.Authenticate(ctx, res.SessionToken); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("stolen/replayed revoked session accepted: %v", err)
	}
	if err := r.svc.SignOut(ctx, res.SessionToken); err != nil { // idempotent
		t.Fatal(err)
	}
	if err := r.svc.SignOut(ctx, "garbage"); err != nil { // reveals nothing
		t.Fatal(err)
	}
}

func TestSignInRotatesTokenAndRevokesPresentedSession(t *testing.T) {
	r := newRig(t)
	r.bootstrap()
	first := r.signIn()
	// Session fixation: the attacker plants a session token the victim then signs in with.
	second, err := r.svc.SignIn(ctx, adminName, adminPass, "", first.SessionToken)
	if err != nil {
		t.Fatal(err)
	}
	if second.SessionToken == first.SessionToken || second.CSRFToken == first.CSRFToken {
		t.Fatal("token reused across sign-in")
	}
	if _, err := r.svc.Authenticate(ctx, first.SessionToken); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("the presented (fixated) session survived sign-in: %v", err)
	}
	if _, err := r.svc.Authenticate(ctx, second.SessionToken); err != nil {
		t.Fatal(err)
	}
}

func TestAttackerChosenTokenCannotBecomeASession(t *testing.T) {
	r := newRig(t)
	r.bootstrap()
	planted := strings.Repeat("Q", 43)
	res, err := r.svc.SignIn(ctx, adminName, adminPass, "", planted)
	if err != nil {
		t.Fatal(err)
	}
	if res.SessionToken == planted {
		t.Fatal("server adopted a client-chosen token")
	}
	if _, err := r.svc.Authenticate(ctx, planted); !errors.Is(err, ErrUnauthenticated) {
		t.Fatal("planted token authenticates")
	}
}

func TestSessionsSurviveRestart(t *testing.T) {
	r := newRig(t)
	r.bootstrap()
	res := r.signIn()
	r.open() // process restart on the same database
	if _, err := r.svc.Authenticate(ctx, res.SessionToken); err != nil {
		t.Fatalf("session lost across restart: %v", err)
	}
	if err := r.svc.SignOut(ctx, res.SessionToken); err != nil {
		t.Fatal(err)
	}
	r.open()
	if _, err := r.svc.Authenticate(ctx, res.SessionToken); !errors.Is(err, ErrUnauthenticated) {
		t.Fatal("revocation lost across restart")
	}
}

func TestConcurrentRequestsAndLogoutRace(t *testing.T) {
	r := newRig(t)
	r.bootstrap()
	res := r.signIn()
	r.clk.add(time.Minute) // make every Authenticate want to touch last_activity
	var wg sync.WaitGroup
	var okBefore atomic.Int32
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := r.svc.Authenticate(ctx, res.SessionToken); err == nil {
				okBefore.Add(1)
			} else if !errors.Is(err, ErrUnauthenticated) {
				t.Error(err)
			}
		}()
		if i == 16 {
			wg.Add(1)
			go func() { defer wg.Done(); _ = r.svc.SignOut(ctx, res.SessionToken) }()
		}
	}
	wg.Wait()
	if okBefore.Load() == 0 {
		t.Fatal("no concurrent request succeeded")
	}
	if _, err := r.svc.Authenticate(ctx, res.SessionToken); !errors.Is(err, ErrUnauthenticated) {
		t.Fatal("a touch resurrected a revoked session")
	}
}

func TestCorruptedSessionRecordsFailClosed(t *testing.T) {
	r := newRig(t)
	r.bootstrap()
	res := r.signIn()
	conn, err := r.db.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	// A timestamp column holding text is a corrupted record: never authenticated, never a panic.
	if _, err := conn.ExecContext(ctx, `UPDATE sessions SET absolute_expires_at = 'not-a-time'`); err != nil {
		t.Fatal(err)
	}
	if sess, err := r.svc.Authenticate(ctx, res.SessionToken); err == nil {
		t.Fatalf("corrupted record authenticated: %+v", sess)
	}
	// A session whose administrator vanished is not a session.
	if _, err := conn.ExecContext(ctx, `UPDATE sessions SET absolute_expires_at = ?`, r.clk.now().Add(time.Hour).UnixNano()); err != nil {
		t.Fatal(err)
	}
	if _, err := r.svc.Authenticate(ctx, res.SessionToken); err != nil {
		t.Fatalf("repaired record: %v", err)
	}
	if _, err := conn.ExecContext(ctx, `PRAGMA foreign_keys = OFF`); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.ExecContext(ctx, `DELETE FROM users`); err != nil {
		t.Fatal(err)
	}
	if _, err := r.svc.Authenticate(ctx, res.SessionToken); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("orphan session: %v", err)
	}
}

func TestResetPasswordRevokesEverySession(t *testing.T) {
	r := newRig(t)
	r.bootstrap()
	a, b := r.signIn(), r.signIn()
	if err := r.svc.ResetPassword(ctx, "a brand new long password"); err != nil {
		t.Fatal(err)
	}
	for _, s := range []SignInResult{a, b} {
		if _, err := r.svc.Authenticate(ctx, s.SessionToken); !errors.Is(err, ErrUnauthenticated) {
			t.Fatalf("session survived a credential change: %v", err)
		}
	}
	if _, err := r.svc.SignIn(ctx, adminName, adminPass, "", ""); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatal("old password still works")
	}
	if _, err := r.svc.SignIn(ctx, adminName, "a brand new long password", "", ""); err != nil {
		t.Fatal(err)
	}
	empty := newRig(t)
	if err := empty.svc.ResetPassword(ctx, "a brand new long password"); !errors.Is(err, ErrNotBootstrapped) {
		t.Fatalf("reset without admin: %v", err)
	}
}

// ---- CSRF ----------------------------------------------------------------------------------------------------------

func TestSessionCSRFToken(t *testing.T) {
	r := newRig(t)
	r.bootstrap()
	res := r.signIn()
	sess, _ := r.svc.Authenticate(ctx, res.SessionToken)
	if !sess.CSRFMatches(res.CSRFToken) || sess.CSRFToken() != res.CSRFToken {
		t.Fatal("issued token rejected")
	}
	if res.CSRFToken == res.SessionToken || strings.Contains(res.CSRFToken, res.SessionToken) {
		t.Fatal("the CSRF token reveals or equals the session token")
	}
	other := r.signIn()
	login := LoginCSRF(res.SessionToken)
	for name, tok := range map[string]string{"empty": "", "wrong": strings.Repeat("A", 43), "other session's": other.CSRFToken,
		"session token": res.SessionToken, "truncated": res.CSRFToken[:42], "extended": res.CSRFToken + "A", "login-purpose token": login} {
		if sess.CSRFMatches(tok) {
			t.Errorf("%s token accepted", name)
		}
	}
	// Stable across requests, tabs, reloads and restarts (it is derived, not stored) ...
	r.open()
	again, err := r.svc.Authenticate(ctx, res.SessionToken)
	if err != nil || !again.CSRFMatches(res.CSRFToken) {
		t.Fatalf("token changed across a restart: %v", err)
	}
	// ... and gone with the session.
	_ = r.svc.SignOut(ctx, res.SessionToken)
	gone, _ := r.svc.Authenticate(ctx, res.SessionToken)
	if gone.CSRFMatches(res.CSRFToken) {
		t.Fatal("token outlived its session")
	}
}

func TestLoginCSRF(t *testing.T) {
	r := newRig(t)
	nonce, tok, err := r.svc.NewLoginNonce()
	if err != nil {
		t.Fatal(err)
	}
	if !LoginCSRFValid(nonce, tok) {
		t.Fatal("issued login token rejected")
	}
	n2, t2, _ := r.svc.NewLoginNonce()
	if n2 == nonce || t2 == tok {
		t.Fatal("nonce or token repeated")
	}
	for name, c := range map[string][2]string{"other nonce": {n2, tok}, "swapped": {nonce, t2}, "empty token": {nonce, ""}, "empty nonce": {"", tok},
		"garbage": {nonce, strings.Repeat("A", 43)}, "malformed nonce": {"short", tok}, "the nonce itself": {nonce, nonce},
		"session-purpose token": {nonce, deriveCSRF(nonce, csrfSession)}} {
		if LoginCSRFValid(c[0], c[1]) {
			t.Errorf("%s accepted", name)
		}
	}
}

// ---- throttling & audit ---------------------------------------------------------------------------------------------

func TestRepeatedFailuresAreRateLimitedWithBackoffAndRecover(t *testing.T) {
	r := newRig(t)
	r.bootstrap()
	for i := 0; i < failFree; i++ {
		if _, err := r.svc.SignIn(ctx, adminName, "wrong password here", "192.0.2.1", ""); !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("attempt %d: %v", i, err)
		}
	}
	var rl *RateLimitedError
	_, err := r.svc.SignIn(ctx, adminName, adminPass, "192.0.2.1", "") // even the right password is refused while blocked
	if !errors.As(err, &rl) || rl.RetryAfter <= 0 || rl.RetryAfter > baseBlock {
		t.Fatalf("blocked: %v", err)
	}
	// Another source cannot bypass the per-username block.
	if _, err := r.svc.SignIn(ctx, adminName, adminPass, "192.0.2.99", ""); !errors.As(err, &rl) {
		t.Fatalf("different source bypassed the username throttle: %v", err)
	}
	r.clk.add(baseBlock + time.Second)
	if _, err := r.svc.SignIn(ctx, adminName, "wrong password here", "192.0.2.1", ""); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("after the block: %v", err)
	}
	if _, err := r.svc.SignIn(ctx, adminName, adminPass, "192.0.2.1", ""); !errors.As(err, &rl) || rl.RetryAfter <= baseBlock {
		t.Fatalf("backoff must grow: %v", err)
	}
	r.clk.add(maxBlock + time.Minute)
	if _, err := r.svc.SignIn(ctx, adminName, adminPass, "192.0.2.1", ""); err != nil {
		t.Fatalf("recovery after the block: %v", err)
	}
}

func TestThrottleDoesNotRevealWhetherUsernameExists(t *testing.T) {
	r := newRig(t)
	r.bootstrap()
	for _, user := range []string{adminName, "nobody"} {
		for i := 0; i < failFree; i++ {
			_, _ = r.svc.SignIn(ctx, user, "wrong password here", "", "")
		}
		var rl *RateLimitedError
		if _, err := r.svc.SignIn(ctx, user, "wrong password here", "", ""); !errors.As(err, &rl) {
			t.Errorf("%s: not throttled: %v", user, err)
		}
	}
}

func TestLimiterIsBounded(t *testing.T) {
	clk := newClock()
	l := newLimiter(clk.now)
	for i := 0; i < maxEntries*3; i++ {
		l.failure("", "user"+itoa(i))
	}
	if len(l.keys) > maxEntries {
		t.Fatalf("%d entries", len(l.keys))
	}
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	s := ""
	for ; i > 0; i /= 10 {
		s = string(rune('0'+i%10)) + s
	}
	return s
}

func TestAuditNeverContainsSecrets(t *testing.T) {
	r := newRig(t)
	r.bootstrap()
	good := r.signIn()
	_, _ = r.svc.SignIn(ctx, adminName, "wrong password here", "203.0.113.5", "")
	_ = r.svc.SignOut(ctx, good.SessionToken)
	evs, err := r.svc.Audit(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var kinds []string
	for _, e := range evs {
		kinds = append(kinds, e.Event+":"+e.Outcome)
		blob := e.Event + e.Outcome + e.Reason + e.Source
		for _, secret := range []string{adminPass, "wrong password here", good.SessionToken, good.CSRFToken, "argon2id"} {
			if strings.Contains(blob, secret) {
				t.Fatalf("audit leaks %q: %+v", secret, e)
			}
		}
	}
	if got, want := strings.Join(kinds, " "), "bootstrap:success sign_in:success sign_in:failure sign_out:success"; got != want {
		t.Fatalf("audit %q, want %q", got, want)
	}
	if _, err := r.db.Exec(`UPDATE auth_audit SET outcome = 'x'`); err == nil {
		t.Fatal("audit is mutable")
	}
	if _, err := r.db.Exec(`DELETE FROM auth_audit`); err == nil {
		t.Fatal("audit is deletable")
	}
}

func TestConfigIsClampedToSafeBounds(t *testing.T) {
	r := newRig(t)
	svc, err := New(ctx, r.db, Config{IdleTimeout: time.Second, AbsoluteTimeout: time.Second, HashConcurrency: 1000, Params: fast})
	if err != nil {
		t.Fatal(err)
	}
	if svc.cfg.IdleTimeout != time.Minute || svc.cfg.AbsoluteTimeout < svc.cfg.IdleTimeout || cap(svc.hashes) != 8 {
		t.Fatalf("%+v", svc.cfg)
	}
	if _, err := New(ctx, r.db, Config{Params: Params{MemoryKiB: 8, Time: 1, Threads: 1, SaltLen: 16, KeyLen: 32}}); err == nil {
		t.Fatal("weak parameters accepted")
	}
}

func TestLimiterNeverEvictsABlockAndFloodingCannotLiftIt(t *testing.T) {
	clk := newClock()
	l := newLimiter(clk.now)
	for i := 0; i < failFree; i++ {
		l.failure("", "admin")
	}
	if l.check("", "admin") == 0 {
		t.Fatal("admin not blocked")
	}
	for i := 0; i < maxEntries*3; i++ { // a flood of fresh names
		l.failure("", "flood"+itoa(i))
	}
	if l.check("", "admin") == 0 {
		t.Fatal("flooding evicted a block")
	}
	if len(l.keys) > maxEntries {
		t.Fatalf("%d entries", len(l.keys))
	}
}

func TestFirstUnknownUserCostsTheSameAsTheRest(t *testing.T) {
	r := newRig(t)
	if r.svc.dummy == "" {
		t.Fatal("the dummy hash must exist before the first request")
	}
}
