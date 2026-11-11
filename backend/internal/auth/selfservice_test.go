package auth

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestChangeOwnPasswordChecksTheCurrentOneEndsOtherSessionsAndKeepsTheCurrent(t *testing.T) {
	ctx := context.Background()
	s, _, _ := newService(t)
	if err := s.AddUser(ctx, "olly", pw1, RoleOperator); err != nil {
		t.Fatal(err)
	}
	a, _ := s.SignIn(ctx, "olly", pw1, "10.0.0.1", "")
	b, _ := s.SignIn(ctx, "olly", pw1, "10.0.0.2", "")

	if err := s.ChangeOwnPassword(ctx, a.Session, a.SessionToken, "not the password!", pw2, "10.0.0.1"); !errors.Is(err, ErrWrongPassword) {
		t.Fatalf("wrong current: %v", err)
	}
	if err := s.ChangeOwnPassword(ctx, a.Session, a.SessionToken, pw1, "short", "10.0.0.1"); !errors.Is(err, ErrPasswordPolicy) {
		t.Fatalf("weak new: %v", err)
	}
	if err := s.ChangeOwnPassword(ctx, a.Session, a.SessionToken, pw1, pw1, "10.0.0.1"); !errors.Is(err, ErrSamePassword) {
		t.Fatalf("same: %v", err)
	}
	if _, err := s.Authenticate(ctx, b.SessionToken); err != nil {
		t.Fatalf("a refused change must not end any session: %v", err)
	}
	if err := s.ChangeOwnPassword(ctx, a.Session, a.SessionToken, pw1, pw2, "10.0.0.1"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Authenticate(ctx, a.SessionToken); err != nil {
		t.Errorf("the session that changed the password stays: %v", err)
	}
	if _, err := s.Authenticate(ctx, b.SessionToken); !errors.Is(err, ErrUnauthenticated) {
		t.Errorf("every other session ends: %v", err)
	}
	if _, err := s.SignIn(ctx, "olly", pw1, "10.0.0.1", ""); !errors.Is(err, ErrInvalidCredentials) {
		t.Errorf("the old password no longer works: %v", err)
	}
	if _, err := s.SignIn(ctx, "olly", pw2, "10.0.0.1", ""); err != nil {
		t.Errorf("the new one does: %v", err)
	}
}

func TestChangeOwnPasswordIsThrottledLikeSignInAndAuditedWithoutThePasswords(t *testing.T) {
	ctx := context.Background()
	s, _, _ := newService(t)
	_ = s.AddUser(ctx, "olly", pw1, RoleOperator)
	a, _ := s.SignIn(ctx, "olly", pw1, "10.0.0.1", "")
	var last error
	for i := 0; i < 8; i++ {
		last = s.ChangeOwnPassword(ctx, a.Session, a.SessionToken, "wrong password number "+string(rune('a'+i)), pw2, "10.0.0.1")
	}
	var rl *RateLimitedError
	if !errors.As(last, &rl) {
		t.Fatalf("repeated wrong current passwords are blocked like sign-in: %v", last)
	}
	// even the right current password is refused while the pair is blocked
	if err := s.ChangeOwnPassword(ctx, a.Session, a.SessionToken, pw1, pw2, "10.0.0.1"); !errors.As(err, &rl) {
		t.Fatalf("blocked: %v", err)
	}
	// and the same pair limiter blocks sign-in too, from the same address
	if _, err := s.SignIn(ctx, "olly", pw1, "10.0.0.1", ""); !errors.As(err, &rl) {
		t.Fatalf("the limiter is shared with sign-in: %v", err)
	}
	log, _ := s.Audit(ctx)
	var failures, blocked int
	for _, ev := range log {
		if ev.Event != "password_change" {
			continue
		}
		if ev.Username != "olly" || strings.Contains(ev.Reason+ev.Outcome+ev.Source+ev.Username, "wrong password") || strings.Contains(ev.Reason, pw1) {
			t.Errorf("audit event: %+v", ev)
		}
		switch ev.Outcome {
		case "failure":
			failures++
		case "blocked":
			blocked++
		}
	}
	if failures == 0 || blocked == 0 {
		t.Errorf("failures=%d blocked=%d", failures, blocked)
	}
}

func TestATemporaryPasswordMustBeChangedAndTheChangeClearsIt(t *testing.T) {
	ctx := context.Background()
	s, _, _ := newService(t)
	if err := s.AddUserWithTemporaryPassword(ctx, "newbie", pw1, RoleViewer); err != nil {
		t.Fatal(err)
	}
	if err := s.AddUser(ctx, "plain", pw1, RoleViewer); err != nil {
		t.Fatal(err)
	}
	us, _ := s.ListUsers(ctx)
	flags := map[string]bool{}
	for _, u := range us {
		flags[u.Username] = u.MustChange
	}
	if !flags["newbie"] || flags["plain"] {
		t.Fatalf("flags: %v", flags)
	}
	res, err := s.SignIn(ctx, "newbie", pw1, "10.0.0.1", "")
	if err != nil || !res.Session.MustChange {
		t.Fatalf("sign-in: %+v %v", res.Session, err)
	}
	if got, _ := s.Authenticate(ctx, res.SessionToken); !got.MustChange {
		t.Fatal("the session carries the flag")
	}
	if !s.MustChangePassword(ctx, res.SessionToken) {
		t.Fatal("MustChangePassword")
	}
	if err := s.ChangeOwnPassword(ctx, res.Session, res.SessionToken, pw1, pw2, "10.0.0.1"); err != nil {
		t.Fatal(err)
	}
	if s.MustChangePassword(ctx, res.SessionToken) {
		t.Fatal("changing the password clears the flag")
	}
	if got, _ := s.Authenticate(ctx, res.SessionToken); got.MustChange {
		t.Fatal("the session no longer carries it")
	}
	// an administrator's reset sets it again, revokes the user's sessions, and the CLI's own reset does not
	if err := s.SetTemporaryPassword(ctx, "newbie", pw3); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Authenticate(ctx, res.SessionToken); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("reset revokes sessions: %v", err)
	}
	again, err := s.SignIn(ctx, "newbie", pw3, "10.0.0.1", "")
	if err != nil || !again.Session.MustChange {
		t.Fatalf("after a reset: %+v %v", again.Session, err)
	}
	if err := s.SetPassword(ctx, "newbie", pw1); err != nil {
		t.Fatal(err)
	}
	cli, _ := s.SignIn(ctx, "newbie", pw1, "10.0.0.1", "")
	if cli.Session.MustChange {
		t.Fatal("the host administrator's own reset (the CLI) is not temporary")
	}
	if s.MustChangePassword(ctx, "not-a-token") {
		t.Fatal("an unknown token never reports true")
	}
}
