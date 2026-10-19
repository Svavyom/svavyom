package auth

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"example.invalid/dedicatedcloud/backend/internal/sqlitedb"
)

func newService(t *testing.T) (*Service, *sql.DB, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "auth.db")
	db, err := sqlitedb.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	s, err := New(context.Background(), db, Config{Params: fast})
	if err != nil {
		t.Fatal(err)
	}
	return s, db, path
}

const pw1, pw2, pw3 = "correct horse battery 1", "correct horse battery 2", "correct horse battery 3"

func TestRoleOrderIsAdminOperatorViewer(t *testing.T) {
	cases := []struct {
		have, need Role
		want       bool
	}{
		{RoleAdmin, RoleAdmin, true}, {RoleAdmin, RoleOperator, true}, {RoleAdmin, RoleViewer, true},
		{RoleOperator, RoleAdmin, false}, {RoleOperator, RoleOperator, true}, {RoleOperator, RoleViewer, true},
		{RoleViewer, RoleOperator, false}, {RoleViewer, RoleViewer, true},
		{"", RoleViewer, false}, {"root", RoleViewer, false},
	}
	for _, c := range cases {
		if got := c.have.AtLeast(c.need); got != c.want {
			t.Errorf("%q.AtLeast(%q) = %v", c.have, c.need, got)
		}
	}
	if _, err := ParseRole("superuser"); !errors.Is(err, ErrBadRole) {
		t.Fatalf("%v", err)
	}
}

func TestUsersHaveRolesAndSessionsCarryThem(t *testing.T) {
	ctx := context.Background()
	s, _, _ := newService(t)
	if err := s.Bootstrap(ctx, "boss", pw1); err != nil {
		t.Fatal(err)
	}
	if err := s.AddUser(ctx, "olly", pw2, RoleOperator); err != nil {
		t.Fatal(err)
	}
	if err := s.AddUser(ctx, "vera", pw3, RoleViewer); err != nil {
		t.Fatal(err)
	}
	if err := s.AddUser(ctx, "olly", pw2, RoleViewer); !errors.Is(err, ErrUserExists) {
		t.Fatalf("duplicate: %v", err)
	}
	if err := s.AddUser(ctx, "Bad Name", pw2, RoleViewer); !errors.Is(err, ErrBadUsername) {
		t.Fatalf("bad name: %v", err)
	}
	if err := s.AddUser(ctx, "zed", pw2, Role("root")); !errors.Is(err, ErrBadRole) {
		t.Fatalf("bad role: %v", err)
	}
	for name, want := range map[string]Role{"boss": RoleAdmin, "olly": RoleOperator, "vera": RoleViewer} {
		pw := map[string]string{"boss": pw1, "olly": pw2, "vera": pw3}[name]
		res, err := s.SignIn(ctx, name, pw, "127.0.0.1", "")
		if err != nil || res.Session.Role != want || res.Session.Username != name {
			t.Fatalf("%s: %+v %v", name, res.Session, err)
		}
		got, err := s.Authenticate(ctx, res.SessionToken)
		if err != nil || got.Role != want {
			t.Fatalf("%s authenticate: %+v %v", name, got, err)
		}
	}
	users, err := s.ListUsers(ctx)
	if err != nil || len(users) != 3 || users[0].Username != "boss" || users[2].Role != RoleViewer {
		t.Fatalf("%+v %v", users, err)
	}
}

func TestARoleChangeOrDisableEndsThatUsersSessionsOnly(t *testing.T) {
	ctx := context.Background()
	s, _, _ := newService(t)
	_ = s.Bootstrap(ctx, "boss", pw1)
	_ = s.AddUser(ctx, "olly", pw2, RoleOperator)
	boss, _ := s.SignIn(ctx, "boss", pw1, "h", "")
	olly, _ := s.SignIn(ctx, "olly", pw2, "h", "")
	if err := s.SetRole(ctx, "olly", RoleViewer); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Authenticate(ctx, olly.SessionToken); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("the old session must end: %v", err)
	}
	if _, err := s.Authenticate(ctx, boss.SessionToken); err != nil {
		t.Fatalf("another user's session must survive: %v", err)
	}
	again, err := s.SignIn(ctx, "olly", pw2, "h", "")
	if err != nil || again.Session.Role != RoleViewer {
		t.Fatalf("%+v %v", again.Session, err)
	}
	if err := s.SetDisabled(ctx, "olly", true); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Authenticate(ctx, again.SessionToken); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("disabled: %v", err)
	}
	if _, err := s.SignIn(ctx, "olly", pw2, "h", ""); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("a disabled user cannot sign in, and is indistinguishable from a wrong password: %v", err)
	}
	if err := s.SetDisabled(ctx, "olly", false); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SignIn(ctx, "olly", pw2, "h", ""); err != nil {
		t.Fatal(err)
	}
}

func TestTheLastEnabledAdministratorIsProtected(t *testing.T) {
	ctx := context.Background()
	s, _, _ := newService(t)
	_ = s.Bootstrap(ctx, "boss", pw1)
	if err := s.SetRole(ctx, "boss", RoleViewer); !errors.Is(err, ErrLastAdmin) {
		t.Fatalf("demote: %v", err)
	}
	if err := s.SetDisabled(ctx, "boss", true); !errors.Is(err, ErrLastAdmin) {
		t.Fatalf("disable: %v", err)
	}
	_ = s.AddUser(ctx, "deputy", pw2, RoleAdmin)
	if err := s.SetRole(ctx, "boss", RoleViewer); err != nil {
		t.Fatalf("with a second administrator the first may be demoted: %v", err)
	}
	if err := s.SetDisabled(ctx, "deputy", true); !errors.Is(err, ErrLastAdmin) {
		t.Fatalf("the remaining administrator: %v", err)
	}
	if err := s.SetRole(ctx, "nobody", RoleViewer); !errors.Is(err, ErrNoSuchUser) {
		t.Fatalf("%v", err)
	}
}

func TestSetPasswordRevokesOnlyThatUsersSessions(t *testing.T) {
	ctx := context.Background()
	s, _, _ := newService(t)
	_ = s.Bootstrap(ctx, "boss", pw1)
	_ = s.AddUser(ctx, "olly", pw2, RoleOperator)
	boss, _ := s.SignIn(ctx, "boss", pw1, "h", "")
	olly, _ := s.SignIn(ctx, "olly", pw2, "h", "")
	if err := s.SetPassword(ctx, "olly", pw3); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Authenticate(ctx, olly.SessionToken); !errors.Is(err, ErrUnauthenticated) {
		t.Fatal(err)
	}
	if _, err := s.Authenticate(ctx, boss.SessionToken); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SignIn(ctx, "olly", pw2, "h", ""); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("the old password must stop working: %v", err)
	}
	if _, err := s.SignIn(ctx, "olly", pw3, "h", ""); err != nil {
		t.Fatal(err)
	}
	if err := s.SetPassword(ctx, "nobody", pw3); !errors.Is(err, ErrNoSuchUser) {
		t.Fatalf("%v", err)
	}
	if err := s.ResetPassword(ctx, pw2); err != nil { // the legacy command still resets the first administrator
		t.Fatal(err)
	}
	if _, err := s.SignIn(ctx, "boss", pw2, "h", ""); err != nil {
		t.Fatal(err)
	}
}

func TestBootstrapStillHappensOnlyOnce(t *testing.T) {
	ctx := context.Background()
	s, _, _ := newService(t)
	if ok, _ := s.Configured(ctx); ok {
		t.Fatal("nothing is configured yet")
	}
	if err := s.Bootstrap(ctx, "boss", pw1); err != nil {
		t.Fatal(err)
	}
	if err := s.Bootstrap(ctx, "second", pw2); !errors.Is(err, ErrAlreadyBootstrapped) {
		t.Fatalf("%v", err)
	}
	if ok, _ := s.Configured(ctx); !ok {
		t.Fatal("configured")
	}
}

// The single administrator of the earlier schema becomes the first admin with the same password and keeps a live session.
func TestMigrationKeepsTheExistingAdministratorAndHisSession(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "legacy.db")
	db, err := sqlitedb.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := sqlitedb.Migrate(ctx, db, "auth", schema[:1]); err != nil {
		t.Fatal(err)
	}
	phc, err := HashPassword(pw1, fast)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UnixNano()
	if _, err := db.ExecContext(ctx, `INSERT INTO admin_account (id, username, password_phc, created_at, password_changed_at) VALUES (1, 'legacy', ?, ?, ?)`, phc, now, now); err != nil {
		t.Fatal(err)
	}
	tok := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ" // 43 characters
	if _, err := db.ExecContext(ctx, `INSERT INTO sessions (id_hash, admin_id, created_at, last_activity, absolute_expires_at) VALUES (?,1,?,?,?)`,
		tokenHash(tok), now, now, now+int64(time.Hour)); err != nil {
		t.Fatal(err)
	}
	s, err := New(ctx, db, Config{Params: fast})
	if err != nil {
		t.Fatal(err)
	}
	sess, err := s.Authenticate(ctx, tok)
	if err != nil || sess.Username != "legacy" || sess.Role != RoleAdmin {
		t.Fatalf("%+v %v", sess, err)
	}
	if _, err := s.SignIn(ctx, "legacy", pw1, "h", ""); err != nil {
		t.Fatal(err)
	}
	if err := s.AddUser(ctx, "olly", pw2, RoleOperator); err != nil {
		t.Fatalf("new users must work after the migration: %v", err)
	}
	if SchemaVersion() != 2 {
		t.Fatalf("schema version %d", SchemaVersion())
	}
}
