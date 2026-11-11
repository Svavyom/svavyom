package sshkeys

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"example.invalid/dedicatedcloud/backend/internal/sqlitedb"
)

func open(t *testing.T) *Store {
	t.Helper()
	db, err := sqlitedb.Open(filepath.Join(t.TempDir(), "k.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	s, err := OpenSQLite(context.Background(), db)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func newKey(t *testing.T) string {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sp, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sp)))
}

func TestAddNormalisesComputesTheFingerprintAndLogsIt(t *testing.T) {
	s, ctx := open(t), context.Background()
	text := newKey(t) + " laptop"
	k, err := s.Add(ctx, "alice", "Alice laptop", text)
	if err != nil {
		t.Fatal(err)
	}
	if k.Type != "ed25519" || strings.Contains(k.PublicKey, "laptop") || !strings.HasPrefix(k.Fingerprint, "SHA256:") || !IDRE.MatchString(k.ID) || k.AddedBy != "alice" {
		t.Fatalf("key: %+v", k)
	}
	list, _ := s.List(ctx)
	if len(list) != 1 || list[0].Fingerprint != k.Fingerprint {
		t.Fatalf("list: %+v", list)
	}
	log, _ := s.Log(ctx)
	if len(log) != 1 || log[0] != [3]string{EventAdded, "alice", k.Fingerprint} {
		t.Fatalf("log: %v", log)
	}
}

func TestRefusesWhatIsNotOnePlainPublicKeyWithoutEchoingIt(t *testing.T) {
	s, ctx := open(t), context.Background()
	good := newKey(t)
	for name, in := range map[string]string{
		"private key":   "-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----",
		"two keys":      good + "\n" + good,
		"options":       `command="id" ` + good,
		"nothing":       "",
		"not a key":     "hello world",
		"hidden second": good + " ssh-ed25519 AAAA",
		"oversize":      strings.Repeat("a", 3000),
	} {
		_, err := s.Add(ctx, "alice", "k", in)
		if !errors.Is(err, ErrInvalid) || strings.Contains(err.Error(), "BEGIN") {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := s.Add(ctx, "alice", "bad/name", good); !errors.Is(err, ErrInvalid) {
		t.Errorf("name: %v", err)
	}
	if list, _ := s.List(ctx); len(list) != 0 {
		t.Fatalf("nothing should be saved: %+v", list)
	}
}

func TestDuplicateKeyAndDuplicateNameAreConflictsAndTheLibraryIsBounded(t *testing.T) {
	s, ctx := open(t), context.Background()
	a := newKey(t)
	if _, err := s.Add(ctx, "alice", "one", a); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Add(ctx, "bob", "two", a+" other-comment"); !errors.Is(err, ErrDuplicate) {
		t.Fatalf("same key: %v", err)
	}
	if _, err := s.Add(ctx, "bob", "ONE", newKey(t)); !errors.Is(err, ErrDuplicate) {
		t.Fatalf("same name, any case: %v", err)
	}
	for i := 1; i < MaxKeys; i++ {
		if _, err := s.Add(ctx, "alice", fmt.Sprintf("key %d", i), newKey(t)); err != nil {
			t.Fatalf("key %d: %v", i, err)
		}
	}
	if _, err := s.Add(ctx, "alice", "one too many", newKey(t)); !errors.Is(err, ErrFull) {
		t.Fatalf("full: %v", err)
	}
}

func TestDeleteByAdminOrAdderOnlyAndLogged(t *testing.T) {
	s, ctx := open(t), context.Background()
	k, _ := s.Add(ctx, "alice", "one", newKey(t))
	if err := s.Delete(ctx, "bob", false, k.ID); !errors.Is(err, ErrForbidden) {
		t.Fatalf("another operator: %v", err)
	}
	if err := s.Delete(ctx, "bob", false, "k-0000000000000000"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown: %v", err)
	}
	if err := s.Delete(ctx, "alice", false, k.ID); err != nil {
		t.Fatalf("the adder: %v", err)
	}
	k2, _ := s.Add(ctx, "alice", "two", newKey(t))
	if err := s.Delete(ctx, "root", true, k2.ID); err != nil {
		t.Fatalf("an admin: %v", err)
	}
	log, _ := s.Log(ctx)
	if len(log) != 4 || log[1] != [3]string{EventDeleted, "alice", k.Fingerprint} || log[3] != [3]string{EventDeleted, "root", k2.Fingerprint} {
		t.Fatalf("log: %v", log)
	}
}

func TestTheLogCannotBeChanged(t *testing.T) {
	s, ctx := open(t), context.Background()
	_, _ = s.Add(ctx, "alice", "one", newKey(t))
	if _, err := s.db.ExecContext(ctx, `UPDATE ssh_key_log SET username = 'x'`); err == nil {
		t.Error("update must be refused")
	}
	if _, err := s.db.ExecContext(ctx, `DELETE FROM ssh_key_log`); err == nil {
		t.Error("delete must be refused")
	}
}
