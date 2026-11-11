// Package sshkeys is the library of saved SSH public keys (DR-040): one list per installation that the create, reinstall and restore forms offer, so a
// key is not pasted again for every VM. It holds public keys only. Every key goes through the same validator as a key sent with an operation
// (provision.NormalizeSSHKey: one plain key, no options, no weak RSA, never a private key), the fingerprint is computed here and never taken from a client,
// and every add and delete is written to an append-only log with the user and the fingerprint.
package sshkeys

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"example.invalid/dedicatedcloud/backend/internal/provision"
	"example.invalid/dedicatedcloud/backend/internal/sqlitedb"
)

// MaxKeys bounds the library.
const MaxKeys = 64

var (
	// ErrInvalid is returned for a bad name or key; it says nothing about the input.
	ErrInvalid = errors.New("sshkeys: invalid name or public key")
	// ErrDuplicate is returned when the name or the key (by fingerprint) is already in the library.
	ErrDuplicate = errors.New("sshkeys: the name or the key is already saved")
	// ErrFull is returned when the library holds MaxKeys keys.
	ErrFull = errors.New("sshkeys: the library is full")
	// ErrNotFound is returned for an unknown id.
	ErrNotFound = errors.New("sshkeys: no such key")
	// ErrForbidden is returned when a user who is not an administrator deletes a key someone else added.
	ErrForbidden = errors.New("sshkeys: only an administrator or the user who added a key may delete it")
)

// Events written to the log.
const (
	EventAdded   = "key_added"
	EventDeleted = "key_deleted"
)

var (
	nameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9 ._()+-]{0,62}$`)
	// IDRE is the form of a key id.
	IDRE = regexp.MustCompile(`^k-[0-9a-f]{16}$`)
)

// Key is one saved public key.
type Key struct {
	ID          string
	Name        string
	Type        string // ed25519, ecdsa or rsa
	PublicKey   string // "<type> <base64>", no options and no comment
	Fingerprint string // SHA256:...
	AddedBy     string
	AddedAt     time.Time
}

var schema = []string{`CREATE TABLE ssh_keys (
	id          TEXT PRIMARY KEY CHECK (length(id) = 18),
	name        TEXT NOT NULL COLLATE NOCASE UNIQUE CHECK (length(name) BETWEEN 1 AND 63),
	key_type    TEXT NOT NULL CHECK (key_type IN ('ed25519','ecdsa','rsa')),
	public_key  TEXT NOT NULL CHECK (length(public_key) BETWEEN 1 AND 2048),
	fingerprint TEXT NOT NULL UNIQUE CHECK (length(fingerprint) BETWEEN 8 AND 64),
	added_by    TEXT NOT NULL,
	added_at    INTEGER NOT NULL
);
CREATE TABLE ssh_key_log (
	seq         INTEGER PRIMARY KEY AUTOINCREMENT,
	at          INTEGER NOT NULL,
	event       TEXT NOT NULL CHECK (event IN ('key_added','key_deleted')),
	username    TEXT NOT NULL,
	fingerprint TEXT NOT NULL
);
CREATE TRIGGER ssh_key_log_append_only BEFORE UPDATE ON ssh_key_log BEGIN SELECT RAISE(ABORT, 'log is append-only'); END;
CREATE TRIGGER ssh_key_log_no_delete BEFORE DELETE ON ssh_key_log BEGIN SELECT RAISE(ABORT, 'log is append-only'); END;`}

// Store is the library over the control plane's database.
type Store struct {
	db  *sql.DB
	now func() time.Time
}

// OpenSQLite migrates the schema in db and returns a store over it. The caller owns db.
func OpenSQLite(ctx context.Context, db *sql.DB) (*Store, error) {
	if err := sqlitedb.Migrate(ctx, db, "sshkeys", schema); err != nil {
		return nil, fmt.Errorf("sshkeys: migrate: %w", err)
	}
	return &Store{db: db, now: time.Now}, nil
}

func keyType(t string) string {
	switch {
	case strings.HasPrefix(t, "ssh-ed25519"):
		return "ed25519"
	case strings.HasPrefix(t, "ecdsa-"):
		return "ecdsa"
	default:
		return "rsa"
	}
}

const cols = `id, name, key_type, public_key, fingerprint, added_by, added_at`

func scan(r interface{ Scan(...any) error }) (Key, error) {
	var (
		k  Key
		at int64
	)
	if err := r.Scan(&k.ID, &k.Name, &k.Type, &k.PublicKey, &k.Fingerprint, &k.AddedBy, &at); err != nil {
		return Key{}, err
	}
	k.AddedAt = time.Unix(0, at).UTC()
	return k, nil
}

// List returns every saved key, by name.
func (s *Store) List(ctx context.Context) ([]Key, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+cols+` FROM ssh_keys ORDER BY name COLLATE NOCASE`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	out := []Key{}
	for rows.Next() {
		k, err := scan(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	return out, rows.Err()
}

// Add validates and saves a public key for actor. The key text is normalised; the fingerprint is computed here.
func (s *Store) Add(ctx context.Context, actor, name, publicKey string) (Key, error) {
	name = strings.TrimSpace(name)
	if !nameRE.MatchString(name) {
		return Key{}, ErrInvalid
	}
	nk, err := provision.NormalizeSSHKey(publicKey)
	if err != nil {
		return Key{}, ErrInvalid
	}
	var raw [8]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return Key{}, err
	}
	k := Key{ID: "k-" + hex.EncodeToString(raw[:]), Name: name, Type: keyType(nk.Type), PublicKey: nk.Authorized, Fingerprint: nk.Fingerprint, AddedBy: actor, AddedAt: s.now().UTC()}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Key{}, err
	}
	defer func() { _ = tx.Rollback() }()
	var n int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM ssh_keys`).Scan(&n); err != nil {
		return Key{}, err
	}
	if n >= MaxKeys {
		return Key{}, ErrFull
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO ssh_keys (`+cols+`) VALUES (?,?,?,?,?,?,?)`, k.ID, k.Name, k.Type, k.PublicKey, k.Fingerprint, k.AddedBy, k.AddedAt.UnixNano()); err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			return Key{}, ErrDuplicate
		}
		return Key{}, err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO ssh_key_log (at, event, username, fingerprint) VALUES (?,?,?,?)`, k.AddedAt.UnixNano(), EventAdded, actor, k.Fingerprint); err != nil {
		return Key{}, err
	}
	return k, tx.Commit()
}

// Delete removes a key. An administrator may delete any key; another user only the keys they added.
func (s *Store) Delete(ctx context.Context, actor string, admin bool, id string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	k, err := scan(tx.QueryRowContext(ctx, `SELECT `+cols+` FROM ssh_keys WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	if !admin && k.AddedBy != actor {
		return ErrForbidden
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM ssh_keys WHERE id = ?`, id); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO ssh_key_log (at, event, username, fingerprint) VALUES (?,?,?,?)`, s.now().UTC().UnixNano(), EventDeleted, actor, k.Fingerprint); err != nil {
		return err
	}
	return tx.Commit()
}

// Log returns the log in order (for tests and the operator): event, user and fingerprint.
func (s *Store) Log(ctx context.Context) ([][3]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT event, username, fingerprint FROM ssh_key_log ORDER BY seq`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out [][3]string
	for rows.Next() {
		var r [3]string
		if err := rows.Scan(&r[0], &r[1], &r[2]); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
