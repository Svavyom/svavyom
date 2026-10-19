package ctl

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"example.invalid/dedicatedcloud/backend/internal/auth"
	"example.invalid/dedicatedcloud/backend/internal/metrics"
	"example.invalid/dedicatedcloud/backend/internal/operation"
	"example.invalid/dedicatedcloud/backend/internal/sqlitedb"
)

// Standalone database backup and restore (M2-E02-S03). The API database holds the accounts and their roles, the operation history and the usage
// samples; it does not hold VM disks, images, the pool or the backup store. `db-backup` takes a consistent copy while the service runs (SQLite's own
// VACUUM INTO), checks it and records its SHA-256 and schema versions; `db-restore` is a dry run unless --apply, refuses a copy that fails its checks
// or comes from a newer build, keeps the database it replaces, and restarts the services.

// DBBackupDir is where the copies are kept (root-owned, 0700).
const DBBackupDir = LibDir + "/db-backups"

var dbBackupIDRE = regexp.MustCompile(`^(?:pre-restore-)?[0-9]{8}T[0-9]{6}Z$`)

// DBBackupMeta is the record kept beside each copy. It holds no account data.
type DBBackupMeta struct {
	ID            string         `json:"id"`
	CreatedAt     string         `json:"created_at"`
	Version       string         `json:"svavyom_version"`
	SchemaVersion map[string]int `json:"db_schema_versions"`
	SHA256        string         `json:"sha256"`
	SizeBytes     int64          `json:"size_bytes"`
}

// buildSchemas are the schema versions this build reads and writes.
func buildSchemas() map[string]int {
	return map[string]int{"operation": operation.SchemaVersion(), "auth": auth.SchemaVersion(), "usage": metrics.SchemaVersion()}
}

func (e *Env) dbBackupPath(id, ext string) string { return filepath.Join(e.P(DBBackupDir), id+ext) }

// DBBackupOptions: Keep is how many of the newest regular copies to retain (0 keeps all); pre-restore copies are never pruned.
type DBBackupOptions struct{ Keep int }

// DBBackup makes, verifies and records a consistent copy of the API database.
func DBBackup(ctx context.Context, e *Env, o DBBackupOptions, w io.Writer) (DBBackupMeta, error) {
	if e.Euid() != 0 {
		return DBBackupMeta{}, errors.New("the database is root/service-owned: run with sudo")
	}
	if _, err := os.Stat(e.dbPath()); err != nil {
		return DBBackupMeta{}, errors.New("there is no API database to back up")
	}
	return e.writeDBBackup(ctx, e.Now().UTC().Format("20060102T150405Z"), o.Keep, w)
}

func (e *Env) writeDBBackup(ctx context.Context, id string, keep int, w io.Writer) (DBBackupMeta, error) {
	if err := os.MkdirAll(e.P(DBBackupDir), 0o700); err != nil {
		return DBBackupMeta{}, err
	}
	dst := e.dbBackupPath(id, ".sqlite")
	if _, err := os.Lstat(dst); err == nil {
		return DBBackupMeta{}, errors.New("a copy with this id exists already (wait a second and retry)")
	}
	if err := e.copyDatabase(ctx, dst); err != nil {
		_ = os.Remove(dst)
		return DBBackupMeta{}, fmt.Errorf("copying the database: %w", err)
	}
	fail := func(err error) (DBBackupMeta, error) { _ = os.Remove(dst); return DBBackupMeta{}, err }
	if err := checkDatabaseFile(ctx, dst); err != nil {
		return fail(err)
	}
	sum, size, err := fileDigest(dst)
	if err != nil {
		return fail(err)
	}
	vs, err := databaseVersions(ctx, dst)
	if err != nil {
		return fail(err)
	}
	meta := DBBackupMeta{ID: id, CreatedAt: e.Now().UTC().Format(time.RFC3339), Version: e.installedVersion(), SchemaVersion: vs, SHA256: sum, SizeBytes: size}
	b, _ := json.MarshalIndent(meta, "", "  ")
	if err := os.WriteFile(e.dbBackupPath(id, ".json"), append(b, '\n'), 0o600); err != nil {
		return fail(err)
	}
	_, _ = fmt.Fprintf(w, "database copy %s: %d bytes, sha256 %s, integrity ok\n", id, size, sum)
	if keep > 0 && !strings.HasPrefix(id, "pre-restore-") {
		e.pruneDBBackups(keep, w)
	}
	return meta, nil
}

func (e *Env) pruneDBBackups(keep int, w io.Writer) {
	l, _ := e.ListDBBackups()
	var regular []DBBackupMeta
	for _, m := range l {
		if !strings.HasPrefix(m.ID, "pre-restore-") {
			regular = append(regular, m)
		}
	}
	for i := keep; i < len(regular); i++ { // ListDBBackups is newest first
		_ = os.Remove(e.dbBackupPath(regular[i].ID, ".sqlite"))
		_ = os.Remove(e.dbBackupPath(regular[i].ID, ".json"))
		_, _ = fmt.Fprintf(w, "removed the older copy %s (keeping %d)\n", regular[i].ID, keep)
	}
}

// ListDBBackups returns the recorded copies, newest first (by creation time).
func (e *Env) ListDBBackups() ([]DBBackupMeta, error) {
	ents, err := os.ReadDir(e.P(DBBackupDir))
	if err != nil {
		return nil, err
	}
	var out []DBBackupMeta
	for _, en := range ents {
		id, ok := strings.CutSuffix(en.Name(), ".json")
		if !ok || !dbBackupIDRE.MatchString(id) {
			continue
		}
		b, err := os.ReadFile(e.dbBackupPath(id, ".json")) // #nosec G304 -- our own directory; the id matched a fixed grammar
		if err != nil {
			continue
		}
		var m DBBackupMeta
		if json.Unmarshal(b, &m) == nil && m.ID == id {
			out = append(out, m)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].CreatedAt > out[j].CreatedAt || (out[i].CreatedAt == out[j].CreatedAt && out[i].ID > out[j].ID)
	})
	return out, nil
}

// VerifyDBBackup re-checks a copy: the file exists, its SHA-256 and size match the record, and SQLite finds it intact.
func (e *Env) VerifyDBBackup(ctx context.Context, m DBBackupMeta) error {
	p := e.dbBackupPath(m.ID, ".sqlite")
	sum, size, err := fileDigest(p)
	if err != nil {
		return errors.New("the copy's file cannot be read")
	}
	if sum != m.SHA256 || size != m.SizeBytes {
		return errors.New("the copy does not match its recorded SHA-256: it was changed or damaged")
	}
	return checkDatabaseFile(ctx, p)
}

// DBRestoreOptions selects the copy ("" or "latest" means the newest regular copy) and whether to apply.
type DBRestoreOptions struct {
	ID    string
	Apply bool
}

// DBRestore replaces the API database with a verified copy.
func DBRestore(ctx context.Context, e *Env, o DBRestoreOptions, w io.Writer) error {
	l, err := e.ListDBBackups()
	if err != nil || len(l) == 0 {
		return errors.New("there is no database copy to restore (see `svavyom-ctl db-backups`)")
	}
	var meta DBBackupMeta
	found := false
	for _, m := range l {
		if (o.ID == "" || o.ID == "latest") && !strings.HasPrefix(m.ID, "pre-restore-") || m.ID == o.ID {
			meta, found = m, true
			break
		}
	}
	if !found {
		return errors.New("no such database copy: " + clean(o.ID))
	}
	_, _ = fmt.Fprintf(w, "restoring database copy %s (made %s by %s)\n", meta.ID, meta.CreatedAt, orNone(meta.Version))
	if e.Euid() != 0 && o.Apply {
		return errors.New("--apply needs root (run with sudo)")
	}
	if err := e.VerifyDBBackup(ctx, meta); err != nil {
		return fmt.Errorf("refusing: %w", err)
	}
	if ahead := schemaAhead(meta.SchemaVersion, buildSchemas()); len(ahead) > 0 {
		return fmt.Errorf("refusing: the copy was made by a newer build (%s) than this one can read", strings.Join(ahead, ", "))
	}
	p := &Plan{}
	p.add("keep a copy of the current database as a pre-restore copy (listed by db-backups, never pruned)", func() error {
		if _, err := os.Stat(e.dbPath()); err != nil {
			return nil // nothing to keep
		}
		_, err := e.writeDBBackup(ctx, "pre-restore-"+e.Now().UTC().Format("20060102T150405Z"), 0, io.Discard)
		return err
	})
	p.add("stop the services in reverse order", func() error { return e.stopAll(ctx) })
	p.add("put the copy in place (the replaced database is kept beside it as svavyom.db.replaced-<time>; VM storage, images and backups are not touched)", func() error {
		return e.restoreDatabaseFile(e.dbBackupPath(meta.ID, ".sqlite"))
	})
	p.add("start the services in order and check health (they bring the schema forward if the copy is older)", func() error {
		if err := e.startAll(ctx); err != nil {
			return err
		}
		return e.waitHealthy(ctx, 90*time.Second)
	})
	if err := p.Run(w, o.Apply); err != nil {
		return err
	}
	if o.Apply {
		_, _ = fmt.Fprintf(w, "database restored from %s; sessions that existed in the copy are valid again, newer ones are gone\n", meta.ID)
	}
	return nil
}

func fileDigest(path string) (string, int64, error) {
	f, err := os.Open(path) // #nosec G304 -- a path inside our own backup directory
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}

// checkDatabaseFile opens the file read-only and runs SQLite's integrity check.
func checkDatabaseFile(ctx context.Context, path string) error {
	db, err := sql.Open("sqlite", "file:"+path+"?mode=ro")
	if err != nil {
		return err
	}
	defer db.Close()
	var res string
	if err := db.QueryRowContext(ctx, "PRAGMA integrity_check").Scan(&res); err != nil {
		return fmt.Errorf("the copy cannot be read as a database: %w", err)
	}
	if res != "ok" {
		return errors.New("SQLite's integrity check failed on the copy")
	}
	return nil
}

func databaseVersions(ctx context.Context, path string) (map[string]int, error) {
	db, err := sql.Open("sqlite", "file:"+path+"?mode=ro")
	if err != nil {
		return nil, err
	}
	defer db.Close()
	return sqlitedb.Versions(ctx, db)
}
