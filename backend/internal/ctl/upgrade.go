package ctl

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"example.invalid/dedicatedcloud/backend/internal/sqlitedb"
)

// BackupMeta describes one pre-upgrade backup. It never contains a secret; the database copy and the configuration inside the backup directory are 0600/0644 under a 0700 directory.
type BackupMeta struct {
	ID          string         `json:"id"`
	CreatedAt   string         `json:"created_at"`
	FromVersion string         `json:"from_version"`
	ToVersion   string         `json:"to_version"`
	DBVersions  map[string]int `json:"db_schema_versions_before"`
	HasDB       bool           `json:"has_database_copy"`
	Files       []string       `json:"files"`
}

var backupIDRE = regexp.MustCompile(`^[0-9]{8}T[0-9]{6}Z-[A-Za-z0-9.+-]{1,40}$`)

// installedVersion returns the recorded version, or "" when the host has no recorded installation.
func (e *Env) installedVersion() string {
	b, err := e.ReadFile(e.P(VersionFile))
	if err != nil {
		return ""
	}
	return clean(strings.TrimSpace(string(b)))
}

func (e *Env) dbPath() string { return e.P(LibDir + "/api/svavyom.db") }

// dbVersions reads the recorded schema versions of the API database read-only; a missing database yields an empty map.
func (e *Env) dbVersions(ctx context.Context) (map[string]int, bool) {
	db, err := sqlitedb.OpenReadOnly(e.dbPath())
	if err != nil {
		return map[string]int{}, false
	}
	defer db.Close()
	v, err := sqlitedb.Versions(ctx, db)
	if err != nil {
		return map[string]int{}, true
	}
	return v, true
}

// copyTree copies a directory tree of regular files (no symlinks) preserving modes.
func copyTree(src, dst string) ([]string, error) {
	var done []string
	err := filepath.WalkDir(src, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		target := filepath.Join(dst, rel)
		if d.IsDir() {
			return os.MkdirAll(target, 0o700)
		}
		if !d.Type().IsRegular() {
			return nil // a symlink or special file is not part of an installation we made
		}
		b, err := os.ReadFile(p) // #nosec G304,G122 -- walking the installation's own root-owned tree; symlinks and special files were skipped above
		if err != nil {
			return err
		}
		fi, _ := d.Info()
		if err := os.WriteFile(target, b, fi.Mode().Perm()|0o200); err != nil { // #nosec G703 -- target is under the backup directory the tool just created (0700); rel comes from walking our own tree
			return err
		}
		done = append(done, rel)
		return nil
	})
	return done, err
}

// snapshotInstall copies everything an application upgrade changes into a new backup directory: the installed binaries, web assets, units and drop-ins, the
// configuration, the VERSION record and a consistent copy of the API database (VACUUM INTO). It does not copy VM disks, the pool, images, backups or the TLS key.
func (e *Env) snapshotInstall(ctx context.Context, from, to string) (BackupMeta, error) {
	id := e.Now().UTC().Format("20060102T150405Z") + "-" + strings.NewReplacer("/", "_", " ", "_").Replace(clean(from+"-to-"+to))
	if len(id) > 60 {
		id = id[:60]
	}
	dir := e.P(BackupRoot + "/" + id)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return BackupMeta{}, err
	}
	meta := BackupMeta{ID: id, CreatedAt: e.Now().UTC().Format(time.RFC3339), FromVersion: from, ToVersion: to}
	for _, t := range []struct{ src, dst string }{
		{LibexecDir, "libexec"}, {ShareDir + "/web", "web"}, {UnitDir, "units"}, {ConfigDir, "config"},
	} {
		if _, err := os.Stat(e.P(t.src)); err != nil {
			continue
		}
		if err := os.MkdirAll(filepath.Join(dir, t.dst), 0o700); err != nil {
			return meta, err
		}
		var files []string
		var err error
		if t.dst == "units" {
			files, err = copyUnits(e.P(t.src), filepath.Join(dir, t.dst))
		} else if t.dst == "config" {
			files, err = copyTLSFree(e.P(t.src), filepath.Join(dir, t.dst))
		} else {
			files, err = copyTree(e.P(t.src), filepath.Join(dir, t.dst))
		}
		if err != nil {
			return meta, fmt.Errorf("backing up %s: %w", t.src, err)
		}
		for _, f := range files {
			meta.Files = append(meta.Files, t.dst+"/"+f)
		}
	}
	meta.DBVersions, meta.HasDB = e.dbVersions(ctx)
	if meta.HasDB {
		if err := e.copyDatabase(ctx, filepath.Join(dir, "database.sqlite")); err != nil {
			return meta, fmt.Errorf("backing up the database: %w", err)
		}
	}
	sort.Strings(meta.Files)
	b, _ := json.MarshalIndent(meta, "", "  ")
	return meta, os.WriteFile(filepath.Join(dir, "backup.json"), append(b, '\n'), 0o600)
}

// copyUnits copies only Svavyom's unit files and drop-in directories, not the other units of /etc/systemd/system.
func copyUnits(src, dst string) ([]string, error) {
	var done []string
	ents, err := os.ReadDir(src)
	if err != nil {
		return nil, err
	}
	for _, en := range ents {
		if !strings.HasPrefix(en.Name(), "svavyom-") {
			continue
		}
		if en.IsDir() {
			if err := os.MkdirAll(filepath.Join(dst, en.Name()), 0o700); err != nil {
				return nil, err
			}
			fs2, err := copyTree(filepath.Join(src, en.Name()), filepath.Join(dst, en.Name()))
			if err != nil {
				return nil, err
			}
			for _, f := range fs2 {
				done = append(done, en.Name()+"/"+f)
			}
			continue
		}
		if en.Type().IsRegular() {
			b, err := os.ReadFile(filepath.Join(src, en.Name())) // #nosec G304 -- Svavyom's own unit files
			if err != nil {
				return nil, err
			}
			if err := os.WriteFile(filepath.Join(dst, en.Name()), b, 0o600); err != nil { // #nosec G703 -- a name read from Svavyom's own unit directory, written under the new backup directory
				return nil, err
			}
			done = append(done, en.Name())
		}
	}
	return done, nil
}

// copyTLSFree copies /etc/svavyom except the tls directory: a private key is never copied into a backup.
func copyTLSFree(src, dst string) ([]string, error) {
	var done []string
	ents, err := os.ReadDir(src)
	if err != nil {
		return nil, err
	}
	for _, en := range ents {
		if en.IsDir() || !en.Type().IsRegular() {
			continue
		}
		b, err := os.ReadFile(filepath.Join(src, en.Name())) // #nosec G304 -- the configuration directory
		if err != nil {
			return nil, err
		}
		if err := os.WriteFile(filepath.Join(dst, en.Name()), b, 0o600); err != nil { // #nosec G703 -- a name read from the configuration directory, written under the new backup directory
			return nil, err
		}
		done = append(done, en.Name())
	}
	return done, nil
}

// copyDatabase makes a consistent copy of the API database with SQLite's own VACUUM INTO (safe while the file is in use).
func (e *Env) copyDatabase(ctx context.Context, dst string) error {
	db, err := sql.Open("sqlite", "file:"+e.dbPath()+"?mode=ro")
	if err != nil {
		return err
	}
	defer db.Close()
	if _, err := db.ExecContext(ctx, "VACUUM INTO ?", dst); err != nil {
		return err
	}
	return os.Chmod(dst, 0o600)
}

// stopAll stops the units in reverse order; startAll starts them in order.
func (e *Env) stopAll(ctx context.Context) error {
	for i := len(Units) - 1; i >= 0; i-- {
		if _, err := e.ReadFile(e.P(UnitDir + "/" + Units[i])); err != nil {
			continue
		}
		if out, err := e.Run.Run(ctx, "systemctl", "stop", "--", Units[i]); err != nil {
			return fmt.Errorf("systemctl stop %s: %s", Units[i], clean(out))
		}
	}
	return nil
}

// startAll reloads systemd and (re)starts the units in dependency order. A unit that crash-looped (a bad new build) is in systemd's start-limit state, where a plain
// start is refused ("Start request repeated too quickly"), so the failed state is cleared first: it is what lets a rollback restart the previous version.
func (e *Env) startAll(ctx context.Context) error {
	if out, err := e.Run.Run(ctx, "systemctl", "daemon-reload"); err != nil {
		return fmt.Errorf("systemctl daemon-reload: %s", clean(out))
	}
	for _, u := range Units {
		if _, err := e.ReadFile(e.P(UnitDir + "/" + u)); err != nil {
			continue // a version that predates this unit (a rollback to it) has no such service to start
		}
		_, _ = e.Run.Run(ctx, "systemctl", "reset-failed", "--", u) // a unit that is not failed answers nothing useful; the start below is what must succeed
		if out, err := e.Run.Run(ctx, "systemctl", "enable", "--", u); err != nil {
			return fmt.Errorf("systemctl enable %s: %s", u, clean(out))
		}
		// restart, not start: a re-run of install over a running system must make the service use the new files and configuration it just wrote
		if out, err := e.Run.Run(ctx, "systemctl", "restart", "--", u); err != nil {
			return fmt.Errorf("systemctl restart %s: %s", u, clean(out))
		}
	}
	return nil
}

// UpgradeOptions are the inputs of an application upgrade.
type UpgradeOptions struct {
	InstallOptions
	// AllowDowngrade permits an artifact with a lower version than the installed one (the schema rule still applies).
	AllowDowngrade bool
}

// semverLess orders MAJOR.MINOR.PATCH[-pre] (a pre-release sorts before the release).
func semverLess(a, b string) bool {
	pa, pb := splitVer(a), splitVer(b)
	for i := 0; i < 3; i++ {
		if pa.n[i] != pb.n[i] {
			return pa.n[i] < pb.n[i]
		}
	}
	switch {
	case pa.pre == pb.pre:
		return false
	case pa.pre == "":
		return false
	case pb.pre == "":
		return true
	}
	return preLess(pa.pre, pb.pre)
}

// preLess orders two non-empty pre-release strings as semantic versioning does: dot-separated identifiers compared one by one, numbers by value (so
// "preview.10" is newer than "preview.9"), a number lower than a name, and the shorter list lower when all it has is equal.
func preLess(a, b string) bool {
	x, y := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < len(x) && i < len(y); i++ {
		if x[i] == y[i] {
			continue
		}
		nx, ex := strconv.Atoi(x[i])
		ny, ey := strconv.Atoi(y[i])
		switch {
		case ex == nil && ey == nil:
			return nx < ny
		case ex == nil:
			return true
		case ey == nil:
			return false
		}
		return x[i] < y[i]
	}
	return len(x) < len(y)
}

type ver struct {
	n   [3]int
	pre string
}

func splitVer(s string) ver {
	var v ver
	main, pre, _ := strings.Cut(s, "-")
	v.pre = pre
	_, _ = fmt.Sscanf(main, "%d.%d.%d", &v.n[0], &v.n[1], &v.n[2])
	return v
}

// schemaOK reports components for which the database is newer than what the build can read.
func schemaAhead(db, build map[string]int) []string {
	var bad []string
	for c, v := range db {
		if b, ok := build[c]; ok && v > b {
			bad = append(bad, fmt.Sprintf("%s (database %d, build %d)", c, v, b))
		}
	}
	sort.Strings(bad)
	return bad
}

// Upgrade moves an installation to a newer verified artifact: compatibility and configuration checks, a backup, an ordered stop, the new files, an ordered start
// and a health check. A failure after the stop restores the previous files automatically (and the database copy only if the new build already migrated it); VMs,
// images, the pool and backups are never touched.
func Upgrade(ctx context.Context, e *Env, o UpgradeOptions, w io.Writer) error {
	o.defaults()
	if err := o.validate(); err != nil {
		return err
	}
	m, err := VerifyArtifact(o.Artifact)
	if err != nil {
		return err
	}
	cur := e.installedVersion()
	_, _ = fmt.Fprintf(w, "installed: %s   artifact: %s\n", orNone(cur), m.Version)
	if cur == "" {
		return errors.New("no installed version is recorded: use `install` for a first install, or write the version to " + VersionFile + " after checking it")
	}
	if cur == m.Version {
		return fmt.Errorf("version %s is already installed; nothing to upgrade", cur)
	}
	if semverLess(m.Version, cur) && !o.AllowDowngrade {
		return fmt.Errorf("the artifact (%s) is older than the installed version (%s): refusing; use rollback to return to a backed-up version", m.Version, cur)
	}
	if e.Euid() != 0 && o.Apply {
		return errors.New("--apply needs root (run with sudo)")
	}
	dbv, _ := e.dbVersions(ctx)
	if bad := schemaAhead(dbv, m.SchemaVersions); len(bad) > 0 {
		return fmt.Errorf("the artifact cannot read the database schema (%s): refusing; this is an irreversible schema change already in your database", strings.Join(bad, ", "))
	}
	pre := ValidateConfig(ctx, e, ValidateOptions{})
	if pre.Verdict == Fail {
		pre.Text(w)
		return errors.New("the installed configuration does not validate; fix it before upgrading")
	}
	p := &Plan{}
	var meta BackupMeta
	p.add("back up binaries, web assets, units, configuration and a consistent copy of the database into "+BackupRoot+" (no VM disk, image, pool or backup is read)", func() error {
		var err error
		meta, err = e.snapshotInstall(ctx, cur, m.Version)
		if err == nil {
			_, _ = fmt.Fprintf(w, "      backup %s (%d files, database copy: %v)\n", meta.ID, len(meta.Files), meta.HasDB)
		}
		return err
	})
	p.add("stop the services in reverse order ("+strings.Join(reverse(Units), ", ")+")", func() error { return e.stopAll(ctx) })
	p.add("refresh the account and directory definitions ("+SysusersFile+", "+TmpfilesFile+") so a service added by this release has its directories", func() error { return e.installAccounts(ctx, o.Artifact) })
	e.installSteps(p, m, o.InstallOptions, w)
	p.add("start the services in order and check health (schema migrations run when the API starts)", func() error {
		if err := e.startAll(ctx); err != nil {
			return err
		}
		return e.waitHealthy(ctx, 90*time.Second)
	})
	p.add("check the firewall for conflicts with the VM network and record the result (read-only; no rule is changed)", func() error { return e.recordFirewall(ctx) })
	e.nightlyStep(ctx, p, o.InstallOptions, w)
	err = p.Run(w, o.Apply)
	if err == nil || !o.Apply || meta.ID == "" {
		if err == nil && o.Apply {
			_, _ = fmt.Fprintf(w, "upgraded %s -> %s; backup %s is kept for `svavyom-ctl rollback`\n", cur, m.Version, meta.ID)
		}
		return err
	}
	_, _ = fmt.Fprintf(w, "\nUPGRADE FAILED: %s\nrestoring the previous version from backup %s ...\n", clean(err.Error()), meta.ID)
	if rerr := Rollback(ctx, e, RollbackOptions{BackupID: meta.ID, Apply: true, AutoRestoreDB: true}, w); rerr != nil {
		return fmt.Errorf("upgrade failed (%v) and the automatic rollback failed (%v); recovery: restore from %s/%s by hand (see docs/OPERATIONS.md)", err, rerr, BackupRoot, meta.ID)
	}
	return fmt.Errorf("upgrade failed and was rolled back to %s: %w", cur, err)
}

func reverse(l []string) []string {
	out := make([]string, len(l))
	for i, s := range l {
		out[len(l)-1-i] = s
	}
	return out
}

func orNone(s string) string {
	if s == "" {
		return "(none recorded)"
	}
	return s
}

// RollbackOptions are the inputs of a rollback.
type RollbackOptions struct {
	// BackupID names the backup to restore; "latest" (or empty) picks the newest.
	BackupID string
	Apply    bool
	// RestoreDB also puts the pre-upgrade database copy back (discarding what the database learned since). Required when the schema moved on.
	RestoreDB bool
	// AutoRestoreDB is set by a failed upgrade: it restores the database only if the schema advanced.
	AutoRestoreDB bool
}

// ListBackups returns the backups newest first.
func (e *Env) ListBackups() ([]BackupMeta, error) {
	ents, err := os.ReadDir(e.P(BackupRoot))
	if err != nil {
		return nil, err
	}
	var out []BackupMeta
	for _, en := range ents {
		if !en.IsDir() || !backupIDRE.MatchString(en.Name()) {
			continue
		}
		b, err := os.ReadFile(filepath.Join(e.P(BackupRoot), en.Name(), "backup.json")) // #nosec G304 -- our own backup directory
		if err != nil {
			continue
		}
		var m BackupMeta
		if json.Unmarshal(b, &m) == nil && m.ID == en.Name() {
			out = append(out, m)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID > out[j].ID })
	return out, nil
}

// Rollback restores the files of a backup (binaries, web assets, units, configuration, VERSION) and restarts the services. It refuses to cross an irreversible
// schema change: if the database has been migrated past what the backed-up version can read, the only way back is the database copy from the same backup, which
// loses what the database recorded since, and that requires --restore-db. VM disks, images, the pool and backups are never touched.
func Rollback(ctx context.Context, e *Env, o RollbackOptions, w io.Writer) error {
	bl, err := e.ListBackups()
	if err != nil || len(bl) == 0 {
		return errors.New("there is no upgrade backup to roll back to")
	}
	meta := bl[0]
	if o.BackupID != "" && o.BackupID != "latest" {
		found := false
		for _, b := range bl {
			if b.ID == o.BackupID {
				meta, found = b, true
			}
		}
		if !found {
			return errors.New("no such backup: " + clean(o.BackupID))
		}
	}
	cur := e.installedVersion()
	_, _ = fmt.Fprintf(w, "installed: %s   rolling back to %s (backup %s)\n", orNone(cur), meta.FromVersion, meta.ID)
	if e.Euid() != 0 && o.Apply {
		return errors.New("--apply needs root (run with sudo)")
	}
	dbNow, _ := e.dbVersions(ctx)
	ahead := schemaAhead(dbNow, meta.DBVersions)
	restoreDB := o.RestoreDB
	if len(ahead) > 0 {
		switch {
		case o.AutoRestoreDB && meta.HasDB:
			restoreDB = true
		case !o.RestoreDB:
			return fmt.Errorf("refusing: the database schema moved past what %s can read (%s), which is an irreversible change. The only way back is the pre-upgrade database copy in backup %s, which discards what the database recorded since: re-run with --restore-db if you accept that", meta.FromVersion, strings.Join(ahead, ", "), meta.ID)
		case !meta.HasDB:
			return errors.New("refusing: the schema moved on and this backup has no database copy")
		}
	}
	dir := e.P(BackupRoot + "/" + meta.ID)
	p := &Plan{}
	p.add("stop the services in reverse order", func() error { return e.stopAll(ctx) })
	p.add("restore the backed-up binaries, web assets, units, configuration and VERSION (the TLS key and VM storage are not touched)", func() error { return e.restoreFiles(dir, meta) })
	if restoreDB {
		p.add("restore the pre-upgrade database copy (the current database is kept next to it as svavyom.db.replaced-<time>)", func() error { return e.restoreDatabase(dir) })
	}
	p.add("start the services in order and check health", func() error {
		if err := e.startAll(ctx); err != nil {
			return err
		}
		return e.waitHealthy(ctx, 90*time.Second)
	})
	if err := p.Run(w, o.Apply); err != nil {
		return err
	}
	if o.Apply {
		_, _ = fmt.Fprintf(w, "rolled back to %s\n", meta.FromVersion)
	}
	return nil
}

func (e *Env) restoreFiles(dir string, meta BackupMeta) error {
	for _, t := range []struct{ src, dst string }{{"libexec", LibexecDir}, {"web", ShareDir + "/web"}} {
		srcDir := filepath.Join(dir, t.src)
		if _, err := os.Stat(srcDir); err != nil {
			continue
		}
		err := filepath.WalkDir(srcDir, func(p string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return err
			}
			rel, _ := filepath.Rel(srcDir, p)
			b, err := os.ReadFile(p) // #nosec G304,G122 -- our own root-owned backup directory (0700)
			if err != nil {
				return err
			}
			mode := os.FileMode(0o644)
			if t.src == "libexec" && rel != "VERSION" {
				mode = 0o755
			}
			dst := e.P(t.dst + "/" + filepath.ToSlash(rel))
			if err := e.ensureDir(filepath.Dir(dst), 0o755, 0, 0); err != nil {
				return err
			}
			_, err = e.writeAtomic(dst, b, mode, 0, 0)
			return err
		})
		if err != nil {
			return err
		}
	}
	// Units: the backed-up Svavyom units and drop-ins replace the current ones; a drop-in that did not exist before is removed.
	cur, _ := os.ReadDir(e.P(UnitDir))
	for _, en := range cur {
		if !strings.HasPrefix(en.Name(), "svavyom-") {
			continue
		}
		if _, err := os.Lstat(filepath.Join(dir, "units", en.Name())); err != nil {
			if en.IsDir() {
				_ = os.RemoveAll(filepath.Join(e.P(UnitDir), en.Name()))
			} else {
				_ = os.Remove(filepath.Join(e.P(UnitDir), en.Name()))
			}
		}
	}
	if err := filepath.WalkDir(filepath.Join(dir, "units"), func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel, _ := filepath.Rel(filepath.Join(dir, "units"), p)
		b, err := os.ReadFile(p) // #nosec G304,G122 -- our own root-owned backup directory (0700)
		if err != nil {
			return err
		}
		dst := e.P(UnitDir + "/" + filepath.ToSlash(rel))
		if err := e.ensureDir(filepath.Dir(dst), 0o755, 0, 0); err != nil {
			return err
		}
		_, err = e.writeAtomic(dst, b, 0o644, 0, 0)
		return err
	}); err != nil && !os.IsNotExist(err) {
		return err
	}
	if b, err := os.ReadFile(filepath.Join(dir, "config", "provision.json")); err == nil { // #nosec G304 -- our own backup directory
		if _, err := e.writeAtomic(e.P(ConfigFile), b, 0o644, 0, 0); err != nil {
			return err
		}
	}
	_, err := e.writeAtomic(e.P(VersionFile), []byte(meta.FromVersion+"\n"), 0o644, 0, 0)
	return err
}

func (e *Env) restoreDatabase(dir string) error {
	return e.restoreDatabaseFile(filepath.Join(dir, "database.sqlite"))
}

// restoreDatabaseFile puts the database file src in place of the live one; the live one is kept beside it as svavyom.db.replaced-<time>.
func (e *Env) restoreDatabaseFile(src string) error {
	b, err := os.ReadFile(src) // #nosec G304 -- our own backup directory
	if err != nil {
		return errors.New("the backup has no database copy")
	}
	cur := e.dbPath()
	uid, gid, _ := e.Getpw("svavyom-api")
	if _, err := os.Lstat(cur); err == nil {
		if err := os.Rename(cur, cur+".replaced-"+e.Now().UTC().Format("20060102T150405Z")); err != nil {
			return err
		}
	}
	for _, sfx := range []string{"-wal", "-shm"} {
		_ = os.Remove(cur + sfx)
	}
	_, err = e.writeAtomic(cur, b, 0o600, uid, gid)
	return err
}
