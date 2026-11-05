// Package backupstore is the local backup store of the stopped-VM backup (M2-S07): one directory per backup holding the root overlay copy and a
// manifest with checksums. A backup becomes visible only when it is complete: it is written under a ".partial-" name, fsynced, and renamed into
// place as the last step, so a crash, a full disk or a cancelled run never leaves a valid-looking incomplete backup. Everything reads and writes
// through file descriptors opened relative to the store directory without following symlinks, and no caller-supplied text becomes a path: the only
// names are the server-generated backup id and two fixed file names.
package backupstore

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"syscall"
	"time"
)

// Errors (no caller input is echoed).
var (
	ErrStore    = errors.New("backupstore: the backup directory is not usable")
	ErrNotFound = errors.New("backupstore: no such backup")
	ErrCorrupt  = errors.New("backupstore: the backup is damaged or incomplete")
	ErrSpace    = errors.New("backupstore: not enough free space for the backup")
	ErrExists   = errors.New("backupstore: a backup with this id already exists")
)

// Schema is the manifest schema version.
const Schema = 1

// File names inside one backup.
const (
	ManifestFile = "manifest.json"
	ChecksumFile = "manifest.sha256"
	RootFile     = "root.qcow2"
)

var (
	idRE        = regexp.MustCompile(`^bk-[0-9a-f]{16}$`)
	hexRE       = regexp.MustCompile(`^[0-9a-f]{64}$`)
	dirPathRE   = regexp.MustCompile(`^/[A-Za-z0-9._/-]{1,198}$`)
	partialPref = ".partial-"
)

// ValidID reports whether id has the grammar of a backup id.
func ValidID(id string) bool { return idRE.MatchString(id) }

// VM is the part of the manifest describing the machine that was backed up. The SSH key itself is not stored (only its fingerprint, which is
// public information); a restore asks for a key again.
type VM struct {
	Name           string `json:"name"`
	UUID           string `json:"uuid"`
	Fingerprint    string `json:"fingerprint"`
	ImageID        string `json:"image_id"`
	ImageSHA256    string `json:"image_sha256"`
	LoginUser      string `json:"login_user"`
	VCPUs          int    `json:"vcpus"`
	MemoryMiB      int    `json:"memory_mib"`
	DiskGiB        int    `json:"disk_gib"`
	Network        string `json:"network"`
	SSHFingerprint string `json:"ssh_fingerprint,omitempty"`
}

// Root describes the copied root overlay.
type Root struct {
	File             string `json:"file"`
	Size             int64  `json:"size_bytes"`
	SHA256           string `json:"sha256"`
	Format           string `json:"format"` // "qcow2-overlay": only the blocks the VM wrote; the backing image is referenced by digest
	VirtualSizeBytes int64  `json:"virtual_size_bytes"`
}

// Manifest is the backup's table of contents.
type Manifest struct {
	Schema    int    `json:"schema"`
	BackupID  string `json:"backup_id"`
	CreatedAt string `json:"created_at"`
	Tool      string `json:"tool"`
	VM        VM     `json:"vm"`
	Root      Root   `json:"root"`
}

// Validate checks every field against its grammar and its bounds.
func (m Manifest) Validate() error {
	vmName := regexp.MustCompile(`^[a-z]([a-z0-9-]{0,61}[a-z0-9])?$`)
	uuid := regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	image := regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,62}$`)
	user := regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)
	net := regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$`)
	if m.Schema != Schema || !idRE.MatchString(m.BackupID) {
		return ErrCorrupt
	}
	if _, err := time.Parse(time.RFC3339, m.CreatedAt); err != nil {
		return ErrCorrupt
	}
	v := m.VM
	if !vmName.MatchString(v.Name) || !uuid.MatchString(v.UUID) || !hexRE.MatchString(v.Fingerprint) || !image.MatchString(v.ImageID) || !hexRE.MatchString(v.ImageSHA256) ||
		!user.MatchString(v.LoginUser) || v.VCPUs < 1 || v.VCPUs > 64 || v.MemoryMiB < 64 || v.MemoryMiB > 1048576 || v.DiskGiB < 1 || v.DiskGiB > 4096 || !net.MatchString(v.Network) ||
		len(v.SSHFingerprint) > 80 || strings.ContainsAny(v.SSHFingerprint, "\r\n\"") {
		return ErrCorrupt
	}
	r := m.Root
	if r.File != RootFile || r.Format != "qcow2-overlay" || r.Size <= 0 || r.Size > 1<<46 || !hexRE.MatchString(r.SHA256) || r.VirtualSizeBytes != int64(v.DiskGiB)<<30 {
		return ErrCorrupt
	}
	return nil
}

// Store is one backup directory.
type Store struct{ dir string }

// Open validates the directory: absolute, clean, plain characters, an existing directory (not a symlink) owned by the current user, closed to
// group and others. It never creates or changes anything.
func Open(dir string) (*Store, error) {
	if !dirPathRE.MatchString(dir) || filepath.Clean(dir) != dir || dir == "/" {
		return nil, ErrStore
	}
	fi, err := os.Lstat(dir)
	if err != nil || !fi.IsDir() || fi.Mode()&os.ModeSymlink != 0 {
		return nil, ErrStore
	}
	if real, err := filepath.EvalSymlinks(dir); err != nil || real != dir { // no symlink in any component
		return nil, ErrStore
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || int(st.Uid) != os.Geteuid() || fi.Mode().Perm()&0o077 != 0 { // #nosec G115 -- uid fits int
		return nil, ErrStore
	}
	return &Store{dir: dir}, nil
}

// Dir is the validated directory.
func (s *Store) Dir() string { return s.dir }

func (s *Store) path(id string, rest ...string) string {
	return filepath.Join(append([]string{s.dir, id}, rest...)...)
}

// FreeBytes reports the space available to the current user on the store's filesystem.
func (s *Store) FreeBytes() (int64, error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(s.dir, &st); err != nil {
		return 0, ErrStore
	}
	return int64(st.Bavail) * int64(st.Bsize), nil // #nosec G115 -- block counts of a real filesystem
}

// TotalBytes reports the size of the store's filesystem (for a free-space percentage).
func (s *Store) TotalBytes() (int64, error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(s.dir, &st); err != nil {
		return 0, ErrStore
	}
	return int64(st.Blocks) * int64(st.Bsize), nil // #nosec G115 -- block counts of a real filesystem
}

// Writer builds one backup.
type Writer struct {
	s       *Store
	id      string
	tmp     string
	f       *os.File
	h       hash.Hash
	written int64
}

// Begin starts a backup. Any earlier ".partial-" directory of the same id (a crashed attempt) is removed first; an id that already exists as a
// finished backup is refused. needBytes is the space the root copy is expected to take; the store refuses to start without 10% headroom.
func (s *Store) Begin(id string, needBytes int64) (*Writer, error) {
	if !idRE.MatchString(id) {
		return nil, ErrStore
	}
	if _, err := os.Lstat(s.path(id)); err == nil {
		return nil, ErrExists
	}
	free, err := s.FreeBytes()
	if err != nil {
		return nil, err
	}
	if needBytes < 0 || free < needBytes+needBytes/10+(1<<20) {
		return nil, ErrSpace
	}
	tmp := filepath.Join(s.dir, partialPref+id)
	if err := removeTree(tmp); err != nil {
		return nil, ErrStore
	}
	if err := os.Mkdir(tmp, 0o700); err != nil {
		return nil, ErrStore
	}
	f, err := os.OpenFile(filepath.Join(tmp, RootFile), os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600) // #nosec G304 -- fixed name inside the id directory we just created
	if err != nil {
		_ = removeTree(tmp)
		return nil, ErrStore
	}
	return &Writer{s: s, id: id, tmp: tmp, f: f, h: sha256.New()}, nil
}

// Write implements io.Writer for the root copy.
func (w *Writer) Write(p []byte) (int, error) {
	n, err := w.f.Write(p)
	_, _ = w.h.Write(p[:n])
	w.written += int64(n)
	return n, err
}

// Size is the number of bytes written so far.
func (w *Writer) Size() int64 { return w.written }

// Check lets fn inspect what has been written so far (read-only, through a fresh descriptor) before the backup is committed.
func (w *Writer) Check(fn func(r io.ReaderAt, size int64) error) error {
	rf, err := os.OpenFile(filepath.Join(w.tmp, RootFile), os.O_RDONLY|syscall.O_NOFOLLOW, 0) // #nosec G304 -- our own partial directory, fixed name
	if err != nil {
		return ErrStore
	}
	defer rf.Close()
	fi, err := rf.Stat()
	if err != nil || fi.Size() != w.written {
		return ErrCorrupt
	}
	return fn(rf, fi.Size())
}

// Abort discards the partial backup.
func (w *Writer) Abort() {
	_ = w.f.Close()
	_ = removeTree(w.tmp)
}

// Commit finishes the backup: the root file is fsynced, its size and digest are put into the manifest, the manifest and its checksum are written and
// fsynced, and the directory is renamed into place. m.Root is completed here (File, Size, SHA256, Format); the caller supplies the rest.
func (w *Writer) Commit(m Manifest) (Manifest, error) {
	if err := w.f.Sync(); err != nil {
		w.Abort()
		return Manifest{}, ErrStore
	}
	if err := w.f.Close(); err != nil {
		w.Abort()
		return Manifest{}, ErrStore
	}
	m.Schema, m.BackupID = Schema, w.id
	m.Root.File, m.Root.Size, m.Root.SHA256, m.Root.Format = RootFile, w.written, hex.EncodeToString(w.h.Sum(nil)), "qcow2-overlay"
	if err := m.Validate(); err != nil {
		w.Abort()
		return Manifest{}, err
	}
	body, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		w.Abort()
		return Manifest{}, ErrStore
	}
	body = append(body, '\n')
	sum := sha256.Sum256(body)
	if err := writeSynced(filepath.Join(w.tmp, ManifestFile), body); err != nil {
		w.Abort()
		return Manifest{}, ErrStore
	}
	if err := writeSynced(filepath.Join(w.tmp, ChecksumFile), []byte(hex.EncodeToString(sum[:])+"  "+ManifestFile+"\n")); err != nil {
		w.Abort()
		return Manifest{}, ErrStore
	}
	if d, err := os.Open(w.tmp); err == nil { // #nosec G304 -- our own partial directory
		_ = d.Sync()
		_ = d.Close()
	}
	if err := os.Rename(w.tmp, w.s.path(w.id)); err != nil {
		w.Abort()
		return Manifest{}, ErrStore
	}
	if d, err := os.Open(w.s.dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return m, nil
}

func writeSynced(path string, b []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600) // #nosec G304 -- fixed names inside our partial directory
	if err != nil {
		return err
	}
	if _, err := f.Write(b); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

// removeTree removes a directory that this package created (a ".partial-" or a backup directory) by removing its known files and then the
// directory itself: never a recursive walk, never a path from outside.
func removeTree(dir string) error {
	for _, n := range []string{RootFile, ManifestFile, ChecksumFile} {
		if err := os.Remove(filepath.Join(dir, n)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	if err := os.Remove(dir); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// Backup is a verified, finished backup.
type Backup struct {
	Manifest Manifest
	dir      string
}

// RootPath is the path of the root copy (inside the store, validated).
func (b *Backup) RootPath() string { return filepath.Join(b.dir, RootFile) }

// FilePath is the path of one of the backup's three known files (name is ManifestFile, ChecksumFile or RootFile).
func (b *Backup) FilePath(name string) (string, bool) {
	switch name {
	case ManifestFile, ChecksumFile, RootFile:
		return filepath.Join(b.dir, name), true
	}
	return "", false
}

// OpenFile opens one of the backup's three known files for reading without following symlinks.
func (b *Backup) OpenFile(name string) (*os.File, error) {
	p, ok := b.FilePath(name)
	if !ok {
		return nil, ErrStore
	}
	return os.OpenFile(p, os.O_RDONLY|syscall.O_NOFOLLOW, 0) // #nosec G304 -- inside the validated store, one of three fixed names
}

// OpenRoot opens the root copy for reading without following symlinks.
func (b *Backup) OpenRoot() (*os.File, error) {
	return os.OpenFile(b.RootPath(), os.O_RDONLY|syscall.O_NOFOLLOW, 0) // #nosec G304 -- inside the validated store, fixed name
}

// Verify opens a finished backup and proves it intact: the directory holds exactly the three known regular files, the manifest matches its
// checksum, validates, names this id, and the root copy has the recorded size and SHA-256 (re-hashed in full). A backup that fails any check is
// ErrCorrupt and must not be used.
func (s *Store) Verify(id string) (*Backup, error) {
	if !idRE.MatchString(id) {
		return nil, ErrNotFound
	}
	return verifyDir(s.path(id), id)
}

// verifyDir is Verify for the backup id held in dir, wherever dir is (a finished backup, or an import's partial directory before it is made visible).
func verifyDir(dir, id string) (*Backup, error) {
	fi, err := os.Lstat(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNotFound
	}
	if err != nil || !fi.IsDir() || fi.Mode()&os.ModeSymlink != 0 {
		return nil, ErrCorrupt
	}
	ents, err := os.ReadDir(dir)
	if err != nil || len(ents) != 3 {
		return nil, ErrCorrupt
	}
	for _, e := range ents {
		if e.Name() != RootFile && e.Name() != ManifestFile && e.Name() != ChecksumFile {
			return nil, ErrCorrupt
		}
		if info, err := e.Info(); err != nil || !info.Mode().IsRegular() {
			return nil, ErrCorrupt
		}
	}
	body, err := readSmall(filepath.Join(dir, ManifestFile), 64<<10)
	if err != nil {
		return nil, ErrCorrupt
	}
	sumFile, err := readSmall(filepath.Join(dir, ChecksumFile), 512)
	if err != nil {
		return nil, ErrCorrupt
	}
	got := sha256.Sum256(body)
	if strings.TrimSpace(string(sumFile)) != hex.EncodeToString(got[:])+"  "+ManifestFile {
		return nil, ErrCorrupt
	}
	var m Manifest
	dec := json.NewDecoder(strings.NewReader(string(body)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&m); err != nil || m.Validate() != nil || m.BackupID != id {
		return nil, ErrCorrupt
	}
	f, err := os.OpenFile(filepath.Join(dir, RootFile), os.O_RDONLY|syscall.O_NOFOLLOW, 0) // #nosec G304 -- fixed name inside the validated store
	if err != nil {
		return nil, ErrCorrupt
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil || n != m.Root.Size || hex.EncodeToString(h.Sum(nil)) != m.Root.SHA256 {
		return nil, ErrCorrupt
	}
	return &Backup{Manifest: m, dir: dir}, nil
}

func readSmall(path string, max int64) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0) // #nosec G304 -- fixed names inside the validated store
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil || int64(len(b)) > max {
		return nil, ErrCorrupt
	}
	return b, nil
}

// Summary is a backup as listed (the manifest was read and checksummed, the root copy was NOT re-hashed: Verify does that before any use).
type Summary struct {
	Manifest Manifest
	Valid    bool
}

// List returns every backup directory, newest first. Directories that are not backups (".partial-*", anything else) are ignored; a directory
// named like a backup whose manifest does not check out is reported with Valid false and a zero manifest carrying only its id.
func (s *Store) List() ([]Summary, error) {
	ents, err := os.ReadDir(s.dir)
	if err != nil {
		return nil, ErrStore
	}
	var out []Summary
	for _, e := range ents {
		if !idRE.MatchString(e.Name()) || !e.IsDir() {
			continue
		}
		sum := Summary{Manifest: Manifest{BackupID: e.Name()}}
		if body, err := readSmall(filepath.Join(s.dir, e.Name(), ManifestFile), 64<<10); err == nil {
			if sf, err := readSmall(filepath.Join(s.dir, e.Name(), ChecksumFile), 512); err == nil {
				h := sha256.Sum256(body)
				var m Manifest
				dec := json.NewDecoder(strings.NewReader(string(body)))
				dec.DisallowUnknownFields()
				if strings.TrimSpace(string(sf)) == hex.EncodeToString(h[:])+"  "+ManifestFile && dec.Decode(&m) == nil && m.Validate() == nil && m.BackupID == e.Name() {
					sum = Summary{Manifest: m, Valid: true}
				}
			}
		}
		out = append(out, sum)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Manifest.CreatedAt > out[j].Manifest.CreatedAt })
	return out, nil
}

// Delete removes one finished backup (its three known files, then the directory). A missing backup is not an error.
func (s *Store) Delete(id string) error {
	if !idRE.MatchString(id) {
		return ErrNotFound
	}
	dir := s.path(id)
	fi, err := os.Lstat(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil || !fi.IsDir() || fi.Mode()&os.ModeSymlink != 0 {
		return ErrCorrupt
	}
	ents, err := os.ReadDir(dir)
	if err != nil {
		return ErrStore
	}
	for _, e := range ents { // refuse to delete a directory that holds anything this package did not put there
		if e.Name() != RootFile && e.Name() != ManifestFile && e.Name() != ChecksumFile {
			return ErrCorrupt
		}
	}
	return removeTree(dir)
}

// UsageBytes is the total size of the finished backups' root copies (from their manifests).
func (s *Store) UsageBytes() int64 {
	var n int64
	l, _ := s.List()
	for _, b := range l {
		if b.Valid {
			n += b.Manifest.Root.Size
		}
	}
	return n
}

// CleanPartials removes ".partial-*" directories (crashed attempts) that are older than maxAge.
func (s *Store) CleanPartials(maxAge time.Duration) int {
	ents, _ := os.ReadDir(s.dir)
	n := 0
	for _, e := range ents {
		if !strings.HasPrefix(e.Name(), partialPref) || !idRE.MatchString(strings.TrimPrefix(e.Name(), partialPref)) {
			continue
		}
		if info, err := e.Info(); err == nil && time.Since(info.ModTime()) > maxAge && removeTree(filepath.Join(s.dir, e.Name())) == nil {
			n++
		}
	}
	return n
}

func (m Manifest) String() string { return fmt.Sprintf("backup %s of %s", m.BackupID, m.VM.Name) }

// Files are the three file names of a backup, in the order an import fetches them (small files first).
var Files = []string{ManifestFile, ChecksumFile, RootFile}

// ImportFrom adds a backup that was made elsewhere (fetched from an off-host copy): fetch writes each of the three files into the writer it is given;
// the files go to a ".partial-" directory, the finished backup is verified in full (checksum, manifest, size and SHA-256 of the root copy) and renamed
// into place only if it is intact. A backup of that id that already exists is refused. needBytes is the expected size of the root copy.
func (s *Store) ImportFrom(id string, needBytes int64, fetch func(name string, w io.Writer) error) error {
	if !idRE.MatchString(id) {
		return ErrStore
	}
	if _, err := os.Lstat(s.path(id)); err == nil {
		return ErrExists
	}
	free, err := s.FreeBytes()
	if err != nil {
		return err
	}
	if needBytes < 0 || free < needBytes+needBytes/10+(1<<20) {
		return ErrSpace
	}
	tmp := filepath.Join(s.dir, partialPref+id)
	if err := removeTree(tmp); err != nil {
		return ErrStore
	}
	if err := os.Mkdir(tmp, 0o700); err != nil {
		return ErrStore
	}
	fail := func(e error) error { _ = removeTree(tmp); return e }
	for _, name := range Files {
		f, err := os.OpenFile(filepath.Join(tmp, name), os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600) // #nosec G304 -- one of three fixed names in the directory we just created
		if err != nil {
			return fail(ErrStore)
		}
		lim := int64(64 << 10)
		if name == RootFile {
			lim = needBytes + importSlackBytes // the size the target reported, plus a little: a hostile or broken target cannot stream past it
		}
		werr := fetch(name, &limitWriter{w: f, left: lim})
		serr := f.Sync()
		cerr := f.Close()
		if werr != nil || serr != nil || cerr != nil {
			return fail(ErrStore)
		}
	}
	// Verified in full while it is still a ".partial-" directory (which List ignores), and only then made visible: a backup that is listed has been checked.
	if _, err := verifyDir(tmp, id); err != nil {
		return fail(ErrCorrupt)
	}
	if err := os.Rename(tmp, s.path(id)); err != nil {
		return fail(ErrStore)
	}
	if d, err := os.Open(s.dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}

// importSlackBytes is how far past the expected size of the root copy an import accepts before it gives up.
const importSlackBytes = 64 << 10

// limitWriter fails once more than left bytes would be written, so a hostile or broken source cannot fill the disk past the expected size.
type limitWriter struct {
	w    io.Writer
	left int64
}

func (l *limitWriter) Write(p []byte) (int, error) {
	if int64(len(p)) > l.left {
		return 0, ErrSpace
	}
	n, err := l.w.Write(p)
	l.left -= int64(n)
	return n, err
}
