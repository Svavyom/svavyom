package offsite

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"example.invalid/dedicatedcloud/backend/internal/backupstore"
	"example.invalid/dedicatedcloud/backend/internal/hypervisor"
	"example.invalid/dedicatedcloud/backend/internal/provision"
)

// Exporter copies verified backups to the declared targets and fetches them back. A copy is made under a ".partial-<id>" name, hashed at the
// target, and renamed into place only when every file matches; a failed or mismatching copy is removed (only the partial one, never anything that
// was already there). Everything it runs on a remote host is a fixed command template whose only variable parts passed a closed grammar (the
// backup id and the operator's own directory), and ssh is started without a shell with a pinned host key and no configuration file.
type Exporter struct {
	Store    *backupstore.Store
	Targets  []provision.BackupTarget
	StateDir string // owned by the service: copies.json and the generated known_hosts files
	SSH      string // path of the ssh client ("" means /usr/bin/ssh)
	Timeout  time.Duration

	mu sync.Mutex
}

// fileNames of one copy.
var copyFiles = backupstore.Files

var sumRE = regexp.MustCompile(`^([0-9a-f]{64})  `)

func (e *Exporter) target(id string) (provision.BackupTarget, bool) {
	for _, t := range e.Targets {
		if t.ID == id {
			return t, true
		}
	}
	return provision.BackupTarget{}, false
}

func (e *Exporter) timeout() time.Duration {
	if e.Timeout > 0 {
		return e.Timeout
	}
	return 6 * time.Hour // a large root overlay over a slow link; the operation layer's own deadline is the real bound
}

func (e *Exporter) sshPath() string {
	if e.SSH != "" {
		return e.SSH
	}
	return "/usr/bin/ssh"
}

// States reports each declared target as ready or unavailable. It touches nothing remote: a path target must be a directory this identity can
// write, an ssh target needs its key file to be readable and the ssh client to exist. Reachability is found out when a copy is made.
func (e *Exporter) States() []TargetState {
	out := make([]TargetState, 0, len(e.Targets))
	for _, t := range e.Targets {
		st := "unavailable"
		switch t.Kind {
		case "path":
			if fi, err := os.Stat(t.Dir); err == nil && fi.IsDir() && syscall.Access(t.Dir, 2) == nil { // #nosec G104 -- Access returns the error compared below
				st = "ready"
			}
		case "ssh":
			if _, err := os.Stat(e.sshPath()); err == nil {
				if f, err := os.Open(t.KeyFile); err == nil { // #nosec G304 -- the operator's own key path from the provisioning configuration
					_ = f.Close()
					st = "ready"
				}
			}
		}
		out = append(out, TargetState{ID: t.ID, Kind: t.Kind, State: st})
	}
	return out
}

// ---- the record of verified copies ----------------------------------------------------------------------------------------------

type copyDoc struct {
	Schema int                 `json:"schema"`
	Copies map[string][]string `json:"copies"`
}

func (e *Exporter) recordPath() string { return filepath.Join(e.StateDir, "copies.json") }

func (e *Exporter) load() (map[string][]string, error) {
	b, err := os.ReadFile(e.recordPath())
	if errors.Is(err, os.ErrNotExist) {
		return map[string][]string{}, nil
	}
	if err != nil || len(b) > 4<<20 {
		return nil, errors.New("offsite: the record of copies cannot be read")
	}
	var d copyDoc
	if err := json.Unmarshal(b, &d); err != nil || d.Schema != 1 || d.Copies == nil {
		return nil, errors.New("offsite: the record of copies is damaged")
	}
	return d.Copies, nil
}

func (e *Exporter) save(m map[string][]string) error {
	b, err := json.MarshalIndent(copyDoc{Schema: 1, Copies: m}, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(e.StateDir, ".copies-*")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	if _, err := tmp.Write(append(b, '\n')); err != nil || tmp.Chmod(0o600) != nil || tmp.Sync() != nil || tmp.Close() != nil {
		return errors.New("offsite: the record of copies cannot be written")
	}
	return os.Rename(tmp.Name(), e.recordPath())
}

// Copies lists, per backup, the declared targets that hold a verified copy. A target no longer declared is not listed.
func (e *Exporter) Copies() ([]Copy, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	m, err := e.load()
	if err != nil {
		return nil, err
	}
	declared := map[string]bool{}
	for _, t := range e.Targets {
		declared[t.ID] = true
	}
	var out []Copy
	for id, ts := range m {
		if !backupstore.ValidID(id) {
			continue
		}
		var keep []string
		for _, t := range ts {
			if declared[t] {
				keep = append(keep, t)
			}
		}
		if len(keep) > 0 {
			sort.Strings(keep)
			out = append(out, Copy{Backup: id, Targets: keep})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Backup < out[j].Backup })
	if len(out) > maxCopies {
		out = out[:maxCopies]
	}
	return out, nil
}

func (e *Exporter) record(backup, target string) error {
	m, err := e.load()
	if err != nil {
		return err
	}
	for _, t := range m[backup] {
		if t == target {
			return nil
		}
	}
	m[backup] = append(m[backup], target)
	sort.Strings(m[backup])
	return e.save(m)
}

// ---- export ---------------------------------------------------------------------------------------------------------------------

// fileSum is the SHA-256 and size of one local file.
type fileSum struct {
	name string
	sum  string
	size int64
}

// Export copies backup id to the target and verifies the copy there. It is safe to run again: a verified copy that is already in place is success.
func (e *Exporter) Export(ctx context.Context, id, targetID string) error {
	t, ok := e.target(targetID)
	if !ok {
		return &Error{Category: "not_found"}
	}
	if !backupstore.ValidID(id) {
		return &Error{Category: "validation"}
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	b, err := e.Store.Verify(id) // the local copy is proven intact first: a damaged backup is never exported
	switch {
	case errors.Is(err, backupstore.ErrNotFound):
		return &Error{Category: "not_found"}
	case err != nil:
		return &Error{Category: "conflict"}
	}
	var sums []fileSum
	for _, name := range copyFiles {
		f, err := b.OpenFile(name)
		if err != nil {
			return &Error{Category: "host_error"}
		}
		h := sha256.New()
		n, err := io.Copy(h, f)
		_ = f.Close()
		if err != nil {
			return &Error{Category: "host_error"}
		}
		sums = append(sums, fileSum{name: name, sum: hex.EncodeToString(h.Sum(nil)), size: n})
	}
	ctx, cancel := context.WithTimeout(ctx, e.timeout())
	defer cancel()
	var xerr error
	switch t.Kind {
	case "path":
		xerr = e.exportPath(t, b, sums)
	case "ssh":
		xerr = e.exportSSH(ctx, t, b, sums)
	}
	if xerr != nil {
		return xerr
	}
	if err := e.record(id, targetID); err != nil {
		return &Error{Category: "host_error"}
	}
	return nil
}

// ---- prune (retention of scheduled copies) ----------------------------------------------------------------------------------------

func (e *Exporter) unrecord(backup, target string) error {
	m, err := e.load()
	if err != nil {
		return err
	}
	var keep []string
	for _, t := range m[backup] {
		if t != target {
			keep = append(keep, t)
		}
	}
	if len(keep) == 0 {
		delete(m, backup)
	} else {
		m[backup] = keep
	}
	return e.save(m)
}

// Prune removes the copy of backup id that this service itself exported to the target (retention of scheduled backups, DR-024 D3). It deletes nothing it
// did not write: the copy must be recorded for that target, only the three known files and then the empty directory are removed, a symbolic link in
// place of the copy is refused, and a directory that holds anything else is left alone. A copy that is already gone is success.
func (e *Exporter) Prune(ctx context.Context, id, targetID string) error {
	t, ok := e.target(targetID)
	if !ok {
		return &Error{Category: "not_found"}
	}
	if !backupstore.ValidID(id) {
		return &Error{Category: "validation"}
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	m, err := e.load()
	if err != nil {
		return &Error{Category: "host_error"}
	}
	recorded := false
	for _, x := range m[id] {
		recorded = recorded || x == targetID
	}
	if !recorded {
		return nil // never exported here (or already pruned): nothing of ours to remove
	}
	ctx, cancel := context.WithTimeout(ctx, e.timeout())
	defer cancel()
	var perr error
	switch t.Kind {
	case "path":
		perr = e.prunePath(t, id)
	case "ssh":
		perr = e.pruneSSH(ctx, t, id)
	}
	if perr != nil {
		return perr
	}
	if err := e.unrecord(id, targetID); err != nil {
		return &Error{Category: "host_error"}
	}
	return nil
}

func (e *Exporter) prunePath(t provision.BackupTarget, id string) error {
	final := filepath.Join(t.Dir, id)
	if fi, err := os.Lstat(t.Dir); err != nil || !fi.IsDir() {
		return &Error{Category: "unavailable"}
	}
	fi, err := os.Lstat(final)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return nil
	case err != nil:
		return &Error{Category: "unavailable"}
	case !fi.IsDir():
		return &Error{Category: "conflict"} // a link or a file where the copy should be: never followed, never removed
	}
	for _, n := range copyFiles {
		if err := os.Remove(filepath.Join(final, n)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return &Error{Category: "unavailable"}
		}
	}
	if err := os.Remove(final); err != nil && !errors.Is(err, os.ErrNotExist) {
		return &Error{Category: "conflict"} // something else lives in there: left alone
	}
	return nil
}

func (e *Exporter) pruneSSH(ctx context.Context, t provision.BackupTarget, id string) error {
	final := t.Dir + "/" + id
	if err := e.remote(ctx, t, "test -d "+quote(final)+" && ! test -L "+quote(final), nil, io.Discard); err != nil {
		if CategoryOf(err) == "timeout" {
			return err
		}
		// Either the copy is already gone or it is a link: look once more to tell them apart.
		if e.remote(ctx, t, "test -e "+quote(final)+" || test -L "+quote(final), nil, io.Discard) == nil {
			return &Error{Category: "conflict"}
		}
		return nil
	}
	return e.remote(ctx, t, "rm -f -- "+quote(final+"/"+copyFiles[0])+" "+quote(final+"/"+copyFiles[1])+" "+quote(final+"/"+copyFiles[2])+" && rmdir -- "+quote(final), nil, io.Discard)
}

// Error is the only error type of the package: a closed category and no free text.
type Error struct{ Category string }

func (e *Error) Error() string { return "offsite: " + e.Category }

// CategoryOf returns the category of an error of this package ("" for others).
func CategoryOf(err error) string {
	var e *Error
	if errors.As(err, &e) {
		return e.Category
	}
	return ""
}

func hashMatches(path string, want fileSum) bool {
	f, err := os.Open(path) // #nosec G304 -- inside a directory the operator declared, names from a fixed set
	if err != nil {
		return false
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, f)
	return err == nil && n == want.size && hex.EncodeToString(h.Sum(nil)) == want.sum
}

// exportPath copies into a directory the operator mounted: the three files go to "<dir>/.partial-<id>", every file is re-read and compared, and the
// directory is renamed to "<dir>/<id>". An existing "<dir>/<id>" that matches is success; one that does not is a conflict and is left alone.
func (e *Exporter) exportPath(t provision.BackupTarget, b *backupstore.Backup, sums []fileSum) error {
	id := b.Manifest.BackupID
	final, partial := filepath.Join(t.Dir, id), filepath.Join(t.Dir, ".partial-"+id)
	if fi, err := os.Lstat(t.Dir); err != nil || !fi.IsDir() {
		return &Error{Category: "unavailable"}
	}
	if _, err := os.Lstat(final); err == nil {
		for _, s := range sums {
			if !hashMatches(filepath.Join(final, s.name), s) {
				return &Error{Category: "conflict"} // somebody else's data under this name: never overwritten, never deleted
			}
		}
		return nil
	}
	removePartial := func() {
		for _, n := range copyFiles {
			_ = os.Remove(filepath.Join(partial, n))
		}
		_ = os.Remove(partial)
	}
	removePartial() // an earlier attempt that died
	if err := os.Mkdir(partial, 0o700); err != nil {
		return &Error{Category: "unavailable"}
	}
	for _, s := range sums {
		src, err := b.OpenFile(s.name)
		if err != nil {
			removePartial()
			return &Error{Category: "host_error"}
		}
		dst, err := os.OpenFile(filepath.Join(partial, s.name), os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600) // #nosec G304 -- a fixed name in the partial directory just created
		if err != nil {
			_ = src.Close()
			removePartial()
			return &Error{Category: "unavailable"}
		}
		_, cerr := io.Copy(dst, src)
		serr := dst.Sync()
		_ = src.Close()
		if err := dst.Close(); cerr != nil || serr != nil || err != nil {
			removePartial()
			return &Error{Category: "unavailable"}
		}
		if !hashMatches(filepath.Join(partial, s.name), s) {
			removePartial()
			return &Error{Category: "host_error"} // the copy does not match what was sent: removed and reported
		}
	}
	if err := os.Rename(partial, final); err != nil {
		removePartial()
		return &Error{Category: "unavailable"}
	}
	if d, err := os.Open(t.Dir); err == nil { // #nosec G304 -- the operator's directory
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}

// ---- ssh --------------------------------------------------------------------------------------------------------------------

// sshArgs builds the fixed ssh command line for a target. The host key is pinned through a generated known_hosts file; no configuration file, no
// agent, no password prompt, no forwarding.
func (e *Exporter) sshArgs(t provision.BackupTarget) ([]string, error) {
	port := t.Port
	if port == 0 {
		port = 22
	}
	kh := filepath.Join(e.StateDir, "known_hosts-"+t.ID)
	line := t.HostKey + "\n"
	if port == 22 {
		line = t.Host + " " + line
	} else {
		line = "[" + t.Host + "]:" + strconv.Itoa(port) + " " + line
	}
	if err := os.WriteFile(kh, []byte(line), 0o600); err != nil {
		return nil, err
	}
	return []string{"-F", "/dev/null", "-p", strconv.Itoa(port), "-i", t.KeyFile,
		"-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes", "-o", "IdentityAgent=none", "-o", "StrictHostKeyChecking=yes",
		"-o", "UserKnownHostsFile=" + kh, "-o", "GlobalKnownHostsFile=/dev/null", "-o", "PasswordAuthentication=no",
		"-o", "ForwardAgent=no", "-o", "ClearAllForwardings=yes", "-o", "RequestTTY=no", "-o", "ConnectTimeout=20",
		"-o", "ServerAliveInterval=20", "-o", "ServerAliveCountMax=6", "-o", "LogLevel=ERROR", t.User + "@" + t.Host}, nil
}

// remote runs one fixed remote command, feeding stdin and returning stdout. The command string is built by this package from validated parts only.
func (e *Exporter) remote(ctx context.Context, t provision.BackupTarget, command string, stdin io.Reader, stdout io.Writer) error {
	args, err := e.sshArgs(t)
	if err != nil {
		return &Error{Category: "unavailable"}
	}
	cmd := exec.CommandContext(ctx, e.sshPath(), append(args, "--", command)...) // #nosec G204 -- fixed binary, fixed options, validated host/user/key, and a command string built from a closed grammar
	cmd.Env = []string{"PATH=/usr/bin:/bin", "LC_ALL=C", "HOME=" + e.StateDir}
	cmd.Stdin = stdin
	cmd.Stdout = stdout
	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return &Error{Category: "timeout"}
		}
		return &Error{Category: "unavailable"}
	}
	return nil
}

func quote(p string) string { return "'" + p + "'" } // p passed targetDirRE plus a backup id: no quote character is possible

func (e *Exporter) remoteSum(ctx context.Context, t provision.BackupTarget, path string) (string, error) {
	var out strings.Builder
	if err := e.remote(ctx, t, "sha256sum -- "+quote(path), nil, &out); err != nil {
		return "", err
	}
	m := sumRE.FindStringSubmatch(out.String())
	if m == nil {
		return "", &Error{Category: "host_error"}
	}
	return m[1], nil
}

func (e *Exporter) exportSSH(ctx context.Context, t provision.BackupTarget, b *backupstore.Backup, sums []fileSum) error {
	id := b.Manifest.BackupID
	final, partial := t.Dir+"/"+id, t.Dir+"/.partial-"+id
	// An existing copy that matches is success; one that does not is a conflict that is left alone.
	if err := e.remote(ctx, t, "test -d "+quote(final), nil, io.Discard); err == nil {
		for _, s := range sums {
			got, err := e.remoteSum(ctx, t, final+"/"+s.name)
			if err != nil || got != s.sum {
				return &Error{Category: "conflict"}
			}
		}
		return nil
	} else if CategoryOf(err) == "timeout" {
		return err
	}
	cleanup := func() {
		cctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		_ = e.remote(cctx, t, "rm -f -- "+quote(partial+"/"+copyFiles[0])+" "+quote(partial+"/"+copyFiles[1])+" "+quote(partial+"/"+copyFiles[2])+" && rmdir -- "+quote(partial), nil, io.Discard)
	}
	cleanup() // an earlier attempt that died
	if err := e.remote(ctx, t, "mkdir -p -- "+quote(t.Dir)+" && mkdir -m 700 -- "+quote(partial), nil, io.Discard); err != nil {
		return err
	}
	for _, s := range sums {
		src, err := b.OpenFile(s.name)
		if err != nil {
			cleanup()
			return &Error{Category: "host_error"}
		}
		rerr := e.remote(ctx, t, "umask 077 && cat > "+quote(partial+"/"+s.name)+" && sync", src, io.Discard)
		_ = src.Close()
		if rerr != nil {
			cleanup()
			return rerr
		}
		got, err := e.remoteSum(ctx, t, partial+"/"+s.name)
		if err != nil {
			cleanup()
			return err
		}
		if got != s.sum {
			cleanup()
			return &Error{Category: "host_error"} // the copy does not match what was sent: removed and reported
		}
	}
	if err := e.remote(ctx, t, "mv -- "+quote(partial)+" "+quote(final), nil, io.Discard); err != nil {
		cleanup()
		return err
	}
	return nil
}

// ---- import (the operator's way back) -------------------------------------------------------------------------------------------

// Import fetches backup id from the target into the local store. The files are verified in full before the backup becomes visible, and an
// existing local backup of that id is never replaced.
func (e *Exporter) Import(ctx context.Context, id, targetID string) error {
	t, ok := e.target(targetID)
	if !ok {
		return &Error{Category: "not_found"}
	}
	if !backupstore.ValidID(id) {
		return &Error{Category: "validation"}
	}
	ctx, cancel := context.WithTimeout(ctx, e.timeout())
	defer cancel()
	need := int64(0)
	var size func() (int64, error)
	switch t.Kind {
	case "path":
		size = func() (int64, error) {
			fi, err := os.Stat(filepath.Join(t.Dir, id, backupstore.RootFile))
			if err != nil {
				return 0, &Error{Category: "not_found"}
			}
			return fi.Size(), nil
		}
	case "ssh":
		size = func() (int64, error) {
			var out strings.Builder
			if err := e.remote(ctx, t, "stat -c %s -- "+quote(t.Dir+"/"+id+"/"+backupstore.RootFile), nil, &out); err != nil {
				return 0, err
			}
			n, err := strconv.ParseInt(strings.TrimSpace(out.String()), 10, 64)
			if err != nil || n <= 0 {
				return 0, &Error{Category: "not_found"}
			}
			return n, nil
		}
	}
	need, err := size()
	if err != nil {
		return err
	}
	err = e.Store.ImportFrom(id, need, func(name string, w io.Writer) error {
		switch t.Kind {
		case "path":
			f, err := os.OpenFile(filepath.Join(t.Dir, id, name), os.O_RDONLY|syscall.O_NOFOLLOW, 0) // #nosec G304 -- the operator's directory, a validated id and one of three fixed names
			if err != nil {
				return err
			}
			defer f.Close()
			_, err = io.Copy(w, f)
			return err
		default:
			return e.remote(ctx, t, "cat -- "+quote(t.Dir+"/"+id+"/"+name), nil, w)
		}
	})
	switch {
	case err == nil:
		return nil
	case errors.Is(err, backupstore.ErrExists):
		return &Error{Category: "conflict"}
	case errors.Is(err, backupstore.ErrSpace):
		return &Error{Category: "conflict"}
	case errors.Is(err, backupstore.ErrCorrupt):
		return &Error{Category: "host_error"}
	}
	if c := CategoryOf(err); c != "" {
		return err
	}
	return &Error{Category: "unavailable"}
}

// hypervisorCategory maps an offsite category to the category the operation layer understands.
func HypervisorCategory(c string) hypervisor.Category {
	switch c {
	case "validation":
		return hypervisor.Validation
	case "not_found":
		return hypervisor.NotFound
	case "conflict":
		return hypervisor.Conflict
	case "timeout":
		return hypervisor.Timeout
	case "unavailable":
		return hypervisor.Unavailable
	}
	return hypervisor.HostError
}

// ToHypervisorError turns an error of this package into the *hypervisor.Error the operation layer understands (a closed category, no text).
func ToHypervisorError(op string, err error) error {
	if err == nil {
		return nil
	}
	return hypervisor.NewError(HypervisorCategory(CategoryOf(err)), op, "", "offsite")
}

// Exporting is what the API side needs of the service: copy a backup to a target.
type Exporting interface {
	Export(ctx context.Context, backup, target string) error
}
