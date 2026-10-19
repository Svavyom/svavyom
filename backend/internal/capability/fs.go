// Package capability is the read-only distribution capability checker
// (story M0-E02-S05; DR-007 D1/D2/D3 = A). It reports whether a filesystem
// root conforms to the M0 support matrix. It never modifies anything, starts
// no processes, opens no sockets or devices and needs no privilege. A
// "supported" verdict means matrix conformance only, never host
// qualification ("qualification": "none").
package capability

import (
	"errors"
	"io"
	"io/fs"
	"os"
	"path"
	"strings"
	"syscall"
)

// Typed filesystem errors; probes map them to reasons.
var (
	ErrTooLarge   = errors.New("input exceeds read limit")
	ErrNotRegular = errors.New("not a regular file")
	ErrEscape     = errors.New("path escapes the root")
	ErrLoop       = errors.New("too many symbolic links")
	ErrVanished   = errors.New("file vanished between lstat and read")
)

// maxHops bounds symlink resolution of the final path component.
const maxHops = 40

// FS is the only way probes touch the filesystem: lstat, readlink and a
// bounded read of a regular file. Tests inject faults through it.
type FS interface {
	Lstat(name string) (fs.FileInfo, error)
	Readlink(name string) (string, error)
	ReadRegular(name string, limit int64) ([]byte, error)
}

// rootFS confines every access to a directory with os.Root: no path,
// including symlink targets in intermediate components, can leave it.
type rootFS struct{ r *os.Root }

// OpenRoot returns an FS confined to dir.
func OpenRoot(dir string) (FS, func() error, error) {
	r, err := os.OpenRoot(dir)
	if err != nil {
		return nil, nil, err
	}
	return rootFS{r}, r.Close, nil
}

func (f rootFS) Lstat(name string) (fs.FileInfo, error) { return f.r.Lstat(name) }

func (f rootFS) Readlink(name string) (string, error) { return f.r.Readlink(name) }

// ReadRegular opens name only if lstat shows a regular file, with
// O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC, re-checks the type on the descriptor and
// reads at most limit bytes. Devices, FIFOs and sockets are never opened.
func (f rootFS) ReadRegular(name string, limit int64) ([]byte, error) {
	fi, err := f.r.Lstat(name)
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, ErrNotRegular
	}
	file, err := f.r.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, ErrVanished // it existed at lstat: unknown, never "absent" (review N1)
	}
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()
	st, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() {
		return nil, ErrNotRegular
	}
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, ErrTooLarge
	}
	return data, nil
}

// resolve follows relative symlinks in the final path component inside the
// root (at most maxHops). Absolute targets and ".." escapes are refused
// (ErrEscape), matching os.Root, which confines intermediate components
// (erratum r2a, note 2).
func resolve(fsys FS, name string) (string, error) {
	cur := path.Clean(name)
	for hop := 0; ; hop++ {
		if cur == ".." || strings.HasPrefix(cur, "../") || strings.HasPrefix(cur, "/") {
			return "", ErrEscape
		}
		fi, err := fsys.Lstat(cur)
		if err != nil {
			return "", err
		}
		if fi.Mode()&fs.ModeSymlink == 0 {
			return cur, nil
		}
		if hop >= maxHops {
			return "", ErrLoop
		}
		target, err := fsys.Readlink(cur)
		if err != nil {
			return "", err
		}
		if strings.HasPrefix(target, "/") {
			return "", ErrEscape
		}
		// ".." after a symlinked parent directory would be resolved lexically
		// here but physically by the kernel; refuse it (review N2).
		if hasDotDot(target) {
			linked, err := parentIsSymlink(fsys, cur)
			if err != nil {
				return "", err
			}
			if linked {
				return "", ErrEscape
			}
		}
		cur = path.Clean(path.Join(path.Dir(cur), target))
	}
}

func hasDotDot(target string) bool {
	for _, part := range strings.Split(target, "/") {
		if part == ".." {
			return true
		}
	}
	return false
}

// parentIsSymlink reports whether any directory component of name is a symlink.
func parentIsSymlink(fsys FS, name string) (bool, error) {
	dir := path.Dir(name)
	if dir == "." {
		return false, nil
	}
	prefix := ""
	for _, part := range strings.Split(dir, "/") {
		prefix = path.Join(prefix, part)
		fi, err := fsys.Lstat(prefix)
		if err != nil {
			return false, err
		}
		if fi.Mode()&fs.ModeSymlink != 0 {
			return true, nil
		}
	}
	return false, nil
}

// read resolves name and reads it with the given limit.
func read(fsys FS, name string, limit int64) ([]byte, error) {
	p, err := resolve(fsys, name)
	if err != nil {
		return nil, err
	}
	return fsys.ReadRegular(p, limit)
}

// lstatResolved resolves name and lstats the result (never opens it).
func lstatResolved(fsys FS, name string) (fs.FileInfo, error) {
	p, err := resolve(fsys, name)
	if err != nil {
		return nil, err
	}
	return fsys.Lstat(p)
}

// reasonFor maps an access error to a typed probe reason.
func reasonFor(err error) string {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, ErrTooLarge):
		return "INPUT_TOO_LARGE"
	case errors.Is(err, ErrNotRegular):
		return "NOT_REGULAR_FILE"
	case errors.Is(err, ErrEscape):
		return "PATH_ESCAPE"
	case errors.Is(err, ErrLoop), errors.Is(err, syscall.ELOOP):
		return "PATH_LOOP"
	case errors.Is(err, ErrVanished):
		return "VANISHED"
	case errors.Is(err, fs.ErrNotExist):
		return "MISSING"
	case errors.Is(err, fs.ErrPermission):
		return "PERMISSION_DENIED"
	case strings.Contains(err.Error(), "escapes"):
		return "PATH_ESCAPE"
	default:
		return "IO_ERROR"
	}
}
