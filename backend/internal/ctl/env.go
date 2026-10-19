// Package ctl is the operator tool behind `svavyom-ctl`: host preflight, configuration validation, service status, support bundle, install, upgrade,
// rollback and uninstall (M4). It is NOT a service: it runs when an administrator runs it, links no libvirt, opens no network listener, and never takes
// a path, command or XML from anything but its own command line and the root-owned installation. Everything that touches the host goes through Env, so
// the tests drive the same code with a temporary root and a recording runner.
package ctl

import (
	"context"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

// Standard installation paths (relative to Env.Root, which is "/" on a real host).
const (
	LibexecDir   = "/usr/libexec/svavyom"
	ConfigDir    = "/etc/svavyom"
	ConfigFile   = "/etc/svavyom/provision.json"
	LibDir       = "/var/lib/svavyom"
	UnitDir      = "/etc/systemd/system"
	SysusersFile = "/etc/sysusers.d/svavyom.conf"
	TmpfilesFile = "/etc/tmpfiles.d/svavyom.conf"
	ShareDir     = "/usr/share/svavyom"
	BackupRoot   = "/var/lib/svavyom/upgrade-backups"
	VersionFile  = "/usr/libexec/svavyom/VERSION"
)

// Units in start order (stop order is the reverse). The agent, the mutation supervisor and the console broker come up before the API that connects to them.
var Units = []string{"svavyom-agent.service", "svavyom-mutation.service", "svavyom-offsite.service", "svavyom-console.service", "svavyom-api.service"}

// Binaries installed into LibexecDir, by artifact name.
var Binaries = []string{"api", "agent", "mutation-supervisor", "mutation-helper", "offsite", "console-broker", "svavyom-ctl"}

// Runner executes a fixed command line (no shell) and returns its combined output. A non-nil error carries the exit status.
type Runner interface {
	Run(ctx context.Context, name string, args ...string) (string, error)
}

// execRunner is the real Runner: fixed argv, a minimal environment, a deadline and a bounded output.
type execRunner struct{ timeout time.Duration }

// NewRunner returns the Runner for a real host.
func NewRunner() Runner { return execRunner{timeout: 60 * time.Second} }

func (r execRunner) Run(ctx context.Context, name string, args ...string) (string, error) {
	cctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()
	cmd := exec.CommandContext(cctx, name, args...) // #nosec G204 -- every caller passes a fixed command name and fixed or validated arguments; no shell
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C", "SYSTEMD_COLORS=0", "SYSTEMD_PAGER="}
	out, err := cmd.CombinedOutput()
	if len(out) > 1<<20 {
		out = out[:1<<20]
	}
	return string(out), err
}

// Env is everything a command needs from the host. The zero value is not usable; use NewEnv.
type Env struct {
	// Root is prefixed to every standard path ("/" or "" on a real host; a temporary directory in tests).
	Root string
	Run  Runner
	Now  func() time.Time
	// Sleep waits between health polls; tests replace it so a fake clock can advance.
	Sleep func(ctx context.Context, d time.Duration) error
	// Euid reports the effective user id; Chown changes ownership (a no-op error in unprivileged tests).
	Euid  func() int
	Chown func(path string, uid, gid int) error
	// Lstat/ReadFile/Statfs are the read primitives the checks use; tests replace them to fake /dev/kvm and similar.
	Lstat    func(path string) (fs.FileInfo, error)
	ReadFile func(path string) ([]byte, error)
	Statfs   func(path string) (freeBytes uint64, err error)
	LookPath func(name string) (string, error)
	Dial     func(path string) error
	// Getpw resolves a service user to its numeric ids and Getgr resolves a group (the real ones use os/user).
	Getpw func(name string) (uid, gid int, err error)
	Getgr func(name string) (gid int, err error)
}

// NewEnv returns the Env of the running host.
func NewEnv() *Env {
	return &Env{Root: "/", Run: NewRunner(), Now: time.Now, Sleep: realSleep, Euid: os.Geteuid, Chown: os.Lchown, Lstat: os.Lstat, ReadFile: readFileBounded,
		Statfs: statfsFree, LookPath: exec.LookPath, Dial: dialUnix, Getpw: lookupUser, Getgr: lookupGroup}
}

// P joins a standard path to the root.
func (e *Env) P(p string) string {
	if e.Root == "" || e.Root == "/" {
		return p
	}
	return filepath.Join(e.Root, strings.TrimPrefix(p, "/"))
}

func readFileBounded(path string) ([]byte, error) {
	f, err := os.Open(path) // #nosec G304 -- operator-controlled paths and fixed system files
	if err != nil {
		return nil, err
	}
	defer f.Close()
	buf := make([]byte, 0, 4096)
	tmp := make([]byte, 32<<10)
	for len(buf) < 4<<20 {
		n, rerr := f.Read(tmp)
		buf = append(buf, tmp[:n]...)
		if rerr != nil {
			break
		}
	}
	return buf, nil
}

func statfsFree(path string) (uint64, error) {
	var s syscall.Statfs_t
	if err := syscall.Statfs(path, &s); err != nil {
		return 0, err
	}
	return s.Bavail * uint64(s.Bsize), nil // #nosec G115 -- block size is positive
}

func realSleep(ctx context.Context, d time.Duration) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(d):
		return nil
	}
}
