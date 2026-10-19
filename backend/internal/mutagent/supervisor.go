package mutagent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"example.invalid/dedicatedcloud/backend/internal/hypervisor"
	"example.invalid/dedicatedcloud/backend/internal/provision"
)

// Defaults and bounds.
const (
	DefaultDeadline = 2 * time.Minute
	MaxDeadline     = 10 * time.Minute
	maxConcurrent   = 4
)

var readDeadline = 5 * time.Second

// SupervisorConfig is server-owned. HelperPath is the exact helper executable; HelperArgs and Env are fixed by the operator
// (for example "--config /etc/svavyom/provision.json"); nothing in a request ever becomes part of the command line or the
// environment, and the helper is never started through a shell.
type SupervisorConfig struct {
	Socket        string
	AllowUIDs     []uint32
	HelperPath    string
	HelperArgs    []string
	Env           []string
	Deadline      time.Duration
	MaxConcurrent int
	// TrustedFiles are the fixed service files the helper depends on (its provisioning configuration). Like the helper itself they
	// must be regular non-symlink files owned by the deployment owner, not writable by the runtime identities, inside a directory
	// chain they cannot write; this is checked at start AND before every helper start.
	TrustedFiles []string
	// Trust decides who must own those files and which runtime identities must not be able to write them. The zero value is the
	// strict production policy; tests set provision.DevPolicy(), which is insecure and never used by a deployment.
	Trust provision.Policy
	// Deployment, when set, lists the remaining operator-owned anchors (catalog, store, published images) that violate the
	// policy; any entry refuses start and every later helper run. Labels only, never paths.
	Deployment func() []string
}

// Supervisor serves the mutation protocol on a Unix socket.
type Supervisor struct {
	cfg     SupervisorConfig
	ln      net.Listener
	uids    map[uint32]bool
	sem     chan struct{}
	wg      sync.WaitGroup
	closing chan struct{}
	once    sync.Once
}

// Listen validates the configuration and binds the socket (mode 0660). It refuses a relative or unclean socket path, an empty
// uid allowlist, a helper that is not an absolute path to an executable regular file, and replacing anything that is not a stale
// socket. The caller should place the socket in a directory only the supervisor user and the API's group can enter.
func Listen(cfg SupervisorConfig) (*Supervisor, error) {
	if !filepath.IsAbs(cfg.Socket) || filepath.Clean(cfg.Socket) != cfg.Socket || len(cfg.Socket) > 100 {
		return nil, errors.New("mutagent: socket path must be a clean absolute path of at most 100 bytes")
	}
	if len(cfg.AllowUIDs) == 0 {
		return nil, errors.New("mutagent: at least one allowed uid is required")
	}
	if err := checkTrustAnchors(cfg); err != nil {
		return nil, err
	}
	if cfg.Deadline <= 0 {
		cfg.Deadline = DefaultDeadline
	}
	cfg.Deadline = min(cfg.Deadline, MaxDeadline)
	if cfg.MaxConcurrent <= 0 {
		cfg.MaxConcurrent = 4 // two operation executors, one read-only request at a time from the API, and one spare
	}
	cfg.MaxConcurrent = min(cfg.MaxConcurrent, maxConcurrent)
	if err := removeStaleSocket(cfg.Socket); err != nil {
		return nil, err
	}
	old := syscall.Umask(0o117)
	ln, err := net.Listen("unix", cfg.Socket)
	syscall.Umask(old)
	if err != nil {
		return nil, fmt.Errorf("mutagent: listen: %w", err)
	}
	if err := os.Chmod(cfg.Socket, 0o660); err != nil { // #nosec G302 -- group access for the API user is the design
		_ = ln.Close()
		return nil, fmt.Errorf("mutagent: chmod: %w", err)
	}
	s := &Supervisor{cfg: cfg, ln: ln, uids: map[uint32]bool{}, sem: make(chan struct{}, cfg.MaxConcurrent), closing: make(chan struct{})}
	for _, u := range cfg.AllowUIDs {
		s.uids[u] = true
	}
	return s, nil
}

// checkTrustAnchors refuses a helper or configuration that an untrusted identity could replace: symlinks, non-regular files,
// foreign owners, group/world-writable files or directories (including the parents that could be used to swap them).
func checkTrustAnchors(cfg SupervisorConfig) error {
	if !filepath.IsAbs(cfg.HelperPath) {
		return errors.New("mutagent: the helper must be an absolute path")
	}
	if fi, err := os.Stat(cfg.HelperPath); err != nil || fi.Mode().Perm()&0o111 == 0 {
		return errors.New("mutagent: the helper must be an executable regular file")
	}
	for _, p := range append([]string{cfg.HelperPath}, cfg.TrustedFiles...) {
		if err := cfg.Trust.Asset(p, false); err != nil {
			return errors.New("mutagent: a service file or one of its parent directories is not trusted (symlink, wrong owner, or writable by the service identities)")
		}
		if !cfg.Trust.Insecure() && (provision.WritableByMe(p) || provision.WritableByMe(filepath.Dir(p))) {
			return errors.New("mutagent: this service identity could rewrite a trust anchor or its directory")
		}
	}
	if cfg.Deployment != nil && len(cfg.Deployment()) > 0 {
		return errors.New("mutagent: the catalog, image store or a published image is not operator-owned and read-only")
	}
	return nil
}

func removeStaleSocket(path string) error {
	fi, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if fi.Mode()&os.ModeSocket == 0 {
		return errors.New("mutagent: refusing to replace a non-socket file")
	}
	if c, err := net.DialTimeout("unix", path, time.Second); err == nil {
		_ = c.Close()
		return errors.New("mutagent: another supervisor is already listening")
	}
	return os.Remove(path)
}

// Serve accepts connections until Close.
func (s *Supervisor) Serve() error {
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			select {
			case <-s.closing:
				s.wg.Wait()
				return nil
			default:
				return err
			}
		}
		select {
		case s.sem <- struct{}{}:
		default: // at capacity: refuse rather than queue; the caller sees a delivery failure and retries later
			_ = conn.Close()
			continue
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer func() { <-s.sem }()
			s.handle(conn)
		}()
	}
}

// Close stops accepting new connections (requests in flight finish, bounded by the deadline).
func (s *Supervisor) Close() {
	s.once.Do(func() {
		close(s.closing)
		_ = s.ln.Close()
	})
}

func peerUID(conn net.Conn) (uint32, bool) {
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		return 0, false
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return 0, false
	}
	var cred *syscall.Ucred
	var cerr error
	if err := raw.Control(func(fd uintptr) {
		cred, cerr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED) // #nosec G115 -- fd fits int
	}); err != nil || cerr != nil || cred == nil {
		return 0, false
	}
	return cred.Uid, true
}

func (s *Supervisor) handle(conn net.Conn) {
	defer conn.Close()
	if uid, ok := peerUID(conn); !ok || !s.uids[uid] {
		return // silent
	}
	_ = conn.SetReadDeadline(time.Now().Add(readDeadline))
	var q Request
	if err := readFrame(conn, &q, MaxRequestBytes); err != nil || !q.Valid() {
		_ = conn.SetWriteDeadline(time.Now().Add(readDeadline))
		_ = writeFrame(conn, Reply{V: Version, Category: string(hypervisor.Validation)}, MaxReplyBytes)
		return
	}
	reply := s.run(q)
	_ = conn.SetWriteDeadline(time.Now().Add(readDeadline))
	_ = writeFrame(conn, reply, MaxReplyBytes)
}

func unknown() Reply { return Reply{V: Version, Category: string(hypervisor.Timeout)} }

// run executes one request in a fresh helper process and enforces the hard deadline. The helper receives the validated request
// on its standard input and answers on standard output; it runs in its own process group so that a kill reaches everything it
// started. Every outcome except a well-formed reply from a helper that exited 0 is reported as "unknown" (timeout).
func (s *Supervisor) run(q Request) Reply {
	body, err := json.Marshal(q)
	if err != nil {
		return Reply{V: Version, Category: string(hypervisor.HostError)}
	}
	if checkTrustAnchors(s.cfg) != nil {
		return Reply{V: Version, Category: string(hypervisor.Unavailable)} // refused before anything started: no effect
	}
	cmd := exec.Command(s.cfg.HelperPath, s.cfg.HelperArgs...) // #nosec G204 -- exact operator-configured executable and fixed arguments, no shell
	cmd.Env = append([]string(nil), s.cfg.Env...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Stdin = bytes.NewReader(body)
	var out limitedBuffer
	out.max = MaxReplyBytes + 1
	cmd.Stdout = &out
	cmd.Stderr = io.Discard
	if err := cmd.Start(); err != nil {
		return Reply{V: Version, Category: string(hypervisor.Unavailable)} // nothing started: the request had no effect
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	deadline := s.cfg.Deadline
	if LongOp(q.Op) {
		deadline = MaxDeadline // copying a disk is allowed longer than a libvirt call; still hard-bounded, and the process group is killed at expiry
	}
	timer := time.NewTimer(deadline)
	defer timer.Stop()
	select {
	case err := <-done:
		if err != nil || out.overflow {
			return unknown() // died, crashed or was killed mid-way: what it did is not known
		}
		var r Reply
		if decodeStrict(out.Bytes(), &r) != nil || r.V != Version {
			return unknown()
		}
		return r
	case <-timer.C:
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) // the whole group
		_ = cmd.Process.Kill()
		<-done // reap: no zombie, no lingering libvirt call
		return unknown()
	}
}

type limitedBuffer struct {
	bytes.Buffer
	max      int
	overflow bool
}

func (l *limitedBuffer) Write(p []byte) (int, error) {
	if l.Len()+len(p) > l.max {
		l.overflow = true
		return len(p), nil // keep draining so the helper is never blocked on a full pipe
	}
	return l.Buffer.Write(p)
}

var _ = context.Background
