package offsite

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"
)

// ServerConfig is server-owned. Nothing in a request becomes part of it.
type ServerConfig struct {
	Socket    string
	AllowUIDs []uint32
	Exporter  *Exporter
	Deadline  time.Duration // one request; exports are long, listing is not
}

// Server serves the protocol on a Unix socket.
type Server struct {
	cfg     ServerConfig
	ln      net.Listener
	uids    map[uint32]bool
	wg      sync.WaitGroup
	sem     chan struct{}
	closing chan struct{}
	once    sync.Once
}

// maxExports bounds the copies running at once: one root overlay at a time keeps the link and the disk usable for everything else.
const maxExports = 1

// Listen validates the configuration and binds the socket (mode 0660).
func Listen(cfg ServerConfig) (*Server, error) {
	if !filepath.IsAbs(cfg.Socket) || filepath.Clean(cfg.Socket) != cfg.Socket || len(cfg.Socket) > 100 {
		return nil, errors.New("offsite: socket path must be a clean absolute path of at most 100 bytes")
	}
	if len(cfg.AllowUIDs) == 0 || cfg.Exporter == nil {
		return nil, errors.New("offsite: an allowed uid and an exporter are required")
	}
	if cfg.Deadline <= 0 {
		cfg.Deadline = 6 * time.Hour
	}
	if fi, err := os.Lstat(cfg.Socket); err == nil {
		if fi.Mode()&os.ModeSocket == 0 {
			return nil, errors.New("offsite: refusing to replace a non-socket file")
		}
		if c, err := net.DialTimeout("unix", cfg.Socket, time.Second); err == nil {
			_ = c.Close()
			return nil, errors.New("offsite: another service is already listening")
		}
		_ = os.Remove(cfg.Socket)
	}
	old := syscall.Umask(0o117)
	ln, err := net.Listen("unix", cfg.Socket)
	syscall.Umask(old)
	if err != nil {
		return nil, fmt.Errorf("offsite: listen: %w", err)
	}
	if err := os.Chmod(cfg.Socket, 0o660); err != nil { // #nosec G302 -- group access for the API user is the design
		_ = ln.Close()
		return nil, err
	}
	s := &Server{cfg: cfg, ln: ln, uids: map[uint32]bool{}, sem: make(chan struct{}, maxExports+3), closing: make(chan struct{})}
	for _, u := range cfg.AllowUIDs {
		s.uids[u] = true
	}
	return s, nil
}

// Serve accepts connections until Close.
func (s *Server) Serve() error {
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
		default:
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

// Close stops accepting; requests in flight finish.
func (s *Server) Close() {
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

func (s *Server) handle(conn net.Conn) {
	defer conn.Close()
	if uid, ok := peerUID(conn); !ok || !s.uids[uid] {
		return // an identity that is not the API gets nothing, not even an error
	}
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	var q Request
	if err := readFrame(conn, &q); err != nil || !q.Valid() {
		_ = writeFrame(conn, Reply{V: Version, Category: "validation"})
		return
	}
	_ = conn.SetReadDeadline(time.Time{})
	ctx, cancel := context.WithTimeout(context.Background(), s.cfg.Deadline)
	defer cancel()
	_ = writeFrame(conn, s.answer(ctx, q))
}

func (s *Server) answer(ctx context.Context, q Request) Reply {
	switch q.Op {
	case OpTargets:
		return Reply{V: Version, OK: true, Targets: s.cfg.Exporter.States()}
	case OpCopies:
		c, err := s.cfg.Exporter.Copies()
		if err != nil {
			return Reply{V: Version, Category: "host_error"}
		}
		return Reply{V: Version, OK: true, Copies: c}
	case OpExport, OpPrune:
		run := s.cfg.Exporter.Export
		if q.Op == OpPrune {
			run = s.cfg.Exporter.Prune
		}
		if err := run(ctx, q.Backup, q.Target); err != nil {
			c := CategoryOf(err)
			if !categoryOK.MatchString(c) {
				c = "host_error"
			}
			return Reply{V: Version, Category: c}
		}
		return Reply{V: Version, OK: true}
	}
	return Reply{V: Version, Category: "validation"}
}
