package agent

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"syscall"
	"time"

	"example.invalid/dedicatedcloud/backend/internal/hypervisor"
)

// Timeouts and limits (variables only so tests can shorten the deadlines).
var (
	readDeadline  = 5 * time.Second
	serveDeadline = 10 * time.Second
)

const maxConnections = 8

// Server answers read-only requests from a hypervisor.Reader on a Unix socket.
type Server struct {
	reader  hypervisor.Reader
	uids    map[uint32]bool
	ln      net.Listener
	sem     chan struct{}
	wg      sync.WaitGroup
	closing chan struct{}
	once    sync.Once
}

// Listen creates the socket at path with mode 0660 (umask 0117 while binding) in an existing directory, refuses to
// replace anything that is not a stale socket, and returns a Server that only serves peers whose uid is in allowUIDs.
// The caller should place the socket in a directory only the agent and the API's group can enter (for example 0750).
func Listen(path string, reader hypervisor.Reader, allowUIDs []uint32) (*Server, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || len(path) > 100 {
		return nil, errors.New("agent: socket path must be a clean absolute path of at most 100 bytes")
	}
	if len(allowUIDs) == 0 {
		return nil, errors.New("agent: at least one allowed uid is required")
	}
	if err := removeStaleSocket(path); err != nil {
		return nil, err
	}
	old := syscall.Umask(0o117)
	ln, err := net.Listen("unix", path)
	syscall.Umask(old)
	if err != nil {
		return nil, fmt.Errorf("agent: listen: %w", err)
	}
	if err := os.Chmod(path, 0o660); err != nil { // #nosec G302 -- group access for the API user is the design
		_ = ln.Close()
		return nil, fmt.Errorf("agent: chmod: %w", err)
	}
	s := &Server{reader: reader, uids: map[uint32]bool{}, ln: ln, sem: make(chan struct{}, maxConnections), closing: make(chan struct{})}
	for _, u := range allowUIDs {
		s.uids[u] = true
	}
	return s, nil
}

// removeStaleSocket deletes path only if it is a Unix socket nobody answers on.
func removeStaleSocket(path string) error {
	fi, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if fi.Mode()&os.ModeSocket == 0 {
		return errors.New("agent: refusing to replace a non-socket file")
	}
	if c, err := net.DialTimeout("unix", path, time.Second); err == nil {
		_ = c.Close()
		return errors.New("agent: another agent is already listening")
	}
	return os.Remove(path)
}

// Serve accepts connections until Close. It returns nil after Close.
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
		default: // too many concurrent peers: refuse rather than queue without bound
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

// Close stops accepting and removes the socket file.
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
		return // silent: an unauthorised peer learns nothing
	}
	_ = conn.SetReadDeadline(time.Now().Add(readDeadline))
	var q Request
	if err := readFrame(conn, &q, MaxRequestBytes); err != nil || !validRequest(q) {
		_ = conn.SetWriteDeadline(time.Now().Add(readDeadline))
		_ = writeFrame(conn, Reply{V: Version, Category: string(hypervisor.Validation)}, MaxReplyBytes)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), serveDeadline)
	defer cancel()
	reply := s.answer(ctx, q)
	_ = conn.SetWriteDeadline(time.Now().Add(readDeadline))
	if err := writeFrame(conn, reply, MaxReplyBytes); err != nil {
		_ = writeFrame(conn, Reply{V: Version, Category: string(hypervisor.HostError)}, MaxReplyBytes)
	}
}

func failure(err error) Reply {
	c := hypervisor.CategoryOf(err)
	switch c {
	case hypervisor.NotFound, hypervisor.Unavailable, hypervisor.Timeout, hypervisor.Validation:
	default:
		c = hypervisor.HostError
	}
	return Reply{V: Version, Category: string(c)}
}

func toWire(d hypervisor.Domain) (Domain, bool) {
	w := Domain{Name: d.Name, Power: string(d.State), VCPUs: d.VCPUs, MemoryMiB: d.MemoryMiB, UUID: d.UUID, Managed: d.Managed,
		Fingerprint: d.Fingerprint, ImageID: d.ImageID, IP: d.IPv4, DiskBytes: d.DiskBytes, Network: d.Network, MAC: d.MAC, CPUTimeNs: d.CPUTimeNs,
		MemUsedMiB: d.MemUsedMiB, DiskIOBytes: d.DiskIOBytes, NetIOBytes: d.NetIOBytes, DataVolumes: d.DataVolumes, Media: d.Media, ISOSHA256: d.ISOSHA256, ISOSHA256s: d.ISOSHA256s, Graphics: d.Graphics, RescueSHA256: d.RescueSHA256}
	for _, sn := range d.Snapshots {
		w.Snapshots = append(w.Snapshots, Snap{ID: sn.ID, Created: sn.Created})
	}
	if !nameRE.MatchString(d.Name) || !powers[d.State] || !validDetails(w) {
		return Domain{}, false
	}
	return w, true
}

func netToWire(n hypervisor.Network) (Net, bool) {
	w := Net{Name: n.Name, UUID: n.UUID, Managed: n.Managed, Active: n.Active, Autostart: n.Autostart, Mode: n.Mode, Bridge: n.Bridge, Subnet: n.Subnet,
		Gateway: n.Gateway, DHCPStart: n.DHCPStart, DHCPEnd: n.DHCPEnd, Attached: n.AttachedVMs}
	if !netModes[w.Mode] {
		w.Mode = "other"
	}
	for _, r := range n.Reservations {
		w.Reservations = append(w.Reservations, Res{MAC: r.MAC, IP: r.IP})
	}
	return w, validNet(w)
}

func (s *Server) answer(ctx context.Context, q Request) Reply {
	switch q.Op {
	case OpNetworks:
		nr, ok := s.reader.(hypervisor.NetworkReader)
		if !ok {
			return Reply{V: Version, Category: string(hypervisor.Unavailable)}
		}
		list, err := nr.Networks(ctx)
		if err != nil {
			return failure(err)
		}
		if len(list) > MaxNetworks {
			return Reply{V: Version, Category: string(hypervisor.HostError)} // never silently truncate an inventory
		}
		out := make([]Net, 0, len(list))
		for _, n := range list {
			w, ok := netToWire(n)
			if !ok {
				return Reply{V: Version, Category: string(hypervisor.HostError)}
			}
			out = append(out, w)
		}
		sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
		return Reply{V: Version, OK: true, Networks: out}
	case OpVolumes:
		vr, ok := s.reader.(hypervisor.DataVolumeReader)
		if !ok {
			return Reply{V: Version, Category: string(hypervisor.Unavailable)}
		}
		list, err := vr.DataVolumes(ctx)
		if err != nil {
			return failure(err)
		}
		if len(list) > MaxVolumes {
			return Reply{V: Version, Category: string(hypervisor.HostError)}
		}
		out := make([]Vol, 0, len(list))
		for _, v := range list {
			w := Vol{Name: v.Name, Capacity: v.CapacityBytes}
			if !validVol(w) {
				return Reply{V: Version, Category: string(hypervisor.HostError)}
			}
			out = append(out, w)
		}
		sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
		return Reply{V: Version, OK: true, Volumes: out}
	case OpLookup:
		d, err := s.reader.Lookup(ctx, q.Name)
		if err != nil {
			return failure(err)
		}
		w, ok := toWire(d)
		if !ok {
			return Reply{V: Version, Category: string(hypervisor.HostError)}
		}
		return Reply{V: Version, OK: true, Domains: []Domain{w}}
	default:
		list, err := s.reader.List(ctx)
		if err != nil {
			return failure(err)
		}
		out := make([]Domain, 0, len(list))
		for _, d := range list {
			w, ok := toWire(d)
			if !ok { // never silently hide a domain: an incomplete inventory must not look complete
				return Reply{V: Version, Category: string(hypervisor.HostError)}
			}
			out = append(out, w)
		}
		sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
		if len(out) > MaxDomains {
			return Reply{V: Version, Category: string(hypervisor.HostError)} // never silently truncate an inventory
		}
		return Reply{V: Version, OK: true, Domains: out}
	}
}
