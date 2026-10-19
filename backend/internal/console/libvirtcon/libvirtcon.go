//go:build libvirt

// Package libvirtcon implements console.Source on libvirt's console stream (virDomainOpenConsole) through the Go bindings: no virsh,
// no shell, no domain XML sent anywhere. It is linked ONLY into the console broker. It can do exactly three things: list the running
// Svavyom-managed VMs with a serial device, report the facts about one VM, and open that VM's serial console. It never defines,
// starts, stops or changes anything, and it accepts the system hypervisor and (for tests) the in-process test driver, nothing else.
package libvirtcon

import (
	"context"
	"encoding/xml"
	"errors"
	"io"
	"net"
	"sync"

	libvirt "libvirt.org/go/libvirt"

	"example.invalid/dedicatedcloud/backend/internal/console"
	"example.invalid/dedicatedcloud/backend/internal/provision"
)

// URIs accepted by Open.
const (
	SystemURI = "qemu:///system"
	TestURI   = "test:///default"
)

// Source is the libvirt-backed console.Source. It reconnects when the libvirt connection has died.
type Source struct {
	uri  string
	mu   sync.Mutex
	conn *libvirt.Connect
}

var _ console.Source = (*Source)(nil)

// Open connects to the hypervisor. The URI must be one of the two allowed values.
func Open(uri string) (*Source, error) {
	if uri != SystemURI && uri != TestURI {
		return nil, errors.New("libvirtcon: uri not allowed")
	}
	s := &Source{uri: uri}
	if _, err := s.connect(); err != nil {
		return nil, err
	}
	return s, nil
}

// Close releases the connection.
func (s *Source) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.conn != nil {
		_, _ = s.conn.Close()
		s.conn = nil
	}
}

func (s *Source) connect() (*libvirt.Connect, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.conn != nil {
		if alive, err := s.conn.IsAlive(); err == nil && alive {
			return s.conn, nil
		}
		_, _ = s.conn.Close()
		s.conn = nil
	}
	c, err := libvirt.NewConnect(s.uri)
	if err != nil {
		return nil, err
	}
	s.conn = c
	return c, nil
}

type notFound struct{}

func (notFound) Error() string    { return "libvirtcon: no such domain" }
func (notFound) IsNotFound() bool { return true }

func wrap(err error) error {
	var lerr libvirt.Error
	if errors.As(err, &lerr) && lerr.Code == libvirt.ERR_NO_DOMAIN {
		return notFound{}
	}
	return err
}

type devicesDoc struct {
	Serials  []struct{} `xml:"devices>serial"`
	Consoles []struct{} `xml:"devices>console"`
}

// facts reads the ownership marker and the serial device from the domain definition.
func facts(x string) (managed, serial bool) {
	pd, err := provision.ParseDomain(x)
	if err != nil {
		return false, false
	}
	var d devicesDoc
	if len(x) > 1<<20 || xml.Unmarshal([]byte(x), &d) != nil {
		return pd.Managed, false
	}
	return pd.Managed, len(d.Serials) > 0
}

// Running implements console.Source.
func (s *Source) Running(ctx context.Context) ([]string, error) {
	c, err := s.connect()
	if err != nil {
		return nil, err
	}
	doms, err := c.ListAllDomains(libvirt.CONNECT_LIST_DOMAINS_ACTIVE)
	if err != nil {
		return nil, err
	}
	var out []string
	for i := range doms {
		if ctx.Err() != nil {
			for j := i; j < len(doms); j++ {
				_ = doms[j].Free()
			}
			return nil, ctx.Err()
		}
		name, nerr := doms[i].GetName()
		x, xerr := doms[i].GetXMLDesc(0)
		_ = doms[i].Free()
		if nerr != nil || xerr != nil {
			continue
		}
		if managed, serial := facts(x); managed && serial {
			out = append(out, name)
		}
	}
	return out, nil
}

// Check implements console.Source.
func (s *Source) Check(_ context.Context, vm string) (console.Info, error) {
	c, err := s.connect()
	if err != nil {
		return console.Info{}, err
	}
	d, err := c.LookupDomainByName(vm)
	if err != nil {
		return console.Info{}, wrap(err)
	}
	defer func() { _ = d.Free() }()
	x, err := d.GetXMLDesc(0)
	if err != nil {
		return console.Info{}, err
	}
	active, err := d.IsActive()
	if err != nil {
		return console.Info{}, err
	}
	managed, serial := facts(x)
	return console.Info{Managed: managed, Configured: serial, Running: active, Graphics: provision.HasGraphics(x)}, nil
}

// Open implements console.Source: it re-checks ownership, the serial device and that the VM runs, then opens the console stream.
func (s *Source) Open(_ context.Context, vm string) (io.ReadWriteCloser, error) {
	c, err := s.connect()
	if err != nil {
		return nil, err
	}
	d, err := c.LookupDomainByName(vm)
	if err != nil {
		return nil, wrap(err)
	}
	defer func() { _ = d.Free() }()
	x, err := d.GetXMLDesc(0)
	if err != nil {
		return nil, err
	}
	active, err := d.IsActive()
	if err != nil {
		return nil, err
	}
	if managed, serial := facts(x); !managed || !serial || !active {
		return nil, errors.New("libvirtcon: not a running Svavyom VM with a serial console")
	}
	st, err := c.NewStream(0)
	if err != nil {
		return nil, err
	}
	// No FORCE flag: if somebody else holds the console the open fails and the broker reports the console unavailable, instead of
	// silently taking it away from a host administrator.
	if err := d.OpenConsole("", st, 0); err != nil {
		_ = st.Free()
		return nil, err
	}
	return &stream{st: st}, nil
}

// OpenGraphics implements console.Source: it re-checks ownership, the VNC device and that the VM runs, then asks libvirt for a connection to the VNC
// server. The VM's VNC device has no listener; libvirt hands over one end of a socket pair, so there is no port and no file to connect to. Authentication is
// skipped for this connection only because it is private to this process; the broker's caller already holds a one-time ticket.
func (s *Source) OpenGraphics(_ context.Context, vm string) (io.ReadWriteCloser, error) {
	c, err := s.connect()
	if err != nil {
		return nil, err
	}
	d, err := c.LookupDomainByName(vm)
	if err != nil {
		return nil, wrap(err)
	}
	defer func() { _ = d.Free() }()
	x, err := d.GetXMLDesc(0)
	if err != nil {
		return nil, err
	}
	active, err := d.IsActive()
	if err != nil {
		return nil, err
	}
	if managed, _ := facts(x); !managed || !provision.HasGraphics(x) || !active {
		return nil, errors.New("libvirtcon: not a running Svavyom VM with a graphical console")
	}
	f, err := d.OpenGraphicsFD(0, libvirt.DOMAIN_OPEN_GRAPHICS_SKIPAUTH)
	if err != nil {
		return nil, err
	}
	// A socket as a net.Conn: closing it wakes a blocked read (a bare file descriptor would not).
	conn, cerr := net.FileConn(f)
	_ = f.Close()
	if cerr != nil {
		return nil, cerr
	}
	return conn, nil
}

// stream adapts a libvirt stream to io.ReadWriteCloser.
type stream struct {
	st   *libvirt.Stream
	once sync.Once
}

func (s *stream) Read(p []byte) (int, error) {
	n, err := s.st.Recv(p)
	if err != nil {
		return 0, err
	}
	if n == 0 {
		return 0, io.EOF
	}
	return n, nil
}

func (s *stream) Write(p []byte) (int, error) {
	total := 0
	for total < len(p) {
		n, err := s.st.Send(p[total:])
		if err != nil {
			return total, err
		}
		total += n
	}
	return total, nil
}

func (s *stream) Close() error {
	s.once.Do(func() {
		_ = s.st.Abort()
		_ = s.st.Free()
	})
	return nil
}
