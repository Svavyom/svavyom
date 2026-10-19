// Package consolesim is a SIMULATION of the hypervisor side of the console broker: scripted VMs whose serial console prints a boot log
// and then a login prompt, echoes input and answers a few commands. It is used by tests and by the test-only broker binary behind the
// browser tests. It is NOT libvirt and proves nothing about libvirt, QEMU or a real guest.
package consolesim

import (
	"context"
	"errors"
	"io"
	"strings"
	"sync"

	"example.invalid/dedicatedcloud/backend/internal/console"
)

var errNotFound = notFound{}

type notFound struct{}

func (notFound) Error() string    { return "consolesim: no such VM" }
func (notFound) IsNotFound() bool { return true }

// VM describes one simulated machine.
type VM struct {
	Managed, Configured, Running bool
	// Graphics gives the VM the simulated VNC console (an RFB server on a private pipe).
	Graphics bool
	// Boot is printed when the VM starts (before the login prompt).
	Boot []string
	// Silent makes the console print nothing at all (a guest without a serial console configured in its kernel).
	Silent bool
}

// Source implements console.Source over a mutable set of VMs.
type Source struct {
	mu      sync.Mutex
	vms     map[string]*VM
	streams map[string]*stream
	// Fail, when set, makes Running/Check/Open return it (the hypervisor is unreachable).
	Fail error
	// OpenCount counts console streams opened per VM.
	OpenCount map[string]int
	// GraphicsOpen counts graphical connections opened per VM.
	GraphicsOpen map[string]int
}

var _ console.Source = (*Source)(nil)

// New returns an empty simulation.
func New() *Source {
	return &Source{vms: map[string]*VM{}, streams: map[string]*stream{}, OpenCount: map[string]int{}, GraphicsOpen: map[string]int{}}
}

// Set creates or replaces a VM. Replacing a running VM with a stopped one ends its console stream.
func (s *Source) Set(name string, v VM) {
	s.mu.Lock()
	old := s.streams[name]
	if !v.Running || old == nil {
		delete(s.streams, name)
	}
	s.vms[name] = &v
	s.mu.Unlock()
	if old != nil && !v.Running {
		old.end()
	}
}

// Remove deletes a VM.
func (s *Source) Remove(name string) {
	s.mu.Lock()
	old := s.streams[name]
	delete(s.vms, name)
	delete(s.streams, name)
	s.mu.Unlock()
	if old != nil {
		old.end()
	}
}

// Running implements console.Source.
func (s *Source) Running(context.Context) ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.Fail != nil {
		return nil, s.Fail
	}
	var out []string
	for n, v := range s.vms {
		if v.Managed && v.Configured && v.Running {
			out = append(out, n)
		}
	}
	return out, nil
}

// Check implements console.Source.
func (s *Source) Check(_ context.Context, vm string) (console.Info, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.Fail != nil {
		return console.Info{}, s.Fail
	}
	v, ok := s.vms[vm]
	if !ok {
		return console.Info{}, errNotFound
	}
	return console.Info{Managed: v.Managed, Configured: v.Configured, Running: v.Running, Graphics: v.Graphics}, nil
}

// Open implements console.Source: one stream per run of a VM (a second Open of the same running VM is refused, like a pty console).
func (s *Source) Open(_ context.Context, vm string) (io.ReadWriteCloser, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.Fail != nil {
		return nil, s.Fail
	}
	v, ok := s.vms[vm]
	if !ok {
		return nil, errNotFound
	}
	if !v.Managed || !v.Configured || !v.Running {
		return nil, errors.New("consolesim: not a running managed VM with a console")
	}
	if s.streams[vm] != nil {
		return nil, errors.New("consolesim: console already open")
	}
	st := newStream(s, vm, v)
	s.streams[vm] = st
	s.OpenCount[vm]++
	return st, nil
}

type stream struct {
	src  *Source
	vm   string
	mu   sync.Mutex
	cond *sync.Cond
	out  []byte
	line strings.Builder
	done bool
	rd   int
}

func newStream(src *Source, vm string, v *VM) *stream {
	st := &stream{src: src, vm: vm}
	st.cond = sync.NewCond(&st.mu)
	if !v.Silent {
		for _, l := range v.Boot {
			st.out = append(st.out, []byte(l+"\r\n")...)
		}
		st.out = append(st.out, []byte(vm+" login: ")...)
	}
	return st
}

func (s *stream) end() {
	s.mu.Lock()
	s.done = true
	s.mu.Unlock()
	s.cond.Broadcast()
}

// Read implements io.Reader: blocks until output exists or the stream ends.
func (s *stream) Read(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for s.rd >= len(s.out) && !s.done {
		s.cond.Wait()
	}
	if s.rd >= len(s.out) {
		return 0, io.EOF
	}
	n := copy(p, s.out[s.rd:])
	s.rd += n
	return n, nil
}

// Write implements io.Writer: echoes the keystrokes and answers a completed line.
func (s *stream) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.done {
		return 0, io.ErrClosedPipe
	}
	for _, c := range p {
		switch c {
		case '\r', '\n':
			cmd := strings.TrimSpace(s.line.String())
			s.line.Reset()
			s.out = append(s.out, '\r', '\n')
			switch cmd {
			case "":
			case "whoami":
				s.out = append(s.out, []byte("root\r\n")...)
			default:
				s.out = append(s.out, []byte("sh: "+cmd+": command not found\r\n")...)
			}
			s.out = append(s.out, []byte(s.vm+" login: ")...)
		default:
			s.line.WriteByte(c)
			s.out = append(s.out, c)
		}
	}
	s.cond.Broadcast()
	return len(p), nil
}

// Close implements io.Closer: the console is detached (the broker closes it when the VM ends or the broker stops).
func (s *stream) Close() error {
	s.src.mu.Lock()
	if s.src.streams[s.vm] == s {
		delete(s.src.streams, s.vm)
	}
	s.src.mu.Unlock()
	s.end()
	return nil
}

// Emit appends guest output (test control).
func (s *Source) Emit(vm, text string) {
	s.mu.Lock()
	st := s.streams[vm]
	s.mu.Unlock()
	if st == nil {
		return
	}
	st.mu.Lock()
	st.out = append(st.out, []byte(text)...)
	st.mu.Unlock()
	st.cond.Broadcast()
}
