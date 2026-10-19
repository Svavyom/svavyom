package agent

import (
	"context"
	"encoding/binary"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"example.invalid/dedicatedcloud/backend/internal/hypervisor"
)

// sockDir returns a short directory: unix socket paths are limited to ~108 bytes.
func sockDir(t *testing.T) string {
	t.Helper()
	d, err := os.MkdirTemp("", "ag")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(d) })
	return d
}

type rig struct {
	t    *testing.T
	path string
	srv  *Server
	done chan error
}

func start(t *testing.T, r hypervisor.Reader, uids ...uint32) *rig {
	t.Helper()
	if len(uids) == 0 {
		uids = []uint32{uint32(os.Getuid())} // #nosec G115
	}
	path := filepath.Join(sockDir(t), "a.sock")
	srv, err := Listen(path, r, uids)
	if err != nil {
		t.Fatal(err)
	}
	g := &rig{t: t, path: path, srv: srv, done: make(chan error, 1)}
	go func() { g.done <- srv.Serve() }()
	t.Cleanup(func() { srv.Close(); <-g.done })
	return g
}

// memReader is a minimal read-only hypervisor.Reader.
type memReader struct{ domains map[string]hypervisor.State }

func newMem() *memReader { return &memReader{domains: map[string]hypervisor.State{}} }

func (m *memReader) Seed(name string, st hypervisor.State) { m.domains[name] = st }

func (m *memReader) Lookup(_ context.Context, name string) (hypervisor.Domain, error) {
	st, ok := m.domains[name]
	if !ok {
		return hypervisor.Domain{}, hypervisor.NewError(hypervisor.NotFound, "lookup", name, "no such domain")
	}
	return hypervisor.Domain{Name: name, State: st}, nil
}

func (m *memReader) List(context.Context) ([]hypervisor.Domain, error) {
	var out []hypervisor.Domain
	for n, st := range m.domains {
		out = append(out, hypervisor.Domain{Name: n, State: st})
	}
	return out, nil
}

func seeded() *memReader {
	h := newMem()
	h.Seed("web-1", hypervisor.StateRunning)
	h.Seed("db-1", hypervisor.StateShutoff)
	return h
}

func client(t *testing.T, g *rig) *Client {
	c, err := NewClient(g.path, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func raw(t *testing.T, g *rig) net.Conn {
	c, err := net.Dial("unix", g.path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	return c
}

func frame(body string) []byte {
	b := make([]byte, 4+len(body))
	binary.BigEndian.PutUint32(b, uint32(len(body)))
	copy(b[4:], body)
	return b
}

func TestListAndLookupRoundTrip(t *testing.T) {
	g := start(t, seeded())
	c := client(t, g)
	list, err := c.List(context.Background())
	if err != nil || len(list) != 2 || list[0].Name != "db-1" || list[0].State != hypervisor.StateShutoff || list[1].Name != "web-1" || list[1].State != hypervisor.StateRunning {
		t.Fatalf("%+v %v", list, err)
	}
	d, err := c.Lookup(context.Background(), "web-1")
	if err != nil || d.State != hypervisor.StateRunning {
		t.Fatalf("%+v %v", d, err)
	}
	if _, err := c.Lookup(context.Background(), "absent"); hypervisor.CategoryOf(err) != hypervisor.NotFound {
		t.Fatalf("absent: %v", err)
	}
	if _, err := c.Lookup(context.Background(), "../x"); hypervisor.CategoryOf(err) != hypervisor.NotFound {
		t.Fatalf("unsafe name: %v", err)
	}
}

func TestSocketIsUnixOnlyWithRestrictivePermissions(t *testing.T) {
	g := start(t, seeded())
	if g.srv.ln.Addr().Network() != "unix" {
		t.Fatalf("network %q: the agent must not listen on TCP", g.srv.ln.Addr().Network())
	}
	fi, err := os.Stat(g.path)
	if err != nil || fi.Mode()&os.ModeSocket == 0 || fi.Mode().Perm() != 0o660 {
		t.Fatalf("%v %v", fi.Mode(), err)
	}
}

func TestMalformedRequestsAreRefusedWithAValidationReplyOrClose(t *testing.T) {
	g := start(t, seeded())
	cases := map[string][]byte{
		"not json":       frame("{nope"),
		"empty object":   frame("{}"),
		"unknown op":     frame(`{"v":1,"op":"start","name":"web-1"}`),
		"mutation op":    frame(`{"v":1,"op":"define","name":"web-1"}`),
		"unknown field":  frame(`{"v":1,"op":"list","xml":"<domain/>"}`),
		"path field":     frame(`{"v":1,"op":"lookup","name":"web-1","path":"/etc/passwd"}`),
		"wrong version":  frame(`{"v":2,"op":"list"}`),
		"list w/ name":   frame(`{"v":1,"op":"list","name":"web-1"}`),
		"lookup no name": frame(`{"v":1,"op":"lookup"}`),
		"unsafe name":    frame(`{"v":1,"op":"lookup","name":"../../etc/passwd"}`),
		"shell name":     frame(`{"v":1,"op":"lookup","name":"a;rm -rf /"}`),
		"trailing data":  frame(`{"v":1,"op":"list"}{"v":1,"op":"list"}`),
		"zero length":    {0, 0, 0, 0},
		"oversize":       append([]byte{0, 0, 0x10, 0}, make([]byte, 4096)...),
	}
	for name, b := range cases {
		c := raw(t, g)
		_, _ = c.Write(b)
		var r Reply
		if err := readFrame(c, &r, MaxReplyBytes); err == nil && (r.OK || r.Category != string(hypervisor.Validation)) {
			t.Errorf("%s: reply %+v", name, r)
		}
	}
	// None of that disturbed the agent.
	if list, err := client(t, g).List(context.Background()); err != nil || len(list) != 2 {
		t.Fatalf("%v %v", list, err)
	}
}

func TestSlowPeerIsDropped(t *testing.T) {
	old := readDeadline
	readDeadline = 200 * time.Millisecond
	defer func() { readDeadline = old }()
	g := start(t, seeded())
	c := raw(t, g)
	start := time.Now()
	buf := make([]byte, 512)
	var err error
	for err == nil { // we send nothing: the agent may answer with a validation error, then it must close
		_, err = c.Read(buf)
	}
	if time.Since(start) > 2*time.Second {
		t.Fatalf("the agent kept a silent connection open for %v", time.Since(start))
	}
}

func TestPeerUIDAllowlist(t *testing.T) {
	other := uint32(os.Getuid()) + 12345 // #nosec G115
	g := start(t, seeded(), other)
	if _, err := client(t, g).List(context.Background()); hypervisor.CategoryOf(err) != hypervisor.Unavailable {
		t.Fatalf("a peer outside the uid allowlist was served: %v", err)
	}
	if _, err := Listen(filepath.Join(sockDir(t), "b.sock"), seeded(), nil); err == nil {
		t.Fatal("an empty allowlist must be refused")
	}
}

func TestConnectionLimit(t *testing.T) {
	g := start(t, seeded())
	var held []net.Conn
	for i := 0; i < maxConnections; i++ {
		c, err := net.Dial("unix", g.path)
		if err != nil {
			t.Fatal(err)
		}
		held = append(held, c) // silent connections occupy slots
	}
	defer func() {
		for _, c := range held {
			_ = c.Close()
		}
	}()
	time.Sleep(100 * time.Millisecond)
	extra, err := net.Dial("unix", g.path)
	if err != nil {
		t.Fatal(err)
	}
	defer extra.Close()
	_ = extra.SetDeadline(time.Now().Add(2 * time.Second))
	_, _ = extra.Write(frame(`{"v":1,"op":"list"}`))
	var r Reply
	if err := readFrame(extra, &r, MaxReplyBytes); err == nil {
		t.Fatalf("a connection over the limit was served: %+v", r)
	}
}

type failing struct{ err error }

func (f failing) Lookup(context.Context, string) (hypervisor.Domain, error) {
	return hypervisor.Domain{}, f.err
}
func (f failing) List(context.Context) ([]hypervisor.Domain, error) { return nil, f.err }

func TestErrorsCrossTheBoundaryAsCategoriesOnly(t *testing.T) {
	secret := "libvirt: /etc/libvirt/qemu/secret-disk.xml: password=hunter2"
	for cat, want := range map[hypervisor.Category]hypervisor.Category{
		hypervisor.NotFound: hypervisor.NotFound, hypervisor.Unavailable: hypervisor.Unavailable, hypervisor.Timeout: hypervisor.Timeout,
		hypervisor.HostError: hypervisor.HostError, hypervisor.Conflict: hypervisor.HostError, hypervisor.Prohibited: hypervisor.HostError,
	} {
		g := start(t, failing{hypervisor.NewError(cat, "x", "d", secret)})
		c := raw(t, g)
		_, _ = c.Write(frame(`{"v":1,"op":"list"}`))
		body := make([]byte, 4096)
		n, _ := c.Read(body)
		if strings.Contains(string(body[:n]), "hunter2") || strings.Contains(string(body[:n]), "/etc") {
			t.Fatalf("%s: text crossed the boundary: %q", cat, body[:n])
		}
		_, err := client(t, g).List(context.Background())
		if hypervisor.CategoryOf(err) != want {
			t.Errorf("%s -> %s, want %s", cat, hypervisor.CategoryOf(err), want)
		}
		if err != nil && strings.Contains(err.Error(), "hunter2") {
			t.Errorf("client error carries the text")
		}
	}
	g := start(t, failing{os.ErrPermission}) // an untyped error is a generic host_error
	if _, err := client(t, g).List(context.Background()); hypervisor.CategoryOf(err) != hypervisor.HostError {
		t.Fatalf("%v", err)
	}
}

func TestNeverTruncatesAnInventoryAndNeverHidesAnUnrepresentableDomain(t *testing.T) {
	big := newMem()
	for i := 0; i < MaxDomains+1; i++ {
		big.Seed("vm-"+itoa(i), hypervisor.StateShutoff)
	}
	g := start(t, big)
	if _, err := client(t, g).List(context.Background()); hypervisor.CategoryOf(err) != hypervisor.HostError {
		t.Fatalf("an inventory over the limit must be an error, not a silent truncation: %v", err)
	}
	for _, name := range []string{"bad name!", "../etc", "-lead", "\u00e9t\u00e9", strings.Repeat("a", 64)} {
		odd := newMem()
		odd.Seed("ok-1", hypervisor.StateRunning)
		odd.Seed(name, hypervisor.StateRunning)
		g2 := start(t, odd)
		list, err := client(t, g2).List(context.Background())
		if hypervisor.CategoryOf(err) != hypervisor.HostError || list != nil {
			t.Fatalf("%q: an unrepresentable domain must fail the whole inventory, got %v %v", name, list, err)
		}
		if strings.Contains(err.Error(), "ok-1") || strings.Contains(err.Error(), "etc") {
			t.Fatalf("the error carries a name: %v", err)
		}
		// The failure crosses the wire as a bare category.
		c := raw(t, g2)
		_, _ = c.Write(frame(`{"v":1,"op":"list"}`))
		var r Reply
		if err := readFrame(c, &r, MaxReplyBytes); err != nil || r.OK || r.Category != string(hypervisor.HostError) || len(r.Domains) != 0 {
			t.Fatalf("%q: reply %+v %v", name, r, err)
		}
	}
	// An unknown power state is likewise refused rather than dropped.
	badPower := newMem()
	badPower.Seed("ok-1", hypervisor.State("exploding"))
	if _, err := client(t, start(t, badPower)).List(context.Background()); hypervisor.CategoryOf(err) != hypervisor.HostError {
		t.Fatalf("%v", err)
	}
}

func itoa(i int) string {
	s := ""
	if i == 0 {
		return "0"
	}
	for ; i > 0; i /= 10 {
		s = string(rune('0'+i%10)) + s
	}
	return s
}

func TestStaleSocketIsReplacedButNothingElseIs(t *testing.T) {
	dir := sockDir(t)
	path := filepath.Join(dir, "a.sock")
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	ln.(*net.UnixListener).SetUnlinkOnClose(false)
	_ = ln.Close()                                                    // leaves a stale socket file behind
	srv, err := Listen(path, seeded(), []uint32{uint32(os.Getuid())}) // #nosec G115
	if err != nil {
		t.Fatalf("stale socket not replaced: %v", err)
	}
	// A second agent must not displace a live one.
	if _, err := Listen(path, seeded(), []uint32{1}); err == nil {
		t.Fatal("a live agent was displaced")
	}
	srv.Close()
	file := filepath.Join(dir, "file")
	if err := os.WriteFile(file, []byte("precious"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Listen(file, seeded(), []uint32{1}); err == nil {
		t.Fatal("a regular file was replaced")
	}
	if b, _ := os.ReadFile(file); string(b) != "precious" {
		t.Fatal("file damaged")
	}
	for _, bad := range []string{"relative.sock", "/tmp/../tmp/x.sock", "/tmp//x.sock", "/" + strings.Repeat("a", 101)} {
		if _, err := Listen(bad, seeded(), []uint32{1}); err == nil {
			t.Errorf("path %q accepted", bad)
		}
		if _, err := NewClient(bad, time.Second); err == nil {
			t.Errorf("client path %q accepted", bad)
		}
	}
}

// A rogue or broken server must not make the client misbehave.
func TestClientDistrustsTheReply(t *testing.T) {
	serve := func(reply func(c net.Conn)) *rig {
		path := filepath.Join(sockDir(t), "r.sock")
		ln, err := net.Listen("unix", path)
		if err != nil {
			t.Fatal(err)
		}
		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				buf := make([]byte, 64)
				_, _ = c.Read(buf)
				reply(c)
				_ = c.Close()
			}
		}()
		t.Cleanup(func() { _ = ln.Close(); wg.Wait() })
		return &rig{t: t, path: path}
	}
	cases := map[string]func(c net.Conn){
		"huge length":   func(c net.Conn) { _, _ = c.Write([]byte{0xff, 0xff, 0xff, 0xff}) },
		"wrong version": func(c net.Conn) { _, _ = c.Write(frame(`{"v":9,"ok":true}`)) },
		"unknown field": func(c net.Conn) { _, _ = c.Write(frame(`{"v":1,"ok":true,"xml":"<a/>"}`)) },
		"bad power": func(c net.Conn) {
			_, _ = c.Write(frame(`{"v":1,"ok":true,"domains":[{"name":"a","power":"exploding"}]}`))
		},
		"bad name": func(c net.Conn) {
			_, _ = c.Write(frame(`{"v":1,"ok":true,"domains":[{"name":"../a","power":"running"}]}`))
		},
		"truncated body": func(c net.Conn) { _, _ = c.Write(append([]byte{0, 0, 0, 50}, []byte("{")...)) },
		"silence":        func(c net.Conn) { time.Sleep(3 * time.Second) },
	}
	for name, reply := range cases {
		g := serve(reply)
		cl, _ := NewClient(g.path, 500*time.Millisecond)
		start := time.Now()
		if list, err := cl.List(context.Background()); err == nil {
			t.Errorf("%s: accepted %v", name, list)
		}
		if time.Since(start) > 2*time.Second {
			t.Errorf("%s: client waited %v", name, time.Since(start))
		}
	}
	// Echoing a different name on lookup is refused.
	g := serve(func(c net.Conn) {
		_, _ = c.Write(frame(`{"v":1,"ok":true,"domains":[{"name":"other","power":"running"}]}`))
	})
	cl, _ := NewClient(g.path, time.Second)
	if _, err := cl.Lookup(context.Background(), "web-1"); err == nil {
		t.Fatal("a reply for another domain was accepted")
	}
	// No agent at all.
	gone, _ := NewClient(filepath.Join(sockDir(t), "none.sock"), time.Second)
	if _, err := gone.List(context.Background()); hypervisor.CategoryOf(err) != hypervisor.Unavailable {
		t.Fatalf("%v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := gone.List(ctx); hypervisor.CategoryOf(err) != hypervisor.Timeout {
		t.Fatalf("cancelled: %v", err)
	}
}

func TestConcurrentClients(t *testing.T) {
	g := start(t, seeded())
	c := client(t, g)
	var wg sync.WaitGroup
	errs := make(chan error, 40)
	for i := 0; i < 40; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := c.List(context.Background())
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	ok := 0
	for err := range errs {
		if err == nil {
			ok++
		}
	}
	if ok == 0 {
		t.Fatal("no request succeeded")
	}
}

// staticReader serves fixed domains, so a test can control every field.
type staticReader struct{ doms []hypervisor.Domain }

func (s staticReader) Lookup(_ context.Context, name string) (hypervisor.Domain, error) {
	for _, d := range s.doms {
		if d.Name == name {
			return d, nil
		}
	}
	return hypervisor.Domain{}, hypervisor.NewError(hypervisor.NotFound, "lookup", name, "no such domain")
}
func (s staticReader) List(context.Context) ([]hypervisor.Domain, error) { return s.doms, nil }

// DR-022: the cumulative CPU time of a running domain crosses the boundary as one bounded integer, and an out-of-range value is never passed on.
func TestCPUTimeCrossesTheBoundaryAsOneBoundedInteger(t *testing.T) {
	g := start(t, staticReader{doms: []hypervisor.Domain{{Name: "web-1", State: hypervisor.StateRunning, VCPUs: 2, CPUTimeNs: 12_345_678_901}}})
	d, err := client(t, g).Lookup(context.Background(), "web-1")
	if err != nil || d.CPUTimeNs != 12_345_678_901 || d.VCPUs != 2 {
		t.Fatalf("%+v %v", d, err)
	}
	for _, bad := range []int64{-1, 1<<62 + 1} {
		if _, ok := toWire(hypervisor.Domain{Name: "x", State: hypervisor.StateRunning, CPUTimeNs: bad}); ok {
			t.Fatalf("CPU time %d must be refused", bad)
		}
		if _, ok := fromWire(Domain{Name: "x", Power: "running", CPUTimeNs: bad}); ok {
			t.Fatalf("CPU time %d must be distrusted", bad)
		}
	}
}
