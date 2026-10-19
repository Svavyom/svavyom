package console_test

import (
	"bytes"
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"example.invalid/dedicatedcloud/backend/internal/console"
	"example.invalid/dedicatedcloud/backend/internal/console/consolesim"
)

type rig struct {
	t    *testing.T
	b    *console.Broker
	src  *consolesim.Source
	sock string
}

func newRig(t *testing.T, mod func(*console.BrokerConfig)) *rig {
	t.Helper()
	dir, err := os.MkdirTemp("", "cb")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	src := consolesim.New()
	cfg := console.BrokerConfig{Socket: filepath.Join(dir, "c.sock"), AllowUIDs: []uint32{uint32(os.Getuid())}, Source: src, ScanEvery: 10 * time.Millisecond}
	if mod != nil {
		mod(&cfg)
	}
	b, err := console.NewBroker(cfg)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { _ = b.Serve(); close(done) }()
	t.Cleanup(func() { b.Close(); <-done })
	return &rig{t: t, b: b, src: src, sock: cfg.Socket}
}

func (r *rig) dial() net.Conn {
	c, err := net.Dial("unix", r.sock)
	if err != nil {
		r.t.Fatal(err)
	}
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	r.t.Cleanup(func() { _ = c.Close() })
	return c
}

func (r *rig) request(q console.Request) (net.Conn, console.Reply) {
	c := r.dial()
	q.V = console.Version
	if err := console.WriteFrame(c, q); err != nil {
		r.t.Fatal(err)
	}
	var rep console.Reply
	if err := console.ReadFrame(c, &rep); err != nil {
		r.t.Fatalf("reply: %v", err)
	}
	return c, rep
}

func (r *rig) snapshot(vm string) console.Reply {
	c, rep := r.request(console.Request{Op: console.OpSnapshot, VM: vm})
	_ = c.Close()
	return rep
}

func decoded(t *testing.T, rep console.Reply) string {
	t.Helper()
	b, err := console.Decode(rep.Data, console.MaxSnapshot)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func eventually(t *testing.T, what string, ok func() bool) {
	t.Helper()
	for i := 0; i < 300; i++ {
		if ok() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// readUntil reads output frames until the accumulated text contains want.
func readUntil(t *testing.T, c net.Conn, want string) string {
	t.Helper()
	var got strings.Builder
	for !strings.Contains(got.String(), want) {
		var f console.Frame
		if err := console.ReadFrame(c, &f); err != nil {
			t.Fatalf("waiting for %q, have %q: %v", want, got.String(), err)
		}
		if f.T == console.FrameOut {
			b, _ := console.Decode(f.D, console.MaxChunk)
			got.Write(b)
		} else if f.T == console.FrameEnd {
			t.Fatalf("ended (%s) while waiting for %q, have %q", f.Reason, want, got.String())
		}
	}
	return got.String()
}

func TestSnapshotStatesAreTyped(t *testing.T) {
	r := newRig(t, nil)
	r.src.Set("web-1", consolesim.VM{Managed: true, Configured: true, Running: true, Boot: []string{"[ 0.1] kernel", "[ 2.0] cloud-init done"}})
	r.src.Set("quiet", consolesim.VM{Managed: true, Configured: true, Running: true, Silent: true})
	r.src.Set("off", consolesim.VM{Managed: true, Configured: true})
	r.src.Set("noserial", consolesim.VM{Managed: true, Configured: false, Running: true})
	r.src.Set("foreign", consolesim.VM{Managed: false, Configured: true, Running: true, Boot: []string{"secret boot text"}})
	eventually(t, "boot output captured", func() bool { return r.snapshot("web-1").State == console.Available })
	rep := r.snapshot("web-1")
	if !strings.Contains(decoded(t, rep), "cloud-init done") || !rep.Running || rep.Truncated {
		t.Fatalf("%+v", rep)
	}
	if rep := r.snapshot("quiet"); rep.State != console.NoOutput || rep.Data != "" {
		t.Fatalf("quiet: %+v", rep)
	}
	if rep := r.snapshot("off"); rep.State != console.NoOutput || rep.Running {
		t.Fatalf("off: %+v", rep)
	}
	if rep := r.snapshot("noserial"); rep.State != console.NotConfigured {
		t.Fatalf("noserial: %+v", rep)
	}
	// A VM Svavyom does not own reveals nothing: not_configured, never its output, and no follower is ever opened for it.
	if rep := r.snapshot("foreign"); rep.State != console.NotConfigured || rep.Data != "" {
		t.Fatalf("foreign: %+v", rep)
	}
	if r.src.OpenCount["foreign"] != 0 || r.src.OpenCount["noserial"] != 0 {
		t.Fatal("a console was opened for a VM that is not ours or has no serial device")
	}
	if rep := r.snapshot("nope"); rep.OK || rep.Category != "not_found" {
		t.Fatalf("missing: %+v", rep)
	}
	r.src.Fail = context.DeadlineExceeded
	if rep := r.snapshot("web-1"); !rep.OK || rep.State != console.Unavailable || rep.Data != "" {
		t.Fatalf("hypervisor unreachable must be reported as unavailable, claiming nothing else: %+v", rep)
	}
}

func TestSnapshotIsBoundedAndKeepsTheLastOutputAfterTheVMStops(t *testing.T) {
	r := newRig(t, nil)
	r.src.Set("web-1", consolesim.VM{Managed: true, Configured: true, Running: true, Boot: []string{"boot"}})
	eventually(t, "boot", func() bool { return r.snapshot("web-1").State == console.Available })
	big := strings.Repeat("x", 100<<10) + "THE-END"
	r.src.Emit("web-1", big)
	eventually(t, "tail", func() bool { return strings.Contains(decoded(t, r.snapshot("web-1")), "THE-END") })
	rep := r.snapshot("web-1")
	if got := decoded(t, rep); len(got) > console.MaxSnapshot || !rep.Truncated || !strings.HasSuffix(got, "THE-END") {
		t.Fatalf("len=%d truncated=%v", len(got), rep.Truncated)
	}
	c, small := r.request(console.Request{Op: console.OpSnapshot, VM: "web-1", Max: 7})
	_ = c.Close()
	if decoded(t, small) != "THE-END" {
		t.Fatalf("max=7: %q", decoded(t, small))
	}
	r.src.Set("web-1", consolesim.VM{Managed: true, Configured: true, Running: false})
	time.Sleep(60 * time.Millisecond)
	if rep := r.snapshot("web-1"); rep.State != console.Available || rep.Running || !strings.HasSuffix(decoded(t, rep), "THE-END") {
		t.Fatalf("the last output must stay visible after the VM stops: %+v", rep)
	}
	// A new run starts a fresh buffer.
	r.src.Set("web-1", consolesim.VM{Managed: true, Configured: true, Running: true, Boot: []string{"second boot"}})
	eventually(t, "second boot", func() bool {
		s := decoded(t, r.snapshot("web-1"))
		return strings.Contains(s, "second boot") && !strings.Contains(s, "THE-END")
	})
}

func TestAttachReplaysThenStreamsAndAcceptsInput(t *testing.T) {
	r := newRig(t, nil)
	r.src.Set("web-1", consolesim.VM{Managed: true, Configured: true, Running: true, Boot: []string{"boot ok"}})
	eventually(t, "boot", func() bool { return r.snapshot("web-1").State == console.Available })
	c, rep := r.request(console.Request{Op: console.OpAttach, VM: "web-1"})
	if !rep.OK {
		t.Fatalf("%+v", rep)
	}
	readUntil(t, c, "web-1 login: ") // the replay of what happened before the attachment
	if err := console.WriteFrame(c, console.Frame{T: console.FrameIn, D: console.Encode([]byte("whoami\r"))}); err != nil {
		t.Fatal(err)
	}
	if got := readUntil(t, c, "root"); !strings.Contains(got, "whoami") {
		t.Fatalf("echo missing: %q", got)
	}
	// Output that appears later is live.
	r.src.Emit("web-1", "\r\nkernel: late message\r\n")
	readUntil(t, c, "late message")
	_ = console.WriteFrame(c, console.Frame{T: console.FrameEnd})
	eventually(t, "detached", func() bool { _, rep := r.request(console.Request{Op: console.OpAttach, VM: "web-1"}); return rep.OK })
}

func TestOneConsolePerVMAndRefusals(t *testing.T) {
	r := newRig(t, nil)
	r.src.Set("web-1", consolesim.VM{Managed: true, Configured: true, Running: true})
	r.src.Set("off", consolesim.VM{Managed: true, Configured: true})
	r.src.Set("foreign", consolesim.VM{Managed: false, Configured: true, Running: true})
	r.src.Set("noserial", consolesim.VM{Managed: true, Running: true})
	// The broker learns about a VM on its next scan, so the very first attach can legitimately answer "unavailable"; wait for it (this was a flake under load).
	var first net.Conn
	eventually(t, "the first attach", func() bool {
		c, rep := r.request(console.Request{Op: console.OpAttach, VM: "web-1"})
		if rep.OK {
			first = c
			return true
		}
		_ = c.Close()
		return false
	})
	defer first.Close()
	for vm, want := range map[string]string{"web-1": "conflict", "off": "conflict", "foreign": "prohibited", "noserial": "prohibited", "ghost": "not_found"} {
		c, rep := r.request(console.Request{Op: console.OpAttach, VM: vm})
		_ = c.Close()
		if rep.OK || rep.Category != want {
			t.Errorf("%s: %+v, want %s", vm, rep, want)
		}
	}
	if r.src.OpenCount["foreign"] != 0 || r.src.OpenCount["noserial"] != 0 || r.src.OpenCount["off"] != 0 {
		t.Fatal("a console was opened for a VM that must be refused")
	}
}

func TestAttachEndsWhenTheVMStopsAndNeedsAFreshAttachment(t *testing.T) {
	r := newRig(t, nil)
	r.src.Set("web-1", consolesim.VM{Managed: true, Configured: true, Running: true})
	c, rep := r.request(console.Request{Op: console.OpAttach, VM: "web-1"})
	if !rep.OK {
		t.Fatal(rep)
	}
	readUntil(t, c, "login: ")
	r.src.Set("web-1", consolesim.VM{Managed: true, Configured: true, Running: false})
	for {
		var f console.Frame
		if err := console.ReadFrame(c, &f); err != nil {
			t.Fatalf("connection closed without an end frame: %v", err)
		}
		if f.T == console.FrameEnd {
			if f.Reason != console.ReasonVMEnded {
				t.Fatalf("reason %q", f.Reason)
			}
			break
		}
	}
	r.src.Set("web-1", consolesim.VM{Managed: true, Configured: true, Running: true})
	eventually(t, "reattach", func() bool {
		c2, rep := r.request(console.Request{Op: console.OpAttach, VM: "web-1"})
		_ = c2.Close()
		return rep.OK
	})
}

func TestBoundedLifetimeAndIdle(t *testing.T) {
	for name, tc := range map[string]struct {
		mod    func(*console.BrokerConfig)
		reason string
	}{
		"idle":     {func(c *console.BrokerConfig) { c.IdleTimeout = 80 * time.Millisecond }, console.ReasonIdle},
		"lifetime": {func(c *console.BrokerConfig) { c.MaxLifetime = 80 * time.Millisecond; c.IdleTimeout = time.Hour }, console.ReasonLifetime},
	} {
		t.Run(name, func(t *testing.T) {
			r := newRig(t, tc.mod)
			r.src.Set("web-1", consolesim.VM{Managed: true, Configured: true, Running: true})
			c, rep := r.request(console.Request{Op: console.OpAttach, VM: "web-1"})
			if !rep.OK {
				t.Fatal(rep)
			}
			for {
				var f console.Frame
				if err := console.ReadFrame(c, &f); err != nil {
					t.Fatalf("no end frame: %v", err)
				}
				if f.T == console.FrameEnd {
					if f.Reason != tc.reason {
						t.Fatalf("reason %q, want %q", f.Reason, tc.reason)
					}
					return
				}
			}
		})
	}
}

func TestMalformedRequestsAndForeignPeersGetNothing(t *testing.T) {
	r := newRig(t, nil)
	for name, q := range map[string]console.Request{
		"unknown op": {V: 1, Op: "exec", VM: "web-1"}, "bad name": {V: 1, Op: console.OpSnapshot, VM: "../etc"}, "upper": {V: 1, Op: console.OpSnapshot, VM: "Web"},
		"version": {V: 2, Op: console.OpSnapshot, VM: "web-1"}, "attach with max": {V: 1, Op: console.OpAttach, VM: "web-1", Max: 5}, "huge max": {V: 1, Op: console.OpSnapshot, VM: "web-1", Max: 1 << 30},
	} {
		c := r.dial()
		_ = console.WriteFrame(c, q)
		var rep console.Reply
		if err := console.ReadFrame(c, &rep); err != nil || rep.OK || rep.Category != "validation" {
			t.Errorf("%s: %+v %v", name, rep, err)
		}
	}
	for name, raw := range map[string][]byte{"garbage": []byte("hello"), "zero length": {0, 0, 0, 0}, "oversize": {0, 1, 0, 0}, "trailing": append([]byte{0, 0, 0, 0x1d}, []byte(`{"v":1,"op":"snapshot","vm":"a"}x`)...)} {
		c := r.dial()
		_, _ = c.Write(raw)
		var rep console.Reply
		if err := console.ReadFrame(c, &rep); err == nil && rep.OK {
			t.Errorf("%s accepted", name)
		}
	}
	// A peer whose uid is not allowed is dropped without a reply.
	dir, _ := os.MkdirTemp("", "cb2")
	defer os.RemoveAll(dir)
	b, err := console.NewBroker(console.BrokerConfig{Socket: filepath.Join(dir, "c.sock"), AllowUIDs: []uint32{uint32(os.Getuid()) + 1}, Source: consolesim.New()})
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = b.Serve() }()
	defer b.Close()
	c, err := net.Dial("unix", filepath.Join(dir, "c.sock"))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(2 * time.Second))
	_ = console.WriteFrame(c, console.Request{V: 1, Op: console.OpSnapshot, VM: "web-1"})
	var rep console.Reply
	if err := console.ReadFrame(c, &rep); err == nil {
		t.Fatalf("a peer outside the allowlist got a reply: %+v", rep)
	}
}

func TestBrokerConfigRefusals(t *testing.T) {
	src := consolesim.New()
	for name, cfg := range map[string]console.BrokerConfig{
		"no source": {Socket: "/tmp/x.sock", AllowUIDs: []uint32{1}}, "relative": {Socket: "x.sock", AllowUIDs: []uint32{1}, Source: src},
		"unclean": {Socket: "/tmp/../tmp/x.sock", AllowUIDs: []uint32{1}, Source: src}, "no uids": {Socket: "/tmp/x.sock", Source: src},
		"too long": {Socket: "/tmp/" + strings.Repeat("a", 120), AllowUIDs: []uint32{1}, Source: src},
	} {
		if _, err := console.NewBroker(cfg); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	dir := t.TempDir()
	p := filepath.Join(dir, "regular")
	_ = os.WriteFile(p, []byte("x"), 0o600)
	if _, err := console.NewBroker(console.BrokerConfig{Socket: p, AllowUIDs: []uint32{1}, Source: src}); err == nil {
		t.Error("replaced a regular file")
	}
}

func TestInputIsRateLimitedNotRefused(t *testing.T) {
	r := newRig(t, func(c *console.BrokerConfig) { c.InputPerSecond = 2000 })
	r.src.Set("web-1", consolesim.VM{Managed: true, Configured: true, Running: true})
	c, rep := r.request(console.Request{Op: console.OpAttach, VM: "web-1"})
	if !rep.OK {
		t.Fatal(rep)
	}
	readUntil(t, c, "login: ")
	payload := bytes.Repeat([]byte("a"), 3000)
	start := time.Now()
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_ = console.WriteFrame(c, console.Frame{T: console.FrameIn, D: console.Encode(payload[:1500])})
		_ = console.WriteFrame(c, console.Frame{T: console.FrameIn, D: console.Encode(payload[1500:])})
	}()
	readUntil(t, c, strings.Repeat("a", 3000))
	wg.Wait()
	if time.Since(start) < 300*time.Millisecond {
		t.Fatalf("3000 bytes at 2000 B/s arrived in %v: not rate limited", time.Since(start))
	}
}

// TestCloseNeverWaitsForAFollowerCreatedDuringShutdown is the regression test of a hang found by the post-merge gate: Close raced with the
// scanner opening a console stream, missed the new follower, and Serve waited for it forever.
func TestCloseNeverWaitsForAFollowerCreatedDuringShutdown(t *testing.T) {
	for i := 0; i < 200; i++ {
		dir, err := os.MkdirTemp("", "cb")
		if err != nil {
			t.Fatal(err)
		}
		src := consolesim.New()
		for n := 0; n < 4; n++ {
			src.Set("vm-"+string(rune('a'+n)), consolesim.VM{Managed: true, Configured: true, Running: true})
		}
		b, err := console.NewBroker(console.BrokerConfig{Socket: filepath.Join(dir, "c.sock"), AllowUIDs: []uint32{uint32(os.Getuid())}, Source: src, ScanEvery: time.Millisecond})
		if err != nil {
			t.Fatal(err)
		}
		done := make(chan struct{})
		go func() { _ = b.Serve(); close(done) }()
		time.Sleep(time.Duration(i%5) * time.Millisecond) // close at varying points of the scan
		b.Close()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatalf("iteration %d: Serve did not return after Close", i)
		}
		_ = os.RemoveAll(dir)
	}
}
