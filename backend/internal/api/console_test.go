package api

import (
	"bufio"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"example.invalid/dedicatedcloud/backend/internal/console"
	"example.invalid/dedicatedcloud/backend/internal/console/consolesim"
	"example.invalid/dedicatedcloud/backend/internal/simhost"
)

type consRig struct {
	*crig
	src     *consolesim.Source
	tickets *console.Tickets
	mu      sync.Mutex
	audits  []ConsoleAudit
	b       *browser
}

func (c *consRig) auditEvents() []ConsoleAudit {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]ConsoleAudit(nil), c.audits...)
}

// newConsRig builds the creation rig, a real console broker over the simulated console source, and a signed-in browser with one
// managed VM, web-1, that is created and started through the API.
func newConsRig(t *testing.T, enabled bool) *consRig {
	t.Helper()
	r := newCRig(t, true)
	dir, err := os.MkdirTemp("", "cr")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	src := consolesim.New()
	sock := filepath.Join(dir, "c.sock")
	br, err := console.NewBroker(console.BrokerConfig{Socket: sock, AllowUIDs: []uint32{uint32(os.Getuid())}, Source: src, ScanEvery: 10 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { _ = br.Serve(); close(done) }()
	t.Cleanup(func() { br.Close(); <-done })
	cl, _ := console.NewClient(sock, 5*time.Second)
	c := &consRig{crig: r, src: src, tickets: console.NewTickets(300*time.Millisecond, nil)}
	r.cons = &Console{Enabled: enabled, Tickets: c.tickets, Broker: cl, SessionCheck: 20 * time.Millisecond,
		Audit: func(a ConsoleAudit) { c.mu.Lock(); c.audits = append(c.audits, a); c.mu.Unlock() }}
	r.wire()
	c.b = signedIn(t, r.env)
	id := opID(t, r.post(c.b, r.createBody("web-1", r.key, nil)))
	r.await(c.b, id, "succeeded")
	sid := opID(t, r.post(c.b, `{"type":"start","kind":"VM","id":"web-1","idempotency_key":"start-web-1"}`))
	r.await(c.b, sid, "succeeded")
	src.Set("web-1", consolesim.VM{Managed: true, Configured: true, Running: true, Boot: []string{"[    0.000000] Linux version 6.8", "\x1b[0;32m  OK  \x1b[0m Reached target Multi-User System.", "cloud-init[512]: Cloud-init v. 24.1 finished"}})
	return c
}

func (c *consRig) ticket(vm string) (string, reply) {
	c.t.Helper()
	rep := c.b.do("POST", "/console/v1/vms/"+vm+"/tickets", "", map[string]string{"X-CSRF-Token": c.b.csrf})
	var tk ticketJSON
	_ = json.Unmarshal(rep.body, &tk)
	return tk.Ticket, rep
}

func (c *consRig) sessionCookie() string {
	u, _ := url.Parse(c.srv.URL)
	for _, ck := range c.b.c.Jar.Cookies(u) {
		if ck.Name == "svavyom_session" {
			return ck.Name + "=" + ck.Value
		}
	}
	c.t.Fatal("no session cookie")
	return ""
}

type wsc struct {
	c    net.Conn
	br   *bufio.Reader
	rbuf []byte // bytes of a message not yet consumed by readN
}

// dialSocket performs the WebSocket handshake by hand and returns the status line.
func (c *consRig) dialSocket(vm, protos string, hdr map[string]string) (*wsc, string) {
	return c.dialPath(vm, "socket", protos, hdr)
}

func (c *consRig) dialPath(vm, route, protos string, hdr map[string]string) (*wsc, string) {
	c.t.Helper()
	u, _ := url.Parse(c.srv.URL)
	conn, err := net.Dial("tcp", u.Host)
	if err != nil {
		c.t.Fatal(err)
	}
	c.t.Cleanup(func() { _ = conn.Close() })
	_ = conn.SetDeadline(time.Now().Add(8 * time.Second))
	var k [16]byte
	_, _ = rand.Read(k[:])
	h := map[string]string{"Host": u.Host, "Upgrade": "websocket", "Connection": "Upgrade", "Sec-WebSocket-Version": "13", "Origin": c.srv.URL,
		"Sec-WebSocket-Key": base64.StdEncoding.EncodeToString(k[:]), "Cookie": c.sessionCookie()}
	if protos != "" {
		h["Sec-WebSocket-Protocol"] = protos
	}
	for k, v := range hdr {
		if v == "" {
			delete(h, k)
		} else {
			h[k] = v
		}
	}
	var sb strings.Builder
	sb.WriteString("GET /console/v1/vms/" + vm + "/" + route + " HTTP/1.1\r\n")
	for k, v := range h {
		sb.WriteString(k + ": " + v + "\r\n")
	}
	sb.WriteString("\r\n")
	_, _ = conn.Write([]byte(sb.String()))
	br := bufio.NewReader(conn)
	status, _ := br.ReadString('\n')
	return &wsc{c: conn, br: br}, status
}

func (w *wsc) skipHeaders(t *testing.T) {
	t.Helper()
	for {
		l, err := w.br.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		if l == "\r\n" {
			return
		}
	}
}

func (w *wsc) send(t *testing.T, op byte, p []byte) {
	t.Helper()
	var mk [4]byte
	_, _ = rand.Read(mk[:])
	h := []byte{0x80 | op}
	switch n := len(p); {
	case n < 126:
		h = append(h, 0x80|byte(n))
	default:
		h = append(h, 0x80|126, byte(n>>8), byte(n))
	}
	h = append(h, mk[:]...)
	b := append([]byte(nil), p...)
	for i := range b {
		b[i] ^= mk[i%4]
	}
	if _, err := w.c.Write(append(h, b...)); err != nil {
		t.Fatal(err)
	}
}

func (w *wsc) frame() (int, []byte, error) {
	var h [2]byte
	if _, err := io.ReadFull(w.br, h[:]); err != nil {
		return 0, nil, err
	}
	n := int(h[1] & 0x7f)
	if n == 126 {
		var b [2]byte
		if _, err := io.ReadFull(w.br, b[:]); err != nil {
			return 0, nil, err
		}
		n = int(binary.BigEndian.Uint16(b[:]))
	}
	p := make([]byte, n)
	if _, err := io.ReadFull(w.br, p); err != nil {
		return 0, nil, err
	}
	return int(h[0] & 0x0f), p, nil
}

func (w *wsc) readUntil(t *testing.T, want string) string {
	t.Helper()
	var got strings.Builder
	for !strings.Contains(got.String(), want) {
		op, p, err := w.frame()
		if err != nil || op == 0x8 {
			t.Fatalf("waiting for %q, have %q: op=%d err=%v", want, got.String(), op, err)
		}
		got.Write(p)
	}
	return got.String()
}

func (c *consRig) open(vm string) *wsc {
	c.t.Helper()
	tk, rep := c.ticket(vm)
	if rep.status != 200 || tk == "" {
		c.t.Fatalf("ticket: %d %s", rep.status, rep.body)
	}
	w, status := c.dialSocket(vm, consoleProto+", "+ticketPrefix+tk, nil)
	if !strings.Contains(status, "101") {
		c.t.Fatalf("handshake: %q", status)
	}
	w.skipHeaders(c.t)
	return w
}

func TestSerialOutputIsTypedBoundedAndSanitised(t *testing.T) {
	c := newConsRig(t, false) // the interactive switch is off: reading the output does not need it
	deadline := time.Now().Add(3 * time.Second)
	var s serialJSON
	for time.Now().Before(deadline) {
		rep := c.b.do("GET", "/console/v1/vms/web-1/serial", "", nil)
		if rep.status != 200 {
			t.Fatalf("%d %s", rep.status, rep.body)
		}
		_ = json.Unmarshal(rep.body, &s)
		if s.State == "available" {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if s.State != "available" || !s.Running || !strings.Contains(s.Text, "Reached target Multi-User System.") || strings.ContainsAny(s.Text, "\x1b\r") {
		t.Fatalf("%+v", s)
	}
	// every other VM state is typed, and a stranger's output is never shown
	_ = c.sim.Add("foreign", simhost.Domain{UUID: "9a9a9a9a-2222-4333-8444-5555555555ab", Running: true, VCPUs: 1, MemoryMiB: 64})
	c.src.Set("foreign", consolesim.VM{Managed: false, Configured: true, Running: true, Boot: []string{"private text"}})
	c.src.Set("nodev", consolesim.VM{Managed: true, Configured: false, Running: true})
	c.src.Set("quiet", consolesim.VM{Managed: true, Configured: true, Running: true, Silent: true})
	for vm, want := range map[string]string{"foreign": "not_configured", "nodev": "not_configured", "quiet": "no_output"} {
		rep := c.b.do("GET", "/console/v1/vms/"+vm+"/serial", "", nil)
		_ = json.Unmarshal(rep.body, &s)
		if rep.status != 200 || s.State != want || s.Text != "" {
			t.Errorf("%s: %d %s", vm, rep.status, rep.body)
		}
	}
	if rep := c.b.do("GET", "/console/v1/vms/ghost/serial", "", nil); rep.status != 404 {
		t.Errorf("unknown VM: %d", rep.status)
	}
	if rep := c.b.do("GET", "/console/v1/vms/web-1/serial?path=/etc/passwd", "", nil); rep.status != 400 {
		t.Errorf("a query is refused: %d", rep.status)
	}
	if rep := c.b.do("POST", "/console/v1/vms/web-1/serial", "", nil); rep.status != 404 {
		t.Errorf("wrong method: %d", rep.status)
	}
	if rep := c.e().browser().do("GET", "/console/v1/vms/web-1/serial", "", nil); rep.status != 401 {
		t.Errorf("anonymous: %d", rep.status)
	}
	// a broker that cannot be reached is a typed console state, not a failure of the API
	c.cons.Broker, _ = console.NewClient("/nonexistent/broker.sock", time.Second)
	rep := c.b.do("GET", "/console/v1/vms/web-1/serial", "", nil)
	_ = json.Unmarshal(rep.body, &s)
	if rep.status != 200 || s.State != "unavailable" || s.Text != "" {
		t.Fatalf("%d %s", rep.status, rep.body)
	}
}

func (c *consRig) e() *env { return c.env }

func TestSerialTextSanitising(t *testing.T) {
	cases := map[string]string{
		"plain\r\nline two\r\n":         "plain\nline two\n",
		"\x1b[31mred\x1b[0m done":       "red done",
		"a\x07b\x00c\x1bXd":             "abcd",
		"bad\xff\xfeutf":                "bad\uFFFDutf",
		"progress 10%\rprogress 100%\n": "progress 10%\nprogress 100%\n",
		"tab\there":                     "tab\there",
		"\x1b[2J\x1b[Hclear":            "clear",
	}
	for in, want := range cases {
		if got := serialText([]byte(in)); got != want {
			t.Errorf("%q -> %q, want %q", in, got, want)
		}
	}
}

func TestTicketMintingRules(t *testing.T) {
	c := newConsRig(t, true)
	tk, rep := c.ticket("web-1")
	if rep.status != 200 || len(tk) != 43 || rep.header.Get("Cache-Control") != "no-store" {
		t.Fatalf("%d %s %v", rep.status, rep.body, rep.header)
	}
	post := func(vm string, hdr map[string]string) reply {
		return c.b.do("POST", "/console/v1/vms/"+vm+"/tickets", "", hdr)
	}
	if rep := post("web-1", nil); rep.status != 403 {
		t.Errorf("no CSRF token: %d", rep.status)
	}
	if rep := post("web-1", map[string]string{"X-CSRF-Token": c.b.csrf, "Origin": "https://evil.example"}); rep.status != 403 {
		t.Errorf("foreign origin: %d", rep.status)
	}
	if rep := c.e().browser().do("POST", "/console/v1/vms/web-1/tickets", "", map[string]string{"X-CSRF-Token": c.b.csrf}); rep.status != 401 {
		t.Errorf("anonymous: %d", rep.status)
	}
	good := map[string]string{"X-CSRF-Token": c.b.csrf}
	if rep := post("ghost", good); rep.status != 404 {
		t.Errorf("unknown VM: %d", rep.status)
	}
	_ = c.sim.Add("foreign", simhost.Domain{UUID: "9a9a9a9a-2222-4333-8444-5555555555ab", Running: true, VCPUs: 1, MemoryMiB: 64})
	if rep := post("foreign", good); rep.status != 422 {
		t.Errorf("a VM Svavyom does not own: %d", rep.status)
	}
	// a stopped VM has no console to attach to
	oid := opID(t, c.post(c.b, `{"type":"force_off","kind":"VM","id":"web-1","idempotency_key":"off-1"}`))
	c.await(c.b, oid, "succeeded")
	if rep := post("web-1", good); rep.status != 409 {
		t.Errorf("stopped VM: %d", rep.status)
	}
	// the switch
	c.cons.Enabled = false
	if rep := post("web-1", good); rep.status != 422 {
		t.Errorf("console switch off: %d %s", rep.status, rep.body)
	}
}

func TestInteractiveConsoleEndToEnd(t *testing.T) {
	c := newConsRig(t, true)
	w := c.open("web-1")
	w.readUntil(t, "web-1 login: ")
	w.send(t, 0x2, []byte("whoami\r"))
	if got := w.readUntil(t, "root"); !strings.Contains(got, "whoami") {
		t.Fatalf("echo: %q", got)
	}
	// the page can reconnect, but only with a FRESH ticket, and not while the first connection holds the console
	w.send(t, 0x8, []byte{0x03, 0xe8})
	time.Sleep(80 * time.Millisecond)
	w2 := c.open("web-1")
	w2.readUntil(t, "web-1 login: ")
	events := map[string]int{}
	for _, a := range c.auditEvents() {
		events[a.Event]++
		if a.Actor != adminName && a.Event != "serial.read" {
			t.Errorf("audit actor %q", a.Actor)
		}
	}
	if events["ticket.minted"] != 2 || events["console.opened"] != 2 || events["console.closed"] < 1 {
		t.Fatalf("audit %v", events)
	}
}

func TestSocketRefusals(t *testing.T) {
	c := newConsRig(t, true)
	status := func(w *wsc, s string) string { return s }
	mustRefuse := func(name, want string, vm, protos string, hdr map[string]string) {
		t.Helper()
		_, s := c.dialSocket(vm, protos, hdr)
		if !strings.Contains(status(nil, s), want) {
			t.Errorf("%s: %q, want %s", name, s, want)
		}
	}
	fresh := func() string { tk, _ := c.ticket("web-1"); return consoleProto + ", " + ticketPrefix + tk }
	mustRefuse("no ticket", "400", "web-1", consoleProto, nil)
	mustRefuse("no subprotocol", "400", "web-1", "", nil)
	mustRefuse("garbage ticket", "403", "web-1", consoleProto+", "+ticketPrefix+strings.Repeat("A", 43), nil)
	mustRefuse("empty ticket", "400", "web-1", consoleProto+", "+ticketPrefix, nil)
	mustRefuse("two tickets", "400", "web-1", fresh()+", "+ticketPrefix+strings.Repeat("A", 43), nil)
	mustRefuse("unknown extra protocol", "400", "web-1", fresh()+", chat", nil)
	mustRefuse("no Origin", "403", "web-1", fresh(), map[string]string{"Origin": ""})
	mustRefuse("foreign Origin", "403", "web-1", fresh(), map[string]string{"Origin": "https://evil.example"})
	mustRefuse("no cookie", "401", "web-1", fresh(), map[string]string{"Cookie": ""})
	mustRefuse("bad version", "400", "web-1", fresh(), map[string]string{"Sec-WebSocket-Version": "8"})
	// wrong VM: a ticket for web-1 is useless for another VM (and for an unknown one)
	_ = c.sim.Add("other", simhost.Domain{UUID: "8a8a8a8a-2222-4333-8444-5555555555ab", Running: true, VCPUs: 1, MemoryMiB: 64})
	mustRefuse("ticket for another VM", "403", "other", fresh(), nil)
	// replay
	tk, _ := c.ticket("web-1")
	p := consoleProto + ", " + ticketPrefix + tk
	w, s := c.dialSocket("web-1", p, nil)
	if !strings.Contains(s, "101") {
		t.Fatalf("first use: %q", s)
	}
	w.skipHeaders(t)
	w.send(t, 0x8, []byte{0x03, 0xe8})
	time.Sleep(80 * time.Millisecond)
	mustRefuse("replayed ticket", "403", "web-1", p, nil)
	// expiry
	tk2, _ := c.ticket("web-1")
	time.Sleep(350 * time.Millisecond)
	mustRefuse("expired ticket", "403", "web-1", consoleProto+", "+ticketPrefix+tk2, nil)
	// another session's ticket
	other := c.e().browser()
	other.status()
	if r := other.signIn(adminName, adminPass); r.status != 200 {
		t.Fatal(r.status)
	}
	otk := func() string {
		rep := other.do("POST", "/console/v1/vms/web-1/tickets", "", map[string]string{"X-CSRF-Token": other.csrf})
		var t2 ticketJSON
		_ = json.Unmarshal(rep.body, &t2)
		return t2.Ticket
	}()
	mustRefuse("another session's ticket", "403", "web-1", consoleProto+", "+ticketPrefix+otk, nil)
	// switch off
	c.cons.Enabled = false
	mustRefuse("console switch off", "422", "web-1", fresh(), nil)
	// plain GET without upgrade
	c.cons.Enabled = true
	rep := c.b.do("GET", "/console/v1/vms/web-1/socket", "", map[string]string{"Origin": c.srv.URL})
	if rep.status != 400 {
		t.Errorf("not an upgrade: %d", rep.status)
	}
}

func TestConsoleEndsWhenTheSessionEndsOrTheVMStops(t *testing.T) {
	c := newConsRig(t, true)
	w := c.open("web-1")
	w.readUntil(t, "login: ")
	if so := c.b.signOut(); so.status != 200 {
		t.Fatal(so.status)
	}
	end := func(w *wsc) {
		t.Helper()
		_ = w.c.SetDeadline(time.Now().Add(3 * time.Second))
		for {
			op, _, err := w.frame()
			if err != nil || op == 0x8 {
				return
			}
		}
	}
	end(w)
	waitAudit := func(c *consRig, ok func(ConsoleAudit) bool) bool {
		for i := 0; i < 100; i++ {
			for _, a := range c.auditEvents() {
				if a.Event == "console.closed" && ok(a) {
					return true
				}
			}
			time.Sleep(20 * time.Millisecond)
		}
		return false
	}
	if !waitAudit(c, func(a ConsoleAudit) bool { return a.Outcome == "session_ended" }) {
		t.Fatalf("a console must close when its session ends: %+v", c.auditEvents())
	}
	// the VM stopping ends the console too
	c2 := newConsRig(t, true)
	w2 := c2.open("web-1")
	w2.readUntil(t, "login: ")
	c2.src.Set("web-1", consolesim.VM{Managed: true, Configured: true, Running: false})
	end(w2)
	if !waitAudit(c2, func(a ConsoleAudit) bool { return a.Outcome == console.ReasonVMEnded || a.Outcome == "broker" }) {
		t.Fatalf("no close audit: %+v", c2.auditEvents())
	}
}

func TestConsoleRoutesAreClosedWithoutABroker(t *testing.T) {
	r := newCRig(t, true)
	b := signedIn(t, r.env)
	for _, p := range []string{"/console/v1/vms/web-1/serial", "/console/v1/vms/web-1/tickets", "/console/v1/vms/web-1/socket", "/console/v1/other", "/console/v1/vms/../serial"} {
		if rep := b.do("GET", p, "", nil); rep.status != 404 {
			t.Errorf("%s: %d", p, rep.status)
		}
	}
	_ = http.StatusOK
}
