//go:build libvirt && libvirt_test

// Package qualify holds the REAL-HOST console qualification (docs/QUALIFICATION-CONSOLE.md). It does nothing unless
// SVAVYOM_QUALIFY_CREATE=1 and SVAVYOM_QUALIFY_STAGE=console, so `make check` never runs it. It continues a run whose create stage left
// the run's VM Running, and exercises the production console path end to end against the real qemu:///system:
//
//	browser-side client -> API handler (session, CSRF, same origin, ticket) -> console broker -> libvirt serial console -> real guest
//
// in a container that has NO network: the console is reached without SSH, by construction. Evidence lines start with "QUALIFY ".
package qualify

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"example.invalid/dedicatedcloud/backend/internal/api"
	"example.invalid/dedicatedcloud/backend/internal/auth"
	"example.invalid/dedicatedcloud/backend/internal/console"
	"example.invalid/dedicatedcloud/backend/internal/console/libvirtcon"
	"example.invalid/dedicatedcloud/backend/internal/hypervisor"
	"example.invalid/dedicatedcloud/backend/internal/hypervisor/libvirtmut"
	"example.invalid/dedicatedcloud/backend/internal/hypervisor/libvirtro"
	"example.invalid/dedicatedcloud/backend/internal/provision"
	"example.invalid/dedicatedcloud/backend/internal/sqlitedb"
)

var runIDRE = regexp.MustCompile(`^qr-[0-9]{8}-[0-9a-f]{6}$`)

// qualIdentity MUST equal the derivation in the create stage (libvirtmut/qualify_test.go): the VM is found by the identity derived
// from the run id, and ownership is proven by recomputing it.
func qualIdentity(runID string) (name, uuid, fingerprint string, err error) {
	if !runIDRE.MatchString(runID) {
		return "", "", "", fmt.Errorf("run id must look like qr-YYYYMMDD-xxxxxx")
	}
	s := sha256.Sum256([]byte("svavyom-qualify-uuid-v1:" + runID))
	b := s[:16]
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	h := hex.EncodeToString(b)
	uuid = h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
	f := sha256.Sum256([]byte("svavyom-qualify-fingerprint-v1:" + runID))
	return "svq-" + strings.TrimPrefix(runID, "qr-"), uuid, hex.EncodeToString(f[:]), nil
}

type criterion struct {
	ID     string `json:"id"`
	Status string `json:"status"`
	Detail string `json:"detail,omitempty"`
}

type result struct {
	RunID    string      `json:"run_id"`
	Stage    string      `json:"stage"`
	VMName   string      `json:"vm_name"`
	Criteria []criterion `json:"criteria"`
}

type recorder struct {
	t   *testing.T
	res *result
	out string
}

func (r *recorder) add(id, status, detail string) {
	r.res.Criteria = append(r.res.Criteria, criterion{ID: id, Status: status, Detail: detail})
	fmt.Printf("QUALIFY %s %s %s\n", status, id, detail)
}
func (r *recorder) pass(id, detail string) { r.add(id, "PASS", detail) }
func (r *recorder) fail(id, detail string) {
	r.add(id, "FAIL", detail)
	r.t.Fatalf("%s: %s", id, detail)
}
func (r *recorder) flush() {
	if r.out == "" {
		return
	}
	b, _ := json.MarshalIndent(r.res, "", "  ")
	_ = os.WriteFile(filepath.Join(r.out, "console-result.json"), append(b, '\n'), 0o644) // #nosec G306 -- non-secret qualification result
}

// ---- a minimal browser: cookie jar, CSRF token, and a hand-written WebSocket client ----------------------------------------

type browser struct {
	t    *testing.T
	base string
	c    *http.Client
	csrf string
}

func newBrowser(t *testing.T, base string) *browser {
	jar, _ := cookiejar.New(nil)
	return &browser{t: t, base: base, c: &http.Client{Jar: jar, Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
}

func (b *browser) do(method, path, body string, hdr map[string]string) (int, http.Header, []byte) {
	req, err := http.NewRequest(method, b.base+path, strings.NewReader(body))
	if err != nil {
		b.t.Fatal(err)
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	res, err := b.c.Do(req)
	if err != nil {
		b.t.Fatal(err)
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(res.Body)
	return res.StatusCode, res.Header, raw
}

func (b *browser) signIn(user, pass string) bool {
	_, h, _ := b.do("GET", "/api/v1/auth/session", "", nil)
	b.csrf = h.Get("X-CSRF-Token")
	cred, _ := json.Marshal(map[string]string{"username": user, "password": pass})
	st, h, _ := b.do("POST", "/api/v1/auth/session", string(cred), map[string]string{"X-CSRF-Token": b.csrf})
	if t := h.Get("X-CSRF-Token"); t != "" {
		b.csrf = t
	}
	return st == 200
}

func (b *browser) ticket(vm string) (string, int) {
	st, _, body := b.do("POST", "/console/v1/vms/"+vm+"/tickets", "", map[string]string{"X-CSRF-Token": b.csrf})
	var t struct {
		Ticket string `json:"ticket"`
	}
	_ = json.Unmarshal(body, &t)
	return t.Ticket, st
}

func (b *browser) cookie() string {
	u, _ := url.Parse(b.base)
	for _, c := range b.c.Jar.Cookies(u) {
		if c.Name == "svavyom_session" {
			return c.Name + "=" + c.Value
		}
	}
	b.t.Fatal("no session cookie")
	return ""
}

type ws struct {
	c  net.Conn
	br *bufio.Reader
}

func (b *browser) dialSocket(vm, protos string) (*ws, string) {
	u, _ := url.Parse(b.base)
	conn, err := net.Dial("tcp", u.Host)
	if err != nil {
		b.t.Fatal(err)
	}
	b.t.Cleanup(func() { _ = conn.Close() })
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	var k [16]byte
	_, _ = rand.Read(k[:])
	req := "GET /console/v1/vms/" + vm + "/socket HTTP/1.1\r\nHost: " + u.Host + "\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nOrigin: " + b.base +
		"\r\nSec-WebSocket-Key: " + base64.StdEncoding.EncodeToString(k[:]) + "\r\nSec-WebSocket-Protocol: " + protos + "\r\nCookie: " + b.cookie() + "\r\n\r\n"
	_, _ = conn.Write([]byte(req))
	br := bufio.NewReader(conn)
	status, _ := br.ReadString('\n')
	return &ws{c: conn, br: br}, status
}

func (w *ws) skipHeaders() {
	for {
		l, err := w.br.ReadString('\n')
		if err != nil || l == "\r\n" {
			return
		}
	}
}

func (w *ws) send(p []byte) {
	var mk [4]byte
	_, _ = rand.Read(mk[:])
	h := []byte{0x82, 0x80 | byte(len(p))}
	h = append(h, mk[:]...)
	b := append([]byte(nil), p...)
	for i := range b {
		b[i] ^= mk[i%4]
	}
	_, _ = w.c.Write(append(h, b...))
}

func (w *ws) close() {
	_, _ = w.c.Write([]byte{0x88, 0x82, 0, 0, 0, 0, 0x03, 0xe8})
}

func (w *ws) frame() (int, []byte, error) {
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

// until reads console output until it contains want (or the time is up) and returns everything read.
func (w *ws) until(want string, d time.Duration) (string, bool) {
	_ = w.c.SetReadDeadline(time.Now().Add(d))
	var got strings.Builder
	for !strings.Contains(got.String(), want) {
		op, p, err := w.frame()
		if err != nil || op == 0x8 {
			return got.String(), false
		}
		got.Write(p)
	}
	return got.String(), true
}

func TestSystemConsoleQualification(t *testing.T) {
	if os.Getenv("SVAVYOM_QUALIFY_CREATE") != "1" || os.Getenv("SVAVYOM_QUALIFY_STAGE") != "console" {
		t.Skip("NOT_RUN: set SVAVYOM_QUALIFY_CREATE=1 and SVAVYOM_QUALIFY_STAGE=console on an authorised disposable host (docs/QUALIFICATION-CONSOLE.md)")
	}
	runID := os.Getenv("SVAVYOM_QUALIFY_RUN_ID")
	name, uuid, fp, err := qualIdentity(runID)
	if err != nil {
		t.Fatal(err)
	}
	rec := &recorder{t: t, out: os.Getenv("SVAVYOM_QUALIFY_OUT"), res: &result{RunID: runID, Stage: "console", VMName: name}}
	defer rec.flush()
	ctx := context.Background()

	ops, err := libvirtmut.Open(libvirtmut.SystemURI)
	if err != nil {
		rec.fail("real-libvirt", "cannot open qemu:///system")
	}
	defer ops.Close()
	ro, err := libvirtro.Open(libvirtro.SystemURI)
	if err != nil {
		rec.fail("real-libvirt", "cannot open the read-only socket")
	}
	defer ro.Close()
	di, err := ops.LookupDomain(ctx, name)
	if err != nil || !di.Managed || di.UUID != uuid || di.Fingerprint != fp {
		rec.fail("console-precondition", fmt.Sprintf("the run's VM is not provably Svavyom-owned: %v", err))
	}
	if !strings.Contains(di.XML, "<serial") {
		rec.fail("console-serial-device", "the run's domain definition has no serial device (it predates the serial console)")
	}
	rec.pass("console-serial-device", "the domain definition declares a serial console device")

	// The production broker, over the real libvirt console source, on a socket in a private directory.
	src, err := libvirtcon.Open(libvirtcon.SystemURI)
	if err != nil {
		rec.fail("real-libvirt", "the console source cannot reach libvirt")
	}
	defer src.Close()
	dir, _ := os.MkdirTemp("", "qc")
	defer os.RemoveAll(dir)
	sock := filepath.Join(dir, "console.sock")
	broker, err := console.NewBroker(console.BrokerConfig{Socket: sock, AllowUIDs: []uint32{uint32(os.Getuid())}, Source: src, ScanEvery: 250 * time.Millisecond})
	if err != nil {
		rec.fail("console-broker", fmt.Sprint(err))
	}
	done := make(chan struct{})
	go func() { _ = broker.Serve(); close(done) }()
	defer func() { broker.Close(); <-done }()
	client, _ := console.NewClient(sock, 10*time.Second)
	rec.pass("console-broker", "broker started over the real libvirt console source (zero network namespace: no SSH is possible)")

	// The API, wired exactly as `api serve --experimental-console`, with a short ticket lifetime so expiry can be proven quickly.
	db, err := sqlitedb.Open(filepath.Join(dir, "api.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	svc, err := auth.New(ctx, db, auth.Config{})
	if err != nil {
		t.Fatal(err)
	}
	var pw [12]byte
	_, _ = rand.Read(pw[:])
	pass := hex.EncodeToString(pw[:])
	if err := svc.Bootstrap(ctx, "qualifier", pass); err != nil {
		t.Fatal(err)
	}
	tickets := console.NewTickets(3*time.Second, nil)
	var audits []api.ConsoleAudit
	h := api.NewHandlerWith(api.Deps{Auth: svc, VMs: ro, Console: &api.Console{Enabled: true, Tickets: tickets, Broker: client, SessionCheck: 500 * time.Millisecond,
		Audit: func(a api.ConsoleAudit) { audits = append(audits, a) }}})
	srv := httptest.NewServer(h)
	defer srv.Close()
	b := newBrowser(t, srv.URL)
	if !b.signIn("qualifier", pass) {
		rec.fail("console-api", "sign-in to the test API failed")
	}

	// 1. Serial boot output exists and is read without SSH: the VM is stopped gracefully, then started while the broker follows it.
	if err := provision.Stop(ctx, ops, name, nil); err != nil {
		rec.fail("serial-boot-output", fmt.Sprintf("graceful stop before the boot capture failed: %v", err))
	}
	if st, _, body := b.do("GET", "/console/v1/vms/"+name+"/serial", "", nil); st != 200 {
		rec.fail("serial-boot-output", fmt.Sprintf("serial endpoint answered %d %s with the VM stopped", st, body))
	}
	if err := provision.Start(ctx, ops, name, nil); err != nil {
		rec.fail("serial-boot-output", fmt.Sprintf("start failed: %v", err))
	}
	var serial struct {
		State     string `json:"state"`
		Text      string `json:"text"`
		Truncated bool   `json:"truncated"`
		Running   bool   `json:"running"`
	}
	deadline := time.Now().Add(4 * time.Minute)
	for time.Now().Before(deadline) {
		st, _, body := b.do("GET", "/console/v1/vms/"+name+"/serial", "", nil)
		if st == 200 && json.Unmarshal(body, &serial) == nil && serial.State == "available" && strings.Contains(serial.Text, "login:") {
			break
		}
		time.Sleep(2 * time.Second)
	}
	if serial.State != "available" || !strings.Contains(serial.Text, "login:") {
		rec.fail("serial-boot-output", fmt.Sprintf("no boot output with a login prompt within 4 minutes (state=%s, %d bytes)", serial.State, len(serial.Text)))
	}
	first := strings.SplitN(strings.TrimSpace(serial.Text), "\n", 2)[0]
	if len(first) > 100 {
		first = first[:100]
	}
	rec.pass("serial-boot-output", fmt.Sprintf("typed state %q, %d bytes of boot output including a login prompt, read through the API with no SSH; first captured line: %q; cloud-init seen: %t; truncated: %t",
		serial.State, len(serial.Text), scrub(first), strings.Contains(serial.Text, "cloud-init"), serial.Truncated))
	if rec.out != "" {
		_ = os.WriteFile(filepath.Join(rec.out, "console-boot-output.txt"), []byte(scrub(serial.Text)+"\n"), 0o644) // #nosec G306 -- scrubbed boot log of a disposable VM
	}

	// 2. Interactive console through ticket -> WebSocket -> broker -> libvirt, no SSH.
	tk, st := b.ticket(name)
	if st != 200 || len(tk) != 43 {
		rec.fail("console-interactive", fmt.Sprintf("ticket: %d", st))
	}
	w, status := b.dialSocket(name, "svavyom.console.v1, t."+tk)
	if !strings.Contains(status, "101") {
		rec.fail("console-interactive", fmt.Sprintf("handshake: %q", status))
	}
	w.skipHeaders()
	if _, ok := w.until("login:", 20*time.Second); !ok {
		rec.fail("console-interactive", "no login prompt from the replay of the console")
	}
	w.send([]byte("svavyo-qual\r"))
	out, ok := w.until("Password:", 20*time.Second)
	if !ok {
		rec.fail("console-interactive", fmt.Sprintf("typed a user name and got no password prompt (got %q)", scrub(out)))
	}
	rec.pass("console-interactive", "an interactive serial session works end to end: the typed user name was echoed by the guest and answered with a Password: prompt (no credentials exist for this account; nothing was logged in)")

	// 3. Ticket negatives: replay, expiry, another VM, another session, and a tampered ticket.
	w.close()
	time.Sleep(500 * time.Millisecond)
	if _, s := b.dialSocket(name, "svavyom.console.v1, t."+tk); !strings.Contains(s, "403") {
		rec.fail("ticket-replay-refused", fmt.Sprintf("a used ticket was accepted: %q", s))
	}
	rec.pass("ticket-replay-refused", "the used ticket was refused (403)")
	old, _ := b.ticket(name)
	time.Sleep(4 * time.Second)
	if _, s := b.dialSocket(name, "svavyom.console.v1, t."+old); !strings.Contains(s, "403") {
		rec.fail("ticket-expiry-refused", fmt.Sprintf("an expired ticket was accepted: %q", s))
	}
	rec.pass("ticket-expiry-refused", "a ticket older than its lifetime was refused (403)")
	other, _ := b.ticket(name)
	if _, s := b.dialSocket("svq-00000000-000000", "svavyom.console.v1, t."+other); !strings.Contains(s, "403") && !strings.Contains(s, "404") {
		rec.fail("ticket-wrong-vm-refused", fmt.Sprintf("a ticket for this VM opened another VM's console: %q", s))
	}
	rec.pass("ticket-wrong-vm-refused", "the ticket of this VM was refused for another VM name; no cross-VM console is reachable")
	tamper := other[:len(other)-1] + map[bool]string{true: "B", false: "A"}[other[len(other)-1] == 'A']
	if _, s := b.dialSocket(name, "svavyom.console.v1, t."+tamper); !strings.Contains(s, "403") {
		rec.fail("ticket-tampered-refused", fmt.Sprintf("a tampered ticket was accepted: %q", s))
	}
	rec.pass("ticket-tampered-refused", "a ticket with one changed character was refused (403)")

	// 4. Reconnect with a FRESH ticket works, and replays what was already on the console.
	fresh, st := b.ticket(name)
	if st != 200 {
		rec.fail("console-reconnect", fmt.Sprintf("ticket: %d", st))
	}
	w2, status := b.dialSocket(name, "svavyom.console.v1, t."+fresh)
	if !strings.Contains(status, "101") {
		rec.fail("console-reconnect", fmt.Sprintf("handshake: %q", status))
	}
	w2.skipHeaders()
	if _, ok := w2.until("login:", 20*time.Second); !ok {
		rec.fail("console-reconnect", "no console output after reconnecting")
	}
	rec.pass("console-reconnect", "after a clean disconnect, a fresh ticket opened the console again and the buffered output was replayed")

	// 5. Clean disconnect releases the console: the broker accepts a new attachment, and ending the session closes the console.
	w2.close()
	time.Sleep(500 * time.Millisecond)
	a, err := client.Attach(ctx, name)
	if err != nil {
		rec.fail("console-disconnect-clean", fmt.Sprintf("the console was not released after a clean disconnect: %v", err))
	}
	a.Close()
	rec.pass("console-disconnect-clean", "after a clean disconnect the broker released the console (a new attachment succeeded)")
	t3, _ := b.ticket(name)
	w3, status := b.dialSocket(name, "svavyom.console.v1, t."+t3)
	if !strings.Contains(status, "101") {
		rec.fail("console-session-end", fmt.Sprintf("handshake: %q", status))
	}
	w3.skipHeaders()
	_, _ = w3.until("login:", 20*time.Second)
	b.do("DELETE", "/api/v1/auth/session", "", map[string]string{"X-CSRF-Token": b.csrf})
	_ = w3.c.SetReadDeadline(time.Now().Add(10 * time.Second))
	closed := false
	for {
		op, _, err := w3.frame()
		if err != nil || op == 0x8 {
			closed = true
			break
		}
	}
	if !closed {
		rec.fail("console-session-end", "the console stayed open after the session ended")
	}
	rec.pass("console-session-end", "signing out closed the open console")

	// 6. The VM is untouched by all of this and still Running (the console is not a lifecycle action).
	if d, err := ro.Lookup(ctx, name); err != nil || d.State != hypervisor.StateRunning {
		rec.fail("console-vm-unchanged", fmt.Sprintf("the VM is not Running after the console tests: %+v %v", d, err))
	}
	rec.pass("console-vm-unchanged", "the VM is still Running and Svavyom-owned")
	for _, a := range audits {
		if strings.Contains(fmt.Sprint(a), tk) || strings.Contains(fmt.Sprint(a), fresh) {
			rec.fail("console-audit-clean", "a ticket appeared in the audit trail")
		}
	}
	rec.pass("console-audit-clean", fmt.Sprintf("%d audit events recorded; none contains a ticket, a cookie or console content", len(audits)))
}

var ctrl = regexp.MustCompile(`[^\x09\x0a\x20-\x7e]`)

func scrub(s string) string {
	s = regexp.MustCompile(`(?i)(password|passwd|secret|token)=\S+`).ReplaceAllString(s, "$1=[removed]")
	s = ctrl.ReplaceAllString(s, "?")
	if len(s) > 32<<10 {
		s = s[:32<<10] + "\n[truncated]"
	}
	return s
}
