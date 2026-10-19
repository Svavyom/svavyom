package console

import (
	"bufio"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// wsClient is a minimal masking client used to drive the server endpoint byte by byte.
type wsClient struct {
	c  net.Conn
	br *bufio.Reader
}

func startWS(t *testing.T, max int, handler func(*WS)) (*wsClient, string) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s, err := Accept(w, r, "svavyom.console.v1", max)
		if err != nil {
			http.Error(w, "no", http.StatusBadRequest)
			return
		}
		handler(s)
	}))
	t.Cleanup(srv.Close)
	return nil, srv.Listener.Addr().String()
}

func dialWS(t *testing.T, addr, protos string, headers map[string]string) (*wsClient, string) {
	t.Helper()
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	var k [16]byte
	_, _ = rand.Read(k[:])
	h := map[string]string{"Host": addr, "Upgrade": "websocket", "Connection": "Upgrade", "Sec-WebSocket-Version": "13", "Sec-WebSocket-Key": base64.StdEncoding.EncodeToString(k[:])}
	if protos != "" {
		h["Sec-WebSocket-Protocol"] = protos
	}
	for k, v := range headers {
		if v == "" {
			delete(h, k)
		} else {
			h[k] = v
		}
	}
	var b strings.Builder
	b.WriteString("GET /ws HTTP/1.1\r\n")
	for k, v := range h {
		b.WriteString(k + ": " + v + "\r\n")
	}
	b.WriteString("\r\n")
	_, _ = c.Write([]byte(b.String()))
	br := bufio.NewReader(c)
	status, _ := br.ReadString('\n')
	return &wsClient{c: c, br: br}, status
}

func (w *wsClient) send(fin bool, op byte, payload []byte, mask bool) {
	h := []byte{op}
	if fin {
		h[0] |= 0x80
	}
	var mk [4]byte
	_, _ = rand.Read(mk[:])
	m := byte(0)
	if mask {
		m = 0x80
	}
	switch n := len(payload); {
	case n < 126:
		h = append(h, m|byte(n))
	case n <= 0xffff:
		h = append(h, m|126, byte(n>>8), byte(n))
	default:
		h = append(h, m|127, 0, 0, 0, 0, byte(n>>24), byte(n>>16), byte(n>>8), byte(n))
	}
	body := append([]byte(nil), payload...)
	if mask {
		h = append(h, mk[:]...)
		for i := range body {
			body[i] ^= mk[i%4]
		}
	}
	_, _ = w.c.Write(append(h, body...))
}

// recv reads headers to the blank line (first call) is skipped by the caller; here: one server frame.
func (w *wsClient) recv(t *testing.T) (op int, payload []byte) {
	t.Helper()
	for {
		line, err := w.br.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		if line == "\r\n" {
			break
		}
	}
	return w.frame(t)
}

func (w *wsClient) frame(t *testing.T) (int, []byte) {
	t.Helper()
	var h [2]byte
	if _, err := io.ReadFull(w.br, h[:]); err != nil {
		t.Fatalf("frame: %v", err)
	}
	n := int(h[1] & 0x7f)
	if n == 126 {
		var b [2]byte
		_, _ = io.ReadFull(w.br, b[:])
		n = int(binary.BigEndian.Uint16(b[:]))
	}
	p := make([]byte, n)
	_, _ = io.ReadFull(w.br, p)
	return int(h[0] & 0x0f), p
}

func TestHandshakeAndEcho(t *testing.T) {
	_, addr := startWS(t, 1024, func(s *WS) {
		defer s.Close(CloseNormal)
		for {
			op, d, err := s.Read()
			if err != nil {
				return
			}
			if op == OpBinary {
				_ = s.Write(append([]byte("echo:"), d...))
			}
		}
	})
	c, status := dialWS(t, addr, "svavyom.console.v1, other", nil)
	if !strings.Contains(status, "101") {
		t.Fatalf("status %q", status)
	}
	c.send(true, OpBinary, []byte("hi"), true)
	op, p := c.recv(t)
	if op != OpBinary || string(p) != "echo:hi" {
		t.Fatalf("%d %q", op, p)
	}
	// ping is answered, a fragmented message is reassembled
	c.send(true, opPing, []byte("p"), true)
	if op, p := c.frame(t); op != opPong || string(p) != "p" {
		t.Fatalf("pong: %d %q", op, p)
	}
	c.send(false, OpBinary, []byte("ab"), true)
	c.send(true, 0x0, []byte("cd"), true)
	if _, p := c.frame(t); string(p) != "echo:abcd" {
		t.Fatalf("fragments: %q", p)
	}
	c.send(true, opClose, []byte{0x03, 0xe8}, true)
	if op, _ := c.frame(t); op != opClose {
		t.Fatalf("close not answered: %d", op)
	}
}

func TestHandshakeRefusals(t *testing.T) {
	_, addr := startWS(t, 1024, func(s *WS) { s.Close(CloseNormal) })
	for name, hdr := range map[string]map[string]string{
		"no key":        {"Sec-WebSocket-Key": ""},
		"short key":     {"Sec-WebSocket-Key": base64.StdEncoding.EncodeToString([]byte("short"))},
		"not base64":    {"Sec-WebSocket-Key": "%%%"},
		"old version":   {"Sec-WebSocket-Version": "8"},
		"no upgrade":    {"Upgrade": ""},
		"no connection": {"Connection": ""},
		"not websocket": {"Upgrade": "h2c"},
	} {
		_, status := dialWS(t, addr, "svavyom.console.v1", hdr)
		if !strings.Contains(status, "400") {
			t.Errorf("%s: %q", name, status)
		}
	}
	if _, status := dialWS(t, addr, "", nil); !strings.Contains(status, "400") {
		t.Errorf("no subprotocol: %q", status)
	}
	if _, status := dialWS(t, addr, "something.else", nil); !strings.Contains(status, "400") {
		t.Errorf("wrong subprotocol: %q", status)
	}
}

func TestProtocolViolationsAreClosed(t *testing.T) {
	results := make(chan error, 8)
	_, addr := startWS(t, 64, func(s *WS) { _, _, err := s.Read(); results <- err })
	for name, send := range map[string]func(*wsClient){
		"unmasked":         func(c *wsClient) { c.send(true, OpBinary, []byte("x"), false) },
		"reserved bit":     func(c *wsClient) { c.send(true, OpBinary|0x40, []byte("x"), true) },
		"unknown opcode":   func(c *wsClient) { c.send(true, 0x3, []byte("x"), true) },
		"stray continue":   func(c *wsClient) { c.send(true, 0x0, []byte("x"), true) },
		"fragmented ping":  func(c *wsClient) { c.send(false, opPing, []byte("x"), true) },
		"oversize message": func(c *wsClient) { c.send(true, OpBinary, make([]byte, 65), true) },
		"bad utf8 text":    func(c *wsClient) { c.send(true, OpText, []byte{0xff, 0xfe}, true) },
	} {
		c, _ := dialWS(t, addr, "svavyom.console.v1", nil)
		send(c)
		select {
		case err := <-results:
			if err == nil {
				t.Errorf("%s: accepted", name)
			}
		case <-time.After(3 * time.Second):
			t.Errorf("%s: not rejected", name)
		}
	}
}
