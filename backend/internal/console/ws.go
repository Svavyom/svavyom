package console

import (
	"bufio"
	"crypto/sha1" // #nosec G505 -- RFC 6455 mandates SHA-1 for the handshake accept value; it is not used for security
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

// A strict, minimal RFC 6455 server endpoint, written here so the browser leg needs no new dependency. It accepts exactly one
// subprotocol, negotiates no extensions (no compression), requires masked client frames, bounds every message, and understands only
// text, binary, ping, pong and close frames.

// WebSocket opcodes and close codes used here.
const (
	OpText   = 0x1
	OpBinary = 0x2
	opClose  = 0x8
	opPing   = 0x9
	opPong   = 0xA

	CloseNormal    = 1000
	CloseGoingAway = 1001
	CloseProtocol  = 1002
	CloseTooBig    = 1009
	ClosePolicy    = 1008
	CloseInternal  = 1011
)

const wsGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

// ErrHandshake means the request is not an acceptable WebSocket upgrade.
var ErrHandshake = errors.New("console: not a valid websocket upgrade")

// WS is an upgraded connection. Reads must come from one goroutine; Write and Close may be called from any.
type WS struct {
	c      net.Conn
	br     *bufio.Reader
	wmu    sync.Mutex
	max    int
	closed bool
}

func headerHas(h http.Header, name, token string) bool {
	for _, v := range h.Values(name) {
		for _, p := range strings.Split(v, ",") {
			if strings.EqualFold(strings.TrimSpace(p), token) {
				return true
			}
		}
	}
	return false
}

// Subprotocols returns the protocols the client offered, trimmed.
func Subprotocols(r *http.Request) []string {
	var out []string
	for _, v := range r.Header.Values("Sec-WebSocket-Protocol") {
		for _, p := range strings.Split(v, ",") {
			if p = strings.TrimSpace(p); p != "" {
				out = append(out, p)
			}
		}
	}
	return out
}

// CheckUpgrade validates the handshake headers without touching the connection.
func CheckUpgrade(r *http.Request) (key string, err error) {
	if r.Method != http.MethodGet || r.ProtoMajor < 1 || !headerHas(r.Header, "Connection", "upgrade") || !headerHas(r.Header, "Upgrade", "websocket") ||
		r.Header.Get("Sec-WebSocket-Version") != "13" || len(r.Header.Values("Sec-WebSocket-Key")) != 1 {
		return "", ErrHandshake
	}
	key = r.Header.Get("Sec-WebSocket-Key")
	if raw, derr := base64.StdEncoding.DecodeString(key); derr != nil || len(raw) != 16 {
		return "", ErrHandshake
	}
	return key, nil
}

// Accept completes the handshake with the single subprotocol `proto` (which the client must have offered) and returns the connection.
// maxMessage bounds one message from the client. On error nothing has been written and the caller still owns the response.
func Accept(w http.ResponseWriter, r *http.Request, proto string, maxMessage int) (*WS, error) {
	key, err := CheckUpgrade(r)
	if err != nil {
		return nil, err
	}
	offered := false
	for _, p := range Subprotocols(r) {
		if p == proto {
			offered = true
		}
	}
	if !offered {
		return nil, ErrHandshake
	}
	hj, ok := w.(http.Hijacker)
	if !ok {
		return nil, ErrHandshake
	}
	sum := sha1.Sum([]byte(key + wsGUID)) // #nosec G401 -- RFC 6455 handshake
	c, rw, err := hj.Hijack()
	if err != nil {
		return nil, ErrHandshake
	}
	resp := "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: " +
		base64.StdEncoding.EncodeToString(sum[:]) + "\r\nSec-WebSocket-Protocol: " + proto + "\r\nCache-Control: no-store\r\n\r\n"
	_ = c.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if _, err := rw.WriteString(resp); err != nil || rw.Flush() != nil {
		_ = c.Close()
		return nil, ErrHandshake
	}
	_ = c.SetDeadline(time.Time{}) // a hijacked connection keeps the server's read and write deadlines until the caller clears them
	return &WS{c: c, br: rw.Reader, max: maxMessage}, nil
}

// SetReadDeadline sets the deadline of the next read.
func (s *WS) SetReadDeadline(t time.Time) { _ = s.c.SetReadDeadline(t) }

var errProto = errors.New("console: websocket protocol error")

// Read returns the next data message (text or binary). Ping frames are answered, pongs ignored, a close frame is answered and
// reported as io.EOF. A protocol violation closes the connection with 1002 (1009 for an oversize message, 1007-like 1002 for bad UTF-8
// in a text message) and returns an error.
func (s *WS) Read() (op int, data []byte, err error) {
	var msg []byte
	var msgOp int
	for {
		fin, fop, payload, err := s.frame()
		if err != nil {
			if errors.Is(err, errTooBig) {
				s.Close(CloseTooBig)
			} else if errors.Is(err, errProto) {
				s.Close(CloseProtocol)
			}
			return 0, nil, err
		}
		switch fop {
		case opPing:
			_ = s.write(opPong, payload)
			continue
		case opPong:
			continue
		case opClose:
			s.Close(CloseNormal)
			return 0, nil, io.EOF
		case 0x0: // continuation
			if msgOp == 0 {
				s.Close(CloseProtocol)
				return 0, nil, errProto
			}
		case OpText, OpBinary:
			if msgOp != 0 {
				s.Close(CloseProtocol)
				return 0, nil, errProto
			}
			msgOp = fop
		default:
			s.Close(CloseProtocol)
			return 0, nil, errProto
		}
		if len(msg)+len(payload) > s.max {
			s.Close(CloseTooBig)
			return 0, nil, errTooBig
		}
		msg = append(msg, payload...)
		if fin {
			if msgOp == OpText && !utf8.Valid(msg) {
				s.Close(CloseProtocol)
				return 0, nil, errProto
			}
			return msgOp, msg, nil
		}
	}
}

var errTooBig = errors.New("console: websocket message too big")

// frame reads one frame. Client frames must be masked, carry no reserved bits and have a bounded length.
func (s *WS) frame() (fin bool, op int, payload []byte, err error) {
	var h [2]byte
	if _, err := io.ReadFull(s.br, h[:]); err != nil {
		return false, 0, nil, err
	}
	fin, op = h[0]&0x80 != 0, int(h[0]&0x0f)
	if h[0]&0x70 != 0 || h[1]&0x80 == 0 {
		return false, 0, nil, errProto
	}
	n := uint64(h[1] & 0x7f)
	switch n {
	case 126:
		var b [2]byte
		if _, err := io.ReadFull(s.br, b[:]); err != nil {
			return false, 0, nil, err
		}
		n = uint64(binary.BigEndian.Uint16(b[:]))
	case 127:
		var b [8]byte
		if _, err := io.ReadFull(s.br, b[:]); err != nil {
			return false, 0, nil, err
		}
		n = binary.BigEndian.Uint64(b[:])
	}
	if op >= 0x8 && (n > 125 || !fin) { // control frames: short and never fragmented
		return false, 0, nil, errProto
	}
	if n > uint64(s.max) { // #nosec G115 -- max is a positive configured bound
		return false, 0, nil, errTooBig
	}
	var mask [4]byte
	if _, err := io.ReadFull(s.br, mask[:]); err != nil {
		return false, 0, nil, err
	}
	payload = make([]byte, n)
	if _, err := io.ReadFull(s.br, payload); err != nil {
		return false, 0, nil, err
	}
	for i := range payload {
		payload[i] ^= mask[i%4]
	}
	return fin, op, payload, nil
}

func (s *WS) write(op int, data []byte) error {
	s.wmu.Lock()
	defer s.wmu.Unlock()
	if s.closed {
		return net.ErrClosed
	}
	hdr := []byte{0x80 | byte(op&0x0f)}
	switch n := len(data); {
	case n < 126:
		hdr = append(hdr, byte(n&0x7f))
	case n <= 0xffff:
		hdr = append(hdr, 126)
		hdr = binary.BigEndian.AppendUint16(hdr, uint16(n&0xffff))
	default:
		hdr = append(hdr, 127)
		hdr = binary.BigEndian.AppendUint64(hdr, uint64(n)) // #nosec G115 -- len is never negative
	}
	_ = s.c.SetWriteDeadline(time.Now().Add(10 * time.Second))
	if _, err := s.c.Write(append(hdr, data...)); err != nil {
		return err
	}
	return nil
}

// Write sends one binary message.
func (s *WS) Write(data []byte) error { return s.write(OpBinary, data) }

// WriteText sends one text message (it must be valid UTF-8).
func (s *WS) WriteText(text string) error { return s.write(OpText, []byte(text)) }

// Close sends a close frame with the code (best effort) and closes the connection. It is safe to call more than once.
func (s *WS) Close(code int) {
	s.wmu.Lock()
	if s.closed {
		s.wmu.Unlock()
		return
	}
	s.closed = true
	_ = s.c.SetWriteDeadline(time.Now().Add(time.Second))
	_, _ = s.c.Write(binary.BigEndian.AppendUint16([]byte{0x80 | opClose, 2}, uint16(code&0xffff)))
	s.wmu.Unlock()
	_ = s.c.Close()
}
