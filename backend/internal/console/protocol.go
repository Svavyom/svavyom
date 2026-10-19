package console

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"regexp"
)

// The API <-> broker protocol is closed: length-prefixed JSON frames (4-byte big-endian length), strict decoding (unknown fields and
// trailing data are errors), small bounds, and exactly two requests. It carries VM names and serial bytes, never paths, XML, tickets,
// cookies or libvirt method names.
const (
	Version = 1
	// MaxFrameBytes bounds one frame on the wire; MaxChunk bounds the decoded bytes one stream frame may carry.
	MaxFrameBytes = 128 << 10
	MaxChunk      = 4 << 10
	// MaxSnapshot bounds what a snapshot may return (and what the broker keeps per VM).
	MaxSnapshot = 64 << 10
)

// Requests (the first frame of a connection).
const (
	OpSnapshot = "snapshot"
	OpAttach   = "attach"
	// OpGraphics opens the VM's graphical console (DR-026 D1). After an OK reply the connection is no longer framed: it is the raw RFB (VNC) byte
	// stream between the API and the VM's VNC server, which has no listener of its own.
	OpGraphics = "graphics"
)

// Availability is the typed state of a VM's serial console.
type Availability string

const (
	// Unavailable: the broker could not establish the state (libvirt or the console is not reachable). Say so, claim nothing else.
	Unavailable Availability = "unavailable"
	// NotConfigured: the VM has no serial console device Svavyom can use (or is not a Svavyom-managed VM).
	NotConfigured Availability = "not_configured"
	// NoOutput: a console exists but nothing has been received yet.
	NoOutput Availability = "no_output"
	// Available: there is output to show (and, when the VM runs, a live console to attach to).
	Available Availability = "available"
)

// Request is the first frame a client sends.
type Request struct {
	V   int    `json:"v"`
	Op  string `json:"op"`
	VM  string `json:"vm"`
	Max int    `json:"max,omitempty"` // snapshot only: at most this many bytes of the tail
}

// Reply answers a request. For attach, an OK reply is followed by stream frames.
type Reply struct {
	V         int          `json:"v"`
	OK        bool         `json:"ok"`
	Category  string       `json:"category,omitempty"` // on failure: not_found | conflict | prohibited | unavailable | validation
	State     Availability `json:"state,omitempty"`
	Data      string       `json:"data,omitempty"` // base64 of the tail (snapshot)
	Truncated bool         `json:"truncated,omitempty"`
	Running   bool         `json:"running,omitempty"`
}

// Stream frame types (after a successful attach).
const (
	FrameOut = "out" // broker -> API: console output
	FrameIn  = "in"  // API -> broker: keystrokes
	FrameEnd = "end" // either way: the session is over
)

// Frame is one stream message.
type Frame struct {
	T      string `json:"t"`
	D      string `json:"d,omitempty"`      // base64
	Reason string `json:"reason,omitempty"` // end only: closed vocabulary
}

// End reasons.
const (
	ReasonClosed   = "closed"   // the client ended it
	ReasonVMEnded  = "vm_ended" // the VM stopped or the console stream ended
	ReasonIdle     = "idle"
	ReasonLifetime = "lifetime"
	ReasonError    = "error"
)

var vmRE = regexp.MustCompile(`^[a-z]([a-z0-9-]{0,61}[a-z0-9])?$`)

// ValidVM reports whether name is a Svavyom VM name (the DNS-label grammar of provision.VMNameRE, restated here so this package
// has no dependency on provisioning).
func ValidVM(name string) bool { return vmRE.MatchString(name) }

// Valid reports whether the request is well formed.
func (q Request) Valid() bool {
	if q.V != Version || !ValidVM(q.VM) {
		return false
	}
	switch q.Op {
	case OpSnapshot:
		return q.Max >= 0 && q.Max <= MaxSnapshot
	case OpAttach, OpGraphics:
		return q.Max == 0
	}
	return false
}

// Data helpers.

// Encode returns the base64 form of b for a frame.
func Encode(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

// Decode returns the bytes of a frame payload, refusing anything longer than max.
func Decode(s string, max int) ([]byte, error) {
	if base64.StdEncoding.DecodedLen(len(s)) > max+3 {
		return nil, errFrame
	}
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil || len(b) > max {
		return nil, errFrame
	}
	return b, nil
}

var errFrame = errors.New("console: bad frame")

// WriteFrame writes v as one frame.
func WriteFrame(w io.Writer, v any) error {
	body, err := json.Marshal(v)
	if err != nil || len(body) > MaxFrameBytes {
		return errFrame
	}
	buf := make([]byte, 4+len(body))
	binary.BigEndian.PutUint32(buf, uint32(len(body))) // #nosec G115 -- bounded by MaxFrameBytes
	copy(buf[4:], body)
	_, err = w.Write(buf)
	return err
}

// ReadFrame reads one frame into dst, strictly.
func ReadFrame(r io.Reader, dst any) error {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n == 0 || int64(n) > MaxFrameBytes {
		return errFrame
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(r, body); err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return errFrame
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return errFrame
	}
	return nil
}
