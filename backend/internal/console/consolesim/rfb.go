package consolesim

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"

	"example.invalid/dedicatedcloud/backend/internal/console"
)

// A SIMULATED VNC server: just enough RFB 3.8 for a real client to connect, see a picture and send input. It is not QEMU and proves nothing about
// QEMU's VNC server; the real host run does that.
const (
	simW, simH = 640, 400
)

// OpenGraphics implements console.Source: a private pipe whose far end is the simulated VNC server of the VM.
func (s *Source) OpenGraphics(_ context.Context, vm string) (io.ReadWriteCloser, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.Fail != nil {
		return nil, s.Fail
	}
	v, ok := s.vms[vm]
	if !ok {
		return nil, errNotFound
	}
	if !v.Managed || !v.Graphics || !v.Running {
		return nil, errors.New("consolesim: not a running managed VM with a graphical console")
	}
	s.GraphicsOpen[vm]++
	a, b := net.Pipe()
	go serveRFB(b, vm)
	return a, nil
}

func serveRFB(c net.Conn, vm string) {
	defer c.Close()
	rd := func(n int) ([]byte, bool) {
		b := make([]byte, n)
		_, err := io.ReadFull(c, b)
		return b, err == nil
	}
	if _, err := c.Write([]byte("RFB 003.008\n")); err != nil {
		return
	}
	if _, ok := rd(12); !ok {
		return
	}
	if _, err := c.Write([]byte{1, 1}); err != nil { // one security type: None
		return
	}
	if _, ok := rd(1); !ok {
		return
	}
	if _, err := c.Write([]byte{0, 0, 0, 0}); err != nil { // SecurityResult: OK
		return
	}
	if _, ok := rd(1); !ok { // ClientInit
		return
	}
	name := "sim:" + vm
	init := make([]byte, 0, 24+len(name))
	init = binary.BigEndian.AppendUint16(init, simW)
	init = binary.BigEndian.AppendUint16(init, simH)
	init = append(init, 32, 24, 0, 1) // bpp, depth, big-endian, true colour
	init = binary.BigEndian.AppendUint16(init, 255)
	init = binary.BigEndian.AppendUint16(init, 255)
	init = binary.BigEndian.AppendUint16(init, 255)
	init = append(init, 16, 8, 0, 0, 0, 0)                        // shifts, padding
	init = binary.BigEndian.AppendUint32(init, uint32(len(name))) // #nosec G115 -- a short constant-derived name
	init = append(init, name...)
	if _, err := c.Write(init); err != nil {
		return
	}
	events := 0
	for {
		t, ok := rd(1)
		if !ok {
			return
		}
		switch t[0] {
		case 0: // SetPixelFormat
			if _, ok := rd(19); !ok {
				return
			}
		case 2: // SetEncodings
			h, ok := rd(3)
			if !ok {
				return
			}
			if _, ok := rd(int(binary.BigEndian.Uint16(h[1:3])) * 4); !ok {
				return
			}
		case 3: // FramebufferUpdateRequest
			r, ok := rd(9)
			if !ok {
				return
			}
			w, h := simW, simH
			if r[0] == 1 { // incremental: a small square that changes with the input received
				w, h = 32, 32
			}
			msg := []byte{0, 0, 0, 1}
			msg = binary.BigEndian.AppendUint16(msg, 0)
			msg = binary.BigEndian.AppendUint16(msg, 0)
			msg = binary.BigEndian.AppendUint16(msg, uint16(w))
			msg = binary.BigEndian.AppendUint16(msg, uint16(h))
			msg = binary.BigEndian.AppendUint32(msg, 0) // Raw
			px := []byte{byte(40 + events*37), byte(90 + events*11), byte(160 - events*5), 0}
			for i := 0; i < w*h; i++ {
				msg = append(msg, px...)
			}
			if _, err := c.Write(msg); err != nil {
				return
			}
		case 4: // KeyEvent
			if _, ok := rd(7); !ok {
				return
			}
			events++
		case 5: // PointerEvent
			if _, ok := rd(5); !ok {
				return
			}
			events++
		case 6: // ClientCutText
			h, ok := rd(7)
			if !ok {
				return
			}
			n := int(binary.BigEndian.Uint32(h[3:7]))
			if n > console.MaxFrameBytes {
				return
			}
			if _, ok := rd(n); !ok {
				return
			}
		default:
			return // an unknown message: a real server drops the client
		}
	}
}
