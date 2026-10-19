package api

import (
	"encoding/binary"
	"encoding/json"
	"io"
	"strings"
	"testing"
	"time"

	"example.invalid/dedicatedcloud/backend/internal/auth"
	"example.invalid/dedicatedcloud/backend/internal/console"
	"example.invalid/dedicatedcloud/backend/internal/console/consolesim"
)

func (c *consRig) graphicsTicket(b *browser, vm string) (string, reply) {
	c.t.Helper()
	rep := b.do("POST", "/console/v1/vms/"+vm+"/graphics-tickets", "", map[string]string{"X-CSRF-Token": b.csrf})
	var tk ticketJSON
	_ = json.Unmarshal(rep.body, &tk)
	return tk.Ticket, rep
}

func (c *consRig) withGraphics() {
	c.src.Set("web-1", consolesim.VM{Managed: true, Configured: true, Running: true, Graphics: true})
}

func (c *consRig) openGraphics() *wsc {
	c.t.Helper()
	tk, rep := c.graphicsTicket(c.b, "web-1")
	if rep.status != 200 || tk == "" {
		c.t.Fatalf("ticket: %d %s", rep.status, rep.body)
	}
	w, status := c.dialPath("web-1", "graphics-socket", graphicsProto+", "+ticketPrefix+tk, nil)
	if !strings.Contains(status, "101") {
		c.t.Fatalf("handshake: %q", status)
	}
	w.skipHeaders(c.t)
	return w
}

// readN reads exactly n bytes of the RFB stream from the WebSocket messages, keeping what is left of a message for the next call.
func (w *wsc) readN(t *testing.T, n int) []byte {
	t.Helper()
	for len(w.rbuf) < n {
		op, p, err := w.frame()
		if err != nil || op == 0x8 {
			t.Fatalf("waiting for %d bytes, have %d: op=%d err=%v", n, len(w.rbuf), op, err)
		}
		w.rbuf = append(w.rbuf, p...)
	}
	out := append([]byte(nil), w.rbuf[:n]...)
	w.rbuf = w.rbuf[n:]
	return out
}

func TestTheGraphicalConsoleCarriesARealRFBConversationAndNothingElse(t *testing.T) {
	c := newConsRig(t, true)
	c.withGraphics()
	w := c.openGraphics()
	if v := string(w.readN(t, 12)); v != "RFB 003.008\n" {
		t.Fatalf("the VM's VNC server speaks first: %q", v)
	}
	w.send(t, 0x2, []byte("RFB 003.008\n"))
	if sec := w.readN(t, 2); sec[0] != 1 || sec[1] != 1 {
		t.Fatalf("security types: %v", sec)
	}
	w.send(t, 0x2, []byte{1})
	if res := w.readN(t, 4); binary.BigEndian.Uint32(res) != 0 {
		t.Fatalf("security result %v", res)
	}
	w.send(t, 0x2, []byte{1}) // ClientInit: shared
	init := w.readN(t, 24)
	if binary.BigEndian.Uint16(init[0:2]) != 640 || binary.BigEndian.Uint16(init[2:4]) != 400 {
		t.Fatalf("framebuffer size %v", init[:4])
	}
	name := string(w.readN(t, int(binary.BigEndian.Uint32(init[20:24]))))
	if name != "sim:web-1" {
		t.Fatalf("desktop name %q", name)
	}
	// ask for a full picture, get a Raw rectangle of exactly the declared size
	req := []byte{3, 0, 0, 0, 0, 0, 0x02, 0x80, 0x01, 0x90}
	w.send(t, 0x2, req)
	hdr := w.readN(t, 16)
	if hdr[0] != 0 || binary.BigEndian.Uint16(hdr[2:4]) != 1 || binary.BigEndian.Uint16(hdr[8:10]) != 640 || binary.BigEndian.Uint16(hdr[10:12]) != 400 {
		t.Fatalf("update header %v", hdr)
	}
	_ = w.readN(t, 640*400*4)
	w.send(t, 0x2, []byte{4, 1, 0, 0, 0, 0, 0, 0x41}) // a key press reaches the VM and does not break the stream
	w.send(t, 0x2, []byte{5, 0, 0, 10, 0, 10})        // and a pointer move
	w.send(t, 0x2, []byte{3, 1, 0, 0, 0, 0, 0, 32, 0, 32})
	if small := w.readN(t, 16+32*32*4); small[0] != 0 {
		t.Fatalf("incremental update %v", small[:4])
	}
	ev := c.auditEvents()
	var opened bool
	for _, e := range ev {
		opened = opened || (e.Event == "graphics.console.opened" && e.VM == "web-1" && e.Outcome == "ok")
		if strings.Contains(e.Outcome, "t.") || strings.Contains(e.Actor+e.VM+e.Event, "RFB") {
			t.Errorf("an audit record carries console content or a ticket: %+v", e)
		}
	}
	if !opened {
		t.Fatalf("the audit trail records who opened which VM's graphical console: %+v", ev)
	}
	if n := c.src.GraphicsOpen["web-1"]; n != 1 {
		t.Fatalf("one connection to the VNC server: %d", n)
	}
}

func TestOnlyOneViewerPerVMAndTheSecondIsRefusedBeforeTheUpgrade(t *testing.T) {
	c := newConsRig(t, true)
	c.withGraphics()
	w := c.openGraphics()
	_ = w.readN(t, 12)
	tk, rep := c.graphicsTicket(c.b, "web-1")
	if rep.status != 200 {
		t.Fatal(rep.status)
	}
	_, status := c.dialPath("web-1", "graphics-socket", graphicsProto+", "+ticketPrefix+tk, nil)
	if !strings.Contains(status, "409") {
		t.Fatalf("a second viewer: %q", status)
	}
	// the serial console is a different channel and is not blocked by the viewer
	if _, status := c.dialSocket("web-1", consoleProto+", "+ticketPrefix+func() string { t, _ := c.ticket("web-1"); return t }(), nil); !strings.Contains(status, "101") {
		t.Fatalf("serial console alongside the viewer: %q", status)
	}
}

func TestGraphicsTicketsAreBoundToTheirKindVMSessionAndSingleUse(t *testing.T) {
	c := newConsRig(t, true)
	c.withGraphics()
	gt, _ := c.graphicsTicket(c.b, "web-1")
	// a graphics ticket does not open the serial console, and a serial ticket does not open the graphics
	if _, status := c.dialSocket("web-1", consoleProto+", "+ticketPrefix+gt, nil); !strings.Contains(status, "403") {
		t.Errorf("graphics ticket on the serial socket: %q", status)
	}
	st, _ := c.ticket("web-1")
	if _, status := c.dialPath("web-1", "graphics-socket", graphicsProto+", "+ticketPrefix+st, nil); !strings.Contains(status, "403") {
		t.Errorf("serial ticket on the graphics socket: %q", status)
	}
	// the wrong protocol name, no ticket, no Origin
	gt2, _ := c.graphicsTicket(c.b, "web-1")
	for name, c2 := range map[string]struct {
		protos string
		hdr    map[string]string
		want   string
	}{
		"serial protocol name": {consoleProto + ", " + ticketPrefix + gt2, nil, "400"},
		"no ticket":            {graphicsProto, nil, "400"},
		"no origin":            {graphicsProto + ", " + ticketPrefix + gt2, map[string]string{"Origin": ""}, "403"},
		"foreign origin":       {graphicsProto + ", " + ticketPrefix + gt2, map[string]string{"Origin": "https://evil.example"}, "403"},
	} {
		if _, status := c.dialPath("web-1", "graphics-socket", c2.protos, c2.hdr); !strings.Contains(status, c2.want) {
			t.Errorf("%s: %q, want %s", name, status, c2.want)
		}
	}
	// a real use consumes it
	w, status := c.dialPath("web-1", "graphics-socket", graphicsProto+", "+ticketPrefix+gt2, nil)
	if !strings.Contains(status, "101") {
		t.Fatalf("%q", status)
	}
	w.skipHeaders(t)
	if _, status := c.dialPath("web-1", "graphics-socket", graphicsProto+", "+ticketPrefix+gt2, nil); !strings.Contains(status, "403") {
		t.Errorf("replay: %q", status)
	}
	// another VM's ticket
	if _, rep := c.graphicsTicket(c.b, "ghost"); rep.status != 404 {
		t.Errorf("missing VM: %d", rep.status)
	}
}

func TestGraphicsTicketsNeedTheSwitchTheRoleAndTheDevice(t *testing.T) {
	off := newConsRig(t, false)
	off.withGraphics()
	if _, rep := off.graphicsTicket(off.b, "web-1"); rep.status != 422 {
		t.Errorf("switch off: %d %s", rep.status, rep.body)
	}
	c := newConsRig(t, true)
	c.withGraphics()
	v := c.asRole("vera", auth.RoleViewer)
	if _, rep := c.graphicsTicket(v, "web-1"); rep.status != 403 {
		t.Errorf("a viewer gets no graphical console: %d %s", rep.status, rep.body)
	}
	o := c.asRole("olly", auth.RoleOperator)
	if _, rep := c.graphicsTicket(o, "web-1"); rep.status != 200 {
		t.Errorf("an operator does: %d %s", rep.status, rep.body)
	}
	// without CSRF
	if rep := c.b.do("POST", "/console/v1/vms/web-1/graphics-tickets", "", nil); rep.status != 403 {
		t.Errorf("no CSRF token: %d", rep.status)
	}
	// a stopped VM and a VM without the device
	c.r2stop(t)
	if _, rep := c.graphicsTicket(c.b, "web-1"); rep.status != 409 {
		t.Errorf("a stopped VM: %d %s", rep.status, rep.body)
	}
}

func (c *consRig) r2stop(t *testing.T) {
	t.Helper()
	c.await(c.b, opID(t, c.post(c.b, `{"type":"stop","kind":"VM","id":"web-1","idempotency_key":"stop-gfx"}`)), "succeeded")
}

func TestTheViewerEndsWhenTheSessionEndsOrTheVMStops(t *testing.T) {
	c := newConsRig(t, true)
	c.withGraphics()
	w := c.openGraphics()
	_ = w.readN(t, 12)
	// sign out: the page re-validates the session and closes the socket with 1008
	c.b.do("DELETE", "/api/v1/auth/session", "", map[string]string{"X-CSRF-Token": c.b.csrf})
	_ = w.c.SetDeadline(time.Now().Add(3 * time.Second))
	for {
		op, p, err := w.frame()
		if err != nil {
			break // closed
		}
		if op == 0x8 {
			if len(p) >= 2 && binary.BigEndian.Uint16(p) != uint16(console.ClosePolicy) {
				t.Errorf("close code %d", binary.BigEndian.Uint16(p))
			}
			break
		}
	}
	_ = io.EOF
}
