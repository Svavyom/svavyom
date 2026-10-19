package console_test

import (
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"

	"example.invalid/dedicatedcloud/backend/internal/console"
	"example.invalid/dedicatedcloud/backend/internal/console/consolesim"
)

func gfxVM() consolesim.VM {
	return consolesim.VM{Managed: true, Configured: true, Running: true, Graphics: true}
}

func (r *rig) graphics(vm string) (net.Conn, console.Reply) {
	return r.request(console.Request{Op: console.OpGraphics, VM: vm})
}

func TestTheBrokerRelaysARawRFBStreamAfterOneOKReply(t *testing.T) {
	r := newRig(t, nil)
	r.src.Set("web-1", gfxVM())
	c, rep := r.graphics("web-1")
	if !rep.OK {
		t.Fatalf("%+v", rep)
	}
	buf := make([]byte, 12)
	if _, err := io.ReadFull(c, buf); err != nil || string(buf) != "RFB 003.008\n" {
		t.Fatalf("%q %v", buf, err)
	}
	_, _ = c.Write([]byte("RFB 003.008\n"))
	sec := make([]byte, 2)
	_, _ = io.ReadFull(c, sec)
	_, _ = c.Write([]byte{1})
	res := make([]byte, 4)
	_, _ = io.ReadFull(c, res)
	_, _ = c.Write([]byte{1})
	init := make([]byte, 24)
	if _, err := io.ReadFull(c, init); err != nil || binary.BigEndian.Uint16(init[:2]) != 640 {
		t.Fatalf("%v %v", init, err)
	}
	if r.src.GraphicsOpen["web-1"] != 1 {
		t.Fatalf("%d", r.src.GraphicsOpen["web-1"])
	}
}

func TestTheBrokerRefusesAGraphicalConsoleItMustNotOpen(t *testing.T) {
	r := newRig(t, nil)
	r.src.Set("foreign", consolesim.VM{Managed: false, Configured: true, Running: true, Graphics: true})
	r.src.Set("nodevice", consolesim.VM{Managed: true, Configured: true, Running: true})
	r.src.Set("off", consolesim.VM{Managed: true, Configured: true, Running: false, Graphics: true})
	for name, want := range map[string]string{"foreign": "prohibited", "nodevice": "prohibited", "off": "conflict", "ghost": "not_found"} {
		_, rep := r.graphics(name)
		if rep.OK || rep.Category != want {
			t.Errorf("%s: %+v, want %s", name, rep, want)
		}
	}
	if n := r.src.GraphicsOpen["foreign"] + r.src.GraphicsOpen["nodevice"] + r.src.GraphicsOpen["off"]; n != 0 {
		t.Fatalf("nothing may be opened for a refused request: %d", n)
	}
}

func TestOnlyOneViewerPerVMAndTheSlotIsFreedWhenItLeaves(t *testing.T) {
	r := newRig(t, nil)
	r.src.Set("web-1", gfxVM())
	first, rep := r.graphics("web-1")
	if !rep.OK {
		t.Fatal(rep)
	}
	if _, rep := r.graphics("web-1"); rep.OK || rep.Category != "conflict" {
		t.Fatalf("second viewer: %+v", rep)
	}
	_ = first.Close()
	deadline := time.Now().Add(3 * time.Second)
	for {
		c, rep := r.graphics("web-1")
		if rep.OK {
			_ = c.Close()
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("the slot was never freed: %+v", rep)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestAnIdleViewerIsEndedAndTheLifetimeIsBounded(t *testing.T) {
	r := newRig(t, func(c *console.BrokerConfig) { c.IdleTimeout = 80 * time.Millisecond })
	r.src.Set("web-1", gfxVM())
	c, rep := r.graphics("web-1")
	if !rep.OK {
		t.Fatal(rep)
	}
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 12)
	_, _ = io.ReadFull(c, buf) // the server's greeting counts as activity
	if _, err := io.ReadAll(c); err != nil {
		t.Fatalf("the broker ends an idle viewer by closing the stream: %v", err)
	}
	r2 := newRig(t, func(c *console.BrokerConfig) { c.MaxLifetime = 80 * time.Millisecond })
	r2.src.Set("web-1", gfxVM())
	c2, rep := r2.graphics("web-1")
	if !rep.OK {
		t.Fatal(rep)
	}
	_ = c2.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.ReadAll(c2); err != nil {
		t.Fatalf("lifetime: %v", err)
	}
}

func TestTheProtocolStaysClosed(t *testing.T) {
	r := newRig(t, nil)
	r.src.Set("web-1", gfxVM())
	for name, q := range map[string]console.Request{
		"max on graphics": {Op: console.OpGraphics, VM: "web-1", Max: 5},
		"bad name":        {Op: console.OpGraphics, VM: "../x"},
		"unknown op":      {Op: "vnc", VM: "web-1"},
	} {
		_, rep := r.request(q)
		if rep.OK || rep.Category != "validation" {
			t.Errorf("%s: %+v", name, rep)
		}
	}
}
