package api

import (
	"encoding/json"
	"os"
	"sort"
	"strings"
	"testing"
	"time"

	"example.invalid/dedicatedcloud/backend/internal/console"
)

// TestConsoleChannelContractMatchesTheImplementation pins contracts/console-channel.json to the code: a route, a state name, a
// subprotocol, a limit or a frame vocabulary cannot change in one place only.
func TestConsoleChannelContractMatchesTheImplementation(t *testing.T) {
	raw, err := os.ReadFile("../../../contracts/console-channel.json")
	if err != nil {
		t.Fatal(err)
	}
	var c struct {
		Routes map[string]struct {
			Method   string `json:"method"`
			Path     string `json:"path"`
			Response struct {
				State []string `json:"state"`
			} `json:"response"`
			Subprotocols []string          `json:"subprotocols"`
			CloseCodes   map[string]string `json:"close_codes"`
		} `json:"routes"`
		Graphics map[string]struct {
			Method       string   `json:"method"`
			Path         string   `json:"path"`
			Subprotocols []string `json:"subprotocols"`
		} `json:"graphics_routes"`
		Broker struct {
			Requests []string `json:"requests"`
			Frames   []string `json:"stream_frames"`
			Reasons  []string `json:"end_reasons"`
		} `json:"broker_protocol"`
	}
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	if err := dec.Decode(&c); err != nil {
		t.Fatal(err)
	}
	want := map[string][2]string{"serial": {"GET", "/console/v1/vms/{id}/serial"}, "ticket": {"POST", "/console/v1/vms/{id}/tickets"}, "socket": {"GET", "/console/v1/vms/{id}/socket"}}
	for name, w := range want {
		r := c.Routes[name]
		if r.Method != w[0] || r.Path != w[1] {
			t.Errorf("%s: %s %s, want %v", name, r.Method, r.Path, w)
		}
		// every declared route is served by the router and by no other method
		p := strings.ReplaceAll(r.Path, "{id}", "web-1")
		if m := consoleRouteRE.FindStringSubmatch(p); m == nil || !strings.HasSuffix(r.Path, "/"+map[string]string{"serial": "serial", "ticket": "tickets", "socket": "socket"}[name]) {
			t.Errorf("%s: path %q is not routed", name, p)
		}
	}
	for name, w := range map[string][2]string{"ticket": {"POST", "/console/v1/vms/{id}/graphics-tickets"}, "socket": {"GET", "/console/v1/vms/{id}/graphics-socket"}} {
		g := c.Graphics[name]
		if g.Method != w[0] || g.Path != w[1] {
			t.Errorf("graphics %s: %s %s, want %v", name, g.Method, g.Path, w)
		}
		if consoleRouteRE.FindStringSubmatch(strings.ReplaceAll(g.Path, "{id}", "web-1")) == nil {
			t.Errorf("graphics %s: path %q is not routed", name, g.Path)
		}
	}
	if g := c.Graphics["socket"]; len(g.Subprotocols) != 2 || g.Subprotocols[0] != graphicsProto || g.Subprotocols[1] != ticketPrefix+"<ticket>" || maxGraphicsMessage != 65536 {
		t.Errorf("graphics subprotocols %v, max %d", g.Subprotocols, maxGraphicsMessage)
	}
	states := []string{string(console.Unavailable), string(console.NotConfigured), string(console.NoOutput), string(console.Available)}
	got := append([]string(nil), c.Routes["serial"].Response.State...)
	sort.Strings(got)
	sort.Strings(states)
	if strings.Join(got, ",") != strings.Join(states, ",") {
		t.Errorf("serial states %v, want %v", got, states)
	}
	if len(c.Routes["socket"].Subprotocols) != 2 || c.Routes["socket"].Subprotocols[0] != consoleProto || c.Routes["socket"].Subprotocols[1] != ticketPrefix+"<ticket>" {
		t.Errorf("subprotocols %v", c.Routes["socket"].Subprotocols)
	}
	if consoleProto != "svavyom.console.v1" || maxInputBytes != 4096 || console.DefaultTicketTTL != 30*time.Second {
		t.Errorf("limits drifted: %s %d %v", consoleProto, maxInputBytes, console.DefaultTicketTTL)
	}
	if strings.Join(c.Broker.Requests, ",") != console.OpSnapshot+","+console.OpAttach+","+console.OpGraphics || strings.Join(c.Broker.Frames, ",") != console.FrameOut+","+console.FrameIn+","+console.FrameEnd {
		t.Errorf("broker vocabulary %v %v", c.Broker.Requests, c.Broker.Frames)
	}
	reasons := []string{console.ReasonClosed, console.ReasonVMEnded, console.ReasonIdle, console.ReasonLifetime, console.ReasonError}
	if strings.Join(c.Broker.Reasons, ",") != strings.Join(reasons, ",") {
		t.Errorf("end reasons %v, want %v", c.Broker.Reasons, reasons)
	}
	for _, code := range []int{console.CloseNormal, console.CloseGoingAway, console.ClosePolicy, console.CloseTooBig, console.CloseProtocol, console.CloseInternal} {
		if _, ok := c.Routes["socket"].CloseCodes[itoa(code)]; !ok {
			t.Errorf("close code %d is used by the code but not documented", code)
		}
	}
}

func itoa(n int) string {
	b, _ := json.Marshal(n)
	return string(b)
}
