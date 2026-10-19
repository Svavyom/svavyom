package api

import (
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestHostSummaryShowsTheRecordedFirewallFindings(t *testing.T) {
	e := newEnv(t, true)
	e.srv.Close()
	e.h = NewHandlerWith(Deps{Auth: e.svc, Hosts: e.hosts, Firewall: func() []FirewallFinding {
		return []FirewallFinding{{Code: "FW_FORWARD_DROP", Remediation: "Allow forwarding for the libvirt bridge."}}
	}})
	e.srv = httptest.NewServer(e.h)
	t.Cleanup(e.srv.Close)
	b := signedIn(t, e)
	rep := b.do("GET", "/api/v1/hosts/local", "", nil)
	if rep.status != 200 || !strings.Contains(string(rep.body), `"code":"FW_FORWARD_DROP"`) || !strings.Contains(string(rep.body), "Allow forwarding") {
		t.Fatalf("%d %s", rep.status, rep.body)
	}
	if !strings.Contains(string(rep.body), `"code":"CONTAINERIZED"`) {
		t.Fatalf("the host's own findings stay: %s", rep.body)
	}
	list := b.do("GET", "/api/v1/hosts", "", nil)
	if !strings.Contains(string(list.body), "FW_FORWARD_DROP") {
		t.Fatalf("the list shows it too: %s", list.body)
	}
}

func TestHostSummaryShowsTheLastNightlyBootAndHidesAnythingUnvouchedFor(t *testing.T) {
	for name, tc := range map[string]struct {
		res  *NightlyResult
		want string
	}{
		"pass":    {&NightlyResult{At: time.Date(2026, 10, 16, 2, 0, 0, 0, time.UTC), Result: "pass", Seconds: 412}, `"nightly_boot":{"at":"2026-10-16T02:00:00Z","result":"pass","seconds":412}`},
		"fail":    {&NightlyResult{At: time.Date(2026, 10, 16, 2, 0, 0, 0, time.UTC), Result: "fail", Seconds: 30}, `"result":"fail"`},
		"none":    {nil, `"nightly_boot":null`},
		"unknown": {&NightlyResult{At: time.Now(), Result: "great", Seconds: 1}, `"nightly_boot":null`},
		"absurd":  {&NightlyResult{At: time.Now(), Result: "pass", Seconds: 999999}, `"nightly_boot":null`},
	} {
		e := newEnv(t, true)
		e.srv.Close()
		res := tc.res
		e.h = NewHandlerWith(Deps{Auth: e.svc, Hosts: e.hosts, NightlyBoot: func() *NightlyResult { return res }})
		e.srv = httptest.NewServer(e.h)
		b := signedIn(t, e)
		rep := b.do("GET", "/api/v1/hosts/local", "", nil)
		if rep.status != 200 || !strings.Contains(string(rep.body), tc.want) {
			t.Errorf("%s: %d %s", name, rep.status, rep.body)
		}
		e.srv.Close()
	}
}

func TestHostSummaryShowsTheBridgeStateAndOnlyFromTheClosedVocabulary(t *testing.T) {
	ten := 90
	for name, tc := range map[string]struct {
		res  *BridgeObserved
		want string
	}{
		"none":                     {nil, `"bridge":null`},
		"planned":                  {&BridgeObserved{State: "planned", Bridge: "svbr0", Interface: "eno1"}, `"bridge":{"state":"planned","bridge":"svbr0","interface":"eno1","seconds_left":null}`},
		"active":                   {&BridgeObserved{State: "active", Bridge: "svbr0", Interface: "eno1"}, `"state":"active"`},
		"pending":                  {&BridgeObserved{State: "pending_confirmation", Bridge: "svbr0", Interface: "eno1", SecondsLeft: &ten}, `"state":"pending_confirmation","bridge":"svbr0","interface":"eno1","seconds_left":90`},
		"pending without a figure": {&BridgeObserved{State: "pending_confirmation", Bridge: "svbr0", Interface: "eno1"}, `"seconds_left":0`},
		"unknown state":            {&BridgeObserved{State: "done", Bridge: "svbr0", Interface: "eno1"}, `"bridge":null`},
		"odd name":                 {&BridgeObserved{State: "active", Bridge: "a b", Interface: "eno1"}, `"bridge":null`},
		"long name":                {&BridgeObserved{State: "active", Bridge: "abcdefghijklmnop", Interface: "eno1"}, `"bridge":null`},
		"absurd countdown":         {&BridgeObserved{State: "pending_confirmation", Bridge: "svbr0", Interface: "eno1", SecondsLeft: func() *int { n := 99999; return &n }()}, `"bridge":null`},
	} {
		e := newEnv(t, true)
		e.srv.Close()
		res := tc.res
		e.h = NewHandlerWith(Deps{Auth: e.svc, Hosts: e.hosts, Bridge: func() *BridgeObserved { return res }})
		e.srv = httptest.NewServer(e.h)
		b := signedIn(t, e)
		rep := b.do("GET", "/api/v1/hosts/local", "", nil)
		if rep.status != 200 || !strings.Contains(string(rep.body), tc.want) {
			t.Errorf("%s: %d %s", name, rep.status, rep.body)
		}
		e.srv.Close()
	}
}
