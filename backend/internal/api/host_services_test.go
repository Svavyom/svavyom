package api

import (
	"testing"
	"time"
)

func TestHostReportsItsOwnServiceAndEachConfiguredPeer(t *testing.T) {
	started := time.Date(2026, 11, 10, 8, 0, 0, 0, time.UTC)
	h := &Handler{deps: Deps{StartedAt: started, Services: func() []ServiceState {
		return []ServiceState{{ID: "agent", State: "ok"}, {ID: "mutation", State: "unreachable"}, {ID: "console", State: "not_enabled"}}
	}}}
	got := h.hostWithSystem(hostJSON{})
	if len(got.Observed.Services) != 4 || got.Observed.Services[0] != (serviceJSON{ID: "api", State: "ok"}) || got.Observed.Services[2] != (serviceJSON{ID: "mutation", State: "unreachable"}) {
		t.Fatalf("services: %+v", got.Observed.Services)
	}
	if got.Observed.StartedAt == nil || *got.Observed.StartedAt != "2026-11-10T08:00:00Z" {
		t.Fatalf("started_at: %v", got.Observed.StartedAt)
	}
}

func TestHostWithoutProbeStillListsTheAPIAndNoStartTime(t *testing.T) {
	got := (&Handler{}).hostWithSystem(hostJSON{})
	if len(got.Observed.Services) != 1 || got.Observed.Services[0].ID != "api" || got.Observed.StartedAt != nil {
		t.Fatalf("got %+v %v", got.Observed.Services, got.Observed.StartedAt)
	}
}

func TestHostReportsTheCertificateOnlyWhenThereIsOne(t *testing.T) {
	if got := (&Handler{}).hostWithSystem(hostJSON{}); got.Observed.Certificate != nil {
		t.Fatal("behind a proxy there is no certificate to report")
	}
	cv := &CertificateView{Names: []string{"console.example.org"}, Source: "lets_encrypt", DaysLeft: 60, Managed: true}
	got := (&Handler{deps: Deps{Certificate: func() *CertificateView { return cv }}}).hostWithSystem(hostJSON{})
	if got.Observed.Certificate != cv {
		t.Fatalf("%+v", got.Observed.Certificate)
	}
}

func TestHostFindingsJoinTheRecordedFirewallFindings(t *testing.T) {
	h := &Handler{deps: Deps{
		Firewall:     func() []FirewallFinding { return []FirewallFinding{{Code: "FW_X", Remediation: "a"}} },
		HostFindings: func() []FirewallFinding { return []FirewallFinding{{Code: "LIBVIRT_GUESTS_OFF", Remediation: "b"}} },
	}}
	got := h.firewallFindings()
	if len(got) != 2 || got[0].Code != "FW_X" || got[1].Code != "LIBVIRT_GUESTS_OFF" {
		t.Fatalf("%+v", got)
	}
	if (&Handler{}).firewallFindings() != nil {
		t.Fatal("nothing recorded, nothing computed: no findings")
	}
}
