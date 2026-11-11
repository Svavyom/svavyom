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
