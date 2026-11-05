package api

import (
	"strings"
	"testing"

	"example.invalid/dedicatedcloud/backend/internal/auth"
)

// The serial boot output is for operators and administrators, and only while the interactive-console switch is on (DR-037, finding F-06). A viewer used to
// read every managed VM's output, switch or no switch.
func TestSerialSnapshotNeedsTheOperatorRoleAndTheSwitch(t *testing.T) {
	for _, enabled := range []bool{true, false} {
		c := newConsRig(t, enabled)
		viewer := c.asRole("vera", auth.RoleViewer)
		operator := c.asRole("olly", auth.RoleOperator)
		path := "/console/v1/vms/web-1/serial"
		wantOK := 200
		if !enabled {
			wantOK = 422 // prohibited
		}
		for name, tc := range map[string]struct {
			b    *browser
			want int
		}{"viewer": {viewer, 403}, "operator": {operator, wantOK}, "admin": {c.b, wantOK}} {
			if rep := tc.b.do("GET", path, "", nil); rep.status != tc.want {
				t.Errorf("switch %v, %s: %d %s, want %d", enabled, name, rep.status, rep.body, tc.want)
			}
		}
		if rep := c.e().browser().do("GET", path, "", nil); rep.status != 401 {
			t.Errorf("switch %v, anonymous: %d", enabled, rep.status)
		}
		// the refusals are audited with the actor and the reason, and never carry the output
		var role, disabled bool
		for _, a := range c.auditEvents() {
			if a.Event != "serial.refused" {
				continue
			}
			role = role || (a.Actor == "vera" && a.Outcome == "role" && a.VM == "web-1")
			disabled = disabled || (a.Outcome == "disabled" && a.VM == "web-1")
			if strings.Contains(a.Actor+a.VM+a.Outcome, "Reached target") {
				t.Errorf("an audit event carries output: %+v", a)
			}
		}
		if !role {
			t.Errorf("switch %v: the viewer's refusal is not audited with reason role", enabled)
		}
		if !enabled && !disabled {
			t.Error("the refusal with the switch off is not audited with reason disabled")
		}
	}
}
