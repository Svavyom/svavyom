package api

import (
	"testing"

	"example.invalid/dedicatedcloud/backend/internal/auth"
)

// A demoted or disabled user's queued, not-yet-started operations do not run (DR-044 D1, finding F-08). The worker is stopped so that what is submitted stays queued.
func TestDemotingOrDisablingAUserCancelsTheirQueuedOperationsAndOnlyTheirs(t *testing.T) {
	for _, c := range []struct {
		name string
		path string
		body string
		// cancelled says whether olly's queued operation is cancelled by this change
		cancelled bool
	}{
		{"demoted to viewer", "/api/v1/users/olly/role", `{"role":"viewer"}`, true},
		{"disabled", "/api/v1/users/olly/disable", "", true},
		{"promoted to admin", "/api/v1/users/olly/role", `{"role":"admin"}`, false},
		{"role set to the same one", "/api/v1/users/olly/role", `{"role":"operator"}`, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			r := newCRig(t, true)
			r.stop() // nothing runs: submitted operations stay pending
			admin := signedIn(t, r.env)
			olly := r.env.asRole("olly", auth.RoleOperator)
			mine := opID(t, r.post(olly, r.createBody("olly-vm", r.key, nil)))
			theirs := opID(t, r.post(admin, r.createBody("admin-vm", r.key, nil)))
			r.await(admin, mine, "pending")
			if rep := admin.do("POST", c.path, c.body, map[string]string{"X-CSRF-Token": admin.csrf}); rep.status != 200 {
				t.Fatalf("%d %s", rep.status, rep.body)
			}
			want := "pending"
			if c.cancelled {
				want = "cancelled"
			}
			r.await(admin, mine, want)
			r.await(admin, theirs, "pending") // another user's work is never touched
		})
	}
}

func TestACancelledOperationStaysCancelledWhenTheUserIsChangedAgain(t *testing.T) {
	r := newCRig(t, true)
	r.stop()
	admin := signedIn(t, r.env)
	olly := r.env.asRole("olly", auth.RoleOperator)
	id := opID(t, r.post(olly, r.createBody("olly-vm", r.key, nil)))
	if rep := admin.do("POST", "/api/v1/users/olly/role", `{"role":"viewer"}`, map[string]string{"X-CSRF-Token": admin.csrf}); rep.status != 200 {
		t.Fatalf("%d %s", rep.status, rep.body)
	}
	op := r.await(admin, id, "cancelled")
	if op["requested_by"] != "olly" {
		t.Fatalf("%v", op)
	}
	// the cancelled operation cannot be started again by anyone: a second change is a no-op
	if rep := admin.do("POST", "/api/v1/users/olly/disable", "", map[string]string{"X-CSRF-Token": admin.csrf}); rep.status != 200 {
		t.Fatalf("%d %s", rep.status, rep.body)
	}
	r.await(admin, id, "cancelled")
}
