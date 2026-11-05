package api

import (
	"encoding/json"
	"strings"
	"testing"

	"example.invalid/dedicatedcloud/backend/internal/auth"
)

// POST /api/v1/operations/{id}/cancel (DR-036, finding F-04): administrators only, audited by the manager, idempotent, and only for an operation that has not
// reached the host.
func TestCancelRouteIsAdminOnlyIdempotentAndTyped(t *testing.T) {
	r := newCRig(t, true)
	admin := signedIn(t, r.env)
	viewer := r.asRole("vera", auth.RoleViewer)
	operator := r.asRole("olly", auth.RoleOperator)
	cancel := func(b *browser, id string, csrf bool) reply {
		h := map[string]string{}
		if csrf {
			h["X-CSRF-Token"] = b.csrf
		}
		return b.do("POST", "/api/v1/operations/"+id+"/cancel", "", h)
	}

	// an operation that already succeeded cannot be cancelled
	done := opID(t, r.post(admin, r.createBody("web-1", r.key, nil)))
	r.await(admin, done, "succeeded")
	if rep := cancel(admin, done, true); rep.status != 409 {
		t.Errorf("a succeeded operation: %d %s, want 409", rep.status, rep.body)
	}

	// with the worker stopped a new operation stays pending: the stand-in for one that is blocked or has not started
	r.stop()
	id := opID(t, r.post(admin, r.createBody("web-2", r.key, nil)))
	for name, tc := range map[string]struct {
		b    *browser
		csrf bool
		want int
	}{
		"viewer": {viewer, true, 403}, "operator": {operator, true, 403}, "admin without the CSRF token": {admin, false, 403}, "anonymous": {r.browser(), false, 401},
	} {
		if rep := cancel(tc.b, id, tc.csrf); rep.status != tc.want {
			t.Errorf("%s: %d %s, want %d", name, rep.status, rep.body, tc.want)
		}
	}
	if rep := admin.do("GET", "/api/v1/operations/"+id, "", nil); !strings.Contains(string(rep.body), `"pending"`) {
		t.Fatalf("a refused cancel changed the operation: %s", rep.body)
	}
	rep := cancel(admin, id, true)
	var op map[string]any
	_ = json.Unmarshal(rep.body, &op)
	if rep.status != 200 || op["status"] != "cancelled" || op["id"] != id {
		t.Fatalf("an admin cancels a pending operation: %d %s", rep.status, rep.body)
	}
	if again := cancel(admin, id, true); again.status != 200 || !strings.Contains(string(again.body), `"cancelled"`) {
		t.Errorf("a second cancel is the same cancelled operation: %d %s", again.status, again.body)
	}
	if rep := cancel(admin, "not an id!", true); rep.status != 400 && rep.status != 404 {
		t.Errorf("a malformed id: %d", rep.status)
	}
	if rep := admin.do("POST", "/api/v1/operations/"+id+"/cancel?x=1", "", map[string]string{"X-CSRF-Token": admin.csrf}); rep.status != 400 {
		t.Errorf("a query is refused: %d", rep.status)
	}
}
