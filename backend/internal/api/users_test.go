package api

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"example.invalid/dedicatedcloud/backend/internal/auth"
)

const tempPass, newPass = "temporary passphrase 1", "a brand new passphrase 2"

func jsonBody(v map[string]string) string {
	b, _ := json.Marshal(v)
	return string(b)
}

func TestUsersRoutesAreAdminOnlyAuditedAndNeverReturnAPassword(t *testing.T) {
	e := newEnv(t, true)
	admin := signedIn(t, e)
	op := e.asRole("olly", auth.RoleOperator)
	vw := e.asRole("vera", auth.RoleViewer)
	h := func(b *browser) map[string]string { return map[string]string{"X-CSRF-Token": b.csrf} }

	// every route refuses anonymous callers, viewers and operators
	for name, b := range map[string]*browser{"anonymous": e.browser(), "viewer": vw, "operator": op} {
		want := 403
		if name == "anonymous" {
			want = 401
		}
		for _, c := range [][3]string{{"GET", "/api/v1/users", ""}, {"POST", "/api/v1/users", jsonBody(map[string]string{"username": "newbie", "role": "viewer", "password": tempPass})},
			{"POST", "/api/v1/users/olly/role", `{"role":"admin"}`}, {"POST", "/api/v1/users/olly/disable", ""}, {"POST", "/api/v1/users/olly/enable", ""}, {"POST", "/api/v1/users/olly/password", `{"password":"` + tempPass + `"}`}} {
			if rep := b.do(c[0], c[1], c[2], h(b)); rep.status != want {
				t.Errorf("%s %s %s: %d, want %d", name, c[0], c[1], rep.status, want)
			}
		}
	}
	if rep := admin.do("POST", "/api/v1/users", jsonBody(map[string]string{"username": "newbie", "role": "viewer", "password": tempPass}), nil); rep.status != 403 {
		t.Errorf("without the CSRF token: %d, want 403", rep.status)
	}

	// list: every user, and what the admin may do to each (nothing to themselves)
	rep := admin.do("GET", "/api/v1/users", "", nil)
	var l struct {
		Items   []userJSON `json:"items"`
		Allowed []string   `json:"allowed_actions"`
	}
	_ = json.Unmarshal(rep.body, &l)
	if rep.status != 200 || len(l.Items) != 3 || len(l.Allowed) != 1 || l.Allowed[0] != "create" {
		t.Fatalf("list: %d %s", rep.status, rep.body)
	}
	for _, u := range l.Items {
		if (u.Username == adminName) != (len(u.Allowed) == 0) {
			t.Errorf("allowed actions of %s: %v", u.Username, u.Allowed)
		}
	}

	// create: a temporary password, validated, never echoed
	create := func(name, role, pw string) reply {
		return admin.do("POST", "/api/v1/users", jsonBody(map[string]string{"username": name, "role": role, "password": pw}), h(admin))
	}
	rep = create("newbie", "viewer", tempPass)
	var u userJSON
	_ = json.Unmarshal(rep.body, &u)
	if rep.status != 201 || u.Username != "newbie" || !u.MustChange || u.Role != "viewer" || strings.Contains(string(rep.body), tempPass) {
		t.Fatalf("create: %d %s", rep.status, rep.body)
	}
	for name, c := range map[string]struct {
		r    reply
		want int
	}{"duplicate": {create("newbie", "viewer", tempPass), 409}, "weak password": {create("weakling", "viewer", "short"), 400}, "bad role": {create("rolex", "root", tempPass), 400},
		"bad name": {create("Bad Name", "viewer", tempPass), 400}} {
		if c.r.status != c.want || strings.Contains(string(c.r.body), tempPass) {
			t.Errorf("%s: %d %s, want %d", name, c.r.status, c.r.body, c.want)
		}
	}

	// role, disable, enable, reset on another user; the target's sessions end; never on yourself; an unknown user is 404
	nb := e.browser()
	nb.status()
	if rep := nb.signIn("newbie", tempPass); rep.status != 200 || !strings.Contains(string(rep.body), `"must_change_password":true`) {
		t.Fatalf("the new user signs in with the temporary password: %d %s", rep.status, rep.body)
	}
	if rep := admin.do("POST", "/api/v1/users/newbie/role", `{"role":"operator"}`, h(admin)); rep.status != 200 || !strings.Contains(string(rep.body), `"operator"`) {
		t.Errorf("role: %d %s", rep.status, rep.body)
	}
	if rep := nb.do("GET", "/api/v1/auth/session", "", nil); strings.Contains(string(rep.body), `"authenticated":true`) {
		t.Errorf("a role change ends the user's sessions: %s", rep.body)
	}
	if rep := admin.do("POST", "/api/v1/users/newbie/role", `{"role":"root"}`, h(admin)); rep.status != 400 {
		t.Errorf("bad role: %d", rep.status)
	}
	if rep := admin.do("POST", "/api/v1/users/newbie/disable", "", h(admin)); rep.status != 200 || !strings.Contains(string(rep.body), `"disabled":true`) || !strings.Contains(string(rep.body), `"enable"`) {
		t.Errorf("disable: %d %s", rep.status, rep.body)
	}
	if rep := e.browser().do("POST", "/api/v1/auth/session", creds("newbie", tempPass), nil); rep.status == 200 {
		t.Errorf("a disabled user cannot sign in")
	}
	if rep := admin.do("POST", "/api/v1/users/newbie/enable", "", h(admin)); rep.status != 200 || !strings.Contains(string(rep.body), `"disabled":false`) {
		t.Errorf("enable: %d %s", rep.status, rep.body)
	}
	rep = admin.do("POST", "/api/v1/users/newbie/password", `{"password":"`+newPass+`"}`, h(admin))
	if rep.status != 200 || !strings.Contains(string(rep.body), `"must_change_password":true`) || strings.Contains(string(rep.body), newPass) {
		t.Errorf("reset: %d %s", rep.status, rep.body)
	}
	if rep := admin.do("POST", "/api/v1/users/newbie/password", `{"password":"short"}`, h(admin)); rep.status != 400 {
		t.Errorf("reset with a weak password: %d", rep.status)
	}
	for _, c := range [][2]string{{"role", `{"role":"viewer"}`}, {"disable", ""}, {"enable", ""}, {"password", `{"password":"` + newPass + `"}`}} {
		if rep := admin.do("POST", "/api/v1/users/"+adminName+"/"+c[0], c[1], h(admin)); rep.status != 403 {
			t.Errorf("an administrator acting on themselves (%s): %d, want 403", c[0], rep.status)
		}
	}
	if rep := admin.do("POST", "/api/v1/users/nobody/disable", "", h(admin)); rep.status != 404 {
		t.Errorf("unknown user: %d, want 404", rep.status)
	}
	if rep := admin.do("POST", "/api/v1/users/Bad%20Name/disable", "", h(admin)); rep.status != 400 {
		t.Errorf("malformed user: %d, want 400", rep.status)
	}

	// who did what to whom is in the audit, without any password
	log, _ := e.svc.Audit(t.Context())
	var seen []string
	for _, ev := range log {
		if strings.Contains(ev.Reason+ev.Username, tempPass) || strings.Contains(ev.Reason+ev.Username, newPass) {
			t.Errorf("a password in the audit: %+v", ev)
		}
		if ev.Username == "newbie" {
			seen = append(seen, ev.Event)
		}
	}
	for _, want := range []string{"user_add", "role_change", "user_disable", "user_enable", "password_reset"} {
		if !slices.Contains(seen, want) {
			t.Errorf("audit lacks %s for newbie: %v", want, seen)
		}
	}
}

func TestChangeOwnPasswordRoute(t *testing.T) {
	e := newEnv(t, true)
	a := e.asRole("olly", auth.RoleOperator)
	b := e.browser()
	b.status()
	if rep := b.signIn("olly", rolePass); rep.status != 200 {
		t.Fatal(rep.status)
	}
	body := func(cur, next string) string {
		return jsonBody(map[string]string{"current_password": cur, "new_password": next})
	}
	h := func(x *browser) map[string]string { return map[string]string{"X-CSRF-Token": x.csrf} }

	if rep := e.browser().do("POST", "/api/v1/auth/password", body(rolePass, newPass), nil); rep.status != 401 {
		t.Errorf("anonymous: %d, want 401", rep.status)
	}
	if rep := a.do("POST", "/api/v1/auth/password", body(rolePass, newPass), nil); rep.status != 403 {
		t.Errorf("without the CSRF token: %d, want 403", rep.status)
	}
	if rep := a.do("POST", "/api/v1/auth/password", body("not the password", newPass), h(a)); rep.status != 403 || strings.Contains(string(rep.body), "not the password") {
		t.Errorf("wrong current: %d %s", rep.status, rep.body)
	}
	if rep := a.do("POST", "/api/v1/auth/password", body(rolePass, "short"), h(a)); rep.status != 400 {
		t.Errorf("weak: %d", rep.status)
	}
	if rep := a.do("POST", "/api/v1/auth/password", body(rolePass, rolePass), h(a)); rep.status != 400 {
		t.Errorf("same: %d", rep.status)
	}
	if rep := a.do("POST", "/api/v1/auth/password", `{"current_password":"x","new_password":"y","extra":1}`, h(a)); rep.status != 400 {
		t.Errorf("unknown field: %d", rep.status)
	}
	rep := a.do("POST", "/api/v1/auth/password", body(rolePass, newPass), h(a))
	if rep.status != 200 || !strings.Contains(string(rep.body), `"must_change_password":false`) || strings.Contains(string(rep.body), newPass) || strings.Contains(string(rep.body), rolePass) {
		t.Fatalf("change: %d %s", rep.status, rep.body)
	}
	if rep := a.do("GET", "/api/v1/hosts", "", nil); rep.status != 200 {
		t.Errorf("the session that changed it stays: %d", rep.status)
	}
	if rep := b.do("GET", "/api/v1/hosts", "", nil); rep.status != 401 {
		t.Errorf("every other session ends: %d", rep.status)
	}
	if rep := e.browser().do("POST", "/api/v1/auth/session", creds("olly", rolePass), nil); rep.status == 200 {
		t.Errorf("the old password no longer signs in")
	}
	// repeated wrong current passwords are throttled like sign-in
	var last reply
	for i := 0; i < 8; i++ {
		last = a.do("POST", "/api/v1/auth/password", body("wrong password "+string(rune('a'+i)), "yet another passphrase 3"), h(a))
	}
	if last.status != 429 || last.header.Get("Retry-After") == "" {
		t.Errorf("throttled: %d", last.status)
	}
}

func TestATemporaryPasswordLimitsEveryRouteButTheChange(t *testing.T) {
	e := newEnv(t, true)
	admin := signedIn(t, e)
	if rep := admin.do("POST", "/api/v1/users", jsonBody(map[string]string{"username": "newbie", "role": "admin", "password": tempPass}), map[string]string{"X-CSRF-Token": admin.csrf}); rep.status != 201 {
		t.Fatalf("create: %d %s", rep.status, rep.body)
	}
	nb := e.browser()
	nb.status()
	if rep := nb.signIn("newbie", tempPass); rep.status != 200 {
		t.Fatalf("sign-in: %d", rep.status)
	}
	if rep := nb.do("GET", "/api/v1/auth/session", "", nil); !strings.Contains(string(rep.body), `"must_change_password":true`) {
		t.Fatalf("status says so: %s", rep.body)
	}
	// every implemented route except the status, the change, sign-out and health is refused with 403, even for an administrator; so is the console
	allowed := map[string]bool{"GET /healthz": true, "GET /api/v1/auth/session": true, "POST /api/v1/auth/session": true, "DELETE /api/v1/auth/session": true, "POST /api/v1/auth/password": true}
	n := 0
	for _, r := range declaredRoutes {
		if !r.implemented || allowed[r.method+" "+r.template] {
			continue
		}
		path := strings.NewReplacer("{id}", "x").Replace(r.template)
		n++
		if rep := nb.do(r.method, path, "", map[string]string{"X-CSRF-Token": nb.csrf}); rep.status != 403 {
			t.Errorf("%s %s with a temporary password: %d, want 403", r.method, path, rep.status)
		}
	}
	if n < 25 {
		t.Errorf("the loop covered only %d routes", n)
	}
	if rep := nb.do("GET", "/console/v1/vms/x/serial", "", nil); rep.status != 403 {
		t.Errorf("the console: %d, want 403", rep.status)
	}
	if rep := nb.do("GET", "/healthz", "", nil); rep.status != 200 {
		t.Errorf("health: %d", rep.status)
	}
	// the change lifts it
	if rep := nb.do("POST", "/api/v1/auth/password", jsonBody(map[string]string{"current_password": tempPass, "new_password": newPass}), map[string]string{"X-CSRF-Token": nb.csrf}); rep.status != 200 {
		t.Fatalf("change: %d %s", rep.status, rep.body)
	}
	if rep := nb.do("GET", "/api/v1/hosts", "", nil); rep.status != 200 {
		t.Errorf("after the change: %d, want 200", rep.status)
	}
	// and signing out is possible while the password is still temporary
	if rep := admin.do("POST", "/api/v1/users/newbie/password", `{"password":"`+tempPass+`"}`, map[string]string{"X-CSRF-Token": admin.csrf}); rep.status != 200 {
		t.Fatalf("reset: %d", rep.status)
	}
	again := e.browser()
	again.status()
	again.signIn("newbie", tempPass)
	if rep := again.signOut(); rep.status != 200 {
		t.Errorf("sign-out with a temporary password: %d", rep.status)
	}
}
