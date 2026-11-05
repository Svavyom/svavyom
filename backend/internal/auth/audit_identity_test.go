package auth

import (
	"strings"
	"testing"
	"time"
)

func auditOf(t *testing.T, r *rig) []AuditEvent {
	t.Helper()
	evs, err := r.svc.Audit(ctx)
	if err != nil {
		t.Fatal(err)
	}
	return evs
}

// Every authentication audit event says who it is about (DR-038, finding F-10): the account that signed in, signed out, was created, changed or reset, and the name
// that was only tried. Before, the trail said "sign_in success" and nobody.
func TestAuditEventsNameTheUser(t *testing.T) {
	r := newRig(t)
	r.bootstrap()
	good := r.signIn()
	_, _ = r.svc.SignIn(ctx, "NoBody", "wrong password here", "203.0.113.5", "")
	if err := r.svc.AddUser(ctx, "olly", "an operator passphrase", RoleOperator); err != nil {
		t.Fatal(err)
	}
	if err := r.svc.SetRole(ctx, "olly", RoleViewer); err != nil {
		t.Fatal(err)
	}
	if err := r.svc.SetPassword(ctx, "olly", "another new passphrase"); err != nil {
		t.Fatal(err)
	}
	if err := r.svc.SignOut(ctx, good.SessionToken); err != nil {
		t.Fatal(err)
	}
	want := map[string]string{}
	for _, e := range auditOf(t, r) {
		want[e.Event+":"+e.Outcome+":"+e.Reason] = e.Username
	}
	for key, user := range map[string]string{
		"bootstrap:success:":                  adminName,
		"sign_in:success:":                    adminName,
		"sign_in:failure:invalid_credentials": "nobody", // a name that was only tried, lower-cased
		"user_add:success:operator":           "olly",
		"password_reset:success:":             "olly",
		"sign_out:success:":                   adminName,
	} {
		if got, ok := want[key]; !ok || got != user {
			t.Errorf("%s: user %q (present %v), want %q; all: %v", key, got, ok, user, want)
		}
	}
	for _, e := range auditOf(t, r) {
		if e.Event != "bootstrap" && e.Event != "session_expired" && e.Username == "" {
			t.Errorf("an event names nobody: %+v", e)
		}
	}
}

// A name that was only typed is the attacker's: it is cut and anything outside a closed set of characters is replaced, so no control character, space or markup can
// reach the trail; and no secret is ever in an event.
func TestAnAuditedNameIsSanitised(t *testing.T) {
	for in, want := range map[string]string{
		"admin":                     "admin",
		"Admin":                     "admin",
		"a b":                       "a?b",
		"<script>alert(1)</script>": "?script?alert?1???script?",
		"line\nbreak":               "line?break",
		"user@example.org":          "user@example.org",
		"tab\there":                 "tab?here",
		"":                          "",
	} {
		if got := auditName(in); got != want {
			t.Errorf("auditName(%q) = %q, want %q", in, got, want)
		}
	}
	if got := auditName(strings.Repeat("a", 200)); len(got) != 64 {
		t.Errorf("a long name is cut to 64 bytes: %d", len(got))
	}
	r := newRig(t)
	r.bootstrap()
	_, _ = r.svc.SignIn(ctx, "x\"; DROP TABLE users;--", "wrong password here", "203.0.113.5", "")
	for _, e := range auditOf(t, r) {
		if strings.ContainsAny(e.Username, " \n\r\t\"';<>()") {
			t.Errorf("an unsafe character reached the audit trail: %q", e.Username)
		}
	}
}

// An audit event that cannot be stored does not pass unseen: the sign-in still answers, the failure is remembered for the alert, and the log callback hears of it with
// the kind and outcome only (DR-038, F-10).
func TestAFailedAuditWriteIsSurfaced(t *testing.T) {
	r := newRig(t)
	r.bootstrap()
	var told []AuditEvent
	r.svc.cfg.AuditFailed = func(ev AuditEvent) { told = append(told, ev) }
	if r.svc.AuditWriteFailedSince(time.Time{}) {
		t.Fatal("a failure before any failure")
	}
	if _, err := r.db.Exec(`ALTER TABLE auth_audit RENAME TO auth_audit_gone`); err != nil { // the trail becomes unwritable
		t.Fatal(err)
	}
	before := r.clk.now()
	if _, err := r.svc.SignIn(ctx, adminName, adminPass, "198.51.100.7", ""); err != nil {
		t.Fatalf("a sign-in is not refused because the trail is unwritable: %v", err)
	}
	if len(told) != 1 || told[0].Event != "sign_in" || told[0].Outcome != "success" || told[0].Username != "" || told[0].Source != "" {
		t.Fatalf("the log callback: %+v (it must carry the kind and the outcome only)", told)
	}
	if !r.svc.AuditWriteFailedSince(before) {
		t.Fatal("the failure is not remembered for the alert")
	}
	r.clk.add(time.Hour)
	if r.svc.AuditWriteFailedSince(r.clk.now().Add(-time.Minute)) {
		t.Fatal("an old failure must not read as current")
	}
}
