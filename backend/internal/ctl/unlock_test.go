package ctl

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

// user-unlock (DR-038 D3): the sign-in blocks live in the API's memory, so unlocking is a restart of the API alone. Without --apply it changes nothing.
func TestUserUnlockRestartsOnlyTheAPIAndOnlyWithApply(t *testing.T) {
	h, _ := dbHost(t)
	var out bytes.Buffer
	if err := UserUnlock(context.Background(), h.env, UserUnlockOptions{Username: "admin"}, &out); err != nil {
		t.Fatalf("%v\n%s", err, out.String())
	}
	if !strings.Contains(out.String(), "PLAN (nothing is changed without --apply)") || !strings.Contains(out.String(), "held in the memory of the API service") {
		t.Fatalf("the plan must explain itself: %s", out.String())
	}
	before := h.run.called("systemctl restart")
	out.Reset()
	if err := UserUnlock(context.Background(), h.env, UserUnlockOptions{Username: "admin"}, &out); err != nil || h.run.called("systemctl restart") != before {
		t.Fatalf("a dry run must change nothing: %v", err)
	}
	if err := UserUnlock(context.Background(), h.env, UserUnlockOptions{Username: "admin", Apply: true}, &out); err != nil {
		t.Fatalf("%v\n%s", err, out.String())
	}
	if h.run.called("systemctl restart") != before+1 || h.run.called("systemctl restart -- svavyom-api.service") < 1 {
		t.Fatalf("exactly the API must be restarted once: %v", h.run.calls)
	}
	if h.run.called("systemctl stop") != 0 {
		t.Fatalf("no service is stopped: %v", h.run.calls)
	}
	if !strings.Contains(out.String(), "every sign-in block is cleared") {
		t.Fatalf("it must say what it did: %s", out.String())
	}
}

func TestUserUnlockRefusals(t *testing.T) {
	h, _ := dbHost(t)
	for _, bad := range []string{"Admin", "a b", "x;y", "../x", strings.Repeat("a", 65)} {
		if err := UserUnlock(context.Background(), h.env, UserUnlockOptions{Username: bad}, &bytes.Buffer{}); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	if err := UserUnlock(context.Background(), h.env, UserUnlockOptions{}, &bytes.Buffer{}); err != nil {
		t.Errorf("no name is fine: %v", err)
	}
	h.run.fail = map[string]bool{"systemctl restart -- svavyom-api.service": true}
	if err := UserUnlock(context.Background(), h.env, UserUnlockOptions{Apply: true}, &bytes.Buffer{}); err == nil {
		t.Error("a failed restart must be an error")
	}
}
