package ctl

import (
	"context"
	"errors"
	"fmt"
	"io"
	"regexp"
	"time"
)

// UserUnlockOptions are the inputs of UserUnlock.
type UserUnlockOptions struct {
	// Username is the account the administrator wants to get back in; it only names the plan (see UserUnlock).
	Username string
	Apply    bool
}

var unlockNameRE = regexp.MustCompile(`^[a-z0-9._@-]{1,64}$`)

// UserUnlock clears the sign-in blocks (DR-038 D3). The blocks live in the API process's memory, not in the database, so there is no per-user unlock: restarting the
// API clears every one of them, and that is what this does. Signed-in sessions are kept in the database and stay valid; nothing else changes. Without --apply it
// prints the plan. A name is optional, only to word the plan; it cannot select anything.
func UserUnlock(ctx context.Context, e *Env, o UserUnlockOptions, w io.Writer) error {
	if o.Username != "" && !unlockNameRE.MatchString(o.Username) {
		return errors.New("--username must be a user name (lower-case letters, digits and . _ @ -)")
	}
	if e.Euid() != 0 && o.Apply {
		return errors.New("--apply needs root (run with sudo)")
	}
	who := "every account"
	if o.Username != "" {
		who = "the account " + o.Username + " (and every other: the blocks are not kept per user)"
	}
	_, _ = fmt.Fprintf(w, "Sign-in blocks are held in the memory of the API service, so they can only be cleared all at once, by restarting it. This frees %s.\nSessions that are signed in are kept in the database and stay valid.\n", who)
	p := &Plan{}
	p.add("restart svavyom-api.service (it clears every sign-in block held in its memory; the other services are not touched)", func() error {
		if out, err := e.Run.Run(ctx, "systemctl", "restart", "--", "svavyom-api.service"); err != nil {
			return fmt.Errorf("systemctl restart svavyom-api.service: %s", clean(out))
		}
		return e.waitHealthy(ctx, 60*time.Second)
	})
	if err := p.Run(w, o.Apply); err != nil {
		return err
	}
	if o.Apply {
		_, _ = fmt.Fprintln(w, "the API was restarted: every sign-in block is cleared")
	}
	return nil
}
