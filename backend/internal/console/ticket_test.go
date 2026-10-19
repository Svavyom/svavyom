package console

import (
	"strings"
	"testing"
	"time"
)

type clock struct{ t time.Time }

func (c *clock) now() time.Time          { return c.t }
func (c *clock) advance(d time.Duration) { c.t = c.t.Add(d) }

func newT() (*Tickets, *clock) {
	c := &clock{t: time.Date(2026, 10, 11, 9, 0, 0, 0, time.UTC)}
	return NewTickets(30*time.Second, c.now), c
}

func TestTicketIsSingleUseBoundAndShortLived(t *testing.T) {
	ts, clk := newT()
	tk, exp, err := ts.Mint("session-A", "web-1", KindSerial)
	if err != nil || len(tk) != 43 || !exp.Equal(clk.t.Add(30*time.Second)) {
		t.Fatalf("%q %v %v", tk, exp, err)
	}
	if err := ts.Redeem(tk, "session-A", "web-1", KindSerial); err != nil {
		t.Fatal(err)
	}
	if err := ts.Redeem(tk, "session-A", "web-1", KindSerial); err != ErrReplayed {
		t.Fatalf("replay: %v", err)
	}
}

func TestTicketRejections(t *testing.T) {
	ts, clk := newT()
	tk, _, _ := ts.Mint("session-A", "web-1", KindSerial)
	flip := tk[:len(tk)-1] + map[bool]string{true: "B", false: "A"}[tk[len(tk)-1] == 'A']
	for name, c := range map[string]struct {
		ticket, session, vm string
		want                error
	}{
		"wrong VM":      {tk, "session-A", "web-2", ErrInvalid},
		"wrong session": {tk, "session-B", "web-1", ErrInvalid},
		"ended session": {tk, "", "web-1", ErrInvalid},
		"tampered":      {flip, "session-A", "web-1", ErrInvalid},
		"truncated":     {tk[:20], "session-A", "web-1", ErrInvalid},
		"padded":        {tk + "AA", "session-A", "web-1", ErrInvalid},
		"empty":         {"", "session-A", "web-1", ErrInvalid},
		"not base64":    {strings.Repeat("!", 43), "session-A", "web-1", ErrInvalid},
	} {
		if err := ts.Redeem(c.ticket, c.session, c.vm, KindSerial); err != c.want {
			t.Errorf("%s: %v", name, err)
		}
	}
	if err := ts.Redeem(tk, "session-A", "web-1", "graphical"); err != ErrInvalid {
		t.Errorf("wrong kind: %v", err)
	}
	// None of those burned the ticket: it still works once.
	if err := ts.Redeem(tk, "session-A", "web-1", KindSerial); err != nil {
		t.Fatalf("a refused redemption must not consume the ticket: %v", err)
	}
	// Expiry.
	tk2, _, _ := ts.Mint("session-A", "web-1", KindSerial)
	clk.advance(31 * time.Second)
	if err := ts.Redeem(tk2, "session-A", "web-1", KindSerial); err != ErrExpired {
		t.Fatalf("expired: %v", err)
	}
	// Mint refuses garbage.
	for _, a := range [][3]string{{"", "web-1", KindSerial}, {"s", "", KindSerial}, {"s", "web-1", "vnc"}} {
		if _, _, err := ts.Mint(a[0], a[1], a[2]); err != ErrInvalid {
			t.Errorf("%v: %v", a, err)
		}
	}
}

func TestSessionRevocationAndBound(t *testing.T) {
	ts, _ := newT()
	a, _, _ := ts.Mint("session-A", "web-1", KindSerial)
	b, _, _ := ts.Mint("session-B", "web-1", KindSerial)
	ts.RevokeSession("session-A")
	if err := ts.Redeem(a, "session-A", "web-1", KindSerial); err != ErrInvalid {
		t.Fatalf("a revoked session's ticket: %v", err)
	}
	if err := ts.Redeem(b, "session-B", "web-1", KindSerial); err != nil {
		t.Fatalf("another session's ticket must survive: %v", err)
	}
	for i := 0; i < maxTickets; i++ {
		_, _, _ = ts.Mint("session-C", "web-1", KindSerial)
	}
	if _, _, err := ts.Mint("session-C", "web-1", KindSerial); err != ErrBusy {
		t.Fatalf("outstanding tickets are bounded: %v", err)
	}
}

func TestTicketsAreRandomAndNotStoredInTheClear(t *testing.T) {
	ts, _ := newT()
	seen := map[string]bool{}
	for i := 0; i < 50; i++ {
		tk, _, _ := ts.Mint("s", "web-1", KindSerial)
		if seen[tk] {
			t.Fatal("duplicate ticket")
		}
		seen[tk] = true
		for k := range ts.m {
			if string(k[:]) == tk {
				t.Fatal("ticket stored in the clear")
			}
		}
	}
}
