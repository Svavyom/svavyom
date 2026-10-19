package console

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"sync"
	"time"
)

// Ticket errors. They are distinct so tests (and the audit trail) can tell the cases apart; the HTTP layer maps every one of them to
// the same answer, so a caller learns nothing about which check failed.
var (
	ErrInvalid  = errors.New("console: invalid ticket") // malformed, unknown, tampered, wrong VM, wrong kind or wrong session
	ErrExpired  = errors.New("console: ticket expired")
	ErrReplayed = errors.New("console: ticket already used")
	ErrBusy     = errors.New("console: too many outstanding tickets")
)

// Kind is the console type a ticket is bound to.
const (
	KindSerial   = "serial"
	KindGraphics = "graphics"
)

func validKind(k string) bool { return k == KindSerial || k == KindGraphics }

// DefaultTicketTTL is the lifetime of an unused ticket.
const DefaultTicketTTL = 30 * time.Second

const (
	ticketBytes = 32
	maxTickets  = 256
)

type entry struct {
	session [sha256.Size]byte
	vm      string
	kind    string
	expires time.Time
	used    bool
}

// Tickets mints and redeems console tickets. A ticket is 256 random bits; only its SHA-256 is kept, so a memory dump of the API does
// not yield redeemable tickets. It is bound to the minting session (by a hash of the session token), one VM and one console kind,
// expires after a short lifetime and can be redeemed exactly once. State is in memory on purpose: tickets must not outlive the process.
type Tickets struct {
	mu  sync.Mutex
	m   map[[sha256.Size]byte]entry
	ttl time.Duration
	now func() time.Time
}

// NewTickets returns a ticket service. ttl <= 0 selects DefaultTicketTTL; now == nil selects time.Now.
func NewTickets(ttl time.Duration, now func() time.Time) *Tickets {
	if ttl <= 0 {
		ttl = DefaultTicketTTL
	}
	if now == nil {
		now = time.Now
	}
	return &Tickets{m: map[[sha256.Size]byte]entry{}, ttl: ttl, now: now}
}

func sessionKey(token string) [sha256.Size]byte {
	return sha256.Sum256([]byte("svavyom-console-session-v1:" + token))
}

// Mint issues a ticket for (session, vm, kind). sessionToken is the caller's session credential; it is only hashed.
func (t *Tickets) Mint(sessionToken, vm, kind string) (ticket string, expires time.Time, err error) {
	if sessionToken == "" || vm == "" || !validKind(kind) {
		return "", time.Time{}, ErrInvalid
	}
	var raw [ticketBytes]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", time.Time{}, err
	}
	ticket = base64.RawURLEncoding.EncodeToString(raw[:])
	now := t.now()
	expires = now.Add(t.ttl)
	t.mu.Lock()
	defer t.mu.Unlock()
	t.purgeLocked(now)
	if len(t.m) >= maxTickets {
		return "", time.Time{}, ErrBusy
	}
	t.m[sha256.Sum256([]byte(ticket))] = entry{session: sessionKey(sessionToken), vm: vm, kind: kind, expires: expires}
	return ticket, expires, nil
}

// Redeem consumes a ticket. It succeeds only for an existing, unexpired, unused ticket minted for exactly this session, VM and kind.
// A ticket that fails the binding check is NOT consumed (a stranger who guesses nothing cannot burn somebody else's ticket), but a
// ticket is consumed by its first successful redemption, so a replay is ErrReplayed until it expires.
func (t *Tickets) Redeem(ticket, sessionToken, vm, kind string) error {
	if len(ticket) != base64.RawURLEncoding.EncodedLen(ticketBytes) || sessionToken == "" || vm == "" || !validKind(kind) {
		return ErrInvalid
	}
	if raw, err := base64.RawURLEncoding.DecodeString(ticket); err != nil || len(raw) != ticketBytes {
		return ErrInvalid
	}
	key := sha256.Sum256([]byte(ticket))
	now := t.now()
	t.mu.Lock()
	defer t.mu.Unlock()
	t.purgeLocked(now)
	e, ok := t.m[key]
	if !ok {
		return ErrInvalid
	}
	want := sessionKey(sessionToken)
	if subtle.ConstantTimeCompare(e.session[:], want[:]) != 1 || e.vm != vm || e.kind != kind {
		return ErrInvalid
	}
	switch {
	case e.used:
		return ErrReplayed
	case !now.Before(e.expires):
		return ErrExpired
	}
	e.used = true
	t.m[key] = e
	return nil
}

// RevokeSession forgets every ticket of one session (sign-out, expiry).
func (t *Tickets) RevokeSession(sessionToken string) {
	want := sessionKey(sessionToken)
	t.mu.Lock()
	defer t.mu.Unlock()
	for k, e := range t.m {
		if e.session == want {
			delete(t.m, k)
		}
	}
}

// purgeLocked drops tickets that expired a while ago (a used or expired ticket is kept for one extra lifetime so a replay is
// reported as a replay).
func (t *Tickets) purgeLocked(now time.Time) {
	for k, e := range t.m {
		if now.After(e.expires.Add(t.ttl)) {
			delete(t.m, k)
		}
	}
}
