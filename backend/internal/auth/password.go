// Package auth is the single-administrator authentication of the Svavyom control plane (DR-015 D2, story
// M1-E04-S05): Argon2id password hashes, server-side SQLite sessions with opaque tokens, CSRF tokens, login failure
// throttling, and the explicit bootstrap that creates the first administrator.
//
// Nothing here logs, returns or stores a password, a password hash outside the credential row, a session token or a CSRF
// secret in clear: tokens exist in clear only in the browser, hashes are stored, and audit events carry identifiers
// and closed vocabulary only.
package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"
)

// Params are the Argon2id cost parameters. They are stored inside every PHC string, so changing the baseline never
// invalidates an existing hash; NeedsRehash upgrades it at the next successful sign-in.
type Params struct {
	MemoryKiB uint32 // m
	Time      uint32 // t
	Threads   uint8  // p
	SaltLen   uint32
	KeyLen    uint32
}

// BaselineParams follow the second recommended option of RFC 9106 section 4 (t=3, p=4, m=64 MiB), which exceeds the
// OWASP minimum (m=19 MiB, t=2, p=1). Measured cost in the pinned container is recorded in docs/AUTH.md.
var BaselineParams = Params{MemoryKiB: 64 * 1024, Time: 3, Threads: 4, SaltLen: 16, KeyLen: 32}

// Safe bounds: a stored hash outside them is rejected without being computed, so a corrupted or tampered credential
// row cannot be turned into a memory or CPU denial of service, and a configuration cannot weaken the hash.
const (
	minMemoryKiB = 19 * 1024
	maxMemoryKiB = 256 * 1024
	minTime      = 2
	maxTime      = 10
	minThreads   = 1
	maxThreads   = 16
	minSalt      = 16
	maxSalt      = 64
	minKey       = 16
	maxKey       = 64
)

// Password policy (NIST SP 800-63B for single-factor memorized secrets, kept deliberately simple).
const (
	MinPasswordBytes = 12
	MaxPasswordBytes = 128
)

// Errors of the password layer. They never carry the password or the hash.
var (
	ErrPasswordPolicy = errors.New("auth: password does not meet the policy")
	ErrBadHash        = errors.New("auth: stored credential is malformed or outside safe bounds")
	ErrParamsUnsafe   = errors.New("auth: argon2id parameters outside safe bounds")
)

// Validate checks the parameters against the safe bounds.
func (p Params) Validate() error {
	if p.MemoryKiB < minMemoryKiB || p.MemoryKiB > maxMemoryKiB || p.Time < minTime || p.Time > maxTime ||
		p.Threads < minThreads || p.Threads > maxThreads || p.SaltLen < minSalt || p.SaltLen > maxSalt ||
		p.KeyLen < minKey || p.KeyLen > maxKey {
		return ErrParamsUnsafe
	}
	return nil
}

// CheckPassword enforces the password policy: 12 to 128 bytes of valid UTF-8, no NUL or other control characters,
// not a single repeated character, and not equal to the username.
func CheckPassword(username, password string) error {
	n := len(password)
	if n < MinPasswordBytes || n > MaxPasswordBytes || !utf8.ValidString(password) {
		return ErrPasswordPolicy
	}
	for _, r := range password {
		if r < 0x20 || r == 0x7f {
			return ErrPasswordPolicy
		}
	}
	if strings.Count(password, password[:1]) == n || strings.EqualFold(password, username) {
		return ErrPasswordPolicy
	}
	return nil
}

var b64 = base64.RawStdEncoding

// HashPassword returns the PHC string of password with a fresh random salt. The caller limits concurrency (memory).
func HashPassword(password string, p Params) (string, error) {
	if err := p.Validate(); err != nil {
		return "", err
	}
	salt := make([]byte, p.SaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("auth: salt: %w", err)
	}
	key := argon2.IDKey([]byte(password), salt, p.Time, p.MemoryKiB, p.Threads, p.KeyLen)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s", argon2.Version, p.MemoryKiB, p.Time, p.Threads,
		b64.EncodeToString(salt), b64.EncodeToString(key)), nil
}

type parsed struct {
	p    Params
	salt []byte
	key  []byte
}

// parsePHC accepts exactly the canonical form HashPassword writes and nothing else.
func parsePHC(s string) (parsed, error) {
	parts := strings.Split(s, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" || parts[2] != "v="+strconv.Itoa(argon2.Version) {
		return parsed{}, ErrBadHash
	}
	var m, t, th uint64
	kv := strings.Split(parts[3], ",")
	if len(kv) != 3 {
		return parsed{}, ErrBadHash
	}
	for i, spec := range []struct {
		name string
		dst  *uint64
		bits int
	}{{"m=", &m, 32}, {"t=", &t, 32}, {"p=", &th, 8}} {
		v, ok := strings.CutPrefix(kv[i], spec.name)
		if !ok {
			return parsed{}, ErrBadHash
		}
		n, err := strconv.ParseUint(v, 10, spec.bits)
		if err != nil || strconv.FormatUint(n, 10) != v {
			return parsed{}, ErrBadHash
		}
		*spec.dst = n
	}
	salt, err1 := b64.DecodeString(parts[4])
	key, err2 := b64.DecodeString(parts[5])
	if err1 != nil || err2 != nil || b64.EncodeToString(salt) != parts[4] || b64.EncodeToString(key) != parts[5] {
		return parsed{}, ErrBadHash
	}
	// The three parameters were range-checked by their bit sizes above, so these conversions cannot truncate.
	out := parsed{p: Params{MemoryKiB: uint32(m), Time: uint32(t), Threads: uint8(th), // #nosec G115
		SaltLen: uint32(len(salt)), KeyLen: uint32(len(key))}, salt: salt, key: key} // #nosec G115 -- bounded below
	if len(salt) > maxSalt || len(key) > maxKey || out.p.Validate() != nil {
		return parsed{}, ErrBadHash
	}
	return out, nil
}

// VerifyPassword reports whether password matches the PHC string. A malformed or out-of-bounds hash returns
// ErrBadHash without computing anything. The comparison is constant time.
func VerifyPassword(password, phc string) (bool, error) {
	h, err := parsePHC(phc)
	if err != nil {
		return false, err
	}
	got := argon2.IDKey([]byte(password), h.salt, h.p.Time, h.p.MemoryKiB, h.p.Threads, uint32(len(h.key))) // #nosec G115
	return subtle.ConstantTimeCompare(got, h.key) == 1, nil
}

// NeedsRehash reports whether phc was produced with weaker parameters than current.
func NeedsRehash(phc string, current Params) bool {
	h, err := parsePHC(phc)
	if err != nil {
		return false
	}
	return h.p.MemoryKiB < current.MemoryKiB || h.p.Time < current.Time || h.p.Threads < current.Threads ||
		h.p.SaltLen < current.SaltLen || h.p.KeyLen < current.KeyLen
}
