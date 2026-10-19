package auth

import (
	"strings"
	"testing"
	"time"
)

var fast = Params{MemoryKiB: 19 * 1024, Time: 2, Threads: 1, SaltLen: 16, KeyLen: 32}

func TestHashVerifyRoundTripAndFormat(t *testing.T) {
	phc, err := HashPassword("correct horse battery", fast)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(phc, "$argon2id$v=19$m=19456,t=2,p=1$") || strings.Count(phc, "$") != 5 {
		t.Fatalf("not canonical PHC: %q", phc)
	}
	if strings.Contains(phc, "correct") {
		t.Fatal("hash contains the password")
	}
	if ok, err := VerifyPassword("correct horse battery", phc); !ok || err != nil {
		t.Fatalf("verify: %v %v", ok, err)
	}
	if ok, err := VerifyPassword("correct horse batterz", phc); ok || err != nil {
		t.Fatalf("wrong password accepted: %v %v", ok, err)
	}
}

func TestSaltIsRandomPerPassword(t *testing.T) {
	a, _ := HashPassword("same password here", fast)
	b, _ := HashPassword("same password here", fast)
	if a == b {
		t.Fatal("two hashes of the same password are identical: salt is not random")
	}
}

func TestMalformedHashesFailClosedWithoutComputing(t *testing.T) {
	good, _ := HashPassword("correct horse battery", fast)
	parts := strings.Split(good, "$")
	with := func(i int, v string) string {
		p := append([]string(nil), parts...)
		p[i] = v
		return strings.Join(p, "$")
	}
	cases := map[string]string{
		"empty":             "",
		"garbage":           "not a hash",
		"bcrypt":            "$2a$10$abcdefghijklmnopqrstuuABCDEFGHIJKLMNOPQRSTUVWXYZ012",
		"argon2i":           with(1, "argon2i"),
		"old version":       with(2, "v=16"),
		"missing part":      strings.Join(parts[:5], "$"),
		"extra part":        good + "$x",
		"huge memory":       with(3, "m=4294967295,t=2,p=1"),
		"memory too small":  with(3, "m=1024,t=2,p=1"),
		"zero time":         with(3, "m=19456,t=0,p=1"),
		"huge time":         with(3, "m=19456,t=4294967295,p=1"),
		"zero threads":      with(3, "m=19456,t=2,p=0"),
		"threads overflow":  with(3, "m=19456,t=2,p=256"),
		"leading zero":      with(3, "m=019456,t=2,p=1"),
		"plus sign":         with(3, "m=+19456,t=2,p=1"),
		"order swapped":     with(3, "t=2,m=19456,p=1"),
		"salt too short":    with(4, "AAAA"),
		"salt not base64":   with(4, "!!!!!!!!!!!!!!!!!!!!!!"),
		"padded base64":     with(5, parts[5]+"="),
		"empty key":         with(5, ""),
		"unicode digits":    with(3, "m=١٩٤٥٦,t=2,p=1"),
		"control character": good + "\n",
	}
	for name, phc := range cases {
		start := time.Now()
		ok, err := VerifyPassword("correct horse battery", phc)
		if ok || err != ErrBadHash {
			t.Errorf("%s: ok=%v err=%v, want ErrBadHash", name, ok, err)
		}
		if time.Since(start) > 50*time.Millisecond {
			t.Errorf("%s: rejected only after %v: the hash was computed", name, time.Since(start))
		}
	}
}

func TestParamsBoundsAndRehash(t *testing.T) {
	if err := BaselineParams.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []Params{{MemoryKiB: 1024, Time: 3, Threads: 4, SaltLen: 16, KeyLen: 32}, {MemoryKiB: 65536, Time: 1, Threads: 4, SaltLen: 16, KeyLen: 32},
		{MemoryKiB: 1 << 30, Time: 3, Threads: 4, SaltLen: 16, KeyLen: 32}, {MemoryKiB: 65536, Time: 3, Threads: 4, SaltLen: 8, KeyLen: 32}} {
		if _, err := HashPassword("whatever password", bad); err != ErrParamsUnsafe {
			t.Errorf("%+v accepted", bad)
		}
	}
	weak, _ := HashPassword("correct horse battery", fast)
	if !NeedsRehash(weak, BaselineParams) || NeedsRehash(weak, fast) || NeedsRehash("garbage", BaselineParams) {
		t.Fatal("NeedsRehash")
	}
}

func TestPasswordPolicy(t *testing.T) {
	ok := []string{"correct horse battery", "ünïcödé-pässwörd-1", strings.Repeat("ab", 64)}
	bad := map[string]string{"short": "short", "eleven": "elevenchars", "repeated": "aaaaaaaaaaaaaaaa", "nul": "has\x00nul-in-password", "newline": "line1\nline2-password",
		"too long": strings.Repeat("x1", 65), "invalid utf8": "bad\xff\xfeutf8-password", "equals user": "administrator"}
	for _, p := range ok {
		if err := CheckPassword("administrator2", p); err != nil {
			t.Errorf("%q rejected: %v", p, err)
		}
	}
	for name, p := range bad {
		if err := CheckPassword("administrator", p); err != ErrPasswordPolicy {
			t.Errorf("%s accepted", name)
		}
	}
}

// TestBaselineCost records the real resource cost of the production parameters in the pinned container (DR-015 D2).
// It bounds the cost generously so a regression to something unusable, or to something cheap, fails.
func TestBaselineCost(t *testing.T) {
	const pw = "correct horse battery"
	start := time.Now()
	phc, err := HashPassword(pw, BaselineParams)
	if err != nil {
		t.Fatal(err)
	}
	hashTime := time.Since(start)
	start = time.Now()
	if ok, _ := VerifyPassword(pw, phc); !ok {
		t.Fatal("verify")
	}
	t.Logf("argon2id m=%d KiB t=%d p=%d: hash %v, verify %v", BaselineParams.MemoryKiB, BaselineParams.Time, BaselineParams.Threads, hashTime, time.Since(start))
	if hashTime < 5*time.Millisecond || hashTime > 5*time.Second {
		t.Fatalf("baseline hash took %v: outside the expected 5ms..5s envelope", hashTime)
	}
}
