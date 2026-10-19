package ctl

import (
	"regexp"
	"strings"
)

// Redaction for the support bundle. It is a deny-list applied to every piece of text that comes from a log, a command or a file, and it errs towards
// removing too much: a support bundle that hides a harmless token is better than one that leaks a credential. The bundle also contains only fixed
// sources (never a glob of host files), so redaction is the second line of defence, not the first.
const redacted = "[REDACTED]"

var (
	pemBlock   = regexp.MustCompile(`(?s)-----BEGIN [A-Z0-9 ]*(PRIVATE KEY|CERTIFICATE REQUEST)[A-Z0-9 ]*-----.*?(-----END [A-Z0-9 ]*-----|$)`)
	pubKey     = regexp.MustCompile(`\b(ssh-(?:rsa|ed25519|dss)|ecdsa-sha2-nistp\d+|sk-ssh-ed25519@openssh\.com)\s+[A-Za-z0-9+/=]{20,}(\s+\S+)?`)
	cookieHdr  = regexp.MustCompile(`(?i)\b(set-cookie|cookie)\s*:[^\n]*`)
	authHdr    = regexp.MustCompile(`(?i)\b(authorization|proxy-authorization|x-csrf-token|x-forwarded-for-token)\s*:[^\n]*`)
	cookieName = regexp.MustCompile(`(?i)(__host-|__secure-)?svavyom[_-]?(session|login|csrf)[A-Za-z0-9_-]*\s*=\s*[^;\s"']+`)
	secretKV   = regexp.MustCompile(`(?i)(["']?(?:pass(?:word|wd|phrase)?|secret|token|ticket|csrf|cookie|session|api[_-]?key|private[_-]?key|credential|bearer|idempotency[_-]?key|auth)[A-Za-z0-9_-]*["']?)(\s*[:=]\s*)("[^"]*"|'[^']*'|[^\s,;&}]+)`)
	urlCred    = regexp.MustCompile(`(?i)\b([a-z][a-z0-9+.-]*://)[^/\s:@]+:[^/\s@]+@`)
	bearer     = regexp.MustCompile(`(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{8,}`)
	longToken  = regexp.MustCompile(`[A-Za-z0-9_-]{40,}`)
	hexOnly    = regexp.MustCompile(`^[0-9a-f]+$`)
	scrubLine  = regexp.MustCompile(`(?i)\b(passw(or)?d|secret|private key)\b`)
)

// Redact removes credentials from s and returns the cleaned text and how many substitutions it made. Hexadecimal digests (SHA-256 of an image, a
// fingerprint) are kept; every other run of 40 or more token characters is removed, because session cookies, CSRF tokens and console tickets are
// 256-bit base64url strings.
func Redact(s string) (string, int) {
	n := 0
	sub := func(re *regexp.Regexp, repl func(string) string) {
		s = re.ReplaceAllStringFunc(s, func(m string) string {
			r := repl(m)
			if r != m {
				n++
			}
			return r
		})
	}
	sub(pemBlock, func(string) string { return "[REDACTED PRIVATE KEY BLOCK]" })
	sub(pubKey, func(m string) string { return strings.Fields(m)[0] + " " + redacted })
	sub(cookieHdr, func(m string) string { return strings.SplitN(m, ":", 2)[0] + ": " + redacted })
	sub(authHdr, func(m string) string { return strings.SplitN(m, ":", 2)[0] + ": " + redacted })
	sub(bearer, func(string) string { return "Bearer " + redacted })
	sub(urlCred, func(m string) string { return m[:strings.Index(m, "://")+3] + redacted + "@" })
	sub(cookieName, func(m string) string { return strings.SplitN(m, "=", 2)[0] + "=" + redacted })
	s = secretKV.ReplaceAllStringFunc(s, func(m string) string {
		g := secretKV.FindStringSubmatch(m)
		if strings.Contains(g[3], redacted) {
			return m
		}
		n++
		return g[1] + g[2] + redacted
	})
	s = longToken.ReplaceAllStringFunc(s, func(m string) string {
		if hexOnly.MatchString(m) {
			return m
		}
		n++
		return redacted
	})
	return s, n
}

// MentionsSecret reports whether text still contains something the redactor is meant to remove; the bundle builder refuses to write a file for which this
// is true after redaction (a defence against a future change to the patterns).
func MentionsSecret(s string) bool {
	if pemBlock.MatchString(s) || bearer.MatchString(s) {
		return true
	}
	for _, m := range longToken.FindAllString(s, -1) {
		if !hexOnly.MatchString(m) {
			return true
		}
	}
	return false
}

var _ = scrubLine
