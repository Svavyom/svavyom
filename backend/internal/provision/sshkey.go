package provision

import (
	"bytes"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"strings"

	"golang.org/x/crypto/ssh"
)

// MaxSSHKeyInput bounds the text accepted for a public key.
const MaxSSHKeyInput = 2048

// ErrSSHKey is returned for every rejected key; it deliberately says nothing about why.
var ErrSSHKey = errors.New("provision: invalid SSH public key")

// SSHKey is a validated, normalised public key.
type SSHKey struct {
	Authorized  string // "<type> <base64>" (no options, no comment)
	Fingerprint string // SHA256:...
	Type        string
}

// NormalizeSSHKey validates one OpenSSH-format public key with the Go SSH parser and returns its canonical form. It rejects
// anything that is not exactly one plain public key: private keys, several keys, key options (command=, from=, ...), comments
// that smuggle another line, unsupported or weak key types (RSA below 3072 bits, DSA, security-key types), and oversized input.
func NormalizeSSHKey(in string) (SSHKey, error) {
	if len(in) == 0 || len(in) > MaxSSHKeyInput || strings.Contains(in, "PRIVATE KEY") {
		return SSHKey{}, ErrSSHKey
	}
	for _, r := range in {
		if r == 0 || (r < 0x20 && r != '\t' && r != '\n' && r != '\r') || r == 0x7f || r > 0x7e {
			return SSHKey{}, ErrSSHKey
		}
	}
	trimmed := strings.TrimRight(in, " \t\r\n")
	if strings.ContainsAny(trimmed, "\r\n") { // one key, one line
		return SSHKey{}, ErrSSHKey
	}
	pub, comment, opts, rest, err := ssh.ParseAuthorizedKey([]byte(trimmed))
	if err != nil || len(opts) != 0 || len(bytes.TrimSpace(rest)) != 0 {
		return SSHKey{}, ErrSSHKey
	}
	for _, word := range strings.Fields(comment) { // "keyA keyB" on one line would hide a second key in the comment
		for _, t := range []string{"ssh-", "ecdsa-sha2-", "sk-ssh-", "sk-ecdsa-"} {
			if strings.HasPrefix(word, t) {
				return SSHKey{}, ErrSSHKey
			}
		}
	}
	switch pub.Type() {
	case ssh.KeyAlgoED25519, ssh.KeyAlgoECDSA256, ssh.KeyAlgoECDSA384, ssh.KeyAlgoECDSA521:
	case ssh.KeyAlgoRSA:
		ck, ok := pub.(ssh.CryptoPublicKey)
		if !ok {
			return SSHKey{}, ErrSSHKey
		}
		rk, ok := ck.CryptoPublicKey().(*rsa.PublicKey)
		if !ok || rk.N.BitLen() < 3072 {
			return SSHKey{}, ErrSSHKey
		}
	default:
		return SSHKey{}, ErrSSHKey
	}
	blob := pub.Marshal()
	canon := pub.Type() + " " + base64.StdEncoding.EncodeToString(blob)
	// Re-parse the canonical form: it must round-trip to the same key.
	again, _, _, _, err := ssh.ParseAuthorizedKey([]byte(canon))
	if err != nil || !bytes.Equal(again.Marshal(), blob) {
		return SSHKey{}, ErrSSHKey
	}
	return SSHKey{Authorized: canon, Fingerprint: ssh.FingerprintSHA256(pub), Type: pub.Type()}, nil
}
