package ctl

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// Signature verification of a release artifact (M4-E02-S02). The signing step (ci/sign/sign-artifact.sh, run by the release owner or by Jenkins) writes
// detached signatures of SHA256SUMS and MANIFEST.json to a directory of their own, with a SIGNING-INFO.json. `verify-artifact --signatures DIR
// --public-key FILE` checks, in this order: that SIGNING-INFO names the artifact and the digests of those two files as they are now; the detached
// signature of each under the operator's own public key (obtained out of band: a key shipped beside the signatures proves nothing); that SHA256SUMS agrees
// with the manifest; and then every file against the manifest (VerifyArtifact). The signing method is not decided yet (S3), so the four the scripts
// support are verified: ed25519 here with the standard library, and gpg, minisign and cosign through those tools with a fixed command line and no shell.

// SigningInfo is ci/sign's SIGNING-INFO.json.
type SigningInfo struct {
	Method         string `json:"method"`
	KeyFingerprint string `json:"key_fingerprint"`
	SignedAt       string `json:"signed_at"`
	Artifact       string `json:"artifact"`
	SumsDigest     string `json:"SHA256SUMS_sha256"`
	ManifestDigest string `json:"MANIFEST_json_sha256"`
}

// SignatureOptions names the signature directory and the trusted public key file.
type SignatureOptions struct{ Dir, PublicKey string }

// SignatureResult is what a successful verification established.
type SignatureResult struct {
	Method    string
	SignedAt  string
	Artifact  string
	KeyDetail string
}

var (
	errBadSig = errors.New("ctl: signature verification failed")
	sigMethod = map[string]string{"gpg": ".asc", "minisign": ".minisig", "cosign-key": ".sig", "ed25519": ".ed25519"}
	signedSet = []string{"SHA256SUMS", ManifestName}
	validFPR  = regexp.MustCompile(`^[0-9A-Fa-f]{16,64}$`)
)

// VerifySignatures checks the signatures of the artifact in dir. It reads, and changes nothing (gpg uses a throw-away key ring in a private temporary directory).
func VerifySignatures(ctx context.Context, e *Env, dir string, o SignatureOptions) (SignatureResult, error) {
	var r SignatureResult
	if o.Dir == "" || o.PublicKey == "" {
		return r, errors.New("a signature directory and a trusted public key are both needed")
	}
	raw, err := readRegular(filepath.Join(o.Dir, "SIGNING-INFO.json"), 64<<10)
	if err != nil {
		return r, fmt.Errorf("%w: no readable SIGNING-INFO.json in the signature directory", errBadSig)
	}
	var info SigningInfo
	if err := json.Unmarshal(raw, &info); err != nil {
		return r, fmt.Errorf("%w: SIGNING-INFO.json is malformed", errBadSig)
	}
	ext, ok := sigMethod[info.Method]
	if !ok {
		return r, fmt.Errorf("%w: unknown signing method %q", errBadSig, clean(info.Method))
	}
	if info.KeyFingerprint != "" && len(info.KeyFingerprint) > 128 {
		return r, fmt.Errorf("%w: SIGNING-INFO.json is malformed", errBadSig)
	}
	sums, err := fileSHA256(filepath.Join(dir, "SHA256SUMS"))
	if err != nil {
		return r, fmt.Errorf("%w: the artifact has no SHA256SUMS", errBadSig)
	}
	man, err := fileSHA256(filepath.Join(dir, ManifestName))
	if err != nil {
		return r, fmt.Errorf("%w: the artifact has no %s", errBadSig, ManifestName)
	}
	if info.SumsDigest != sums || info.ManifestDigest != man {
		return r, fmt.Errorf("%w: SIGNING-INFO.json describes different SHA256SUMS or MANIFEST.json files than this artifact has", errBadSig)
	}
	if info.Artifact != filepath.Base(filepath.Clean(dir)) {
		return r, fmt.Errorf("%w: the signatures are for %s, not for %s", errBadSig, clean(info.Artifact), clean(filepath.Base(filepath.Clean(dir))))
	}
	pubFile, err := readRegular(o.PublicKey, 64<<10)
	if err != nil {
		return r, errors.New("the trusted public key file cannot be read")
	}
	detail := ""
	for _, f := range signedSet {
		sig := filepath.Join(o.Dir, f+ext)
		if _, err := readRegular(sig, 64<<10); err != nil {
			return r, fmt.Errorf("%w: no signature file %s", errBadSig, f+ext)
		}
		d, err := verifyOne(ctx, e, info.Method, pubFile, o.PublicKey, sig, filepath.Join(dir, f))
		if err != nil {
			return r, fmt.Errorf("%w: %s: %s", errBadSig, f, clean(err.Error()))
		}
		detail = d
	}
	if err := checkSums(dir); err != nil {
		return r, err
	}
	if _, err := VerifyArtifact(dir); err != nil {
		return r, err
	}
	return SignatureResult{Method: info.Method, SignedAt: info.SignedAt, Artifact: info.Artifact, KeyDetail: detail}, nil
}

func verifyOne(ctx context.Context, e *Env, method string, pub []byte, pubPath, sig, file string) (string, error) {
	switch method {
	case "ed25519":
		return verifyEd25519(pub, sig, file)
	case "minisign":
		if out, err := e.Run.Run(ctx, "minisign", "-V", "-q", "-p", pubPath, "-m", file, "-x", sig); err != nil {
			return "", errors.New("minisign: " + out)
		}
		return "minisign key", nil
	case "cosign-key":
		if out, err := e.Run.Run(ctx, "cosign", "verify-blob", "--key", pubPath, "--insecure-ignore-tlog=true", "--signature", sig, file); err != nil {
			return "", errors.New("cosign: " + out)
		}
		return "cosign key", nil
	case "gpg":
		return verifyGPG(ctx, e, pubPath, sig, file)
	}
	return "", errors.New("unknown method")
}

// verifyEd25519 accepts the public key as a PEM "PUBLIC KEY" (what `openssl pkey -pubout` writes) and the signature as base64 text or as the raw 64 bytes.
func verifyEd25519(pubFile []byte, sigPath, file string) (string, error) {
	blk, _ := pem.Decode(pubFile)
	if blk == nil || blk.Type != "PUBLIC KEY" {
		return "", errors.New("the public key is not a PEM public key")
	}
	k, err := x509.ParsePKIXPublicKey(blk.Bytes)
	pub, ok := k.(ed25519.PublicKey)
	if err != nil || !ok {
		return "", errors.New("the public key is not an Ed25519 key")
	}
	sig, err := readRegular(sigPath, 4096)
	if err != nil {
		return "", errors.New("the signature cannot be read")
	}
	if len(sig) != ed25519.SignatureSize {
		dec, derr := base64.StdEncoding.DecodeString(strings.TrimSpace(string(sig)))
		if derr != nil {
			return "", errors.New("the signature is neither raw nor base64")
		}
		sig = dec
	}
	msg, err := readRegular(file, 32<<20)
	if err != nil {
		return "", errors.New("the signed file cannot be read")
	}
	if len(sig) != ed25519.SignatureSize || !ed25519.Verify(pub, msg, sig) {
		return "", errors.New("the signature does not match the file under this key")
	}
	return fmt.Sprintf("ed25519 key %x", pub[:8]), nil
}

func verifyGPG(ctx context.Context, e *Env, pubPath, sig, file string) (string, error) {
	home, err := os.MkdirTemp("", "svavyom-gpg-")
	if err != nil {
		return "", err
	}
	defer func() { _ = os.RemoveAll(home) }()
	if out, err := e.Run.Run(ctx, "gpg", "--batch", "--no-tty", "--quiet", "--homedir", home, "--import", pubPath); err != nil {
		return "", errors.New("gpg could not import the public key: " + out)
	}
	lk, err := e.Run.Run(ctx, "gpg", "--batch", "--no-tty", "--homedir", home, "--with-colons", "--list-keys")
	if err != nil {
		return "", errors.New("gpg could not list the key")
	}
	fpr := ""
	sc := bufio.NewScanner(strings.NewReader(lk))
	for sc.Scan() {
		if f := strings.Split(sc.Text(), ":"); len(f) > 9 && f[0] == "fpr" && validFPR.MatchString(f[9]) {
			fpr = strings.ToUpper(f[9])
			break
		}
	}
	if fpr == "" {
		return "", errors.New("the public key file holds no key")
	}
	out, err := e.Run.Run(ctx, "gpg", "--batch", "--no-tty", "--homedir", home, "--status-fd", "1", "--verify", sig, file)
	if err != nil || !strings.Contains(out, "[GNUPG:] VALIDSIG "+fpr+" ") {
		return "", errors.New("gpg did not report a valid signature by the trusted key")
	}
	return "gpg key " + fpr, nil
}

// checkSums verifies that SHA256SUMS says exactly what the manifest says (every file, plus MANIFEST.json itself): a signed SHA256SUMS then covers every file.
func checkSums(dir string) error {
	raw, err := readRegular(filepath.Join(dir, "SHA256SUMS"), 4<<20)
	if err != nil {
		return fmt.Errorf("%w: no readable SHA256SUMS", errBadArtf)
	}
	got := map[string]string{}
	for _, line := range strings.Split(strings.TrimRight(string(raw), "\n"), "\n") {
		sum, path, ok := strings.Cut(line, "  ")
		if !ok || !hexSHA256.MatchString(sum) || !relPathRE.MatchString(path) {
			return fmt.Errorf("%w: SHA256SUMS is malformed", errBadArtf)
		}
		got[path] = sum
	}
	mraw, err := readRegular(filepath.Join(dir, ManifestName), 4<<20)
	if err != nil {
		return fmt.Errorf("%w: no readable %s", errBadArtf, ManifestName)
	}
	var m Manifest
	if err := json.Unmarshal(mraw, &m); err != nil {
		return fmt.Errorf("%w: the manifest is malformed", errBadArtf)
	}
	want := map[string]string{ManifestName: fileMust(filepath.Join(dir, ManifestName))}
	for _, f := range m.Files {
		want[f.Path] = f.SHA256
	}
	if len(got) != len(want) {
		return fmt.Errorf("%w: SHA256SUMS and the manifest list different files", errBadArtf)
	}
	for p, s := range want {
		if got[p] != s {
			return fmt.Errorf("%w: SHA256SUMS disagrees with the manifest about %s", errBadArtf, p)
		}
	}
	return nil
}

func fileMust(p string) string { s, _ := fileSHA256(p); return s }
