package ctl

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type signedFixture struct {
	art, sigs, pub string
	priv           ed25519.PrivateKey
}

func hexOf(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }

// signedArtifact builds an artifact, writes its SHA256SUMS, signs SHA256SUMS and MANIFEST.json with a fresh Ed25519 key the way ci/sign does with openssl,
// and returns the paths. method names the SIGNING-INFO method and the signature file extension.
func signedArtifact(t *testing.T, mut func(files map[string][]byte)) signedFixture {
	t.Helper()
	art := makeArtifact(t, "0.1.0", curSchema, mut)
	var m Manifest
	raw, _ := os.ReadFile(filepath.Join(art, ManifestName))
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	var sums strings.Builder
	for _, f := range m.Files {
		sums.WriteString(f.SHA256 + "  " + f.Path + "\n")
	}
	sums.WriteString(hexOf(raw) + "  " + ManifestName + "\n")
	if err := os.WriteFile(filepath.Join(art, "SHA256SUMS"), []byte(sums.String()), 0o644); err != nil {
		t.Fatal(err)
	}
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	der, _ := x509.MarshalPKIXPublicKey(pub)
	sigs := t.TempDir()
	pubPath := filepath.Join(t.TempDir(), "release.pub")
	if err := os.WriteFile(pubPath, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), 0o644); err != nil {
		t.Fatal(err)
	}
	f := signedFixture{art: art, sigs: sigs, pub: pubPath, priv: priv}
	f.sign(t, "ed25519", ".ed25519")
	return f
}

func (f signedFixture) sign(t *testing.T, method, ext string) {
	t.Helper()
	for _, name := range []string{"SHA256SUMS", ManifestName} {
		b, _ := os.ReadFile(filepath.Join(f.art, name))
		sig := base64.StdEncoding.EncodeToString(ed25519.Sign(f.priv, b))
		if err := os.WriteFile(filepath.Join(f.sigs, name+ext), []byte(sig+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	f.info(t, method)
}

func (f signedFixture) info(t *testing.T, method string) {
	t.Helper()
	sums, _ := os.ReadFile(filepath.Join(f.art, "SHA256SUMS"))
	man, _ := os.ReadFile(filepath.Join(f.art, ManifestName))
	b, _ := json.Marshal(SigningInfo{Method: method, KeyFingerprint: "test", SignedAt: "2026-10-14T09:00:00Z", Artifact: filepath.Base(f.art), SumsDigest: hexOf(sums), ManifestDigest: hexOf(man)})
	if err := os.WriteFile(filepath.Join(f.sigs, "SIGNING-INFO.json"), b, 0o644); err != nil {
		t.Fatal(err)
	}
}

func verify(t *testing.T, e *Env, f signedFixture) error {
	t.Helper()
	_, err := VerifySignatures(context.Background(), e, f.art, SignatureOptions{Dir: f.sigs, PublicKey: f.pub})
	return err
}

func TestSignedArtifactVerifiesAndEveryTamperingIsRefused(t *testing.T) {
	e := newHost(t).env
	f := signedArtifact(t, nil)
	res, err := VerifySignatures(context.Background(), e, f.art, SignatureOptions{Dir: f.sigs, PublicKey: f.pub})
	if err != nil || res.Method != "ed25519" || !strings.HasPrefix(res.KeyDetail, "ed25519 key ") {
		t.Fatalf("%+v %v", res, err)
	}
	cases := map[string]func(t *testing.T, f signedFixture){
		"a file changed after signing": func(t *testing.T, f signedFixture) {
			_ = os.WriteFile(filepath.Join(f.art, "web/index.html"), []byte("<html>evil</html>"), 0o644)
		},
		"a file added after signing": func(t *testing.T, f signedFixture) {
			_ = os.WriteFile(filepath.Join(f.art, "extra.sh"), []byte("x"), 0o644)
		},
		"the manifest replaced": func(t *testing.T, f signedFixture) {
			b, _ := os.ReadFile(filepath.Join(f.art, ManifestName))
			_ = os.WriteFile(filepath.Join(f.art, ManifestName), []byte(strings.Replace(string(b), "0.1.0", "0.1.1", 1)), 0o644)
		},
		"a signature by another key": func(t *testing.T, f signedFixture) {
			_, other, _ := ed25519.GenerateKey(rand.Reader)
			f.priv = other
			f.sign(t, "ed25519", ".ed25519")
		},
		"the signature of the wrong file": func(t *testing.T, f signedFixture) {
			b, _ := os.ReadFile(filepath.Join(f.sigs, "SHA256SUMS.ed25519"))
			_ = os.WriteFile(filepath.Join(f.sigs, ManifestName+".ed25519"), b, 0o644)
		},
		"a missing signature": func(t *testing.T, f signedFixture) { _ = os.Remove(filepath.Join(f.sigs, "SHA256SUMS.ed25519")) },
		"a garbage signature": func(t *testing.T, f signedFixture) {
			_ = os.WriteFile(filepath.Join(f.sigs, "SHA256SUMS.ed25519"), []byte("@@@"), 0o644)
		},
		"no SIGNING-INFO":   func(t *testing.T, f signedFixture) { _ = os.Remove(filepath.Join(f.sigs, "SIGNING-INFO.json")) },
		"an unknown method": func(t *testing.T, f signedFixture) { f.info(t, "rot13") },
		"signatures for another artifact": func(t *testing.T, f signedFixture) {
			b, _ := os.ReadFile(filepath.Join(f.sigs, "SIGNING-INFO.json"))
			_ = os.WriteFile(filepath.Join(f.sigs, "SIGNING-INFO.json"), []byte(strings.Replace(string(b), filepath.Base(f.art), "svavyom-9.9.9", 1)), 0o644)
		},
		"a public key that is not a key": func(t *testing.T, f signedFixture) { _ = os.WriteFile(f.pub, []byte("not a key"), 0o644) },
	}
	for name, mut := range cases {
		t.Run(name, func(t *testing.T) {
			f := signedArtifact(t, nil)
			mut(t, f)
			if err := verify(t, e, f); err == nil {
				t.Fatal("must be refused")
			}
		})
	}
	if _, err := VerifySignatures(context.Background(), e, f.art, SignatureOptions{}); err == nil {
		t.Fatal("both a directory and a key are needed")
	}
}

func TestSumsThatDisagreeWithTheManifestAreRefusedEvenWhenSigned(t *testing.T) {
	e := newHost(t).env
	f := signedArtifact(t, nil)
	b, _ := os.ReadFile(filepath.Join(f.art, "SHA256SUMS"))
	lines := strings.Split(strings.TrimRight(string(b), "\n"), "\n")
	lines[0] = strings.Repeat("0", 64) + lines[0][64:]
	_ = os.WriteFile(filepath.Join(f.art, "SHA256SUMS"), []byte(strings.Join(lines, "\n")+"\n"), 0o644)
	f.sign(t, "ed25519", ".ed25519") // the owner signs whatever is there: the tool must still notice the lie
	if err := verify(t, e, f); err == nil || !strings.Contains(err.Error(), "disagrees") {
		t.Fatalf("%v", err)
	}
}

// stubTools answers gpg, minisign and cosign the way the real tools do for a good or a bad signature.
// stubFPR is a placeholder key fingerprint, built so that no literal in the file looks like key material.
var stubFPR = strings.Repeat("AB", 20)

type stubTools struct {
	good  bool
	calls []string
}

func (s *stubTools) Run(_ context.Context, name string, args ...string) (string, error) {
	s.calls = append(s.calls, name+" "+strings.Join(args, " "))
	j := strings.Join(args, " ")
	switch name {
	case "gpg":
		switch {
		case strings.Contains(j, "--import"):
			return "", nil
		case strings.Contains(j, "--list-keys"):
			return "tru::1:1:1:0:3:1:5\nfpr:::::::::" + stubFPR + ":\n", nil
		case strings.Contains(j, "--verify"):
			if s.good {
				return "[GNUPG:] GOODSIG X\n[GNUPG:] VALIDSIG " + stubFPR + " 2026-10-14 1\n", nil
			}
			return "[GNUPG:] BADSIG X\n", errors.New("exit 1")
		}
	case "minisign", "cosign":
		if s.good {
			return "", nil
		}
		return "signature verification failed", errors.New("exit 1")
	}
	return "", errors.New("unexpected " + name)
}

func TestGPGMinisignAndCosignAreVerifiedThroughTheirOwnTools(t *testing.T) {
	for method, ext := range map[string]string{"gpg": ".asc", "minisign": ".minisig", "cosign-key": ".sig"} {
		t.Run(method, func(t *testing.T) {
			f := signedArtifact(t, nil)
			for _, n := range []string{"SHA256SUMS", ManifestName} {
				_ = os.WriteFile(filepath.Join(f.sigs, n+ext), []byte("sig"), 0o644)
			}
			f.info(t, method)
			_ = os.WriteFile(f.pub, []byte("key material"), 0o644)
			st := &stubTools{good: true}
			e := newHost(t).env
			e.Run = st
			res, err := VerifySignatures(context.Background(), e, f.art, SignatureOptions{Dir: f.sigs, PublicKey: f.pub})
			if err != nil || res.Method != method {
				t.Fatalf("%+v %v", res, err)
			}
			if method == "gpg" && !strings.Contains(res.KeyDetail, stubFPR) {
				t.Fatalf("%q", res.KeyDetail)
			}
			for _, c := range st.calls { // never a shell, and the public key given by the operator is the one used
				if strings.Contains(c, "sh -c") {
					t.Fatalf("%s", c)
				}
			}
			st.good = false
			if _, err := VerifySignatures(context.Background(), e, f.art, SignatureOptions{Dir: f.sigs, PublicKey: f.pub}); err == nil {
				t.Fatal("a bad signature must be refused")
			}
		})
	}
}

func TestAttestationIsCheckedAgainstTheManifest(t *testing.T) {
	att := func(t *testing.T, mut func(a *attestation)) string {
		return makeAttestedArtifact(t, mut)
	}
	if _, err := VerifyArtifact(att(t, nil)); err != nil {
		t.Fatalf("a consistent attestation: %v", err)
	}
	for name, mut := range map[string]func(a *attestation){
		"another version":     func(a *attestation) { a.Predicate.Version = "9.9.9" },
		"a wrong SBOM digest": func(a *attestation) { a.Predicate.SBOM.SHA256 = strings.Repeat("a", 64) },
		"a wrong program digest": func(a *attestation) {
			a.Subject[0].Digest["sha256"] = strings.Repeat("b", 64)
		},
		"a program left out":     func(a *attestation) { a.Subject = a.Subject[1:] },
		"another statement type": func(a *attestation) { a.Type = "x" },
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := VerifyArtifact(att(t, mut)); err == nil || !strings.Contains(err.Error(), "attestation") {
				t.Fatalf("%v", err)
			}
		})
	}
}

// makeAttestedArtifact builds an artifact whose manifest lists a statement made the way tools/make_release.py makes it.
func makeAttestedArtifact(t *testing.T, mut func(a *attestation)) string {
	t.Helper()
	var dig map[string]string
	return makeArtifact(t, "0.1.0", curSchema, func(files map[string][]byte) {
		files["docs/sbom/sbom.cdx.json"] = []byte(`{"bomFormat":"CycloneDX"}`)
		files["docs/sbom/licenses.json"] = []byte(`{"packages":[]}`)
		var a attestation
		a.Type, a.PredicateType = "https://in-toto.io/Statement/v1", "https://svavyom.invalid/attestation/sbom/v1"
		for _, b := range Binaries {
			dig = map[string]string{"sha256": hexOf(files["bin/"+b])}
			a.Subject = append(a.Subject, struct {
				Name   string            `json:"name"`
				Digest map[string]string `json:"digest"`
			}{"bin/" + b, dig})
		}
		a.Predicate.Version, a.Predicate.BuiltFrom = "0.1.0", "test"
		a.Predicate.SBOM.Path, a.Predicate.SBOM.SHA256 = "docs/sbom/sbom.cdx.json", hexOf(files["docs/sbom/sbom.cdx.json"])
		a.Predicate.Licenses.Path, a.Predicate.Licenses.SHA256 = "docs/sbom/licenses.json", hexOf(files["docs/sbom/licenses.json"])
		a.Predicate.Note = "test"
		if mut != nil {
			mut(&a)
		}
		files[AttestationName], _ = json.Marshal(a)
	})
}
