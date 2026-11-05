package ctl

import (
	"bytes"
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func runInstall(t *testing.T, h *testHost, listen string, o InstallOptions) (string, error) {
	t.Helper()
	o.Apply, o.Listen = true, listen
	var out bytes.Buffer
	err := Install(context.Background(), h.env, o, &out)
	return out.String(), err
}

// An artifact that nobody vouches for is refused, and nothing on the host changes (finding F-02, M0-E01-S13): a manifest inside the artifact authenticates nothing.
func TestAnUnauthenticatedArtifactIsRefusedByDefault(t *testing.T) {
	h, listen := serverHost(t)
	art := makeArtifact(t, "0.1.0", curSchema, nil)
	before := snapshotTree(t, h.root)
	out, err := runInstall(t, h, listen, InstallOptions{Artifact: art})
	if err == nil || !strings.Contains(err.Error(), "not authenticated") || !strings.Contains(err.Error(), "--allow-unsigned") {
		t.Fatalf("an unsigned artifact must be refused with the way out: %v\n%s", err, out)
	}
	if got := snapshotTree(t, h.root); got != before {
		t.Fatal("a refused install changed the host")
	}
	var up bytes.Buffer
	if err := Upgrade(context.Background(), h.env, UpgradeOptions{InstallOptions: InstallOptions{Artifact: art, Apply: true, Listen: listen}}, &up); err == nil || !strings.Contains(err.Error(), "not authenticated") {
		t.Fatalf("upgrade must refuse it too: %v", err)
	}
}

// A signed artifact installs wherever it is (the signature, not the directory, is what is trusted), and says so.
func TestASignedArtifactInstallsEvenWhereOthersCanWrite(t *testing.T) {
	h, listen := serverHost(t)
	h.env.OwnerOf = func(fs.FileInfo) (int, bool) { return 1000, true } // the artifact is in somebody's home: not root's
	f := signedArtifact(t, nil)
	out, err := runInstall(t, h, listen, InstallOptions{Artifact: f.art, Signatures: f.sigs, PublicKey: f.pub})
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if !strings.Contains(out, "signature: valid (ed25519") {
		t.Fatalf("the output must say the signature was checked: %s", out)
	}
	if _, err := os.Stat(filepath.Join(h.root, LibexecDir, "api")); err != nil {
		t.Fatalf("the binaries were not installed: %v", err)
	}
}

func TestASignedArtifactWithAChangedFileOrAnotherKeyIsRefused(t *testing.T) {
	h, listen := serverHost(t)
	f := signedArtifact(t, nil)
	if err := os.WriteFile(filepath.Join(f.art, "web/index.html"), []byte("<html>changed after signing</html>"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := runInstall(t, h, listen, InstallOptions{Artifact: f.art, Signatures: f.sigs, PublicKey: f.pub}); err == nil {
		t.Fatal("a file changed after signing was installed")
	}
	g := signedArtifact(t, nil)
	if _, err := runInstall(t, h, listen, InstallOptions{Artifact: g.art, Signatures: g.sigs, PublicKey: f.pub}); err == nil { // f's key, g's signatures
		t.Fatal("another key's public half verified these signatures")
	}
	if _, err := os.Stat(filepath.Join(h.root, LibexecDir, "api")); err == nil {
		t.Fatal("something was installed from a refused artifact")
	}
	if _, err := runInstall(t, h, listen, InstallOptions{Artifact: g.art, Signatures: g.sigs}); err == nil {
		t.Fatal("--signatures without --public-key was accepted")
	}
}

// Without a signature the only protection is where the artifact sits: every directory above it and every file in it must be root's and not writable by group or others.
func TestAnUnsignedArtifactMustSitWhereOnlyRootCanChangeIt(t *testing.T) {
	h, listen := serverHost(t)
	art := makeArtifact(t, "0.1.0", curSchema, nil)

	h.env.OwnerOf = func(fs.FileInfo) (int, bool) { return 1000, true }
	if _, err := runInstall(t, h, listen, InstallOptions{Artifact: art, AllowUnsigned: true}); err == nil || !strings.Contains(err.Error(), "is not owned by root") || !strings.Contains(err.Error(), "sudo cp -a") {
		t.Fatalf("an artifact owned by an ordinary user: %v", err)
	}
	h.env.OwnerOf = func(fs.FileInfo) (int, bool) { return 0, true }

	// a file inside that group or others can write
	if err := os.Chmod(filepath.Join(art, "web/index.html"), 0o666); err != nil {
		t.Fatal(err)
	}
	if _, err := runInstall(t, h, listen, InstallOptions{Artifact: art, AllowUnsigned: true}); err == nil || !strings.Contains(err.Error(), "can be written by group or others") {
		t.Fatalf("a writable file inside the artifact: %v", err)
	}
	if err := os.Chmod(filepath.Join(art, "web/index.html"), 0o644); err != nil {
		t.Fatal(err)
	}
	// the directory itself
	if err := os.Chmod(art, 0o777); err != nil {
		t.Fatal(err)
	}
	if _, err := runInstall(t, h, listen, InstallOptions{Artifact: art, AllowUnsigned: true}); err == nil || !strings.Contains(err.Error(), "can be written by group or others") {
		t.Fatalf("a writable artifact directory: %v", err)
	}
	if err := os.Chmod(art, 0o755); err != nil {
		t.Fatal(err)
	}
	// a place only root can change: accepted, with a loud warning
	out, err := runInstall(t, h, listen, InstallOptions{Artifact: art, AllowUnsigned: true})
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if !strings.Contains(out, "WARNING: --allow-unsigned") {
		t.Fatalf("it must say the artifact is not authenticated: %s", out)
	}
}

// The reviewer's reproduction: a binary rewritten after the artifact was verified (while the host preflight runs) used to be installed into /usr/libexec as root. Now every
// file is read once and hashed against the manifest at the moment it is used, so the swap is refused and nothing is installed from it.
func TestAFileSwappedAfterVerificationIsNotInstalled(t *testing.T) {
	h, listen := serverHost(t)
	art := makeArtifact(t, "0.1.0", curSchema, nil)
	swapped := false
	h.run.hook = func(string) {
		if !swapped {
			swapped = true
			_ = os.WriteFile(filepath.Join(art, "bin/api"), []byte("#!/bin/sh\necho evil\n"), 0o755)
		}
	}
	out, err := runInstall(t, h, listen, InstallOptions{Artifact: art, AllowUnsigned: true})
	if !swapped {
		t.Fatal("the swap hook never ran: the test proves nothing")
	}
	if err == nil || !strings.Contains(err.Error(), "changed after it was verified") {
		t.Fatalf("the swapped binary must be refused: %v\n%s", err, out)
	}
	if b, rerr := os.ReadFile(filepath.Join(h.root, LibexecDir, "api")); rerr == nil && bytes.Contains(b, []byte("evil")) {
		t.Fatal("the swapped binary was installed")
	}
	// control: the same change BEFORE verification is refused by the verification itself
	art2 := makeArtifact(t, "0.1.0", curSchema, nil)
	_ = os.WriteFile(filepath.Join(art2, "bin/api"), []byte("#!/bin/sh\necho evil\n"), 0o755)
	if _, err := runInstall(t, h, listen, InstallOptions{Artifact: art2, AllowUnsigned: true}); err == nil || !errors.Is(err, errBadArtf) {
		t.Fatalf("tampering before verification: %v", err)
	}
}

func TestTheTrustedReaderRefusesWhatTheManifestDoesNotList(t *testing.T) {
	art := makeArtifact(t, "0.1.0", curSchema, nil)
	m, err := VerifyArtifact(art)
	if err != nil {
		t.Fatal(err)
	}
	ta := newTrusted(art, m)
	if _, err := ta.read("bin/api"); err != nil {
		t.Fatal(err)
	}
	if _, err := ta.read("not/listed"); err == nil {
		t.Fatal("an unlisted file was read")
	}
	if _, err := ta.read("../etc/passwd"); err == nil {
		t.Fatal("a path outside the artifact was read")
	}
}

// The manifest the signature covers is the manifest that is parsed: the digest signed over (ed25519: the bytes verified from memory) equals the digest of the parse.
func TestTheSignedManifestDigestIsTheParsedManifestDigest(t *testing.T) {
	h := newHost(t)
	f := signedArtifact(t, nil)
	res, err := VerifySignatures(context.Background(), h.env, f.art, SignatureOptions{Dir: f.sigs, PublicKey: f.pub})
	if err != nil {
		t.Fatal(err)
	}
	_, digest, err := VerifyArtifactDigest(f.art)
	if err != nil || res.ManifestSHA256 == "" || res.ManifestSHA256 != digest {
		t.Fatalf("signed %q, parsed %q, %v", res.ManifestSHA256, digest, err)
	}
}
