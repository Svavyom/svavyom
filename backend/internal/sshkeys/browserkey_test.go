package sshkeys

import (
	"bytes"
	"os"
	"testing"

	"golang.org/x/crypto/ssh"
)

// The key file the browser makes (frontend/src/product/keygen.ts) is pinned by a golden file; here an independent implementation of the OpenSSH key format
// (golang.org/x/crypto/ssh) must read it, and the public key it derives must be the public line the page shows, which the library accepts.
func TestTheBrowserMadeKeyFileIsAValidOpenSSHKeyWhosePublicHalfTheLibraryAccepts(t *testing.T) {
	body, err := os.ReadFile("testdata/browser-generated.b64") // the armour is added here so that no private-key armour is committed
	if err != nil {
		t.Fatal(err)
	}
	priv := []byte("-----BEGIN OPENSSH " + "PRIVATE KEY-----\n" + string(body) + "-----END OPENSSH " + "PRIVATE KEY-----\n")
	signer, err := ssh.ParsePrivateKey(priv)
	if err != nil {
		t.Fatalf("x/crypto/ssh cannot read the browser's key file: %v", err)
	}
	line, err := os.ReadFile("testdata/browser-generated.pub")
	if err != nil {
		t.Fatal(err)
	}
	want, comment, _, _, err := ssh.ParseAuthorizedKey(line)
	if err != nil || comment != "golden@svavyom" {
		t.Fatalf("public line: %v %q", err, comment)
	}
	if !bytes.Equal(signer.PublicKey().Marshal(), want.Marshal()) {
		t.Fatal("the public key inside the private file is not the public line the page shows")
	}
	// and the library saves that line
	s, ctx := open(t), t.Context()
	k, err := s.Add(ctx, "alice", "from the browser", string(line))
	if err != nil || k.Fingerprint != ssh.FingerprintSHA256(signer.PublicKey()) || k.Type != "ed25519" {
		t.Fatalf("add: %+v %v", k, err)
	}
	// a signature made with the private key verifies against the saved public key (the key really works)
	sig, err := signer.Sign(nil, []byte("x"))
	if err != nil {
		t.Fatal(err)
	}
	saved, _, _, _, _ := ssh.ParseAuthorizedKey([]byte(k.PublicKey))
	if err := saved.Verify([]byte("x"), sig); err != nil {
		t.Fatalf("signature: %v", err)
	}
}
