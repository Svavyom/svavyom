package provision

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

func authorized(t *testing.T, pub any) string {
	t.Helper()
	k, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return string(ssh.MarshalAuthorizedKey(k))
}

func TestSSHKeyAcceptsModernKeysAndNormalises(t *testing.T) {
	edPub, edPriv, _ := ed25519.GenerateKey(rand.Reader)
	ec256, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ec384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	rsa3072, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		t.Fatal(err)
	}
	for name, pub := range map[string]any{"ed25519": edPub, "ecdsa-p256": &ec256.PublicKey, "ecdsa-p384": &ec384.PublicKey, "rsa-3072": &rsa3072.PublicKey} {
		raw := authorized(t, pub)
		withComment := strings.TrimSpace(raw) + " admin@laptop with spaces\n"
		for _, in := range []string{raw, withComment, "  " + strings.TrimSpace(raw) + "  \r\n"} {
			k, err := NormalizeSSHKey(in)
			if err != nil {
				t.Fatalf("%s %q: %v", name, in, err)
			}
			if k.Authorized != strings.TrimSpace(strings.SplitN(strings.TrimSpace(raw), "\n", 2)[0]) || strings.Count(k.Authorized, " ") != 1 || !strings.HasPrefix(k.Fingerprint, "SHA256:") {
				t.Fatalf("%s: not normalised: %+v", name, k)
			}
		}
	}
	_ = edPriv
}

func TestSSHKeyRejections(t *testing.T) {
	edPub, edPriv, _ := ed25519.GenerateKey(rand.Reader)
	good := strings.TrimSpace(authorized(t, edPub))
	edPub2, _, _ := ed25519.GenerateKey(rand.Reader)
	good2 := strings.TrimSpace(authorized(t, edPub2))
	rsa2048, _ := rsa.GenerateKey(rand.Reader, 2048)
	der, _ := x509.MarshalPKCS8PrivateKey(edPriv)
	privPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	openssh, _ := ssh.MarshalPrivateKey(edPriv, "")
	cases := map[string]string{
		"empty":                     "",
		"whitespace":                "   \n",
		"garbage":                   "not a key",
		"type only":                 "ssh-ed25519",
		"bad base64":                "ssh-ed25519 !!!!",
		"truncated blob":            good[:len(good)-12],
		"two keys on two lines":     good + "\n" + good2,
		"two keys on one line":      good + " " + good2,
		"trailing second key":       good + "\n" + good2 + "\n",
		"option command":            `command="rm -rf /" ` + good,
		"option from":               `from="10.0.0.1" ` + good,
		"option no-pty":             "no-pty " + good,
		"rsa 2048":                  authorized(t, &rsa2048.PublicKey),
		"pkcs8 private pem":         privPEM,
		"openssh private":           string(pem.EncodeToMemory(openssh)),
		"private marker in comment": good + " -----BEGIN OPENSSH PRIVATE KEY-----",
		"dsa":                       "ssh-dss AAAAB3NzaC1kc3MAAACBAP1/U4EddRIpUt9KnC7s5Of2EbdSPO9EAMMeP4C2USZpRV1AIlH7WT2NWPq/xfW6MPbLm1Vs14E7gB00b/JmYLdrmVClpJ+f6AR7ECLCT7up1/63xhv4O1fnxqimFQ8E+4P208UewwI1VBNaFpEy9nXzrith1yrv8iIDGZ3RSAHHAAAAFQCXYFCPFSMLzLKSuYKi64QL8Fgc9QAAAIEA9+GghdabPd7LvKtcNrhXuXmUr7v6OuqC+VdMCz0HgmdRWVeOutRZT+ZxBxCBgLRJFnEj6EwoFhO3zwkyjMim4TwWeotUfI0o4KOuHiuzpnWRbqN/C/ohNWLx+2J6ASQ7zKTxvqhRkImog9/hWuWfBpKLZl6Ae1UlZAFMO/7PSSoAAACBAJ6hqbY4rsEmBUrOCLDfaS3LDnN4bnb8tvRUzaL1u7Mk0MOMlc/Z1mHBLmMtBt0P3V6n0cZ4UbTw8kbQh0YlX7bnCsGH0ZNqHk4Wq0+0uJ0nDfr0yWv8k5D9kZ3tQQ1pZ6Q4vKXk+0sKcOQa3iM0hSmhVB1cT0gO6mXjGH admin",
		"sk key":                    "sk-ssh-ed25519@openssh.com AAAAGnNrLXNzaC1lZDI1NTE5QG9wZW5zc2guY29tAAAAIGg4Zgd2sQ0v9i6Y0bq7n3m9c1m3k3Qm8iH6m3f3b2ydAAAABHNzaDo=",
		"oversized":                 good + " " + strings.Repeat("a", MaxSSHKeyInput),
		"nul byte":                  good[:20] + "\x00" + good[20:],
		"non ascii comment":         good + " éé",
		"control char":              good + " \x07",
		"cr injection":              good + "\rssh-rsa AAAA",
		"yaml breakout comment":     good + "\n  - injected",
	}
	for name, in := range cases {
		if k, err := NormalizeSSHKey(in); err == nil {
			t.Errorf("%s accepted: %+v", name, k)
		}
	}
	// The normalised form is a fixed point and cannot carry a newline, quote or comment.
	k, _ := NormalizeSSHKey(good + " c")
	again, err := NormalizeSSHKey(k.Authorized)
	if err != nil || again != k || strings.ContainsAny(k.Authorized, "\n\"'\\") {
		t.Fatalf("%+v %+v %v", k, again, err)
	}
	_ = base64.StdEncoding
}

func TestSpecValidationRejectsInjection(t *testing.T) {
	base := specForTest(t)
	if err := base.Validate(); err != nil {
		t.Fatal(err)
	}
	mut := map[string]func(*Spec){
		"name quote":      func(s *Spec) { s.Name = "a'b" },
		"name markup":     func(s *Spec) { s.Name = "a></name><x" },
		"name upper":      func(s *Spec) { s.Name = "Web" },
		"name dot":        func(s *Spec) { s.Name = "a.b" },
		"name trailing -": func(s *Spec) { s.Name = "web-" },
		"name long":       func(s *Spec) { s.Name = "a" + strings.Repeat("b", 63) },
		"uuid v1":         func(s *Spec) { s.UUID = "11111111-2222-1333-8444-555555555555" },
		"uuid caps":       func(s *Spec) { s.UUID = "11111111-2222-4333-8444-55555555555A" },
		"fp short":        func(s *Spec) { s.Fingerprint = "abc" },
		"image path":      func(s *Spec) { s.ImageID = "../etc/passwd" },
		"image sha bad":   func(s *Spec) { s.ImageSHA256 = "xyz" },
		"vcpus 3":         func(s *Spec) { s.VCPUs = 3 },
		"vcpus 64":        func(s *Spec) { s.VCPUs = 64 },
		"mem odd":         func(s *Spec) { s.MemoryMiB = 1000 },
		"disk 1":          func(s *Spec) { s.DiskGiB = 1 },
		"network xml":     func(s *Spec) { s.Network = "n'/><x" },
		"key unnormal":    func(s *Spec) { s.SSHPublicKey = s.SSHPublicKey + " comment" },
		"key empty":       func(s *Spec) { s.SSHPublicKey = "" },
	}
	for name, f := range mut {
		s := base
		f(&s)
		if s.Validate() == nil {
			t.Errorf("%s accepted", name)
		}
		cfg := Config{CatalogDir: "/c", Pool: "p", Network: "n", DomainType: "test", LibvirtURI: "test:///default", StateDir: "/s"}
		if _, err := DomainXML(cfg, s, backingForTest(cfg, s), rootForTest(s)); err == nil {
			t.Errorf("%s: DomainXML rendered an invalid spec", name)
		}
	}
}

func TestChoicesAreNarrowedByHostCapacity(t *testing.T) {
	o := Choices(2, 4096)
	if len(o.VCPUs) != 2 || o.VCPUs[len(o.VCPUs)-1] != 2 {
		t.Fatalf("%v", o.VCPUs)
	}
	for _, m := range o.MemoryMiB {
		if m > 3072 {
			t.Fatalf("memory %d exceeds three quarters of the host", m)
		}
	}
	if o := Choices(0, 0); len(o.VCPUs) != 1 || len(o.MemoryMiB) != 0 {
		t.Fatalf("unknown capacity: %+v", o)
	}
	if d := DiskChoicesFor(30, Choices(8, 65536).DiskGiB); d[0] < 30 {
		t.Fatalf("%v", d)
	}
}

func TestDerivedNamesAndMAC(t *testing.T) {
	u := "11111111-2222-4333-8444-555555555555"
	if RootVolumeName(u) != "svavyom-"+u+"-root.qcow2" || SeedVolumeName(u) != "svavyom-"+u+"-seed.iso" {
		t.Fatal("names")
	}
	m := MAC(u)
	if len(m) != 17 || !strings.HasPrefix(m, "52:54:00:") || m != MAC(u) || m == MAC("21111111-2222-4333-8444-555555555555") {
		t.Fatalf("mac %q", m)
	}
}
