package provision

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/diskfs/go-diskfs/backend/file"
	"github.com/diskfs/go-diskfs/filesystem/iso9660"
)

const testKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGg4Zgd2sQ0v9i6Y0bq7n3m9c1m3k3Qm8iH6m3f3b2yd"

func specForTest(t *testing.T) Spec {
	t.Helper()
	k, err := NormalizeSSHKey(testKey)
	if err != nil {
		t.Fatalf("test key: %v", err)
	}
	return Spec{Name: "web-1", UUID: "11111111-2222-4333-8444-555555555555", Fingerprint: strings.Repeat("ab", 32), VCPUs: 2, MemoryMiB: 1024,
		ImageID: "debian-13", ImageSHA256: strings.Repeat("cd", 32), DiskGiB: 20, SSHPublicKey: k.Authorized, Network: "svavyom-nat"}
}

func TestSeedIsANoCloudISOWithTheServerOwnedFiles(t *testing.T) {
	s := specForTest(t)
	dir := t.TempDir()
	iso, err := BuildSeed(s, dir)
	if err != nil {
		t.Fatal(err)
	}
	if left, _ := os.ReadDir(dir); len(left) != 0 {
		t.Fatalf("scratch files left behind: %v", left)
	}
	if len(iso) == 0 || len(iso) > SeedCapacityBytes {
		t.Fatalf("size %d", len(iso))
	}
	if !bytes.Contains(iso[0x8000:0x8800], []byte("CD001")) {
		t.Fatal("no ISO 9660 primary volume descriptor")
	}
	if !bytes.Contains(iso[0x8000:0x8800], []byte("cidata")) && !bytes.Contains(iso[0x8000:0x8800], []byte("CIDATA")) {
		t.Fatal("volume label is not cidata")
	}
	// Read it back through the library the way a guest would see the files.
	p := filepath.Join(dir, "rb.iso")
	if err := os.WriteFile(p, iso, 0o600); err != nil {
		t.Fatal(err)
	}
	b, err := file.OpenFromPath(p, true)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	fs, err := iso9660.Read(b, int64(len(iso)), 0, 2048)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimRight(fs.Label(), " \x00"); got != "cidata" {
		t.Fatalf("label %q", got)
	}
	if !bytes.Equal(iso[0x8000+40:0x8000+72], []byte("cidata"+strings.Repeat(" ", 26))) {
		t.Fatalf("volume identifier is not space padded: %q", iso[0x8000+40:0x8000+72])
	}
	ud, err := fs.ReadFile("user-data")
	if err != nil {
		t.Fatalf("user-data: %v", err)
	}
	md, err := fs.ReadFile("meta-data")
	if err != nil {
		t.Fatalf("meta-data: %v", err)
	}
	wantUD, _ := UserData(s)
	wantMD, _ := MetaData(s)
	if string(ud) != wantUD || string(md) != wantMD {
		t.Fatalf("content differs:\n%q\n%q", ud, md)
	}
	entries, _ := fs.ReadDir(".")
	if len(entries) != 2 {
		t.Fatalf("seed must hold exactly two files, got %d", len(entries))
	}
}

func TestSeedRefusesAnInvalidSpec(t *testing.T) {
	s := specForTest(t)
	s.Name = "Bad Name"
	if _, err := BuildSeed(s, t.TempDir()); err == nil {
		t.Fatal("invalid spec accepted")
	}
	if _, err := BuildSeed(specForTest(t), filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("missing scratch dir accepted")
	}
}

func TestCloudConfigIsAFixedTemplate(t *testing.T) {
	s := specForTest(t)
	ud, _ := UserData(s)
	for _, must := range []string{"#cloud-config\n", "ssh_pwauth: false", "disable_root: true", "hostname: \"web-1\"", s.SSHPublicKey} {
		if !strings.Contains(ud, must) {
			t.Errorf("user-data lacks %q:\n%s", must, ud)
		}
	}
	for _, forbidden := range []string{"runcmd", "bootcmd", "packages", "write_files", "users:", "chpasswd", "password", "sudo", "ssh_import_id"} {
		if strings.Contains(ud, forbidden) {
			t.Errorf("user-data contains %q:\n%s", forbidden, ud)
		}
	}
	md, _ := MetaData(s)
	if md != "instance-id: "+s.UUID+"\nlocal-hostname: web-1\n" {
		t.Fatalf("%q", md)
	}
	// Two different VMs never share an instance id.
	other := s
	other.UUID = "21111111-2222-4333-8444-555555555555"
	md2, _ := MetaData(other)
	if md == md2 {
		t.Fatal("instance ids collide")
	}
}
