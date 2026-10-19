package provision

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"example.invalid/dedicatedcloud/backend/internal/provision/provtest"
)

func isoReq(src string) RegisterRequest {
	return RegisterRequest{ID: "alpine-iso", DisplayName: "Alpine installer", Distribution: "Alpine", Version: "3.20", Source: src, MinDiskGiB: 2, Media: MediaISO}
}

func TestRegisterAnISOKeepsItVerifiedByDigestAndImmutable(t *testing.T) {
	dir := catalogDir(t)
	im, err := Register(DevPolicy(), dir, isoReq(source(t, "alpine.iso", provtest.ISO("a"))))
	if err != nil {
		t.Fatal(err)
	}
	if !im.IsISO() || im.Format != "iso" || im.File != im.SHA256+".iso" || im.State != StateVerified || im.CloudInit || im.LoginUser != "" {
		t.Fatalf("%+v", im)
	}
	fi, err := os.Stat(storeFile(dir, im))
	if err != nil || fi.Mode().Perm() != 0o444 {
		t.Fatalf("the media is stored read-only: %v %v", fi, err)
	}
	cat, err := LoadTrustedCatalog(DevPolicy(), dir)
	if err != nil {
		t.Fatal(err)
	}
	got, err := cat.Usable("alpine-iso")
	if err != nil || !got.IsISO() {
		t.Fatalf("an ISO is usable once registered: %v", err)
	}
	// the digest is checked again before use, and a changed file is refused
	if _, err := cat.Verify(got); err != nil {
		t.Fatal(err)
	}
	p, _ := cat.Path(got)
	_ = os.Chmod(p, 0o644)
	_ = os.WriteFile(p, provtest.ISO("tampered"), 0o444)
	if _, err := cat.Verify(got); err == nil {
		t.Fatal("a changed ISO must not verify")
	}
}

func TestRegisterAnISORefusesWhatIsNotOne(t *testing.T) {
	dir := catalogDir(t)
	cases := map[string]RegisterRequest{
		"a qcow2 file":     isoReq(source(t, "disk.iso", provtest.Qcow2("x"))),
		"a truncated file": isoReq(source(t, "short.iso", []byte("CD001"))),
		"cloud-init asserted": func() RegisterRequest {
			r := isoReq(source(t, "a.iso", provtest.ISO("b")))
			r.CloudInit = true
			return r
		}(),
		"a login user": func() RegisterRequest {
			r := isoReq(source(t, "b.iso", provtest.ISO("c")))
			r.LoginUser = "root"
			return r
		}(),
		"an unknown media": func() RegisterRequest {
			r := isoReq(source(t, "c.iso", provtest.ISO("d")))
			r.Media = "floppy"
			return r
		}(),
	}
	for name, r := range cases {
		if _, err := Register(DevPolicy(), dir, r); err == nil {
			t.Errorf("%s must be refused", name)
		}
	}
	// and a cloud image is not accepted as media of the other kind
	if _, err := Register(DevPolicy(), dir, RegisterRequest{ID: "d1", DisplayName: "D", Distribution: "Debian", Version: "13", Source: source(t, "x.qcow2", provtest.ISO("e")), LoginUser: "debian", MinDiskGiB: 3, CloudInit: true}); err == nil {
		t.Error("an ISO is not a cloud image")
	}
}

func TestAnISOCannotBeQualifiedOrRemoved(t *testing.T) {
	dir := catalogDir(t)
	im, err := Register(DevPolicy(), dir, isoReq(source(t, "alpine.iso", provtest.ISO("a"))))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := SetState(DevPolicy(), dir, im.ID, StateQualified, "qr-20261011-5e5e5e"); err == nil {
		t.Fatal("installation media is never real-host qualified")
	}
	if _, err := SetState(DevPolicy(), dir, im.ID, StateDisabled, ""); err != nil {
		t.Fatal(err)
	}
	cat, _ := LoadCatalog(dir)
	got, _ := cat.Get(im.ID)
	if _, err := ImageReferences(cat, got, filepath.Join(t.TempDir(), "pool"), nil); err != ErrImageAmbiguous {
		t.Fatalf("an ISO's removal is not offered: %v", err)
	}
}

func TestISODomainDefinitionHasTheMediaFirstAndNoSeed(t *testing.T) {
	cfg := Config{CatalogDir: "/var/lib/svavyom/images", Pool: "svavyom", Network: "svavyom-nat", DomainType: "test", LibvirtURI: "test:///default", StateDir: "/var/lib/svavyom/state"}
	sum := strings.Repeat("ab", 32)
	s := Spec{Name: "inst-1", UUID: "11111111-2222-4333-8444-555555555555", Fingerprint: strings.Repeat("cd", 32), VCPUs: 2, MemoryMiB: 1024, ImageID: "alpine-iso", ImageSHA256: sum, DiskGiB: 20, Network: "svavyom-nat", Media: MediaISO}
	root := VolumeSource{Name: RootVolumeName(s.UUID), Path: "/var/lib/svavyom/pool/" + RootVolumeName(s.UUID), PoolPath: "/var/lib/svavyom/pool"}
	iso := ISOImage{Path: "/var/lib/svavyom/images/store/" + sum + ".iso", SHA256: sum}
	x, err := DomainXMLISO(cfg, s, iso, root)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"media='iso'", "<boot order='1'/>", "<boot order='2'/>", "relabel='no'", iso.Path, root.Path} {
		if !strings.Contains(x, want) {
			t.Errorf("the definition lacks %q:\n%s", want, x)
		}
	}
	if strings.Contains(x, "seed") || strings.Contains(x, "<boot dev=") {
		t.Errorf("no seed, and boot order is per device:\n%s", x)
	}
	pd, err := ParseDomain(x)
	if err != nil || !pd.Managed || pd.Media != MediaISO || pd.ISO != sum || pd.Root != root.Name || pd.Seed != "" {
		t.Fatalf("%+v %v", pd, err)
	}
	if err := CheckDomainRootSource(x, root); err != nil {
		t.Fatalf("the ownership proof of the root tolerates the media: %v", err)
	}
	if sha, path, dev, ok := ISODisk(x); !ok || sha != sum || path != iso.Path || dev != "sda" {
		t.Fatalf("%s %s %s %v", sha, path, dev, ok)
	}
	// a key, another path or another digest is refused
	bad := s
	bad.SSHPublicKey = "ssh-ed25519 AAAA"
	if _, err := DomainXMLISO(cfg, bad, iso, root); err == nil {
		t.Error("an ISO install takes no key")
	}
	if _, err := DomainXMLISO(cfg, s, ISOImage{Path: "/tmp/x.iso", SHA256: sum}, root); err == nil {
		t.Error("the media must be the store file of the recorded digest")
	}
}

func TestISOHeaderCheck(t *testing.T) {
	if checkISOHeader(provtest.ISO("x")[:32774]) != nil {
		t.Fatal("a valid descriptor")
	}
	if checkISOHeader(make([]byte, 32774)) == nil || checkISOHeader([]byte("CD001")) == nil {
		t.Fatal("anything else is refused")
	}
}
