package provision

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"example.invalid/dedicatedcloud/backend/internal/provision/provtest"
)

func qcow2Bytes(extra string) []byte { return provtest.Qcow2(extra) }

func catalogDir(t *testing.T) string {
	t.Helper()
	d := filepath.Join(t.TempDir(), "images")
	if err := os.Mkdir(d, 0o750); err != nil {
		t.Fatal(err)
	}
	return d
}

// source writes an operator's source file outside the catalog and returns its path.
func source(t *testing.T, name string, b []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, b, 0o640); err != nil {
		t.Fatal(err)
	}
	return p
}

func reg(src string) RegisterRequest {
	return RegisterRequest{ID: "debian-13", DisplayName: "Debian 13 (cloud)", Distribution: "Debian", Version: "13", Source: src, LoginUser: "debian", MinDiskGiB: 3, CloudInit: true}
}

func storeFile(dir string, im Image) string { return filepath.Join(dir, StoreDir, im.File) }

func TestRegisterImportsIntoTheManagedImmutableStore(t *testing.T) {
	dir := catalogDir(t)
	src := source(t, "debian-13.qcow2", qcow2Bytes("payload"))
	im, err := Register(DevPolicy(), dir, reg(src))
	if err != nil {
		t.Fatal(err)
	}
	if im.SizeBytes != int64(len(qcow2Bytes("payload"))) || !im.CloudInit || im.Architecture != "x86_64" || im.LoginUser != "debian" || im.State != StateVerified {
		t.Fatalf("%+v", im)
	}
	if im.File != im.SHA256+".qcow2" {
		t.Fatalf("the published name must be the content hash: %q", im.File)
	}
	fi, err := os.Lstat(storeFile(dir, im))
	if err != nil || !fi.Mode().IsRegular() || fi.Mode().Perm() != 0o444 {
		t.Fatalf("the published image must be a regular read-only file: %v %v", fi, err)
	}
	if fi, _ := os.Stat(filepath.Join(dir, CatalogFile)); fi.Mode().Perm() != 0o644 {
		t.Fatalf("catalog mode %v", fi.Mode().Perm())
	}
	ents, _ := os.ReadDir(filepath.Join(dir, StoreDir))
	for _, e := range ents {
		if strings.HasPrefix(e.Name(), ".import-") {
			t.Fatalf("a temporary import file was left behind: %s", e.Name())
		}
	}
	cat, err := LoadTrustedCatalog(DevPolicy(), dir)
	if err != nil {
		t.Fatal(err)
	}
	got, err := cat.Usable("debian-13")
	if err != nil || got != im {
		t.Fatalf("%+v %v", got, err)
	}
	if _, err := cat.Verify(got); err != nil {
		t.Fatal(err)
	}
	if _, err := Register(DevPolicy(), dir, reg(src)); err == nil {
		t.Fatal("duplicate id accepted")
	}
}

func TestTheSourceIsNeverReferencedAfterImport(t *testing.T) {
	dir := catalogDir(t)
	src := source(t, "a.qcow2", qcow2Bytes("original"))
	im, err := Register(DevPolicy(), dir, reg(src))
	if err != nil {
		t.Fatal(err)
	}
	cat, _ := LoadTrustedCatalog(DevPolicy(), dir)
	if err := os.WriteFile(src, qcow2Bytes("replaced after import"), 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := cat.Verify(im); err != nil {
		t.Fatalf("replacing the source changed the managed image: %v", err)
	}
	if err := os.Remove(src); err != nil {
		t.Fatal(err)
	}
	if _, err := cat.Verify(im); err != nil {
		t.Fatalf("removing the source broke the managed image: %v", err)
	}
	// The same bytes registered under another id reuse the one stored file.
	r := reg(source(t, "b.qcow2", qcow2Bytes("original")))
	r.ID = "debian-13-b"
	im2, err := Register(DevPolicy(), dir, r)
	if err != nil || im2.File != im.File {
		t.Fatalf("%+v %v", im2, err)
	}
}

func TestRegisterRefusesUnsafeOrUnsupportedSources(t *testing.T) {
	dir := catalogDir(t)
	outside := t.TempDir()
	good := source(t, "good.qcow2", qcow2Bytes("x"))
	link := filepath.Join(outside, "link.qcow2")
	if err := os.Symlink(good, link); err != nil {
		t.Fatal(err)
	}
	header := func(mut func(h []byte)) []byte {
		h := qcow2Bytes("x")
		mut(h)
		return h
	}
	cases := map[string]string{
		"symlink":          link,
		"relative":         "good.qcow2",
		"traversal":        outside + "/../x.qcow2",
		"missing":          filepath.Join(outside, "none.qcow2"),
		"directory":        outside,
		"raw disk":         source(t, "raw.img", []byte("raw disk bytes, not qcow2 at all, long enough to read a header from.................")),
		"truncated":        source(t, "short.qcow2", []byte{'Q', 'F', 'I', 0xfb, 0, 0, 0, 3}),
		"empty":            source(t, "empty.qcow2", nil),
		"qcow2 version 1":  source(t, "v1.qcow2", header(func(h []byte) { binary.BigEndian.PutUint32(h[4:], 1) })),
		"has backing file": source(t, "bf.qcow2", header(func(h []byte) { binary.BigEndian.PutUint64(h[8:], 4096); binary.BigEndian.PutUint32(h[16:], 12) })),
		"encrypted":        source(t, "enc.qcow2", header(func(h []byte) { binary.BigEndian.PutUint32(h[32:], 1) })),
		"zero size":        source(t, "zero.qcow2", header(func(h []byte) { binary.BigEndian.PutUint64(h[24:], 0) })),
		"bad cluster":      source(t, "cl.qcow2", header(func(h []byte) { binary.BigEndian.PutUint32(h[20:], 40) })),
	}
	for name, src := range cases {
		if im, err := Register(DevPolicy(), dir, reg(src)); err == nil {
			t.Errorf("%s accepted: %+v", name, im)
		}
	}
	bad := reg(good)
	for name, mut := range map[string]func(*RegisterRequest){
		"id caps": func(r *RegisterRequest) { r.ID = "Debian" }, "id path": func(r *RegisterRequest) { r.ID = "../x" },
		"user root-ish": func(r *RegisterRequest) { r.LoginUser = "Root!" }, "user empty": func(r *RegisterRequest) { r.LoginUser = "" },
		"min disk 0": func(r *RegisterRequest) { r.MinDiskGiB = 0 }, "name markup": func(r *RegisterRequest) { r.DisplayName = "<b>x</b>" },
	} {
		r := bad
		mut(&r)
		if _, err := Register(DevPolicy(), dir, r); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	if cat, _ := LoadTrustedCatalog(DevPolicy(), dir); len(cat.Images) != 0 {
		t.Fatal("a refused registration changed the catalog")
	}
	if ents, _ := os.ReadDir(filepath.Join(dir, StoreDir)); len(ents) != 0 {
		t.Fatalf("a refused registration left files in the store: %d", len(ents))
	}
}

func TestAPartiallyImportedImageIsNeverPublishedOrUsed(t *testing.T) {
	dir := catalogDir(t)
	store := filepath.Join(dir, StoreDir)
	if err := os.Mkdir(store, 0o755); err != nil {
		t.Fatal(err)
	}
	// A crash mid-copy leaves a temporary file: it has no valid published name, no catalog entry, and cannot be verified.
	stray := filepath.Join(store, ".import-123")
	if err := os.WriteFile(stray, qcow2Bytes("half"), 0o600); err != nil {
		t.Fatal(err)
	}
	im, err := Register(DevPolicy(), dir, reg(source(t, "a.qcow2", qcow2Bytes("whole image"))))
	if err != nil {
		t.Fatal(err)
	}
	cat, _ := LoadTrustedCatalog(DevPolicy(), dir)
	for _, c := range cat.Images {
		if strings.HasPrefix(c.File, ".") {
			t.Fatal("a temporary file is referenced by the catalog")
		}
	}
	fake := im
	fake.File = ".import-123"
	if _, err := cat.Verify(fake); err == nil {
		t.Fatal("a temporary import file was accepted as an image")
	}
	// A published file shorter than recorded (a partially written image) fails the size/hash check.
	_ = os.Chmod(storeFile(dir, im), 0o644)
	if err := os.Truncate(storeFile(dir, im), 10); err != nil {
		t.Fatal(err)
	}
	_ = os.Chmod(storeFile(dir, im), 0o444)
	if _, err := cat.Verify(im); err != ErrImageChanged {
		t.Fatalf("a truncated image was accepted: %v", err)
	}
}

func TestVerifyDetectsReplacementSymlinksAndUnsafePermissions(t *testing.T) {
	fresh := func(t *testing.T) (string, *Catalog, Image) {
		dir := catalogDir(t)
		im, err := Register(DevPolicy(), dir, reg(source(t, "a.qcow2", qcow2Bytes("original"))))
		if err != nil {
			t.Fatal(err)
		}
		cat, _ := LoadTrustedCatalog(DevPolicy(), dir)
		return dir, cat, im
	}
	t.Run("replaced content, same size", func(t *testing.T) {
		dir, cat, im := fresh(t)
		_ = os.Chmod(storeFile(dir, im), 0o644)
		if err := os.WriteFile(storeFile(dir, im), qcow2Bytes("tampered"), 0o444); err != nil {
			t.Fatal(err)
		}
		_ = os.Chmod(storeFile(dir, im), 0o444)
		if _, err := cat.Verify(im); err != ErrImageChanged {
			t.Fatalf("%v", err)
		}
	})
	t.Run("replaced by a symlink with identical content", func(t *testing.T) {
		dir, cat, im := fresh(t)
		outside := source(t, "same.qcow2", qcow2Bytes("original"))
		_ = os.Remove(storeFile(dir, im))
		if err := os.Symlink(outside, storeFile(dir, im)); err != nil {
			t.Fatal(err)
		}
		if _, err := cat.Verify(im); err == nil {
			t.Fatal("a symlinked image was accepted")
		}
	})
	for name, mode := range map[string]os.FileMode{"group writable": 0o464, "world writable": 0o446, "owner writable": 0o644} {
		t.Run(name, func(t *testing.T) {
			dir, cat, im := fresh(t)
			_ = os.Chmod(storeFile(dir, im), mode)
			if _, err := cat.Verify(im); err == nil {
				t.Fatalf("an image with mode %o was accepted", mode)
			}
		})
	}
	t.Run("missing", func(t *testing.T) {
		dir, cat, im := fresh(t)
		_ = os.Remove(storeFile(dir, im))
		if _, err := cat.Verify(im); err == nil {
			t.Fatal("missing image accepted")
		}
	})
	t.Run("digest mismatch in the catalog entry", func(t *testing.T) {
		_, cat, im := fresh(t)
		im.SHA256 = strings.Repeat("0", 64)
		im.File = im.SHA256 + ".qcow2"
		if _, err := cat.Verify(im); err == nil {
			t.Fatal("wrong digest accepted")
		}
	})
	t.Run("store directory writable by others", func(t *testing.T) {
		dir, cat, im := fresh(t)
		_ = os.Chmod(filepath.Join(dir, StoreDir), 0o777)
		if _, err := cat.Verify(im); err == nil {
			t.Fatal("a world-writable store was accepted")
		}
	})
	t.Run("store directory replaced by a symlink", func(t *testing.T) {
		dir, cat, im := fresh(t)
		elsewhere := t.TempDir()
		real := filepath.Join(dir, StoreDir)
		if err := os.Rename(real, elsewhere+"/store"); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(elsewhere+"/store", real); err != nil {
			t.Fatal(err)
		}
		if _, err := cat.Verify(im); err == nil {
			t.Fatal("a symlinked store directory was accepted")
		}
	})
	t.Run("a parent directory others can write", func(t *testing.T) {
		dir, cat, im := fresh(t)
		_ = os.Chmod(filepath.Dir(dir), 0o777) // not sticky: someone could rename our directory away and put theirs in place
		if _, err := cat.Verify(im); err == nil {
			t.Fatal("a swappable parent directory was accepted")
		}
		if _, err := LoadTrustedCatalog(DevPolicy(), dir); err == nil {
			t.Fatal("the catalog under a swappable parent was trusted")
		}
	})
}

func TestCatalogFileMustBeARealNonWritableFile(t *testing.T) {
	dir := catalogDir(t)
	if _, err := Register(DevPolicy(), dir, reg(source(t, "a.qcow2", qcow2Bytes("x")))); err != nil {
		t.Fatal(err)
	}
	real := filepath.Join(dir, CatalogFile)
	moved := filepath.Join(t.TempDir(), "elsewhere.json")
	if err := os.Rename(real, moved); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(moved, real); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadCatalog(dir); err == nil {
		t.Fatal("a symlinked catalog was loaded")
	}
	_ = os.Remove(real)
	_ = os.Rename(moved, real)
	_ = os.Chmod(real, 0o666)
	if _, err := LoadCatalog(dir); err == nil {
		t.Fatal("a world-writable catalog was loaded")
	}
}

func TestQualificationStatesAreSeparateClaims(t *testing.T) {
	dir := catalogDir(t)
	r := reg(source(t, "a.qcow2", qcow2Bytes("x")))
	r.CloudInit = false
	im, err := Register(DevPolicy(), dir, r)
	if err != nil || im.State != StateRegistered {
		t.Fatalf("%+v %v", im, err)
	}
	cat, _ := LoadTrustedCatalog(DevPolicy(), dir)
	if _, err := cat.Usable("debian-13"); err != ErrImageNotReady {
		t.Fatalf("a merely registered image must not be usable: %v", err)
	}
	// verified needs the cloud-init assertion, which this image never made.
	if _, err := SetState(DevPolicy(), dir, "debian-13", StateVerified, ""); err == nil {
		t.Fatal("verified without cloud-init accepted")
	}
	r2 := reg(source(t, "b.qcow2", qcow2Bytes("y")))
	r2.ID = "other"
	if _, err := Register(DevPolicy(), dir, r2); err != nil {
		t.Fatal(err)
	}
	cat, _ = LoadTrustedCatalog(DevPolicy(), dir)
	if im, err := cat.Usable("other"); err != nil || im.State != StateVerified {
		t.Fatalf("%+v %v", im, err)
	}
	if _, err := SetState(DevPolicy(), dir, "other", StateQualified, ""); err == nil {
		t.Fatal("qualified without evidence accepted")
	}
	if im, err := SetState(DevPolicy(), dir, "other", StateQualified, "QUAL-2026-10-01"); err != nil || im.State != StateQualified || im.Evidence == "" {
		t.Fatalf("%+v %v", im, err)
	}
	if im, err := SetState(DevPolicy(), dir, "other", StateVerified, "ignored"); err != nil || im.Evidence != "" {
		t.Fatalf("leaving qualified must drop the evidence: %+v %v", im, err)
	}
	if _, err := SetState(DevPolicy(), dir, "other", StateDisabled, ""); err != nil {
		t.Fatal(err)
	}
	cat, _ = LoadTrustedCatalog(DevPolicy(), dir)
	if _, err := cat.Usable("other"); err != ErrImageDisabled {
		t.Fatalf("%v", err)
	}
	if _, err := SetState(DevPolicy(), dir, "none", StateDisabled, ""); err != ErrImageNotFound {
		t.Fatalf("%v", err)
	}
	if _, err := SetState(DevPolicy(), dir, "other", "bogus", ""); err == nil {
		t.Fatal("unknown state accepted")
	}
}

func TestLoadCatalogIsStrict(t *testing.T) {
	dir := catalogDir(t)
	write := func(body string, mode os.FileMode) {
		if err := os.WriteFile(filepath.Join(dir, CatalogFile), []byte(body), mode); err != nil {
			t.Fatal(err)
		}
		_ = os.Chmod(filepath.Join(dir, CatalogFile), mode)
	}
	sum := strings.Repeat("a", 64)
	img := `{"id":"a","display_name":"A","distribution":"D","version":"1","architecture":"x86_64","file":"` + sum + `.qcow2","format":"qcow2","sha256":"` + sum + `","size_bytes":5,"min_disk_gib":3,"cloud_init":true,"login_user":"u","state":"verified"}`
	write(`{"schema":2,"images":[`+img+`]}`, 0o640)
	if _, err := LoadCatalog(dir); err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string]string{
		"unknown field": `{"schema":2,"images":[],"extra":1}`, "old schema": `{"schema":1,"images":[]}`, "garbage": `{`,
		"duplicate id":            `{"schema":2,"images":[` + img + `,` + img + `]}`,
		"path in file":            strings.Replace(`{"schema":2,"images":[`+img+`]}`, sum+`.qcow2`, `../`+sum+`.qcow2`, 1),
		"file is not the hash":    strings.Replace(`{"schema":2,"images":[`+img+`]}`, `"file":"`+sum, `"file":"`+strings.Repeat("b", 64), 1),
		"arch":                    strings.Replace(`{"schema":2,"images":[`+img+`]}`, `x86_64`, `aarch64`, 1),
		"unknown state":           strings.Replace(`{"schema":2,"images":[`+img+`]}`, `"verified"`, `"trusted"`, 1),
		"verified w/o cloud-init": strings.Replace(`{"schema":2,"images":[`+img+`]}`, `"cloud_init":true`, `"cloud_init":false`, 1),
		"qualified w/o evidence":  strings.Replace(`{"schema":2,"images":[`+img+`]}`, `"verified"`, `"qualified"`, 1),
	} {
		write(body, 0o640)
		if _, err := LoadCatalog(dir); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	write(`{"schema":2,"images":[`+img+`]}`, 0o666)
	if _, err := LoadCatalog(dir); err == nil {
		t.Error("a world-writable catalog was accepted")
	}
	if _, err := LoadCatalog("relative/dir"); err == nil {
		t.Error("relative dir accepted")
	}
	if c, err := LoadCatalog(t.TempDir()); err != nil || len(c.Images) != 0 {
		t.Errorf("missing catalog should be empty: %v", err)
	}
}

func TestTrustPrimitives(t *testing.T) {
	root := t.TempDir()
	f := filepath.Join(root, "f")
	_ = os.WriteFile(f, []byte("x"), 0o644)
	if err := DevPolicy().Asset(f, false); err != nil {
		t.Fatalf("a plain owner-writable file in an owned tree: %v", err)
	}
	if err := DevPolicy().Asset(f, true); err == nil {
		t.Fatal("readOnly must refuse an owner-writable file")
	}
	_ = os.Chmod(f, 0o664)
	if err := DevPolicy().Asset(f, false); err == nil {
		t.Fatal("group-writable file accepted")
	}
	_ = os.Chmod(f, 0o644)
	l := filepath.Join(root, "l")
	_ = os.Symlink(f, l)
	if err := DevPolicy().Asset(l, false); err == nil {
		t.Fatal("symlink accepted")
	}
	if err := DevPolicy().Asset("relative", false); err == nil {
		t.Fatal("relative path accepted")
	}
	sticky := filepath.Join(root, "sticky")
	_ = os.Mkdir(sticky, 0o755)
	_ = os.Chmod(sticky, 0o777|os.ModeSticky)
	child := filepath.Join(sticky, "c")
	_ = os.Mkdir(child, 0o755)
	if err := DevPolicy().Dir(child); err != nil {
		t.Fatalf("a sticky world-writable ancestor (like /tmp) is acceptable: %v", err)
	}
	if !WritableByMe(f) {
		t.Fatal("this process owns the file, WritableByMe must say so")
	}
}

func TestConfigValidation(t *testing.T) {
	ok := Config{CatalogDir: "/var/lib/svavyom/images", Pool: "svavyom", Network: "svavyom-nat", DomainType: "kvm", LibvirtURI: "qemu:///system", StateDir: "/var/lib/svavyom/state",
		Trust: &TrustSpec{DeployUID: 0, Runtime: []TrustIdentity{{Name: "api", UID: 990}, {Name: "agent", UID: 991}, {Name: "mutation", UID: 992}}}}
	if err := ok.Validate(); err != nil {
		t.Fatal(err)
	}
	for name, mut := range map[string]func(*Config){
		"relative catalog": func(c *Config) { c.CatalogDir = "images" }, "unclean": func(c *Config) { c.StateDir = "/a/../b" },
		"pool xml": func(c *Config) { c.Pool = "p'/>" }, "network empty": func(c *Config) { c.Network = "" },
		"remote uri": func(c *Config) { c.LibvirtURI = "qemu+ssh://h/system" }, "kvm on test uri": func(c *Config) { c.LibvirtURI = "test:///default" },
		"type": func(c *Config) { c.DomainType = "lxc" }, "kvm without trust": func(c *Config) { c.Trust = nil },
	} {
		c := ok
		mut(&c)
		if c.Validate() == nil {
			t.Errorf("%s accepted", name)
		}
	}
	p := filepath.Join(t.TempDir(), "c.json")
	_ = os.WriteFile(p, []byte(`{"catalog_dir":"/a","pool":"p","network":"n","domain_type":"test","libvirt_uri":"test:///default","state_dir":"/s","extra":1}`), 0o600)
	if _, err := LoadConfig(p); err == nil {
		t.Error("unknown config field accepted")
	}
}
