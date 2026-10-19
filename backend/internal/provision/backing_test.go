package provision

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"example.invalid/dedicatedcloud/backend/internal/hypervisor"
)

// backingForTest is the declaration the catalog would qualify for s under cfg (no filesystem involved).
func backingForTest(cfg Config, s Spec) BackingImage {
	return BackingImage{Path: filepath.Join(cfg.CatalogDir, StoreDir, s.ImageSHA256+".qcow2"), Format: BackingFormat, SHA256: s.ImageSHA256}
}

// rootForTest is the resolved placement of the VM's writable overlay and NoCloud seed in a directory pool at /pool.
func rootForTest(s Spec) DiskSources {
	return DiskSources{
		Root: VolumeSource{Name: RootVolumeName(s.UUID), Path: "/pool/" + RootVolumeName(s.UUID), PoolPath: "/pool"},
		Seed: VolumeSource{Name: SeedVolumeName(s.UUID), Path: "/pool/" + SeedVolumeName(s.UUID), PoolPath: "/pool"},
	}
}

func testCfg() Config {
	return Config{CatalogDir: "/c", Pool: "svavyom", Network: "svavyom-nat", DomainType: "test", LibvirtURI: "test:///default", StateDir: "/s"}
}

func goodXML(t *testing.T) (string, Config, Spec, BackingImage) {
	t.Helper()
	cfg, s := testCfg(), specForTest(t)
	b := backingForTest(cfg, s)
	x, err := DomainXML(cfg, s, b, rootForTest(s))
	if err != nil {
		t.Fatal(err)
	}
	return x, cfg, s, b
}

func TestDomainXMLDeclaresTheImmutableBackingImageAndForbidsItsDACRelabel(t *testing.T) {
	x, _, s, b := goodXML(t)
	want := "<backingStore type='file'>\n        <format type='qcow2'/>\n        <source file='/c/store/" + s.ImageSHA256 + ".qcow2'>\n" +
		"          <seclabel model='dac' relabel='no'/>\n        </source>\n        <backingStore/>\n      </backingStore>"
	if !strings.Contains(x, want) {
		t.Fatalf("explicit backing chain missing or malformed:\n%s", x)
	}
	if n := strings.Count(x, "relabel='no'"); n != 1 {
		t.Fatalf("exactly the backing source may disable DAC relabelling, found %d directives", n)
	}
	// Narrow by construction: nothing domain-wide, nothing on the writable overlay or the seed volume.
	for _, forbidden := range []string{"<seclabel model='none'", "<seclabel type='none'", "model='apparmor'", "dynamic_ownership"} {
		if strings.Contains(x, forbidden) {
			t.Errorf("XML contains %q", forbidden)
		}
	}
	root := x[strings.Index(x, "<disk type='file' device='disk'>"):strings.Index(x, "<disk type='file' device='cdrom'>")]
	if i := strings.Index(root, "<source file="); i < 0 || strings.Contains(root[i:strings.Index(root[i:], "/>")+i], "seclabel") {
		t.Error("the writable overlay source carries a security label")
	}
	if cd := x[strings.Index(x, "device='cdrom'"):]; strings.Contains(cd[:strings.Index(cd, "</disk>")], "seclabel") {
		t.Error("the seed volume carries a security label")
	}
	if err := CheckDomainBacking(x, b); err != nil {
		t.Fatalf("the generated document fails its own check: %v", err)
	}
	if d, err := ParseDomain(x); err != nil || d.Root != RootVolumeName(s.UUID) || d.Seed != SeedVolumeName(s.UUID) {
		t.Fatalf("the overlay and seed volumes changed: %+v %v", d, err)
	}
}

func TestDomainXMLRefusesABackingImageThatIsNotTheCatalogQualifiedOne(t *testing.T) {
	cfg, s := testCfg(), specForTest(t)
	good := backingForTest(cfg, s)
	other := strings.Repeat("ef", 32)
	cases := map[string]BackingImage{
		"other digest in the path": {Path: "/c/store/" + other + ".qcow2", Format: "qcow2", SHA256: s.ImageSHA256},
		"digest field differs":     {Path: good.Path, Format: "qcow2", SHA256: other},
		"outside the store":        {Path: "/c/" + s.ImageSHA256 + ".qcow2", Format: "qcow2", SHA256: s.ImageSHA256},
		"another directory":        {Path: "/tmp/store/" + s.ImageSHA256 + ".qcow2", Format: "qcow2", SHA256: s.ImageSHA256},
		"traversal":                {Path: "/c/store/../store/" + s.ImageSHA256 + ".qcow2", Format: "qcow2", SHA256: s.ImageSHA256},
		"relative":                 {Path: "store/" + s.ImageSHA256 + ".qcow2", Format: "qcow2", SHA256: s.ImageSHA256},
		"empty path":               {Format: "qcow2", SHA256: s.ImageSHA256},
		"missing format":           {Path: good.Path, SHA256: s.ImageSHA256},
		"raw format":               {Path: good.Path, Format: "raw", SHA256: s.ImageSHA256},
		"upper-case format":        {Path: good.Path, Format: "QCOW2", SHA256: s.ImageSHA256},
		"format with markup":       {Path: good.Path, Format: "qcow2'/><x a='", SHA256: s.ImageSHA256},
		"path with a quote":        {Path: "/c/store/" + s.ImageSHA256 + ".qcow2'", Format: "qcow2", SHA256: s.ImageSHA256},
	}
	for name, b := range cases {
		if x, err := DomainXML(cfg, s, b, rootForTest(s)); err == nil || x != "" {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := DomainXML(cfg, s, BackingImage{}, rootForTest(s)); err == nil {
		t.Error("an absent backing declaration was accepted")
	}
	// A catalog directory whose characters could break out of the attribute is refused as well.
	weird := cfg
	weird.CatalogDir = "/c'><x/>"
	if _, err := DomainXML(weird, s, backingForTest(weird, s), rootForTest(s)); err == nil {
		t.Error("an unsafe catalog directory reached the template")
	}
}

func TestCheckDomainBackingRejectsAnyDocumentThatWeakensTheDeclaration(t *testing.T) {
	x, _, _, b := goodXML(t)
	sec := "<seclabel model='dac' relabel='no'/>"
	back := x[strings.Index(x, "<backingStore type='file'>") : strings.Index(x, "</backingStore>\n      <target")+len("</backingStore>")]
	cases := map[string]string{
		"DAC relabel permitted (directive removed)": strings.Replace(x, sec, "", 1),
		"DAC relabel explicitly yes":                strings.Replace(x, sec, "<seclabel model='dac' relabel='yes'/>", 1),
		"label for another model only":              strings.Replace(x, sec, "<seclabel model='apparmor' relabel='no'/>", 1),
		"backing declaration absent":                strings.Replace(x, back, "", 1),
		"backing format missing":                    strings.Replace(x, "<format type='qcow2'/>\n        <source file", "<source file", 1),
		"backing format raw":                        strings.Replace(x, "<format type='qcow2'/>\n        <source file", "<format type='raw'/>\n        <source file", 1),
		"backing path differs":                      strings.Replace(x, "/c/store/", "/c/other/", 1),
		"backing is a block device":                 strings.Replace(x, "<backingStore type='file'>", "<backingStore type='block'>", 1),
		"chain not terminated":                      strings.Replace(x, "<backingStore/>", "", 1),
		"chain continues past the base":             strings.Replace(x, "<backingStore/>", "<backingStore type='file'><format type='qcow2'/><source file='/c/store/x.qcow2'/><backingStore/></backingStore>", 1),
		"overlay relabel disabled":                  strings.Replace(x, "<source file='"+rootForTest(specForTest(t)).Root.Path+"'/>", "<source file='"+rootForTest(specForTest(t)).Root.Path+"'>"+sec+"</source>", 1),
		"seed relabel disabled":                     strings.Replace(x, "<source file='"+rootForTest(specForTest(t)).Seed.Path+"'/>", "<source file='"+rootForTest(specForTest(t)).Seed.Path+"'>"+sec+"</source>", 1),
		"domain-wide DAC relabel disabled":          strings.Replace(x, "<clock ", "<seclabel type='none' model='dac' relabel='no'/>\n  <clock ", 1),
		"security model none":                       strings.Replace(x, "<clock ", "<seclabel type='none' model='none'/>\n  <clock ", 1),
		"two directives on the backing":             strings.Replace(x, sec, sec+sec, 1),
	}
	for name, bad := range cases {
		if bad == x {
			t.Errorf("%s: the mutation did not change the document (test bug)", name)
			continue
		}
		if err := CheckDomainBacking(bad, b); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if err := CheckDomainBacking("<domain", b); err == nil {
		t.Error("broken XML accepted")
	}
	wrong := b
	wrong.Path = "/c/store/" + strings.Repeat("ef", 32) + ".qcow2"
	if err := CheckDomainBacking(x, wrong); err == nil {
		t.Error("a document declaring a different image than the expected one was accepted")
	}
	// What libvirt adds when it normalises or starts the domain (index attributes, a dynamic AppArmor label) is not a weakening.
	live := strings.Replace(x, "<backingStore type='file'>", "<backingStore type='file' index='1'>", 1)
	live = strings.Replace(live, "<clock ", "<seclabel type='dynamic' model='apparmor' relabel='yes'/>\n  <clock ", 1)
	if err := CheckDomainBacking(live, b); err != nil {
		t.Errorf("libvirt's own normalisation was refused: %v", err)
	}
}

// stubOps proves that a refused image never reaches the host: every method counts.
type stubOps struct{ calls int }

func (o *stubOps) hit() { o.calls++ }
func (o *stubOps) NetworkActive(context.Context, string) (bool, error) {
	o.hit()
	return true, nil
}
func (o *stubOps) PoolActive(context.Context, string) (bool, error) { o.hit(); return true, nil }
func (o *stubOps) LookupDomain(context.Context, string) (DomainInfo, error) {
	o.hit()
	return DomainInfo{}, hypervisor.NewError(hypervisor.NotFound, "lookup", "", "")
}
func (o *stubOps) LookupVolume(context.Context, string, string) (VolumeInfo, error) {
	o.hit()
	return VolumeInfo{}, hypervisor.NewError(hypervisor.NotFound, "lookup", "", "")
}
func (o *stubOps) CreateRootVolume(context.Context, string, string, int64, string) error {
	o.hit()
	return nil
}
func (o *stubOps) CreateSeedVolume(context.Context, string, string, int64) error { o.hit(); return nil }
func (o *stubOps) UploadSeed(context.Context, string, string, []byte) error      { o.hit(); return nil }
func (o *stubOps) DefineDomain(context.Context, string) error                    { o.hit(); return nil }
func (o *stubOps) StartDomain(context.Context, string) error                     { o.hit(); return nil }
func (o *stubOps) ShutdownDomain(context.Context, string) error                  { o.hit(); return nil }
func (o *stubOps) RebootDomain(context.Context, string, time.Duration) error     { o.hit(); return nil }
func (o *stubOps) DestroyDomain(context.Context, string) error                   { o.hit(); return nil }
func (o *stubOps) UndefineDomain(context.Context, string) error                  { o.hit(); return nil }
func (o *stubOps) DeleteVolume(context.Context, string, string) error            { o.hit(); return nil }
func (o *stubOps) PoolStats(context.Context, string) (PoolStats, error) {
	o.hit()
	return PoolStats{}, nil
}
func (o *stubOps) ListVolumes(context.Context, string) ([]string, error)     { o.hit(); return nil, nil }
func (o *stubOps) ResizeVolume(context.Context, string, string, int64) error { o.hit(); return nil }
func (o *stubOps) ListSnapshots(context.Context, string) ([]SnapshotInfo, error) {
	o.hit()
	return nil, nil
}
func (o *stubOps) CreateSnapshot(context.Context, string, string, string) error { o.hit(); return nil }
func (o *stubOps) RevertSnapshot(context.Context, string, string) error         { o.hit(); return nil }
func (o *stubOps) DeleteSnapshot(context.Context, string, string) error         { o.hit(); return nil }
func (o *stubOps) DownloadVolume(context.Context, string, string, io.Writer) (int64, error) {
	o.hit()
	return 0, nil
}
func (o *stubOps) UploadVolume(context.Context, string, string, io.Reader, int64) error {
	o.hit()
	return nil
}

func (o *stubOps) ListDomains(context.Context) ([]DomainInfo, error)   { o.hit(); return nil, nil }
func (o *stubOps) ListNetworks(context.Context) ([]NetworkInfo, error) { o.hit(); return nil, nil }
func (o *stubOps) LookupNetwork(context.Context, string) (NetworkInfo, error) {
	o.hit()
	return NetworkInfo{}, hypervisor.NewError(hypervisor.NotFound, "network", "", "")
}
func (o *stubOps) DefineNetwork(context.Context, string) error                  { o.hit(); return nil }
func (o *stubOps) StartNetwork(context.Context, string) error                   { o.hit(); return nil }
func (o *stubOps) StopNetwork(context.Context, string) error                    { o.hit(); return nil }
func (o *stubOps) SetNetworkAutostart(context.Context, string, bool) error      { o.hit(); return nil }
func (o *stubOps) UndefineNetwork(context.Context, string) error                { o.hit(); return nil }
func (o *stubOps) AddNetworkHost(context.Context, string, string, string) error { o.hit(); return nil }
func (o *stubOps) RemoveNetworkHost(context.Context, string, string, string) error {
	o.hit()
	return nil
}
func (o *stubOps) NetworkLeases(context.Context, string) ([]NetLease, error) {
	o.hit()
	return nil, nil
}
func (o *stubOps) CreateDataVolume(context.Context, string, string, int64) error { o.hit(); return nil }
func (o *stubOps) AttachDataDisk(context.Context, string, string, string, string) error {
	o.hit()
	return nil
}
func (o *stubOps) DetachDataDisk(context.Context, string, string) error     { o.hit(); return nil }
func (o *stubOps) SetDomainCompute(context.Context, string, int, int) error { o.hit(); return nil }

func TestBackingIsTheVerifiedStoreImageAndUnsafeImagesNeverReachTheHost(t *testing.T) {
	d := newDeployment(t)
	cat, err := LoadTrustedCatalog(d.pol, d.catDir)
	if err != nil {
		t.Fatal(err)
	}
	b, err := cat.Backing(d.im)
	if err != nil || b.Path != d.image || b.Format != "qcow2" || b.SHA256 != d.im.SHA256 {
		t.Fatalf("%+v %v", b, err)
	}
	s := specForTest(t)
	s.ImageID, s.ImageSHA256 = d.im.ID, d.im.SHA256
	if x, err := DomainXML(d.cfg, s, b, rootForTest(s)); err != nil || !strings.Contains(x, "<source file='"+d.image+"'>") {
		t.Fatalf("%v", err)
	}

	mutations := map[string]func(t *testing.T, d *deployment){
		"writable base image": func(t *testing.T, d *deployment) {
			if err := os.Chmod(d.image, 0o644); err != nil {
				t.Fatal(err)
			}
		},
		"group-writable base image": func(t *testing.T, d *deployment) {
			if err := os.Chmod(d.image, 0o464); err != nil {
				t.Fatal(err)
			}
		},
		"base image not owned by the deployment owner": func(t *testing.T, d *deployment) {
			d.pol.Owner = myUID + 1 // the files belong to this user, so as "root" they would be foreign
		},
		"symlinked base image":      func(t *testing.T, d *deployment) { replaceWithSymlink(t, d.image) },
		"symlinked store directory": func(t *testing.T, d *deployment) { replaceDirWithSymlink(t, d.store) },
		"content changed": func(t *testing.T, d *deployment) {
			if err := os.Chmod(d.image, 0o644); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(d.image, []byte("tampered"), 0o444); err != nil { // #nosec G306
				t.Fatal(err)
			}
		},
		"image removed": func(t *testing.T, d *deployment) {
			if err := os.Remove(d.image); err != nil {
				t.Fatal(err)
			}
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			d := newDeployment(t)
			cat, err := LoadTrustedCatalog(d.pol, d.catDir) // loaded while the layout is still good: the helper loads, then verifies at use
			if err != nil {
				t.Fatal(err)
			}
			mutate(t, d)
			cat.trust = d.pol
			if _, err := cat.Backing(d.im); err == nil {
				t.Fatal("Backing accepted an image the trust model forbids")
			}
			ops := &stubOps{}
			s := specForTest(t)
			s.ImageID, s.ImageSHA256, s.Network = d.im.ID, d.im.SHA256, d.cfg.Network
			perr := Provision(context.Background(), ops, d.cfg, cat, s, d.cfg.StateDir, nil)
			if hypervisor.CategoryOf(perr) != hypervisor.Conflict || ops.calls != 0 {
				t.Fatalf("Provision proceeded: %v (host calls %d)", perr, ops.calls)
			}
		})
	}
}

func TestADeclaredBackingPathMustBeCanonical(t *testing.T) {
	d := newDeployment(t)
	alias := filepath.Join(t.TempDir(), "alias")
	if err := os.Symlink(d.root, alias); err != nil { // the catalog is reached through a symlinked ancestor
		t.Fatal(err)
	}
	via := filepath.Join(alias, "images")
	cat, err := LoadTrustedCatalog(d.pol, via)
	if err != nil {
		t.Skipf("the trust policy already refuses this layout: %v", err)
	}
	if _, err := cat.Backing(d.im); err == nil {
		t.Fatal("a backing path that is not the real path was declared: AppArmor and libvirt act on the resolved path")
	}
	ops := &stubOps{}
	s := specForTest(t)
	s.ImageID, s.ImageSHA256, s.Network = d.im.ID, d.im.SHA256, d.cfg.Network
	cfg := d.cfg
	cfg.CatalogDir = via
	if err := Provision(context.Background(), ops, cfg, cat, s, d.cfg.StateDir, nil); hypervisor.CategoryOf(err) != hypervisor.Conflict || ops.calls != 0 {
		t.Fatalf("Provision proceeded: %v (host calls %d)", err, ops.calls)
	}
}
