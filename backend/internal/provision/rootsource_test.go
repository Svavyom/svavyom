package provision

import (
	"context"
	"strings"
	"testing"

	"example.invalid/dedicatedcloud/backend/internal/hypervisor"
)

// placeHost is a HostOps double that reports a controllable placement for the root volume and counts what Provision creates. The
// placement function receives the volume name and how many times that volume has been looked up.
type placeHost struct {
	stubOps
	vols           map[string]VolumeInfo
	lookups        map[string]int
	placement      func(name string, n int) VolumeInfo
	rootCreates    int
	seedCreates    int
	defines        int
	failDefineOnce bool
	domain         *DomainInfo
	definedXML     string
}

func newPlaceHost(place func(string, int) VolumeInfo) *placeHost {
	return &placeHost{vols: map[string]VolumeInfo{}, lookups: map[string]int{}, placement: place}
}

func (h *placeHost) LookupDomain(context.Context, string) (DomainInfo, error) {
	if h.domain != nil {
		return *h.domain, nil
	}
	return DomainInfo{}, hypervisor.NewError(hypervisor.NotFound, "lookup", "", "")
}

func (h *placeHost) LookupVolume(_ context.Context, _ string, name string) (VolumeInfo, error) {
	v, ok := h.vols[name]
	if !ok {
		return VolumeInfo{}, hypervisor.NewError(hypervisor.NotFound, "lookup", "", "")
	}
	h.lookups[name]++
	p := h.placement(name, h.lookups[name])
	v.Name, v.Path, v.PoolPath, v.FSChecked, v.Regular, v.Symlink, v.Canonical = p.Name, p.Path, p.PoolPath, p.FSChecked, p.Regular, p.Symlink, p.Canonical
	return v, nil
}

func (h *placeHost) CreateRootVolume(_ context.Context, _ string, name string, c int64, backing string) error {
	h.rootCreates++
	h.vols[name] = VolumeInfo{CapacityBytes: c, BackingPath: backing}
	return nil
}

func (h *placeHost) CreateSeedVolume(_ context.Context, _ string, name string, c int64) error {
	h.seedCreates++
	h.vols[name] = VolumeInfo{CapacityBytes: c}
	return nil
}

func (h *placeHost) DefineDomain(_ context.Context, x string) error {
	if h.failDefineOnce {
		h.failDefineOnce = false
		return hypervisor.NewError(hypervisor.HostError, "define", "", "unknown outcome")
	}
	h.defines++
	h.definedXML = x
	d, _ := ParseDomain(x)
	h.domain = &DomainInfo{UUID: d.UUID, Fingerprint: d.Fingerprint, Managed: d.Managed}
	return nil
}

// goodPlacement is a clean directory-pool answer: the file is /pool/<volume>, regular, no symlink anywhere.
func goodPlacement(name string, _ int) VolumeInfo {
	return VolumeInfo{Name: name, Path: "/pool/" + name, PoolPath: "/pool", FSChecked: true, Regular: true, Canonical: true}
}

func provisionWith(t *testing.T, h *placeHost) (Spec, error) {
	t.Helper()
	d := newDeployment(t)
	cat, err := LoadTrustedCatalog(d.pol, d.catDir)
	if err != nil {
		t.Fatal(err)
	}
	s := specForTest(t)
	s.ImageID, s.ImageSHA256, s.Network = d.im.ID, d.im.SHA256, d.cfg.Network
	err = Provision(context.Background(), h, d.cfg, cat, s, t.TempDir(), nil)
	return s, err
}

func TestProvisionDefinesRootAndSeedAsFilesAtTheResolvedVolumePaths(t *testing.T) {
	h := newPlaceHost(goodPlacement)
	s, err := provisionWith(t, h)
	if err != nil {
		t.Fatal(err)
	}
	root, seed := RootVolumeName(s.UUID), SeedVolumeName(s.UUID)
	if !strings.Contains(h.definedXML, "<disk type='file' device='disk'>") || !strings.Contains(h.definedXML, "<source file='/pool/"+root+"'/>") {
		t.Fatalf("root disk is not a file source at the resolved path:\n%s", h.definedXML)
	}
	if !strings.Contains(h.definedXML, "<disk type='file' device='cdrom'>") || !strings.Contains(h.definedXML, "<source file='/pool/"+seed+"'/>") ||
		!strings.Contains(h.definedXML, "<driver name='qemu' type='raw'/>") || !strings.Contains(h.definedXML, "<readonly/>") {
		t.Fatalf("seed is not a readonly raw file cdrom at the resolved path:\n%s", h.definedXML)
	}
	if strings.Contains(h.definedXML, "volume=") || strings.Contains(h.definedXML, "pool=") {
		t.Error("a pool/volume source remains in the definition")
	}
	if !strings.Contains(h.definedXML, "<backingStore type='file'>") || strings.Count(h.definedXML, "relabel='no'") != 1 {
		t.Error("the immutable backing declaration changed")
	}
	// relabel='no' is on the immutable backing source only: the overlay's own <source .../> is self-closing and unlabelled, and the
	// seed (which follows the root disk) carries none.
	disk := h.definedXML[strings.Index(h.definedXML, "<disk type='file'"):]
	if strings.Index(disk, "relabel='no'") < strings.Index(disk, "<backingStore") || strings.Index(disk, "relabel='no'") > strings.Index(disk, "device='cdrom'") {
		t.Error("a no-relabel directive is somewhere other than the immutable backing source")
	}
	// The lifecycle still goes through the volume API: the exact volume names are recoverable from the definition.
	if d, err := ParseDomain(h.definedXML); err != nil || d.Root != root || d.Seed != seed {
		t.Fatalf("volume identity lost: %+v %v", d, err)
	}
	if h.rootCreates != 1 || h.seedCreates != 1 || h.defines != 1 || len(h.vols) != 2 {
		t.Fatalf("creates root=%d seed=%d define=%d volumes=%d", h.rootCreates, h.seedCreates, h.defines, len(h.vols))
	}
}

func TestProvisionRefusesAVolumePathItCannotProveIsThatVolume(t *testing.T) {
	good := func(name string) VolumeInfo { return goodPlacement(name, 1) }
	other := func(name string) string { // the lookalike: the other qualification volume of the same VM
		if strings.HasSuffix(name, "-root.qcow2") {
			return strings.Replace(name, "-root.qcow2", "-seed.iso", 1)
		}
		return strings.Replace(name, "-seed.iso", "-root.qcow2", 1)
	}
	cases := map[string]func(v *VolumeInfo){
		"relative path":              func(v *VolumeInfo) { v.Path = "pool/" + v.Name },
		"empty path":                 func(v *VolumeInfo) { v.Path = "" },
		"outside the pool":           func(v *VolumeInfo) { v.Path = "/elsewhere/" + v.Name },
		"in a subdirectory":          func(v *VolumeInfo) { v.Path = "/pool/sub/" + v.Name },
		"sibling pool prefix":        func(v *VolumeInfo) { v.PoolPath = "/poo"; v.Path = "/poo/../pool/" + v.Name },
		"traversal":                  func(v *VolumeInfo) { v.Path = "/pool/../etc/" + v.Name },
		"another volume's file":      func(v *VolumeInfo) { v.Path = "/pool/" + other(v.Name) },
		"another volume's name":      func(v *VolumeInfo) { v.Name = other(v.Name); v.Path = "/pool/" + v.Name },
		"name differs from the path": func(v *VolumeInfo) { v.Name = "svavyom-other-root.qcow2" },
		"wrong volume name":          func(v *VolumeInfo) { v.Name = "svavyom-other-seed.iso"; v.Path = "/pool/" + v.Name },
		"pool path empty":            func(v *VolumeInfo) { v.PoolPath = "" },
		"pool is the filesystem":     func(v *VolumeInfo) { v.PoolPath = "/"; v.Path = "/" + v.Name },
		"unsafe character":           func(v *VolumeInfo) { v.Path += "'" },
		"markup in the path":         func(v *VolumeInfo) { v.Path = "/pool/><x/>" },
		"symlink":                    func(v *VolumeInfo) { v.Symlink, v.Regular = true, false },
		"symlink flag with regular":  func(v *VolumeInfo) { v.Symlink = true },
		"not a regular file":         func(v *VolumeInfo) { v.Regular = false },
		"symlink in an ancestor":     func(v *VolumeInfo) { v.Canonical = false },
		"path not inspectable":       func(v *VolumeInfo) { v.FSChecked = false },
	}
	for _, target := range []string{"-root.qcow2", "-seed.iso"} {
		for name, mutate := range cases {
			t.Run(strings.TrimLeft(target, "-")[:4]+"/"+name, func(t *testing.T) {
				h := newPlaceHost(func(n string, _ int) VolumeInfo {
					v := good(n)
					if strings.HasSuffix(n, target) {
						mutate(&v)
					}
					return v
				})
				_, err := provisionWith(t, h)
				if hypervisor.CategoryOf(err) != hypervisor.Conflict {
					t.Fatalf("accepted or wrong category: %v", err)
				}
				if h.defines != 0 {
					t.Fatal("a domain was defined from an unproven path")
				}
			})
		}
	}
}

func TestProvisionRefusesAPathThatMovesBetweenCreationAndDefinition(t *testing.T) {
	for _, target := range []string{"-root.qcow2", "-seed.iso"} {
		t.Run(target, func(t *testing.T) {
			h := newPlaceHost(func(name string, n int) VolumeInfo {
				v := goodPlacement(name, n)
				if strings.HasSuffix(name, target) && n >= 2 { // a later answer (just before definition) differs
					v.PoolPath, v.Path = "/pool2", "/pool2/"+name
				}
				return v
			})
			if _, err := provisionWith(t, h); hypervisor.CategoryOf(err) != hypervisor.Conflict || h.defines != 0 {
				t.Fatalf("path change accepted: %v defines=%d", err, h.defines)
			}
		})
	}
}

func TestUnknownOutcomeRetryDoesNotDuplicateVolumesOrDomains(t *testing.T) {
	h := newPlaceHost(goodPlacement)
	h.failDefineOnce = true
	d := newDeployment(t)
	cat, err := LoadTrustedCatalog(d.pol, d.catDir)
	if err != nil {
		t.Fatal(err)
	}
	s := specForTest(t)
	s.ImageID, s.ImageSHA256, s.Network = d.im.ID, d.im.SHA256, d.cfg.Network
	run := func() error { return Provision(context.Background(), h, d.cfg, cat, s, t.TempDir(), nil) }
	if err := run(); err == nil {
		t.Fatal("the injected unknown outcome was swallowed")
	}
	for i := 0; i < 2; i++ { // the recovery, then an identical repeat
		if err := run(); err != nil {
			t.Fatalf("retry %d: %v", i, err)
		}
	}
	if h.rootCreates != 1 || h.seedCreates != 1 || h.defines != 1 || len(h.vols) != 2 {
		t.Fatalf("duplicates: root=%d seed=%d define=%d volumes=%d", h.rootCreates, h.seedCreates, h.defines, len(h.vols))
	}
}

func TestCheckDomainSourcesRejectsAnythingButTheExactFileSources(t *testing.T) {
	x, cfg, s, _ := goodXML(t)
	src := rootForTest(s)
	if err := CheckDomainSources(x, src); err != nil {
		t.Fatal(err)
	}
	rootFile := "<source file='" + src.Root.Path + "'/>"
	seedFile := "<source file='" + src.Seed.Path + "'/>"
	rep := strings.Replace
	cases := map[string]string{
		"root pool/volume reference":   rep(rep(x, "<disk type='file' device='disk'>", "<disk type='volume' device='disk'>", 1), rootFile, "<source pool='"+cfg.Pool+"' volume='"+RootVolumeName(s.UUID)+"'/>", 1),
		"root a different file":        rep(x, rootFile, "<source file='/pool/other.qcow2'/>", 1),
		"root disk type volume":        rep(x, "<disk type='file' device='disk'>", "<disk type='volume' device='disk'>", 1),
		"root file and pool named":     rep(x, rootFile, "<source file='"+src.Root.Path+"' pool='"+cfg.Pool+"' volume='x'/>", 1),
		"no root disk":                 rep(x, "device='disk'", "device='lun'", 1),
		"seed reverted to pool/volume": rep(rep(x, "<disk type='file' device='cdrom'>", "<disk type='volume' device='cdrom'>", 1), seedFile, "<source pool='"+cfg.Pool+"' volume='"+SeedVolumeName(s.UUID)+"'/>", 1),
		"seed a different file":        rep(x, seedFile, "<source file='/pool/other.iso'/>", 1),
		"seed outside the pool":        rep(x, seedFile, "<source file='/elsewhere/"+SeedVolumeName(s.UUID)+"'/>", 1),
		"seed disk type volume":        rep(x, "<disk type='file' device='cdrom'>", "<disk type='volume' device='cdrom'>", 1),
		"seed file and pool named":     rep(x, seedFile, "<source file='"+src.Seed.Path+"' pool='"+cfg.Pool+"' volume='x'/>", 1),
		"seed writable":                rep(x, "<readonly/>", "", 1),
		"seed wrong media format":      rep(x, "<driver name='qemu' type='raw'/>", "<driver name='qemu' type='qcow2'/>", 1),
		"seed relabel disabled":        rep(x, seedFile, "<source file='"+src.Seed.Path+"'><seclabel model='dac' relabel='no'/></source>", 1),
		"root relabel disabled":        rep(x, rootFile, "<source file='"+src.Root.Path+"'><seclabel model='dac' relabel='no'/></source>", 1),
		"no seed":                      rep(x, "device='cdrom'", "device='floppy'", 1),
		"two seeds":                    rep(x, "</devices>", "<disk type='file' device='cdrom'><driver name='qemu' type='raw'/><source file='"+src.Seed.Path+"'/><target dev='sdb' bus='sata'/><readonly/></disk></devices>", 1),
	}
	for name, bad := range cases {
		if bad == x {
			t.Errorf("%s: mutation did not change the document", name)
		} else if CheckDomainSources(bad, src) == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if CheckDomainSources(x, DiskSources{}) == nil || CheckDomainSources(x, DiskSources{Root: src.Root}) == nil || CheckDomainSources("<domain", src) == nil {
		t.Error("empty expectation or broken XML accepted")
	}
	// Each half stands on its own: the seed check fails when only the seed is wrong, and the root check when only the root is.
	if CheckDomainRootSource(cases["seed writable"], src.Root) != nil || CheckDomainSeedSource(cases["seed writable"], src.Seed) == nil ||
		CheckDomainSeedSource(cases["root a different file"], src.Seed) != nil || CheckDomainRootSource(cases["root a different file"], src.Root) == nil {
		t.Error("the per-disk checks do not isolate the disk they report on")
	}
	// The writable overlay and the seed keep normal libvirt security handling: a no-relabel directive on either is refused by the
	// backing check as well, and the immutable backing image remains the only one.
	b := backingForTest(cfg, s)
	for _, bad := range []string{cases["root relabel disabled"], cases["seed relabel disabled"]} {
		if CheckDomainBacking(bad, b) == nil {
			t.Error("relabel='no' on the writable overlay or the seed accepted by the backing check")
		}
	}
}

func TestParseDomainRecoversVolumeNamesOnlyWhenTheyBelongToTheDomain(t *testing.T) {
	x, _, s, _ := goodXML(t)
	rootFile, seedFile := "/pool/"+RootVolumeName(s.UUID), "/pool/"+SeedVolumeName(s.UUID)
	other := "2a1a1a1a-2222-4333-8444-5555555555ab"
	cases := map[string]struct{ x, root, seed string }{
		"file-backed, valid": {x, RootVolumeName(s.UUID), SeedVolumeName(s.UUID)},
		"root of another VM": {strings.Replace(x, rootFile, "/pool/"+RootVolumeName(other), 1), "", SeedVolumeName(s.UUID)},
		"seed of another VM": {strings.Replace(x, seedFile, "/pool/"+SeedVolumeName(other), 1), RootVolumeName(s.UUID), ""},
		"arbitrary basename": {strings.Replace(strings.Replace(x, rootFile, "/pool/anything.qcow2", 1), seedFile, "/pool/anything.iso", 1), "", ""},
		"seed named as root": {strings.Replace(x, seedFile, rootFile, 1), RootVolumeName(s.UUID), ""},
		"relative path":      {strings.Replace(x, seedFile, "pool/"+SeedVolumeName(s.UUID), 1), RootVolumeName(s.UUID), ""},
		"traversal":          {strings.Replace(x, seedFile, "/pool/../x/"+SeedVolumeName(s.UUID), 1), RootVolumeName(s.UUID), ""},
		"legacy pool/volume": {strings.Replace(strings.Replace(x, "<source file='"+seedFile+"'/>", "<source pool='p' volume='"+SeedVolumeName(s.UUID)+"'/>", 1), "type='file' device='cdrom'", "type='volume' device='cdrom'", 1), RootVolumeName(s.UUID), SeedVolumeName(s.UUID)},
		"legacy foreign vol": {strings.Replace(x, "<source file='"+seedFile+"'/>", "<source pool='p' volume='x.iso'/>", 1), RootVolumeName(s.UUID), ""},
		"file and volume":    {strings.Replace(x, "<source file='"+seedFile+"'/>", "<source file='"+seedFile+"' pool='p' volume='"+SeedVolumeName(s.UUID)+"'/>", 1), RootVolumeName(s.UUID), ""},
	}
	for name, c := range cases {
		if d, err := ParseDomain(c.x); err != nil || d.Root != c.root || d.Seed != c.seed {
			t.Errorf("%s: root=%q seed=%q err=%v, want root=%q seed=%q", name, d.Root, d.Seed, err, c.root, c.seed)
		}
	}
}

func TestResolveVolumeSourceIsGenericOverRootAndSeed(t *testing.T) {
	s := specForTest(t)
	for _, name := range []string{RootVolumeName(s.UUID), SeedVolumeName(s.UUID)} {
		r, err := ResolveVolumeSource(name, goodPlacement(name, 1))
		if err != nil || r.Name != name || r.Path != "/pool/"+name || r.PoolPath != "/pool" {
			t.Errorf("%s: %+v %v", name, r, err)
		}
		if _, err := ResolveVolumeSource("", goodPlacement(name, 1)); err == nil {
			t.Error("an empty expected name was accepted")
		}
	}
	if _, err := ResolveRootSource(s, goodPlacement(SeedVolumeName(s.UUID), 1)); err == nil {
		t.Error("the seed volume resolved as the root")
	}
	if _, err := ResolveSeedSource(s, goodPlacement(RootVolumeName(s.UUID), 1)); err == nil {
		t.Error("the root volume resolved as the seed")
	}
}
