//go:build libvirt && libvirt_test

package libvirtmut

// Provisioning against libvirt's in-process TEST driver (test:///default): the generated domain XML, the volume XML, the storage
// pool and network lookups, define and start are exercised through the real libvirt API. SIMULATION: the test driver has no real
// storage and does not implement volume upload (virStorageVolUpload), so the seed upload is skipped here and exercised only by
// the real-host qualification (docs/QUALIFICATION-LIBVIRT-CREATE.md).

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
	libvirt "libvirt.org/go/libvirt"

	"example.invalid/dedicatedcloud/backend/internal/hypervisor"
	"example.invalid/dedicatedcloud/backend/internal/hypervisor/libvirtro"
	"example.invalid/dedicatedcloud/backend/internal/provision"
	"example.invalid/dedicatedcloud/backend/internal/provision/provtest"
)

type env struct {
	t    *testing.T
	ops  *Ops
	cfg  provision.Config
	cat  *provision.Catalog
	spec provision.Spec
	img  provision.Image
}

func newEnv(t *testing.T, name, uuid string) *env {
	t.Helper()
	root := t.TempDir()
	catDir, state := filepath.Join(root, "images"), filepath.Join(root, "state")
	_ = os.MkdirAll(catDir, 0o750)
	_ = os.MkdirAll(state, 0o700)
	src := filepath.Join(root, "debian.qcow2")
	_ = os.WriteFile(src, provtest.Qcow2("body"), 0o640)
	img, err := provision.Register(provision.DevPolicy(), catDir, provision.RegisterRequest{ID: "debian-13", DisplayName: "Debian 13", Distribution: "Debian", Version: "13", Source: src, LoginUser: "debian", MinDiskGiB: 3, CloudInit: true})
	if err != nil {
		t.Fatal(err)
	}
	cat, _ := provision.LoadTrustedCatalog(provision.DevPolicy(), catDir)
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	sp, _ := ssh.NewPublicKey(pub)
	key, _ := provision.NormalizeSSHKey(string(ssh.MarshalAuthorizedKey(sp)))
	ops, err := Open(TestURI)
	if err != nil {
		t.Fatal(err)
	}
	ops.SkipUploadUnsupported = true
	// The test driver has no filesystem behind its volumes: answer the inspection as a clean regular file. (Like the skipped seed
	// upload this is a simulation gap, stated here; the real inspection is exercised by TestPlacementReportsWhatTheHostInspectionSees
	// and on the real host by the qualification.)
	plain := filepath.Join(root, "plain-file")
	_ = os.WriteFile(plain, nil, 0o600)
	ops.Lstat = func(string) (os.FileInfo, error) { return os.Lstat(plain) }
	ops.Canonical = func(p string) (string, error) { return p, nil }
	t.Cleanup(ops.Close)
	cfg := provision.Config{CatalogDir: catDir, Pool: "default-pool", Network: "default", DomainType: "test", LibvirtURI: TestURI, StateDir: state}
	return &env{t: t, ops: ops, cfg: cfg, cat: cat, img: img, spec: provision.Spec{Name: name, UUID: uuid, Fingerprint: strings.Repeat("ab", 32), VCPUs: 2, MemoryMiB: 1024,
		ImageID: "debian-13", ImageSHA256: img.SHA256, DiskGiB: 20, SSHPublicKey: key.Authorized, Network: "default"}}
}

func (e *env) cleanup() {
	c, err := libvirt.NewConnect(TestURI)
	if err != nil {
		return
	}
	defer c.Close()
	if d, err := c.LookupDomainByName(e.spec.Name); err == nil {
		_ = d.Destroy()
		_ = d.Undefine()
		_ = d.Free()
	}
	if p, err := c.LookupStoragePoolByName("default-pool"); err == nil {
		for _, n := range []string{provision.RootVolumeName(e.spec.UUID), provision.SeedVolumeName(e.spec.UUID)} {
			if v, err := p.LookupStorageVolByName(n); err == nil {
				_ = v.Delete(0)
				_ = v.Free()
			}
		}
		_ = p.Free()
	}
}

func TestOpenRefusesEveryOtherURI(t *testing.T) {
	for _, uri := range []string{"", "qemu:///session", "qemu+ssh://h/system", "qemu+tcp://x/system", "test:///other", "QEMU:///system", "xen:///"} {
		if o, err := Open(uri); o != nil || hypervisor.CategoryOf(err) != hypervisor.Prohibited {
			t.Errorf("Open(%q) = %v, %v", uri, o, err)
		}
	}
}

func TestProvisionAndStartOnTheTestDriverAndObservedByTheReadOnlyAdapter(t *testing.T) {
	e := newEnv(t, "lm-web", "3a3a3a3a-2222-4333-8444-5555555555ab")
	t.Cleanup(e.cleanup)
	ctx := context.Background()
	if r := provision.Preflight(ctx, e.ops, e.cfg); r.Network != "available" || r.Pool != "available" {
		t.Fatalf("%+v", r)
	}
	if err := provision.Provision(ctx, e.ops, e.cfg, e.cat, e.spec, e.cfg.StateDir, nil); err != nil {
		t.Fatal(err)
	}
	ro, err := libvirtro.Open(libvirtro.TestURI)
	if err != nil {
		t.Fatal(err)
	}
	defer ro.Close()
	d, err := ro.Lookup(ctx, "lm-web")
	if err != nil || d.State != hypervisor.StateShutoff || !d.Managed || d.UUID != e.spec.UUID || d.Fingerprint != e.spec.Fingerprint || d.ImageID != "debian-13" ||
		d.VCPUs != 2 || d.MemoryMiB != 1024 || d.IPv4 != "" {
		t.Fatalf("%+v %v", d, err)
	}
	// Idempotent.
	if err := provision.Provision(ctx, e.ops, e.cfg, e.cat, e.spec, e.cfg.StateDir, nil); err != nil {
		t.Fatalf("repeat: %v", err)
	}
	// libvirt's own parser accepted the explicit backing declaration; report what its stored definition keeps (the test driver uses the
	// same XML parser and formatter as qemu:///system for the disk element, but it is not KVM evidence).
	b, err := e.cat.Backing(e.img)
	if err != nil {
		t.Fatal(err)
	}
	dom, err := e.ops.conn.LookupDomainByName("lm-web")
	if err != nil {
		t.Fatal(err)
	}
	stored, err := dom.GetXMLDesc(libvirt.DOMAIN_XML_INACTIVE)
	_ = dom.Free()
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("stored definition (disk): %s", stored[strings.Index(stored, "<disk"):strings.Index(stored, "</disk>")])
	if err := provision.CheckDomainBacking(stored, b); err != nil {
		t.Errorf("libvirt's stored definition lost the explicit backing store or its no-DAC-relabel directive: %v", err)
	}
	// Both the root overlay and the seed are stored as file sources at the paths libvirt resolved for their volumes.
	rv, err := e.ops.LookupVolume(ctx, "default-pool", provision.RootVolumeName(e.spec.UUID))
	if err != nil {
		t.Fatal(err)
	}
	rs, err := provision.ResolveRootSource(e.spec, rv)
	if err != nil {
		t.Fatalf("root volume placement %+v: %v", rv, err)
	}
	sv, err := e.ops.LookupVolume(ctx, "default-pool", provision.SeedVolumeName(e.spec.UUID))
	if err != nil {
		t.Fatal(err)
	}
	ss, err := provision.ResolveSeedSource(e.spec, sv)
	if err != nil {
		t.Fatalf("seed volume placement %+v: %v", sv, err)
	}
	if err := provision.CheckDomainSources(stored, provision.DiskSources{Root: rs, Seed: ss}); err != nil {
		t.Errorf("libvirt's stored definition does not name the root overlay as %s and the seed as %s: %v", rs.Path, ss.Path, err)
	}
	if d, err := provision.ParseDomain(stored); err != nil || d.Root != provision.RootVolumeName(e.spec.UUID) || d.Seed != provision.SeedVolumeName(e.spec.UUID) {
		t.Errorf("the volume identities are not recoverable from the stored definition: %+v %v", d, err)
	}
	// The root volume is a qcow2 volume of the requested size backed by the verified image.
	v, err := e.ops.LookupVolume(ctx, "default-pool", provision.RootVolumeName(e.spec.UUID))
	imgPath, _ := e.cat.Path(e.img)
	if err != nil || v.CapacityBytes != 20<<30 || v.BackingPath != imgPath {
		t.Fatalf("%+v %v", v, err)
	}
	if err := provision.Start(ctx, e.ops, "lm-web", nil); err != nil {
		t.Fatal(err)
	}
	d, err = ro.Lookup(ctx, "lm-web")
	if err != nil || d.State != hypervisor.StateRunning {
		t.Fatalf("%+v %v", d, err)
	}
	if d.IPv4 != "" && !provision.IsIPv4(d.IPv4) { // the test driver reports a lease; real hosts depend on DHCP
		t.Fatalf("ip %q", d.IPv4)
	}
	if err := provision.Start(ctx, e.ops, "lm-web", nil); err != nil {
		t.Fatalf("start is idempotent: %v", err)
	}
}

func TestConflictsAndRefusalsOnTheTestDriver(t *testing.T) {
	e := newEnv(t, "lm-conf", "4a4a4a4a-2222-4333-8444-5555555555ab")
	t.Cleanup(e.cleanup)
	ctx := context.Background()
	// A foreign (unmanaged) domain of the same name.
	c, _ := libvirt.NewConnect(TestURI)
	defer c.Close()
	d, err := c.DomainDefineXML(`<domain type="test"><name>lm-conf</name><memory unit="MiB">64</memory><vcpu>1</vcpu><os><type>hvm</type></os></domain>`)
	if err != nil {
		t.Fatal(err)
	}
	if err := provision.Provision(ctx, e.ops, e.cfg, e.cat, e.spec, e.cfg.StateDir, nil); hypervisor.CategoryOf(err) != hypervisor.Conflict {
		t.Fatalf("foreign domain: %v", err)
	}
	if err := provision.Start(ctx, e.ops, "lm-conf", nil); hypervisor.CategoryOf(err) != hypervisor.Prohibited {
		t.Fatalf("an unmanaged domain must not be started by Svavyom: %v", err)
	}
	if st, _, _ := d.GetState(); st == libvirt.DOMAIN_RUNNING {
		t.Fatal("the foreign domain was started")
	}
	_ = d.Undefine()
	_ = d.Free()
	// Network and pool absent: fail closed before anything is created.
	bad := e.cfg
	bad.Network = "no-such-net"
	s2 := e.spec
	s2.Network = "no-such-net"
	if err := provision.Provision(ctx, e.ops, bad, e.cat, s2, e.cfg.StateDir, nil); hypervisor.CategoryOf(err) != hypervisor.Unavailable {
		t.Fatalf("missing network: %v", err)
	}
	bad = e.cfg
	bad.Pool = "no-such-pool"
	if err := provision.Provision(ctx, e.ops, bad, e.cat, e.spec, e.cfg.StateDir, nil); hypervisor.CategoryOf(err) != hypervisor.Unavailable {
		t.Fatalf("missing pool: %v", err)
	}
	if p, err := c.LookupStoragePoolByName("default-pool"); err == nil {
		if _, err := p.LookupStorageVolByName(provision.RootVolumeName(e.spec.UUID)); err == nil {
			t.Fatal("a refused provisioning created a volume")
		}
	}
}

func TestResumeAfterEveryStepOnTheTestDriver(t *testing.T) {
	for i, step := range []string{provision.StepRootVolume, provision.StepSeedVolume, provision.StepDomainDefined} {
		e := newEnv(t, "lm-res"+string(rune('a'+i)), "5a5a5a5a-2222-4333-8444-55555555555"+string(rune('a'+i)))
		t.Cleanup(e.cleanup)
		func() {
			defer func() { _ = recover() }()
			_ = provision.Provision(context.Background(), e.ops, e.cfg, e.cat, e.spec, e.cfg.StateDir, func(s string) {
				if s == step {
					panic("simulated helper death")
				}
			})
		}()
		if err := provision.Provision(context.Background(), e.ops, e.cfg, e.cat, e.spec, e.cfg.StateDir, nil); err != nil {
			t.Fatalf("resume after %s: %v", step, err)
		}
		ro, _ := libvirtro.Open(libvirtro.TestURI)
		d, err := ro.Lookup(context.Background(), e.spec.Name)
		ro.Close()
		if err != nil || !d.Managed || d.UUID != e.spec.UUID {
			t.Fatalf("after %s: %+v %v", step, d, err)
		}
	}
}

// TestPlacementReportsWhatTheHostInspectionSees: the path and pool directory come from libvirt, the file facts from an inspection
// that does not follow symlinks, and anything that is not a clean regular file at the volume's own path is refused by
// provision.ResolveVolumeSource (root and seed alike).
func TestPlacementReportsWhatTheHostInspectionSees(t *testing.T) {
	e := newEnv(t, "lm-place", "5a5a5a5a-2222-4333-8444-5555555555ab")
	t.Cleanup(e.cleanup)
	ctx := context.Background()
	if err := provision.Provision(ctx, e.ops, e.cfg, e.cat, e.spec, e.cfg.StateDir, nil); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	link := filepath.Join(dir, "link")
	_ = os.WriteFile(target, nil, 0o600)
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	cases := map[string]struct {
		lstat func(string) (os.FileInfo, error)
		canon func(string) (string, error)
		ok    bool
	}{
		"regular and canonical":  {func(string) (os.FileInfo, error) { return os.Lstat(target) }, func(p string) (string, error) { return p, nil }, true},
		"symlink":                {func(string) (os.FileInfo, error) { return os.Lstat(link) }, func(p string) (string, error) { return p, nil }, false},
		"directory":              {func(string) (os.FileInfo, error) { return os.Lstat(dir) }, func(p string) (string, error) { return p, nil }, false},
		"symlinked ancestor":     {func(string) (os.FileInfo, error) { return os.Lstat(target) }, func(p string) (string, error) { return "/elsewhere/x", nil }, false},
		"canonical lookup fails": {func(string) (os.FileInfo, error) { return os.Lstat(target) }, func(p string) (string, error) { return "", os.ErrPermission }, false},
		"not inspectable":        {func(string) (os.FileInfo, error) { return nil, os.ErrNotExist }, func(p string) (string, error) { return p, nil }, false},
	}
	resolvers := map[string]func(provision.Spec, provision.VolumeInfo) (provision.VolumeSource, error){
		provision.RootVolumeName(e.spec.UUID): provision.ResolveRootSource,
		provision.SeedVolumeName(e.spec.UUID): provision.ResolveSeedSource,
	}
	for vol, resolve := range resolvers {
		for name, c := range cases {
			t.Run(name+"/"+strings.TrimPrefix(vol[strings.LastIndex(vol, "-")+1:], "-"), func(t *testing.T) {
				e.ops.Lstat, e.ops.Canonical = c.lstat, c.canon
				v, err := e.ops.LookupVolume(ctx, e.cfg.Pool, vol)
				if err != nil {
					t.Fatal(err)
				}
				if v.Name != vol || !strings.HasSuffix(v.Path, "/"+vol) || v.PoolPath == "" || v.Path != v.PoolPath+"/"+vol {
					t.Fatalf("placement not taken from libvirt: %+v", v)
				}
				_, rerr := resolve(e.spec, v)
				if c.ok != (rerr == nil) {
					t.Fatalf("ok=%v but resolve said %v for %+v", c.ok, rerr, v)
				}
				if name == "not inspectable" && v.FSChecked {
					t.Error("an uninspectable path was reported as inspected")
				}
			})
		}
	}
}

// TestFileBackedSourcesKeepVolumeOwnership: root and seed are named in the domain as files, yet they are still libvirt storage volumes.
// The names recovered from the stored definition address exactly the two volumes of this VM through the storage-volume API; deleting
// them leaves a neighbouring volume of the same pool alone, and a repeat of the whole create after an unknown outcome adds nothing.
func TestFileBackedSourcesKeepVolumeOwnership(t *testing.T) {
	e := newEnv(t, "lm-own", "6a6a6a6a-2222-4333-8444-5555555555ab")
	t.Cleanup(e.cleanup)
	ctx := context.Background()
	p, err := e.ops.conn.LookupStoragePoolByName(e.cfg.Pool)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = p.Free() }()
	decoy := "svavyom-decoy-neighbour.raw"
	dv, err := p.StorageVolCreateXML("<volume><name>"+decoy+"</name><capacity unit='bytes'>1048576</capacity><target><format type='raw'/></target></volume>", 0)
	if err != nil {
		t.Fatal(err)
	}
	_ = dv.Free()
	t.Cleanup(func() {
		if v, err := p.LookupStorageVolByName(decoy); err == nil {
			_ = v.Delete(0)
			_ = v.Free()
		}
	})
	count := func() int {
		n, err := p.NumOfStorageVolumes()
		if err != nil {
			t.Fatal(err)
		}
		return n
	}
	before := count()
	for i := 0; i < 3; i++ { // first run, then identical repeats: nothing is duplicated
		if err := provision.Provision(ctx, e.ops, e.cfg, e.cat, e.spec, e.cfg.StateDir, nil); err != nil {
			t.Fatalf("provision %d: %v", i, err)
		}
	}
	if got := count(); got != before+2 {
		t.Fatalf("expected exactly two new volumes, pool went from %d to %d", before, got)
	}
	dom, err := e.ops.conn.LookupDomainByName(e.spec.Name)
	if err != nil {
		t.Fatal(err)
	}
	stored, err := dom.GetXMLDesc(libvirt.DOMAIN_XML_INACTIVE)
	_ = dom.Free()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(stored, "volume=") {
		t.Errorf("a pool/volume source remains in the stored definition: %s", stored[strings.Index(stored, "<disk"):strings.LastIndex(stored, "</disk>")])
	}
	d, err := provision.ParseDomain(stored)
	if err != nil || d.Root != provision.RootVolumeName(e.spec.UUID) || d.Seed != provision.SeedVolumeName(e.spec.UUID) {
		t.Fatalf("volume identities not recoverable: %+v %v", d, err)
	}
	for _, name := range []string{d.Root, d.Seed} {
		v, err := p.LookupStorageVolByName(name)
		if err != nil {
			t.Fatalf("recovered name %s is not a libvirt volume: %v", name, err)
		}
		if err := v.Delete(0); err != nil {
			t.Fatal(err)
		}
		_ = v.Free()
	}
	if got := count(); got != before {
		t.Fatalf("after deleting the recovered volumes the pool has %d volumes, want %d", got, before)
	}
	if v, err := p.LookupStorageVolByName(decoy); err != nil {
		t.Fatalf("the neighbouring volume was touched: %v", err)
	} else {
		_ = v.Free()
	}
}

// TestLifecycleOnTheTestDriver runs Stop, Force Off and the ownership-proving Delete through the real libvirt API (the test driver):
// the domain XML libvirt stores is the proof, the two volumes of the VM are removed with it, and a neighbouring volume survives.
// Reboot is not asserted here: the test driver does not restart a guest, so no new boot id can be observed (the real-host
// qualification covers it).
func TestLifecycleOnTheTestDriver(t *testing.T) {
	e := newEnv(t, "lm-life", "5a5a5a5a-2222-4333-8444-5555555555ab")
	t.Cleanup(e.cleanup)
	ctx := context.Background()
	if err := provision.Provision(ctx, e.ops, e.cfg, e.cat, e.spec, e.cfg.StateDir, nil); err != nil {
		t.Fatal(err)
	}
	// A neighbour volume in the same pool: Delete must never touch it.
	p, err := e.ops.conn.LookupStoragePoolByName("default-pool")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = p.Free() }()
	nb, err := p.StorageVolCreateXML("<volume type='file'><name>lm-neighbour.qcow2</name><capacity unit='bytes'>1048576</capacity><target><format type='raw'/></target></volume>", 0)
	if err != nil {
		t.Fatal(err)
	}
	_ = nb.Free()
	t.Cleanup(func() {
		if v, err := p.LookupStorageVolByName("lm-neighbour.qcow2"); err == nil {
			_ = v.Delete(0)
			_ = v.Free()
		}
	})
	if err := provision.Start(ctx, e.ops, "lm-life", nil); err != nil {
		t.Fatal(err)
	}
	if err := provision.Delete(ctx, e.ops, e.cfg, "lm-life", nil); hypervisor.CategoryOf(err) != hypervisor.Conflict {
		t.Fatalf("a running VM is never deleted: %v", err)
	}
	if err := provision.Stop(ctx, e.ops, "lm-life", nil); err != nil {
		t.Fatalf("stop: %v", err)
	}
	if di, err := e.ops.LookupDomain(ctx, "lm-life"); err != nil || di.Running {
		t.Fatalf("stop left it running: %+v %v", di, err)
	}
	if err := provision.Start(ctx, e.ops, "lm-life", nil); err != nil {
		t.Fatal(err)
	}
	if err := provision.ForceOff(ctx, e.ops, "lm-life", nil); err != nil {
		t.Fatalf("force off: %v", err)
	}
	if di, err := e.ops.LookupDomain(ctx, "lm-life"); err != nil || di.Running || len(di.XML) == 0 || di.Root == "" || di.Seed == "" {
		t.Fatalf("%+v %v", di, err)
	}
	if err := provision.Delete(ctx, e.ops, e.cfg, "lm-life", nil); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := e.ops.LookupDomain(ctx, "lm-life"); hypervisor.CategoryOf(err) != hypervisor.NotFound {
		t.Fatalf("the domain must be gone: %v", err)
	}
	for _, vn := range []string{provision.RootVolumeName(e.spec.UUID), provision.SeedVolumeName(e.spec.UUID)} {
		if _, err := e.ops.LookupVolume(ctx, "default-pool", vn); hypervisor.CategoryOf(err) != hypervisor.NotFound {
			t.Fatalf("volume %s must be gone: %v", vn, err)
		}
	}
	if _, err := e.ops.LookupVolume(ctx, "default-pool", "lm-neighbour.qcow2"); err != nil {
		t.Fatalf("the neighbouring volume must survive: %v", err)
	}
}
