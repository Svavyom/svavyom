package simhost_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"

	"golang.org/x/crypto/ssh"

	"example.invalid/dedicatedcloud/backend/internal/hypervisor"
	"example.invalid/dedicatedcloud/backend/internal/provision"
	"example.invalid/dedicatedcloud/backend/internal/provision/provtest"
	"example.invalid/dedicatedcloud/backend/internal/simhost"
)

type rig struct {
	t       *testing.T
	host    *simhost.Host
	counter *counting
	cfg     provision.Config
	cat     *provision.Catalog
	scratch string
	spec    provision.Spec
	image   provision.Image
}

// counting wraps the host to count mutating calls: a retry must never repeat one.
type counting struct {
	*simhost.Host
	rootCreates, seedCreates, defines, starts atomic.Int32
}

func (c *counting) CreateRootVolume(ctx context.Context, p, n string, capb int64, b string) error {
	c.rootCreates.Add(1)
	return c.Host.CreateRootVolume(ctx, p, n, capb, b)
}
func (c *counting) CreateSeedVolume(ctx context.Context, p, n string, capb int64) error {
	c.seedCreates.Add(1)
	return c.Host.CreateSeedVolume(ctx, p, n, capb)
}
func (c *counting) DefineDomain(ctx context.Context, x string) error {
	c.defines.Add(1)
	return c.Host.DefineDomain(ctx, x)
}
func (c *counting) StartDomain(ctx context.Context, n string) error {
	c.starts.Add(1)
	return c.Host.StartDomain(ctx, n)
}

func newRig(t *testing.T) *rig {
	t.Helper()
	root := t.TempDir()
	catDir := filepath.Join(root, "images")
	state := filepath.Join(root, "state")
	for _, d := range []string{catDir, state} {
		if err := os.MkdirAll(d, 0o750); err != nil {
			t.Fatal(err)
		}
	}
	_ = os.Chmod(catDir, 0o750)
	src := filepath.Join(root, "debian.qcow2")
	if err := os.WriteFile(src, provtest.Qcow2("fake image body"), 0o640); err != nil {
		t.Fatal(err)
	}
	im, err := provision.Register(provision.DevPolicy(), catDir, provision.RegisterRequest{ID: "debian-13", DisplayName: "Debian 13", Distribution: "Debian", Version: "13",
		Source: src, LoginUser: "debian", MinDiskGiB: 3, CloudInit: true})
	if err != nil {
		t.Fatal(err)
	}
	cat, err := provision.LoadTrustedCatalog(provision.DevPolicy(), catDir)
	if err != nil {
		t.Fatal(err)
	}
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	sp, _ := ssh.NewPublicKey(pub)
	key, err := provision.NormalizeSSHKey(string(ssh.MarshalAuthorizedKey(sp)))
	if err != nil {
		t.Fatal(err)
	}
	h, err := simhost.New(filepath.Join(root, "sim"))
	if err != nil {
		t.Fatal(err)
	}
	cfg := provision.Config{CatalogDir: catDir, Pool: "svavyom", Network: "svavyom-nat", DomainType: "test", LibvirtURI: "test:///default", StateDir: state}
	return &rig{t: t, host: h, counter: &counting{Host: h}, cfg: cfg, cat: cat, scratch: state, image: im,
		spec: provision.Spec{Name: "web-1", UUID: "1a1a1a1a-2222-4333-8444-5555555555ab", Fingerprint: strings.Repeat("ab", 32), VCPUs: 2, MemoryMiB: 1024,
			ImageID: "debian-13", ImageSHA256: im.SHA256, DiskGiB: 20, SSHPublicKey: key.Authorized, Network: "svavyom-nat"}}
}

func (r *rig) provision(hook provision.Hook) error {
	return provision.Provision(context.Background(), r.counter, r.cfg, r.cat, r.spec, r.scratch, hook)
}

// backing is the catalog-verified declaration of the rig's image.
func (r *rig) backing() provision.BackingImage {
	b, err := r.cat.Backing(r.image)
	if err != nil {
		r.t.Fatal(err)
	}
	return b
}

// root is where the simulation places the VM's root overlay (the same answer simhost gives Provision).
func (r *rig) root(s provision.Spec) provision.DiskSources {
	dir := "/sim/" + r.cfg.Pool
	return provision.DiskSources{
		Root: provision.VolumeSource{Name: provision.RootVolumeName(s.UUID), Path: dir + "/" + provision.RootVolumeName(s.UUID), PoolPath: dir},
		Seed: provision.VolumeSource{Name: provision.SeedVolumeName(s.UUID), Path: dir + "/" + provision.SeedVolumeName(s.UUID), PoolPath: dir},
	}
}

func cat(err error) hypervisor.Category { return hypervisor.CategoryOf(err) }

func TestProvisionCreatesAStoppedManagedVMAndIsIdempotent(t *testing.T) {
	r := newRig(t)
	if err := r.provision(nil); err != nil {
		t.Fatal(err)
	}
	st := r.host.Load()
	d, ok := st.Domains["web-1"]
	if !ok || d.Running || !d.Managed || d.UUID != r.spec.UUID || d.Fingerprint != r.spec.Fingerprint || d.Image != "debian-13" || d.VCPUs != 2 || d.MemoryMiB != 1024 {
		t.Fatalf("%+v", d)
	}
	root := st.Volumes["svavyom/"+provision.RootVolumeName(r.spec.UUID)]
	if root.Capacity != 20<<30 || !strings.HasSuffix(root.Backing, "/"+provision.StoreDir+"/"+r.cat.Images[0].File) {
		t.Fatalf("root volume %+v", root)
	}
	seed := st.Volumes["svavyom/"+provision.SeedVolumeName(r.spec.UUID)]
	if seed.Capacity != provision.SeedCapacityBytes || seed.SeedLen == 0 || seed.SeedSHA == "" {
		t.Fatalf("seed volume %+v", seed)
	}
	if d.Root != provision.RootVolumeName(r.spec.UUID) || d.Seed != provision.SeedVolumeName(r.spec.UUID) {
		t.Fatalf("disks: %+v", d)
	}
	if err := r.provision(nil); err != nil { // running it again changes nothing
		t.Fatal(err)
	}
	if r.counter.rootCreates.Load() != 1 || r.counter.seedCreates.Load() != 1 || r.counter.defines.Load() != 1 {
		t.Fatalf("repeat created things again: %d %d %d", r.counter.rootCreates.Load(), r.counter.seedCreates.Load(), r.counter.defines.Load())
	}
}

type crash struct{}

// provisionCrashingAfter simulates the helper dying right after step: the state files persist, the call is abandoned.
func (r *rig) provisionCrashingAfter(step string) (crashed bool) {
	defer func() {
		if v := recover(); v != nil {
			if _, ok := v.(crash); !ok {
				panic(v)
			}
			crashed = true
		}
	}()
	_ = r.provision(func(s string) {
		if s == step {
			panic(crash{})
		}
	})
	return false
}

func TestProvisionResumesAfterACrashAtEveryStepWithoutDuplicates(t *testing.T) {
	for _, step := range []string{provision.StepImageVerified, provision.StepPreflight, provision.StepRootVolume, provision.StepSeedVolume, provision.StepDomainDefined} {
		t.Run(step, func(t *testing.T) {
			r := newRig(t)
			if !r.provisionCrashingAfter(step) {
				t.Fatal("did not crash")
			}
			if err := r.provision(nil); err != nil { // the retry after recovery
				t.Fatal(err)
			}
			if r.counter.rootCreates.Load() > 1 || r.counter.seedCreates.Load() > 1 || r.counter.defines.Load() > 1 {
				t.Fatalf("a step was repeated: root=%d seed=%d define=%d", r.counter.rootCreates.Load(), r.counter.seedCreates.Load(), r.counter.defines.Load())
			}
			st := r.host.Load()
			if len(st.Volumes) != 2 || len(st.Domains) != 1 || !st.Domains["web-1"].Managed {
				t.Fatalf("final state: %d volumes, %d domains", len(st.Volumes), len(st.Domains))
			}
		})
	}
}

func TestAForeignDomainOfTheSameNameIsAConflictAndNothingIsCreated(t *testing.T) {
	r := newRig(t)
	foreign := r.spec
	foreign.UUID = "2a1a1a1a-2222-4333-8444-5555555555ab"
	foreign.Fingerprint = strings.Repeat("cd", 32)
	x, _ := provision.DomainXML(r.cfg, foreign, r.backing(), r.root(foreign))
	if err := r.host.DefineDomain(context.Background(), x); err != nil {
		t.Fatal(err)
	}
	if err := r.provision(nil); cat(err) != hypervisor.Conflict {
		t.Fatalf("%v", err)
	}
	if len(r.host.Load().Volumes) != 0 || r.counter.rootCreates.Load() != 0 {
		t.Fatal("volumes were created next to a foreign domain")
	}
}

func TestAnUnmanagedDomainOfTheSameNameIsAConflict(t *testing.T) {
	r := newRig(t)
	st := r.host.Load()
	st.Domains["web-1"] = simhost.Domain{UUID: r.spec.UUID, VCPUs: 2, MemoryMiB: 1024} // same uuid but no ownership marker
	_ = r.host.Save(st)
	if err := r.provision(nil); cat(err) != hypervisor.Conflict {
		t.Fatalf("%v", err)
	}
}

func TestForeignOrAlteredVolumesAreConflictsAndNeverOverwritten(t *testing.T) {
	cases := map[string]func(r *rig, st *simhost.State){
		"root with the wrong capacity": func(r *rig, st *simhost.State) {
			st.Volumes["svavyom/"+provision.RootVolumeName(r.spec.UUID)] = simhost.Volume{Capacity: 1 << 30, Backing: "/x"}
		},
		"root with a different backing file": func(r *rig, st *simhost.State) {
			st.Volumes["svavyom/"+provision.RootVolumeName(r.spec.UUID)] = simhost.Volume{Capacity: 20 << 30, Backing: "/etc/passwd"}
		},
		"seed with the wrong capacity": func(r *rig, st *simhost.State) {
			p, _ := r.cat.Path(r.image)
			st.Volumes["svavyom/"+provision.RootVolumeName(r.spec.UUID)] = simhost.Volume{Capacity: 20 << 30, Backing: p}
			st.Volumes["svavyom/"+provision.SeedVolumeName(r.spec.UUID)] = simhost.Volume{Capacity: 5}
		},
	}
	for name, plant := range cases {
		t.Run(name, func(t *testing.T) {
			r := newRig(t)
			st := r.host.Load()
			plant(r, &st)
			_ = r.host.Save(st)
			before := r.host.Load()
			if err := r.provision(nil); cat(err) != hypervisor.Conflict {
				t.Fatalf("%v", err)
			}
			after := r.host.Load()
			if len(after.Volumes) != len(before.Volumes) || len(after.Domains) != 0 {
				t.Fatalf("host changed despite the conflict: %d -> %d volumes, %d domains", len(before.Volumes), len(after.Volumes), len(after.Domains))
			}
			for k, v := range before.Volumes {
				if !reflect.DeepEqual(after.Volumes[k], v) {
					t.Fatalf("volume %s was overwritten", k)
				}
			}
		})
	}
}

func TestMissingNetworkOrPoolFailsClosedBeforeAnyMutation(t *testing.T) {
	for name, set := range map[string]func(*simhost.State){"network": func(s *simhost.State) { s.NetworkDown = true }, "pool": func(s *simhost.State) { s.PoolDown = true }} {
		r := newRig(t)
		st := r.host.Load()
		set(&st)
		_ = r.host.Save(st)
		if err := r.provision(nil); cat(err) != hypervisor.Unavailable {
			t.Fatalf("%s: %v", name, err)
		}
		if got := r.host.Load(); len(got.Volumes) != 0 || len(got.Domains) != 0 {
			t.Fatalf("%s: something was created", name)
		}
		if rd := provision.Preflight(context.Background(), r.host, r.cfg); (name == "network" && rd.Network != "unavailable") || (name == "pool" && rd.Pool != "unavailable") {
			t.Fatalf("%s: %+v", name, rd)
		}
	}
}

func TestImageProblemsAreRefusedBeforeAnyMutation(t *testing.T) {
	mut := map[string]func(r *rig){
		"unknown image":      func(r *rig) { r.spec.ImageID = "nope" },
		"hash moved on":      func(r *rig) { r.spec.ImageSHA256 = strings.Repeat("00", 32) },
		"disk below minimum": func(r *rig) { r.cat.Images[0].MinDiskGiB = 30 },
		"file tampered": func(r *rig) {
			p := filepath.Join(r.cfg.CatalogDir, provision.StoreDir, r.cat.Images[0].File)
			_ = os.Chmod(p, 0o644)
			_ = os.WriteFile(p, provtest.Qcow2("tampered body"), 0o644)
		},
		"file removed":    func(r *rig) { _ = os.Remove(filepath.Join(r.cfg.CatalogDir, provision.StoreDir, r.cat.Images[0].File)) },
		"network differs": func(r *rig) { r.spec.Network = "other-net" },
	}
	for name, f := range mut {
		t.Run(name, func(t *testing.T) {
			r := newRig(t)
			f(r)
			if err := r.provision(nil); err == nil {
				t.Fatal("accepted")
			}
			if got := r.host.Load(); len(got.Volumes) != 0 || len(got.Domains) != 0 {
				t.Fatal("something was created")
			}
		})
	}
	t.Run("disabled image", func(t *testing.T) {
		r := newRig(t)
		r.cat.Images[0].State = provision.StateDisabled
		if err := r.provision(nil); cat(err) != hypervisor.Validation {
			t.Fatalf("%v", err)
		}
	})
}

func TestStartOnlyBootsManagedDomainsAndIsIdempotent(t *testing.T) {
	r := newRig(t)
	if err := r.provision(nil); err != nil {
		t.Fatal(err)
	}
	if err := provision.Start(context.Background(), r.counter, "web-1", nil); err != nil {
		t.Fatal(err)
	}
	rd, _ := simhost.Reader{H: r.host}.Lookup(context.Background(), "web-1")
	if rd.State != hypervisor.StateRunning || rd.IPv4 == "" || !strings.HasPrefix(rd.IPv4, "192.168.122.") || !rd.Managed {
		t.Fatalf("%+v", rd)
	}
	if err := provision.Start(context.Background(), r.counter, "web-1", nil); err != nil || r.counter.starts.Load() != 1 {
		t.Fatalf("second start: %v starts=%d", err, r.counter.starts.Load())
	}
	st := r.host.Load()
	st.Domains["foreign"] = simhost.Domain{UUID: "x"}
	_ = r.host.Save(st)
	if err := provision.Start(context.Background(), r.counter, "foreign", nil); cat(err) != hypervisor.Prohibited {
		t.Fatalf("unmanaged domain: %v", err)
	}
	if err := provision.Start(context.Background(), r.counter, "absent", nil); cat(err) != hypervisor.NotFound {
		t.Fatalf("absent: %v", err)
	}
	if err := provision.Start(context.Background(), r.counter, "../x", nil); cat(err) != hypervisor.Validation {
		t.Fatalf("bad name: %v", err)
	}
	if r.counter.starts.Load() != 1 {
		t.Fatal("a refused start reached the host")
	}
}

func TestDomainXMLCarriesOwnershipAndOnlyServerOwnedReferences(t *testing.T) {
	r := newRig(t)
	x, err := provision.DomainXML(r.cfg, r.spec, r.backing(), r.root(r.spec))
	if err != nil {
		t.Fatal(err)
	}
	for _, must := range []string{"<name>web-1</name>", "<uuid>" + r.spec.UUID + "</uuid>", "fingerprint='" + r.spec.Fingerprint + "'", "image='debian-13'",
		"https://svavyom.invalid/xml/1", "<disk type='file' device='disk'>", "<source file='" + r.root(r.spec).Root.Path + "'/>", "<disk type='file' device='cdrom'>", "<source file='" + r.root(r.spec).Seed.Path + "'/>", "network='svavyom-nat'", "mac address='" + provision.MAC(r.spec.UUID) + "'"} {
		if !strings.Contains(x, must) {
			t.Errorf("XML lacks %q", must)
		}
	}
	// The only file paths in the document are the resolved root overlay, the resolved seed and the managed backing image, the latter
	// declared explicitly and exempt from DAC relabelling. No pool/volume reference remains.
	b := r.backing()
	if !strings.Contains(x, "<source file='"+b.Path+"'>") || !strings.Contains(x, "<seclabel model='dac' relabel='no'/>") || strings.Count(x, "file=") != 3 || strings.Contains(x, "volume=") || strings.Count(x, "relabel='no'") != 1 {
		t.Errorf("explicit backing declaration missing: %s", x)
	}
	// The only graphics device is a VNC console that listens nowhere: no port, no address, no password in the definition (DR-026 D1).
	if strings.Count(x, "<graphics") != 1 || !strings.Contains(x, "<graphics type='vnc'><listen type='none'/></graphics>") || strings.Contains(x, "autoport") || strings.Contains(x, "passwd") {
		t.Errorf("graphics device: %s", x)
	}
	for _, forbidden := range []string{"/var/", "/etc", "<hostdev", "<filesystem", "type='bridge'", "<qemu:commandline", "<script"} {
		if strings.Contains(x, forbidden) {
			t.Errorf("XML contains %q", forbidden)
		}
	}
}

func TestSimHostReaderSeesWhatMutationCreated(t *testing.T) {
	r := newRig(t)
	if err := r.provision(nil); err != nil {
		t.Fatal(err)
	}
	list, _ := simhost.Reader{H: r.host}.List(context.Background())
	if len(list) != 1 || list[0].Name != "web-1" || list[0].State != hypervisor.StateShutoff || list[0].IPv4 != "" || !list[0].Managed {
		t.Fatalf("%+v", list)
	}
	if _, err := (simhost.Reader{H: r.host}).Lookup(context.Background(), "nope"); !errors.Is(err, err) || cat(err) != hypervisor.NotFound {
		t.Fatalf("%v", err)
	}
}

func TestAHalfUploadedSeedIsRepairedNotTrusted(t *testing.T) {
	r := newRig(t)
	// A crash between creating the seed volume and finishing the upload leaves a volume of the right capacity and no content.
	st := r.host.Load()
	p, _ := r.cat.Path(r.image)
	st.Volumes["svavyom/"+provision.RootVolumeName(r.spec.UUID)] = simhost.Volume{Capacity: 20 << 30, Backing: p}
	st.Volumes["svavyom/"+provision.SeedVolumeName(r.spec.UUID)] = simhost.Volume{Capacity: provision.SeedCapacityBytes}
	_ = r.host.Save(st)
	if err := r.provision(nil); err != nil {
		t.Fatal(err)
	}
	if v := r.host.Load().Volumes["svavyom/"+provision.SeedVolumeName(r.spec.UUID)]; v.SeedLen == 0 || v.SeedSHA == "" {
		t.Fatalf("the seed was trusted without content: %+v", v)
	}
	if r.counter.seedCreates.Load() != 0 {
		t.Fatal("an existing seed volume was created again")
	}
}
