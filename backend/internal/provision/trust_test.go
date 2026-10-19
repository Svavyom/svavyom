package provision

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// These tests model the production ownership split without root: the unprivileged test user stands in for the deployment owner
// (root), and the runtime identities (API, agent, mutation) are declared separately. "Writable by a runtime identity" is tested
// as an effective-identity question (owner / group / other evaluation), not only by looking at mode bits.

var (
	myUID = uint32(os.Geteuid()) // #nosec G115
	myGID = uint32(os.Getegid()) // #nosec G115
)

func runtimeIDs() []Identity {
	return []Identity{{Name: "api", UID: 4000, GIDs: []uint32{4100}}, {Name: "agent", UID: 4001, GIDs: []uint32{4101}}, {Name: "mutation", UID: 4002, GIDs: []uint32{4102}}}
}

type deployment struct {
	root, cfgPath, helper, catDir, store, catalog, image string
	cfg                                                  Config
	im                                                   Image
	pol                                                  Policy
}

// newDeployment builds the official layout (config, helper, catalog, store, one published image) as the deployment owner.
func newDeployment(t *testing.T) *deployment {
	t.Helper()
	root := t.TempDir()
	if err := os.Chmod(root, 0o755); err != nil {
		t.Fatal(err)
	}
	d := &deployment{root: root, pol: Policy{Owner: myUID, Runtime: runtimeIDs(), floor: root}}
	for _, dir := range []string{"etc", "libexec", "images"} {
		if err := os.Mkdir(filepath.Join(root, dir), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	d.cfgPath, d.helper, d.catDir = filepath.Join(root, "etc", "provision.json"), filepath.Join(root, "libexec", "mutation-helper"), filepath.Join(root, "images")
	if err := os.WriteFile(d.cfgPath, []byte("{}\n"), 0o644); err != nil { // #nosec G306 -- public configuration, no secrets
		t.Fatal(err)
	}
	if err := os.WriteFile(d.helper, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil { // #nosec G306
		t.Fatal(err)
	}
	im, err := Register(d.pol, d.catDir, reg(source(t, "a.qcow2", qcow2Bytes("official"))))
	if err != nil {
		t.Fatal(err)
	}
	d.im, d.store, d.catalog = im, filepath.Join(d.catDir, StoreDir), filepath.Join(d.catDir, CatalogFile)
	d.image = filepath.Join(d.store, im.File)
	d.cfg = Config{CatalogDir: d.catDir, Pool: "p", Network: "n", DomainType: "test", LibvirtURI: "test:///default", StateDir: filepath.Join(root, "state")}
	return d
}

// refused reports every way the deployment is judged: the supervisor/API deployment check, the helper's trusted catalog load and
// image verification, and the helper executable and configuration checks.
func (d *deployment) refusals(t *testing.T) (all map[string]bool) {
	t.Helper()
	all = map[string]bool{}
	if len(d.pol.CheckDeployment(d.cfgPath, d.cfg)) > 0 {
		all["deployment"] = true
	}
	if d.pol.Asset(d.helper, false) != nil {
		all["helper"] = true
	}
	if cat, err := LoadTrustedCatalog(d.pol, d.catDir); err != nil {
		all["catalog-load"] = true
	} else if _, err := cat.Verify(d.im); err != nil {
		all["verify"] = true
	}
	return all
}

func TestOfficialOperatorOwnedLayoutIsAccepted(t *testing.T) {
	d := newDeployment(t)
	if got := d.refusals(t); len(got) != 0 {
		t.Fatalf("the official root-owned/read-only layout was refused: %v", got)
	}
	// Register published a regular 0444 image and a catalog every runtime identity can read but not write.
	if fi, _ := os.Lstat(d.image); fi.Mode().Perm() != 0o444 {
		t.Fatalf("image mode %v", fi.Mode().Perm())
	}
	if fi, _ := os.Lstat(d.catalog); fi.Mode().Perm() != 0o644 {
		t.Fatalf("catalog mode %v", fi.Mode().Perm())
	}
	if fi, _ := os.Lstat(d.store); fi.Mode().Perm() != 0o755 {
		t.Fatalf("store mode %v", fi.Mode().Perm())
	}
}

func TestProductionRefusesWritableOrRuntimeOwnedTrustAnchors(t *testing.T) {
	chmod := func(p string, m os.FileMode) func(*deployment) {
		return func(*deployment) {
			if err := os.Chmod(p, m); err != nil {
				t.Fatal(err)
			}
		}
	}
	at := func(path func(*deployment) string, m os.FileMode) func(*deployment) {
		return func(d *deployment) { chmod(path(d), m)(d) }
	}
	cfg := func(d *deployment) string { return d.cfgPath }
	helper := func(d *deployment) string { return d.helper }
	catalog := func(d *deployment) string { return d.catalog }
	store := func(d *deployment) string { return d.store }
	catDir := func(d *deployment) string { return d.catDir }
	image := func(d *deployment) string { return d.image }
	etc := func(d *deployment) string { return filepath.Dir(d.cfgPath) }
	libexec := func(d *deployment) string { return filepath.Dir(d.helper) }
	cases := []struct {
		name  string
		setup func(*deployment)
		want  string // which judgement must refuse
	}{
		{"helper writable by others (any runtime identity)", at(helper, 0o757), "helper"},
		{"helper writable by its group", at(helper, 0o775), "helper"},
		{"provisioning config writable by others", at(cfg, 0o646), "deployment"},
		{"provisioning config group-writable", at(cfg, 0o664), "deployment"},
		{"catalog writable by the API (others)", at(catalog, 0o666), "deployment"},
		{"catalog group-writable", at(catalog, 0o664), "catalog-load"},
		{"image store directory writable by others", at(store, 0o777), "deployment"},
		{"image store directory group-writable", at(store, 0o775), "verify"},
		{"catalog directory writable by others", at(catDir, 0o777), "deployment"},
		{"published image writable by owner-only mode is not read-only", at(image, 0o644), "verify"},
		{"published image replaceable: world-writable", at(image, 0o666), "deployment"},
		{"config directory writable by others (file can be swapped)", at(etc, 0o777), "deployment"},
		{"helper directory writable by others (helper can be swapped)", at(libexec, 0o777), "helper"},
		{"helper directory group-writable", at(libexec, 0o775), "helper"},
		{"grandparent writable by others", func(d *deployment) { chmod(d.root, 0o777)(d) }, "deployment"},
		{"helper is a symlink", func(d *deployment) { replaceWithSymlink(t, d.helper) }, "helper"},
		{"config is a symlink", func(d *deployment) { replaceWithSymlink(t, d.cfgPath) }, "deployment"},
		{"catalog is a symlink", func(d *deployment) { replaceWithSymlink(t, d.catalog) }, "catalog-load"},
		{"store is a symlink", func(d *deployment) { replaceDirWithSymlink(t, d.store) }, "verify"},
		{"image is a symlink", func(d *deployment) { replaceWithSymlink(t, d.image) }, "verify"},
		{"store directory has a sticky world-writable parent", func(d *deployment) { chmod(d.catDir, 0o777|os.ModeSticky)(d) }, "deployment"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d := newDeployment(t)
			c.setup(d)
			if got := d.refusals(t); !got[c.want] {
				t.Fatalf("not refused by %q (refusals: %v)", c.want, got)
			}
		})
	}
}

func replaceWithSymlink(t *testing.T, p string) {
	t.Helper()
	target := filepath.Join(filepath.Dir(p), ".real")
	if err := os.Rename(p, target); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, p); err != nil {
		t.Fatal(err)
	}
}

func replaceDirWithSymlink(t *testing.T, p string) { replaceWithSymlink(t, p) }

// The decisive cases: the ownership itself, not a mode bit. The unprivileged test user is both the owner of the files and, in
// each case, a declared runtime identity or a member of one's group. Mode bits alone would accept 0755/0444; identity rules refuse.
func TestRuntimeIdentitiesMustNotOwnOrBeGroupMembersOfTrustAnchors(t *testing.T) {
	for _, role := range []string{"api", "agent", "mutation"} {
		t.Run(role+" identity owns the anchors", func(t *testing.T) {
			d := newDeployment(t)
			rt := slices.Clone(runtimeIDs())
			for i := range rt {
				if rt[i].Name == role {
					rt[i].UID = myUID // this runtime identity IS the owner of every file in the tree
				}
			}
			d.pol = Policy{Owner: myUID + 1, Runtime: rt, floor: d.root} // deployment owner is someone else (root)
			got := d.refusals(t)
			for _, k := range []string{"deployment", "helper", "catalog-load"} {
				if !got[k] {
					t.Fatalf("%s: owned by the %s identity, but judgement %q accepted it (%v)", role, role, k, got)
				}
			}
		})
		t.Run(role+" identity cannot rewrite even with every mode bit correct", func(t *testing.T) {
			d := newDeployment(t)
			rt := slices.Clone(runtimeIDs())
			for i := range rt {
				if rt[i].Name == role {
					rt[i].UID = myUID
				}
			}
			d.pol = Policy{Owner: myUID, Runtime: rt, floor: d.root} // owner == runtime identity: owner can chmod, so refuse
			if got := d.refusals(t); !got["deployment"] || !got["helper"] {
				t.Fatalf("%s: a runtime identity equal to the owner was accepted (%v)", role, got)
			}
		})
	}
}

func TestRuntimeCanWriteEvaluatesOwnerGroupAndOther(t *testing.T) {
	d := newDeployment(t)
	fi := func(m os.FileMode) os.FileInfo {
		if err := os.Chmod(d.cfgPath, m); err != nil {
			t.Fatal(err)
		}
		st, _ := os.Lstat(d.cfgPath)
		return st
	}
	mine := Policy{Owner: myUID + 1, Runtime: []Identity{{Name: "mutation", UID: 4002, GIDs: []uint32{myGID}}}}
	if !mine.runtimeCanWrite(fi(0o664)) {
		t.Error("a group member must be able to write a group-writable file")
	}
	if mine.runtimeCanWrite(fi(0o644)) {
		t.Error("a group member cannot write a file that is not group-writable (other write not set)")
	}
	if !mine.runtimeCanWrite(fi(0o666)) || !(Policy{Runtime: []Identity{{UID: 4000}}}).runtimeCanWrite(fi(0o602)) {
		t.Error("world-writable must be writable by every identity")
	}
	if (Policy{Runtime: []Identity{{UID: 4000}}}).runtimeCanWrite(fi(0o664)) {
		t.Error("a non-member must not write a group-writable file")
	}
	if !(Policy{Runtime: []Identity{{UID: myUID}}}).runtimeCanWrite(fi(0o400)) {
		t.Error("an owner can chmod and therefore always counts as able to write")
	}
}

func TestSymlinkedTrustAnchorsAreRefusedByEveryPolicy(t *testing.T) {
	d := newDeployment(t)
	replaceWithSymlink(t, d.helper)
	for _, p := range []Policy{d.pol, DevPolicy()} {
		if p.Asset(d.helper, false) == nil {
			t.Fatalf("symlinked helper accepted by %+v", p.Insecure())
		}
	}
}

func TestProductionNeverRestsOnTmpStickySemantics(t *testing.T) {
	d := newDeployment(t)
	sticky := filepath.Join(d.root, "sticky")
	_ = os.Mkdir(sticky, 0o755)
	_ = os.Chmod(sticky, 0o777|os.ModeSticky)
	child := filepath.Join(sticky, "c")
	_ = os.Mkdir(child, 0o755)
	f := filepath.Join(child, "f")
	_ = os.WriteFile(f, []byte("x"), 0o644)
	if err := d.pol.Asset(f, false); err == nil {
		t.Fatal("production accepted an anchor under a sticky world-writable directory (/tmp semantics)")
	}
	dev := DevPolicy()
	if err := dev.Asset(f, false); err != nil {
		t.Fatalf("the insecure development policy keeps accepting a sticky ancestor for isolated tests: %v", err)
	}
	if !dev.Insecure() || d.pol.Insecure() {
		t.Fatal("only the development policy may report itself insecure")
	}
}

func TestImageAdministrationIsOperatorOnly(t *testing.T) {
	d := newDeployment(t)
	notOwner := d.pol
	notOwner.Owner = myUID + 1 // as if this process were not root
	if _, err := Register(notOwner, d.catDir, RegisterRequest{ID: "second", DisplayName: "Second", Distribution: "D", Version: "1", Source: source(t, "b.qcow2", qcow2Bytes("b")), LoginUser: "u", MinDiskGiB: 3}); !errors.Is(err, ErrNotAdministrator) {
		t.Fatalf("register-image by a non-owner identity: %v", err)
	}
	if _, err := SetState(notOwner, d.catDir, d.im.ID, StateDisabled, ""); !errors.Is(err, ErrNotAdministrator) {
		t.Fatalf("image-state by a non-owner identity: %v", err)
	}
	if _, err := SetState(d.pol, d.catDir, d.im.ID, StateDisabled, ""); err != nil {
		t.Fatalf("the deployment owner may change image state: %v", err)
	}
	// The runtime path (trusted load) never rewrites anything: the catalog bytes are unchanged by a load and a verify.
	before, _ := os.ReadFile(d.catalog)
	if cat, err := LoadTrustedCatalog(d.pol, d.catDir); err != nil {
		t.Fatal(err)
	} else if _, err := cat.Verify(cat.Images[0]); err != nil {
		t.Fatal(err)
	}
	if after, _ := os.ReadFile(d.catalog); string(after) != string(before) {
		t.Fatal("a runtime load changed the catalog")
	}
}

func TestTrustPolicyFromConfiguration(t *testing.T) {
	ok := Config{CatalogDir: "/var/lib/svavyom/images", Pool: "p", Network: "n", DomainType: "kvm", LibvirtURI: "qemu:///system", StateDir: "/var/lib/svavyom/state",
		Trust: &TrustSpec{DeployUID: 0, Runtime: []TrustIdentity{{Name: "api", UID: 990}, {Name: "agent", UID: 991}, {Name: "mutation", UID: 992, GIDs: []uint32{993}}}}}
	if p, err := ok.TrustPolicy(false); err != nil || p.Owner != 0 || len(p.Runtime) != 3 || p.Insecure() {
		t.Fatalf("%+v %v", p, err)
	}
	// The console broker, when the deployment has one, is a fourth declared identity (and the packaged template declares it).
	withConsole := ok
	withConsole.Trust = &TrustSpec{DeployUID: 0, Runtime: append(append([]TrustIdentity(nil), ok.Trust.Runtime...), TrustIdentity{Name: "console", UID: 994, GIDs: []uint32{995, 993}})}
	if p, err := withConsole.TrustPolicy(false); err != nil || len(p.Runtime) != 4 {
		t.Fatalf("a declared console identity must be accepted: %+v %v", p, err)
	}
	bad := map[string]func(*Config){
		"console without the three": func(c *Config) {
			c.Trust = &TrustSpec{Runtime: []TrustIdentity{{Name: "api", UID: 990}, {Name: "console", UID: 994}, {Name: "mutation", UID: 992}}}
		},
		"two consoles": func(c *Config) {
			c.Trust = &TrustSpec{Runtime: append(append([]TrustIdentity(nil), ok.Trust.Runtime...), TrustIdentity{Name: "console", UID: 994}, TrustIdentity{Name: "console", UID: 995})}
		},
		"console is owner": func(c *Config) {
			c.Trust = &TrustSpec{Runtime: append(append([]TrustIdentity(nil), ok.Trust.Runtime...), TrustIdentity{Name: "console", UID: 0})}
		},
		"missing":            func(c *Config) { c.Trust = nil },
		"kvm owner not root": func(c *Config) { c.Trust = &TrustSpec{DeployUID: 5, Runtime: ok.Trust.Runtime} },
		"mutation is owner": func(c *Config) {
			c.Trust = &TrustSpec{DeployUID: 0, Runtime: []TrustIdentity{{Name: "api", UID: 990}, {Name: "agent", UID: 991}, {Name: "mutation", UID: 0}}}
		},
		"duplicate name": func(c *Config) {
			c.Trust = &TrustSpec{Runtime: []TrustIdentity{{Name: "api", UID: 990}, {Name: "api", UID: 991}, {Name: "mutation", UID: 992}}}
		},
		"unknown name": func(c *Config) {
			c.Trust = &TrustSpec{Runtime: []TrustIdentity{{Name: "api", UID: 990}, {Name: "agent", UID: 991}, {Name: "web", UID: 992}}}
		},
		"missing identity": func(c *Config) { c.Trust = &TrustSpec{Runtime: ok.Trust.Runtime[:2]} },
	}
	for name, mut := range bad {
		c := ok
		mut(&c)
		if _, err := c.TrustPolicy(false); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	noTrust := ok
	noTrust.Trust, noTrust.DomainType, noTrust.LibvirtURI = nil, "test", "test:///default"
	if _, err := noTrust.TrustPolicy(false); err == nil {
		t.Error("production policy built without a trust declaration")
	}
	if p, err := noTrust.TrustPolicy(true); err != nil || !p.Insecure() {
		t.Errorf("the explicit development flag must select the insecure policy: %v", err)
	}
}

func TestOldCatalogSchemaGivesAnOperatorInstruction(t *testing.T) {
	dir := catalogDir(t)
	if err := os.WriteFile(filepath.Join(dir, CatalogFile), []byte(`{"schema":1,"images":[{"id":"old","unknown_v5_field":true}]}`), 0o644); err != nil { // #nosec G306
		t.Fatal(err)
	}
	_, err := LoadCatalog(dir)
	if !errors.Is(err, ErrCatalogSchema) || !errors.Is(err, ErrCatalog) || !strings.Contains(err.Error(), "register-image") {
		t.Fatalf("a V5 catalog must fail with the re-import instruction, got %v", err)
	}
}

// Anchors owned by an identity that is neither the deployment owner nor a declared runtime identity are refused as well: the
// owner must be exactly the deployment owner (root).
func TestProductionRequiresTheExactDeploymentOwner(t *testing.T) {
	d := newDeployment(t)
	d.pol = Policy{Owner: myUID + 1, Runtime: runtimeIDs(), floor: d.root} // the files are owned by this user, not by "root"
	got := d.refusals(t)
	for _, k := range []string{"deployment", "helper", "catalog-load"} {
		if !got[k] {
			t.Fatalf("judgement %q accepted anchors that the deployment owner does not own (%v)", k, got)
		}
	}
	if d.pol.File(d.image, true) == nil || d.pol.Dir(d.store) == nil {
		t.Fatal("image or store accepted although not owned by the deployment owner")
	}
}

// TestThePackagedProvisioningTemplateIsAValidTrustDeclaration renders packages/ubuntu/etc/provision.json.in with plausible identities and requires
// LoadConfig and TrustPolicy to accept it: the deployment package and the services must agree on who the runtime identities are.
func TestThePackagedProvisioningTemplateIsAValidTrustDeclaration(t *testing.T) {
	raw, err := os.ReadFile("../../../packages/ubuntu/etc/provision.json.in")
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	for k, v := range map[string]string{"@SVAVYOM_API_UID@": "987", "@SVAVYOM_API_GID@": "987", "@SVAVYOM_RO_UID@": "986", "@SVAVYOM_RO_GID@": "986", "@SVAVYOM_MUT_UID@": "985",
		"@SVAVYOM_MUT_GID@": "985", "@SVAVYOM_CON_UID@": "984", "@SVAVYOM_CON_GID@": "984", "@LIBVIRT_GID@": "113"} {
		text = strings.ReplaceAll(text, k, v)
	}
	if strings.Contains(text, "@") {
		t.Fatalf("an unreplaced placeholder remains: %s", text)
	}
	path := filepath.Join(t.TempDir(), "provision.json")
	if err := os.WriteFile(path, []byte(text), 0o644); err != nil {
		t.Fatal(err)
	}
	c, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("the packaged configuration is refused by the loader: %v", err)
	}
	p, err := c.TrustPolicy(false)
	if err != nil || len(p.Runtime) != 4 || p.Owner != 0 {
		t.Fatalf("the packaged trust declaration is refused: %+v %v", p, err)
	}
}
