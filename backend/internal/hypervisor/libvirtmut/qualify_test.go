//go:build libvirt && libvirt_test

package libvirtmut

// REAL-HOST create qualification (docs/QUALIFICATION-LIBVIRT-CREATE.md). It does nothing unless SVAVYOM_QUALIFY_CREATE=1, so
// `make check` never runs it. Two stages, both keyed by one qualification RUN ID (qr-YYYYMMDD-xxxxxx):
//
//	create   (default) provisions ONE VM with the production code path against the real qemu:///system, forces an interrupted
//	         provision and recovers it, starts the VM and waits for a DHCP lease. Writes SVAVYOM_QUALIFY_OUT/result.json.
//	cleanup  removes the resources of that run, and only those whose Svavyom ownership it can prove; otherwise it stops and says
//	         that manual cleanup is required. It never deletes by name alone. This is qualification-harness code only: the
//	         product has no Delete.
//
// Guest-side checks (cloud-init consumed the seed, the login user exists, the supplied key authenticates) cannot run in this
// network-less container; tools/qualify_create.py runs them on the host with an operator-supplied disposable private key that
// never enters the container, the repository, the logs or the report. Evidence lines start with "QUALIFY ".

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	libvirt "libvirt.org/go/libvirt"

	"example.invalid/dedicatedcloud/backend/internal/hypervisor"
	"example.invalid/dedicatedcloud/backend/internal/hypervisor/libvirtro"
	"example.invalid/dedicatedcloud/backend/internal/provision"
)

var runIDRE = regexp.MustCompile(`^qr-[0-9]{8}-[0-9a-f]{6}$`)

// qualIdentity derives every identifier of a run from its run ID, so ownership of what a run created can be PROVEN later
// (recomputed) instead of guessed from a name.
func qualIdentity(runID string) (name, uuid, fingerprint string, err error) {
	if !runIDRE.MatchString(runID) {
		return "", "", "", fmt.Errorf("run id must look like qr-YYYYMMDD-xxxxxx")
	}
	s := sha256.Sum256([]byte("svavyom-qualify-uuid-v1:" + runID))
	b := s[:16]
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	h := hex.EncodeToString(b)
	uuid = h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
	f := sha256.Sum256([]byte("svavyom-qualify-fingerprint-v1:" + runID))
	return "svq-" + strings.TrimPrefix(runID, "qr-"), uuid, hex.EncodeToString(f[:]), nil
}

func TestQualificationIdentityIsDerivedFromTheRunID(t *testing.T) {
	n1, u1, f1, err := qualIdentity("qr-20261012-a1b2c3")
	if err != nil {
		t.Fatal(err)
	}
	n2, u2, f2, _ := qualIdentity("qr-20261012-a1b2c3")
	n3, u3, f3, _ := qualIdentity("qr-20261012-a1b2c4")
	if n1 != n2 || u1 != u2 || f1 != f2 {
		t.Fatal("not deterministic: a rerun of the same run must resume, not duplicate")
	}
	if n1 == n3 || u1 == u3 || f1 == f3 {
		t.Fatal("two runs share an identifier")
	}
	if !provision.VMNameRE.MatchString(n1) || !strings.Contains(n1, "20261012-a1b2c3") {
		t.Fatalf("name %q", n1)
	}
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	sp, _ := ssh.NewPublicKey(pub)
	k, err := provision.NormalizeSSHKey(string(ssh.MarshalAuthorizedKey(sp)))
	if err != nil {
		t.Fatal(err)
	}
	spec := provision.Spec{Name: n1, UUID: u1, Fingerprint: f1, VCPUs: 1, MemoryMiB: 1024, ImageID: "x", ImageSHA256: strings.Repeat("a", 64), DiskGiB: 10,
		SSHPublicKey: k.Authorized, Network: "n"}
	if err := spec.Validate(); err != nil {
		t.Fatalf("a derived identity must be a valid Spec identity: %v", err)
	}
	for _, bad := range []string{"", "qr-1", "x-20261012-a1b2c3", "qr-20261012-A1B2C3", "qr-20261012-a1b2c3/../x"} {
		if _, _, _, err := qualIdentity(bad); err == nil {
			t.Errorf("run id %q accepted", bad)
		}
	}
}

type criterion struct {
	ID     string `json:"id"`
	Status string `json:"status"` // PASS | FAIL | NOT_RUN
	Detail string `json:"detail,omitempty"`
}

type result struct {
	RunID      string            `json:"run_id"`
	Stage      string            `json:"stage"`
	VMName     string            `json:"vm_name,omitempty"`
	UUID       string            `json:"uuid,omitempty"`
	RootVolume string            `json:"root_volume,omitempty"`
	SeedVolume string            `json:"seed_volume,omitempty"`
	IPv4       string            `json:"ipv4,omitempty"`
	LoginUser  string            `json:"login_user,omitempty"`
	ImageID    string            `json:"image_id,omitempty"`
	Criteria   []criterion       `json:"criteria"`
	Host       map[string]string `json:"host,omitempty"`
}

type recorder struct {
	t   *testing.T
	res *result
	out string
}

func (r *recorder) add(id, status, detail string) {
	r.res.Criteria = append(r.res.Criteria, criterion{ID: id, Status: status, Detail: detail})
	fmt.Printf("QUALIFY %s %s %s\n", status, id, detail)
}

func (r *recorder) pass(id, detail string) { r.add(id, "PASS", detail) }
func (r *recorder) fail(id, detail string) { r.add(id, "FAIL", detail) }

func (r *recorder) flush() {
	if r.out == "" {
		return
	}
	b, _ := json.MarshalIndent(r.res, "", "  ")
	_ = os.WriteFile(filepath.Join(r.out, r.res.Stage+"-result.json"), append(b, '\n'), 0o644) // #nosec G306 -- non-secret qualification result
}

func (r *recorder) failed() bool {
	for _, c := range r.res.Criteria {
		if c.Status == "FAIL" {
			return true
		}
	}
	return false
}

func qualEnv(t *testing.T) (cfg provision.Config, pol provision.Policy, rec *recorder, name, uuid, fp string) {
	t.Helper()
	if os.Getenv("SVAVYOM_QUALIFY_CREATE") != "1" {
		t.Skip("NOT_RUN: set SVAVYOM_QUALIFY_CREATE=1 on an authorised disposable host (docs/QUALIFICATION-LIBVIRT-CREATE.md)")
	}
	runID := os.Getenv("SVAVYOM_QUALIFY_RUN_ID")
	name, uuid, fp, err := qualIdentity(runID)
	if err != nil {
		t.Fatalf("SVAVYOM_QUALIFY_RUN_ID: %v", err)
	}
	cfgPath := os.Getenv("SVAVYOM_QUALIFY_CONFIG")
	cfg, err = provision.LoadConfig(cfgPath)
	if err != nil || cfg.DomainType != "kvm" || cfg.LibvirtURI != SystemURI {
		t.Fatalf("SVAVYOM_QUALIFY_CONFIG must name a valid kvm/qemu:///system provisioning config: %v", err)
	}
	pol, err = cfg.TrustPolicy(false) // the real trust model: no development escape in a qualification run
	if err != nil {
		t.Fatalf("the configuration has no valid trust declaration: %v", err)
	}
	rec = &recorder{t: t, out: os.Getenv("SVAVYOM_QUALIFY_OUT"), res: &result{RunID: runID, VMName: name, UUID: uuid, RootVolume: provision.RootVolumeName(uuid), SeedVolume: provision.SeedVolumeName(uuid), Host: map[string]string{}}}
	return cfg, pol, rec, name, uuid, fp
}

// resourcesOf counts what exists for one VM identity in the real libvirt: domains by name AND by UUID, volumes by their derived
// names. Duplicates (or a foreign resource under our name) show up here.
func resourcesOf(o *Ops, pool, name, uuid string) (domains, volumes int, err error) {
	doms, err := o.conn.ListAllDomains(0)
	if err != nil {
		return 0, 0, err
	}
	for i := range doms {
		n, _ := doms[i].GetName()
		u, _ := doms[i].GetUUIDString()
		if n == name || strings.EqualFold(u, uuid) {
			domains++
		}
		_ = doms[i].Free()
	}
	p, err := o.conn.LookupStoragePoolByName(pool)
	if err != nil {
		return 0, 0, err
	}
	defer func() { _ = p.Free() }()
	vols, err := p.ListAllStorageVolumes(0)
	if err != nil {
		return 0, 0, err
	}
	for i := range vols {
		n, _ := vols[i].GetName()
		if strings.Contains(n, uuid) {
			volumes++
		}
		_ = vols[i].Free()
	}
	return domains, volumes, nil
}

// anchorFile is the base-image record the create stage writes and the cleanup stage compares against.
const anchorFile = "image-anchor.json"

// anchorWantFor is what the trust model requires of the catalog image: root:root (the deployment owner), 0444, regular, not a
// symlink, at its canonical store path, with the catalog's size and digest.
func anchorWantFor(pol provision.Policy, cat *provision.Catalog, img provision.Image) (provision.AnchorWant, error) {
	p, err := cat.Path(img)
	if err != nil {
		return provision.AnchorWant{}, err
	}
	return provision.AnchorWant{Path: p, UID: pol.Owner, GID: 0, SHA256: img.SHA256, Size: img.SizeBytes}, nil
}

// checkAnchor judges the base image now (against the trust model and, when base is given, against the earlier record) and returns
// the observed record and a one-line evidence string.
func checkAnchor(want provision.AnchorWant, base *provision.Anchor) (provision.Anchor, string, error) {
	a, err := provision.CheckAnchor(want, base)
	return a, a.String(), err
}

var ctrlRE = regexp.MustCompile(`[^\x09\x0a\x20-\x7e]`)

// scrub bounds and cleans diagnostic text before it is stored: control characters removed, PEM private-key blocks and obvious
// credential assignments replaced. The harness never reads a private key; this is defence in depth for libvirt/QEMU text.
func scrub(s string) string {
	s = regexp.MustCompile(`(?s)-----BEGIN [A-Z ]*PRIVATE KEY-----.*?(-----END [A-Z ]*PRIVATE KEY-----|$)`).ReplaceAllString(s, "[private key removed]")
	s = regexp.MustCompile(`(?i)(password|passwd|secret|token)=\S+`).ReplaceAllString(s, "$1=[removed]")
	s = ctrlRE.ReplaceAllString(s, "?")
	if len(s) > 16<<10 {
		s = s[:16<<10] + "\n[truncated]"
	}
	return s
}

// evidence stores one non-secret evidence file in the qualification output directory.
func (r *recorder) evidence(name, body string) {
	if r.out == "" {
		return
	}
	_ = os.WriteFile(filepath.Join(r.out, name), []byte(scrub(body)+"\n"), 0o644) // #nosec G306 -- non-secret qualification evidence
}

// domainXML returns the domain definition libvirt holds ("" when the domain is not readable).
func domainXML(o *Ops, name string, flags libvirt.DomainXMLFlags) string {
	dom, err := o.conn.LookupDomainByName(name)
	if err != nil {
		return ""
	}
	defer func() { _ = dom.Free() }()
	x, err := dom.GetXMLDesc(flags)
	if err != nil {
		return ""
	}
	return x
}

// volumePaths returns the filesystem paths libvirt resolves for the run's own root and seed volumes, one "name path" line each. The
// host stage feeds the root path to qemu-img to capture the real backing chain (CT-PRODUCT-DELIVERY-008 addendum).
func volumePaths(o *Ops, pool, uuid string) string {
	p, err := o.conn.LookupStoragePoolByName(pool)
	if err != nil {
		return "(pool not readable)"
	}
	defer func() { _ = p.Free() }()
	var b strings.Builder
	for _, vn := range []string{provision.RootVolumeName(uuid), provision.SeedVolumeName(uuid)} {
		v, err := p.LookupStorageVolByName(vn)
		if err != nil {
			fmt.Fprintf(&b, "%s (not found)\n", vn)
			continue
		}
		path, perr := v.GetPath()
		_ = v.Free()
		if perr != nil {
			fmt.Fprintf(&b, "%s (path not readable)\n", vn)
			continue
		}
		fmt.Fprintf(&b, "%s %s\n", vn, path)
	}
	return b.String()
}

func TestSystemCreateQualification(t *testing.T) {
	cfg, pol, rec, name, uuid, fp := qualEnv(t)
	if os.Getenv("SVAVYOM_QUALIFY_STAGE") == "cleanup" {
		t.Skip("cleanup stage selected")
	}
	rec.res.Stage = "create"
	defer rec.flush()
	keyBytes, err := os.ReadFile(os.Getenv("SVAVYOM_QUALIFY_SSH_PUBKEY_FILE")) // #nosec G304 -- operator-supplied PUBLIC key
	if err != nil {
		t.Fatal(err)
	}
	key, err := provision.NormalizeSSHKey(string(keyBytes))
	if err != nil {
		t.Fatalf("the qualification key must be one acceptable public key: %v", err)
	}
	ctx := context.Background()

	// Deployment trust (the same check the services run), then the catalog image.
	if bad := pol.CheckDeployment(os.Getenv("SVAVYOM_QUALIFY_CONFIG"), cfg); len(bad) > 0 {
		rec.fail("trust-layout", "not operator-owned and read-only for the runtime identities: "+strings.Join(bad, ", "))
		t.Fatal("trust layout")
	}
	rec.pass("trust-layout", "config, catalog, store and images are operator-owned")
	cat, err := provision.LoadTrustedCatalog(pol, cfg.CatalogDir)
	if err != nil {
		rec.fail("managed-image", fmt.Sprint(err))
		t.Fatal(err)
	}
	img, err := cat.Usable(os.Getenv("SVAVYOM_QUALIFY_IMAGE_ID"))
	if err != nil {
		rec.fail("managed-image", fmt.Sprint(err))
		t.Fatal(err)
	}
	if _, err := cat.Verify(img); err != nil {
		rec.fail("managed-image", "digest verification failed")
		t.Fatal(err)
	}
	rec.res.ImageID, rec.res.LoginUser = img.ID, img.LoginUser
	rec.pass("managed-image", fmt.Sprintf("image %s sha256=%s state=%s", img.ID, img.SHA256, img.State))

	// The immutable trust anchor of every overlay (CT-PRODUCT-DELIVERY-008): record it before anything exists, and require the
	// production shape now: root:root, 0444, regular, not a symlink, canonical store path, catalog size and digest.
	want, err := anchorWantFor(pol, cat, img)
	if err != nil {
		rec.fail("image-immutable-before", "managed image path not resolvable")
		t.Fatal(err)
	}
	baseline, line, err := checkAnchor(want, nil)
	if err != nil {
		rec.fail("image-immutable-before", fmt.Sprintf("the base image is not the required root-owned read-only image BEFORE any domain exists: %v; %s", err, line))
		t.Fatal(err)
	}
	if b, err := json.MarshalIndent(baseline, "", "  "); err == nil && rec.out != "" {
		_ = os.WriteFile(filepath.Join(rec.out, anchorFile), append(b, '\n'), 0o644) // #nosec G306 -- non-secret record: path, ids, mode, size, digest
	}
	backing, err := cat.Backing(img)
	if err != nil {
		rec.fail("managed-image", "no verified canonical backing declaration for the managed image")
		t.Fatal(err)
	}

	ops, err := Open(SystemURI)
	if err != nil {
		rec.fail("real-libvirt", "cannot open qemu:///system read-write")
		t.Fatal(err)
	}
	defer ops.Close()
	var raw []string // raw libvirt text of failed define/start: harness evidence only, never product output
	ops.Diag = func(op, detail string) { raw = append(raw, op+": "+detail) }
	typ, terr := ops.conn.GetType()
	if uri, uerr := ops.conn.GetURI(); terr != nil || uerr != nil || typ != "QEMU" || uri != SystemURI {
		rec.fail("real-libvirt", fmt.Sprintf("connected hypervisor type=%q uri=%q", typ, uri))
		t.Fatal("not a real QEMU system connection")
	}
	if ver, err := ops.conn.GetLibVersion(); err == nil {
		rec.res.Host["libvirt_version"] = fmt.Sprint(ver)
	}
	if _, err := ops.conn.GetDomainCapabilities("", "", "", "kvm", 0); err != nil {
		rec.fail("kvm-capable", "libvirt reports no usable kvm domain capabilities")
		t.Fatal(err)
	}
	rec.pass("real-libvirt", "qemu:///system, driver QEMU")
	r := provision.Preflight(ctx, ops, cfg)
	if r.Network != "available" || r.Pool != "available" {
		rec.fail("host-ready", fmt.Sprintf("network=%s pool=%s", r.Network, r.Pool))
		t.Fatalf("host not ready: %+v", r)
	}
	rec.pass("host-ready", fmt.Sprintf("network=%s pool=%s", r.Network, r.Pool))

	scratch := t.TempDir()
	spec := provision.Spec{Name: name, UUID: uuid, Fingerprint: fp, VCPUs: 1, MemoryMiB: 1024, ImageID: img.ID, ImageSHA256: img.SHA256, DiskGiB: 10, SSHPublicKey: key.Authorized, Network: cfg.Network}

	// Forced unknown outcome: the first provision "crashes" after the seed volume (goroutine terminated from the step hook, so
	// the host is left half built exactly as a killed helper would leave it). The recovery must finish the SAME VM.
	crashed := make(chan struct{})
	go func() {
		defer close(crashed)
		_ = provision.Provision(ctx, ops, cfg, cat, spec, scratch, func(step string) {
			if step == provision.StepSeedVolume {
				runtime.Goexit()
			}
		})
	}()
	<-crashed
	// Root and seed are named in the domain by the paths libvirt resolved for the volumes Svavyom just created (CT-008 addendum 009 and
	// its seed addendum). Resolve both exactly as Provision does and record, for each, the logical volume name, the path, the pool
	// directory and the inspection result, whatever the verdict.
	rootName, seedName := provision.RootVolumeName(uuid), provision.SeedVolumeName(uuid)
	var placement strings.Builder
	look := func(vol string, resolve func(provision.Spec, provision.VolumeInfo) (provision.VolumeSource, error)) (provision.VolumeSource, bool) {
		v, lerr := ops.LookupVolume(ctx, cfg.Pool, vol)
		fmt.Fprintf(&placement, "volume=%s lookup_err=%v\nlibvirt_name=%s path=%s pool_path=%s\ninspected=%t regular=%t symlink=%t canonical=%t\n\n",
			vol, lerr, v.Name, v.Path, v.PoolPath, v.FSChecked, v.Regular, v.Symlink, v.Canonical)
		src, rerr := resolve(spec, v)
		id := "root-source-resolved"
		if vol == seedName {
			id = "seed-source-resolved"
		}
		if lerr != nil || rerr != nil {
			rec.fail(id, fmt.Sprintf("volume %s: resolved path %q in pool directory %q, inspected=%t regular=%t symlink=%t canonical=%t (lookup: %v, resolve: %v). If inspected=false the pool directory is not visible to this process.",
				vol, v.Path, v.PoolPath, v.FSChecked, v.Regular, v.Symlink, v.Canonical, lerr, rerr))
			return src, false
		}
		rec.pass(id, fmt.Sprintf("libvirt volume %s -> %s inside pool directory %s: absolute, regular file, no symlink in any component", vol, src.Path, src.PoolPath))
		return src, true
	}
	rootSrc, rootOK := look(rootName, provision.ResolveRootSource)
	seedSrc, seedOK := look(seedName, provision.ResolveSeedSource)
	rec.evidence("volume-placement.txt", placement.String())
	if !rootOK || !seedOK {
		t.Fatal("root or seed source not provable")
	}
	sources := provision.DiskSources{Root: rootSrc, Seed: seedSrc}
	rec.res.Host["root_volume_name"], rec.res.Host["root_source_path"] = rootName, rootSrc.Path
	rec.res.Host["seed_volume_name"], rec.res.Host["seed_source_path"] = seedName, seedSrc.Path
	d0, v0, err := resourcesOf(ops, cfg.Pool, name, uuid)
	if err != nil || d0 != 0 || v0 != 2 {
		rec.fail("forced-recovery", fmt.Sprintf("after the interrupted provision expected 0 domains and 2 volumes, found %d and %d (%v)", d0, v0, err))
		t.Fatal("interrupted state not as expected")
	}
	var steps []string
	if err := provision.Provision(ctx, ops, cfg, cat, spec, scratch, func(s string) { steps = append(steps, s) }); err != nil {
		rec.fail("forced-recovery", fmt.Sprintf("recovery provision failed: %v", err))
		t.Fatal(err)
	}
	if err := provision.Provision(ctx, ops, cfg, cat, spec, scratch, nil); err != nil { // an identical repeat must be a no-op
		rec.fail("forced-recovery", fmt.Sprintf("repeat provision failed: %v", err))
		t.Fatal(err)
	}
	d1, v1, err := resourcesOf(ops, cfg.Pool, name, uuid)
	if err != nil || d1 != 1 || v1 != 2 {
		rec.fail("no-duplicates", fmt.Sprintf("expected exactly 1 domain and 2 volumes, found %d and %d (%v)", d1, v1, err))
		t.Fatal("duplicate or missing resources")
	}
	rec.pass("forced-recovery", "interrupted after seed-volume; recovery completed the same VM; steps="+strings.Join(steps, ","))
	rec.pass("no-duplicates", "1 domain, 2 volumes (root, seed) after interruption, recovery and an identical repeat")

	// Resource-level proof of what Provision claims to have done.
	rv, err := ops.LookupVolume(ctx, cfg.Pool, provision.RootVolumeName(uuid))
	imgPath, _ := cat.Path(img)
	if err != nil || rv.CapacityBytes != int64(spec.DiskGiB)<<30 || rv.BackingPath != imgPath {
		rec.fail("root-volume", fmt.Sprintf("root volume wrong: %+v %v", rv, err))
		t.Fatal("root volume")
	}
	rec.pass("root-volume", fmt.Sprintf("capacity=%dGiB backing=managed image", spec.DiskGiB))
	if sv, err := ops.LookupVolume(ctx, cfg.Pool, provision.SeedVolumeName(uuid)); err != nil || sv.CapacityBytes != provision.SeedCapacityBytes {
		rec.fail("seed-volume", fmt.Sprintf("seed volume wrong: %+v %v", sv, err))
		t.Fatal("seed volume")
	}
	rec.pass("seed-volume", "NoCloud seed volume created and uploaded")

	ro, err := libvirtro.Open(libvirtro.SystemURI)
	if err != nil {
		t.Fatal(err)
	}
	defer ro.Close()
	d, err := ro.Lookup(ctx, name)
	if err != nil || d.State != hypervisor.StateShutoff || !d.Managed || d.UUID != uuid {
		rec.fail("domain-defined", fmt.Sprintf("expected a stopped managed VM: %+v %v", d, err))
		t.Fatal("domain")
	}
	rec.pass("domain-defined", "defined, stopped, carries the Svavyom ownership marker")
	generated, gerr := provision.DomainXML(cfg, spec, backing, sources)
	rec.evidence("domain-generated.xml", generated)
	if gerr != nil || provision.CheckDomainBacking(generated, backing) != nil || provision.CheckDomainSources(generated, sources) != nil {
		rec.fail("domain-backing-declared", "the generated domain XML lacks the explicit backing store or the no-DAC-relabel directive for the managed image")
		t.Fatal("generated XML")
	}
	inactive := domainXML(ops, name, libvirt.DOMAIN_XML_INACTIVE)
	rec.evidence("domain-defined.xml", inactive)
	if err := provision.CheckDomainBacking(inactive, backing); err != nil {
		rec.fail("domain-backing-declared", "libvirt's stored definition does not keep the explicit backing store with relabel='no' on the managed image only; see domain-defined.xml")
	} else {
		rec.pass("domain-backing-declared", "backingStore file/qcow2 -> the managed store path, <seclabel model='dac' relabel='no'/> on that source only, empty terminating backingStore; overlay and seed keep default handling")
	}
	// Root and seed are checked separately so each criterion reports on its own disk; each check also proves that no pool/volume
	// source remains anywhere and that no source carries a no-relabel directive.
	if err := provision.CheckDomainRootSource(inactive, rootSrc); err != nil {
		rec.fail("domain-root-source", fmt.Sprintf("libvirt's stored definition does not name the root overlay as a file source at the resolved path %s (volume %s); see domain-defined.xml", rootSrc.Path, rootName))
	} else {
		rec.pass("domain-root-source", fmt.Sprintf("stored root disk is type=file with source file %s, exactly the path libvirt resolved for volume %s; no pool/volume source", rootSrc.Path, rootName))
	}
	if err := provision.CheckDomainSeedSource(inactive, seedSrc); err != nil {
		rec.fail("domain-seed-source", fmt.Sprintf("libvirt's stored definition does not name the seed as a readonly file cdrom at the resolved path %s (volume %s); see domain-defined.xml", seedSrc.Path, seedName))
	} else {
		rec.pass("domain-seed-source", fmt.Sprintf("stored seed is a readonly type=file cdrom (raw) with source file %s, exactly the path libvirt resolved for volume %s; no pool/volume source", seedSrc.Path, seedName))
	}
	if d, err := provision.ParseDomain(inactive); err != nil || d.Root != rootName || d.Seed != seedName {
		rec.fail("domain-volume-identity", fmt.Sprintf("the logical volume names are not recoverable from the stored file-backed definition: root=%q seed=%q (%v)", d.Root, d.Seed, err))
	} else {
		rec.pass("domain-volume-identity", fmt.Sprintf("stored definition recovers root=%s seed=%s, validated against the VM UUID", d.Root, d.Seed))
	}
	if di, err := ops.LookupDomain(ctx, name); err != nil || !di.Managed || di.UUID != uuid || di.Fingerprint != fp {
		rec.fail("svavyom-owned", "ownership marker does not match the run identity")
		t.Fatal("ownership")
	}
	rec.pass("svavyom-owned", "uuid and fingerprint recompute from the run id: ownership provable")

	// A, immediately before start: unchanged from the baseline recorded before the domain existed.
	if _, line, err := checkAnchor(want, &baseline); err != nil {
		rec.fail("image-immutable-before", fmt.Sprintf("the base image changed before the guest started: %v; %s", err, line))
		t.Fatal(err)
	} else {
		rec.pass("image-immutable-before", "root:root 0444 regular file, unchanged from the baseline before domain definition and immediately before start; "+line)
	}
	rec.evidence("storage-volume-paths.txt", volumePaths(ops, cfg.Pool, uuid))
	if err := provision.Start(ctx, ops, name, nil); err != nil {
		// A start failure is a FAIL with the underlying cause, never NOT_RUN: raw libvirt/QEMU text, the base image state after the
		// attempt and the definition libvirt holds all go to the evidence directory.
		_, after, aerr := checkAnchor(want, &baseline)
		state := "base image after the failed start: unchanged and correct; " + after
		if aerr != nil {
			state = fmt.Sprintf("base image after the failed start CHANGED: %v; %s", aerr, after)
		}
		rec.evidence("start-failure.txt", fmt.Sprintf("category: %v\nlibvirt volumes: root=%s seed=%s\nresolved paths in the domain: root=%s seed=%s\nraw libvirt text:\n%s\n%s", err, rootName, seedName, rootSrc.Path, seedSrc.Path, strings.Join(raw, "\n"), state))
		rec.evidence("domain-after-failed-start.xml", domainXML(ops, name, 0))
		rec.fail("vm-started", fmt.Sprintf("domain start failed (%v); libvirt said: %s; %s", err, strings.Join(raw, " | "), state))
		t.Fatalf("start: %v", err)
	}
	rec.pass("vm-started", "start accepted")
	deadline := time.Now().Add(4 * time.Minute)
	for time.Now().Before(deadline) {
		d, err = ro.Lookup(ctx, name)
		if err == nil && d.State == hypervisor.StateRunning && provision.IsIPv4(d.IPv4) {
			break
		}
		time.Sleep(5 * time.Second)
	}
	if err != nil || d.State != hypervisor.StateRunning {
		rec.fail("vm-running", fmt.Sprintf("not running: %+v %v", d, err))
		t.Fatal("not running")
	}
	rec.pass("vm-running", "state Running")
	if dom, err := ops.conn.LookupDomainByName(name); err == nil {
		x, _ := dom.GetXMLDesc(0)
		_ = dom.Free()
		if strings.Contains(x, "<domain type='kvm'") {
			rec.pass("kvm-guest", "domain type kvm is running")
		} else {
			rec.fail("kvm-guest", "domain is not type kvm")
		}
	}
	// B, while the guest runs: libvirt's DAC driver must not have relabelled the backing chain. Re-verify under the production policy
	// and compare every recorded field with the baseline.
	rec.evidence("domain-running.xml", domainXML(ops, name, 0))
	if _, err := cat.Verify(img); err != nil {
		rec.fail("image-immutable-running", "the managed base image no longer verifies (ownership, mode or content changed) while the VM runs; see docs/UBUNTU-DEPLOYMENT.md 'Base-image ownership and libvirt relabelling'")
	} else if _, line, err := checkAnchor(want, &baseline); err != nil {
		rec.fail("image-immutable-running", fmt.Sprintf("the base image changed while the guest runs: %v; %s", err, line))
	} else {
		rec.pass("image-immutable-running", "with the guest running: root:root 0444 regular file, same path, size and digest as the baseline; "+line)
	}
	if provision.IsIPv4(d.IPv4) {
		rec.res.IPv4 = d.IPv4
		rec.pass("address-observed", "DHCP lease observed on the NAT network")
	} else {
		rec.fail("address-observed", "no DHCP lease within 4 minutes")
	}
	fmt.Printf("QUALIFY handoff name=%s ip=%s login_user=%s (guest checks run on the host: tools/qualify_create.py)\n", name, rec.res.IPv4, img.LoginUser)
	if rec.failed() {
		t.Fatal("one or more criteria failed")
	}
}

// TestSystemCreateQualificationCleanup removes ONE run's resources, and only after proving every one of them is that run's.
func TestSystemCreateQualificationCleanup(t *testing.T) {
	cfg, pol, rec, name, uuid, fp := qualEnv(t)
	if os.Getenv("SVAVYOM_QUALIFY_STAGE") != "cleanup" {
		t.Skip("create stage selected")
	}
	rec.res.Stage = "cleanup"
	defer rec.flush()
	refuse := func(why string) {
		rec.fail("cleanup", "REFUSED, manual cleanup required: "+why)
		t.Fatalf("MANUAL CLEANUP REQUIRED: %s", why)
	}
	// C, after shutdown and cleanup (also when cleanup is refused or finds nothing): the base image must still be exactly the one the
	// create stage recorded. The record lives in the operator's output directory, so it is trusted only after it is tied to the
	// catalog: its path must be the store path of a catalog image with the same digest.
	defer func() {
		const id = "image-immutable-after"
		raw, err := os.ReadFile(filepath.Join(rec.out, anchorFile)) // #nosec G304 -- fixed name inside the run's output directory
		if err != nil {
			rec.add(id, "NOT_RUN", "no "+anchorFile+" from the create stage: nothing to compare with")
			return
		}
		var base provision.Anchor
		cat, cerr := provision.LoadTrustedCatalog(pol, cfg.CatalogDir)
		if json.Unmarshal(raw, &base) != nil || cerr != nil {
			rec.fail(id, "the base-image record or the catalog is unreadable")
			return
		}
		for _, im := range cat.Images {
			if p, perr := cat.Path(im); perr == nil && p == base.Path && im.SHA256 == base.SHA256 {
				want := provision.AnchorWant{Path: p, UID: pol.Owner, GID: 0, SHA256: im.SHA256, Size: im.SizeBytes}
				if _, line, err := checkAnchor(want, &base); err != nil {
					rec.fail(id, fmt.Sprintf("the base image changed or is no longer the required root-owned read-only image after shutdown and cleanup: %v; %s", err, line))
				} else {
					rec.pass(id, "after shutdown and cleanup: root:root 0444 regular file, identical to the baseline; "+line)
				}
				return
			}
		}
		rec.fail(id, "the recorded base image is not a catalog store image")
	}()
	ops, err := Open(SystemURI)
	if err != nil {
		t.Fatal(err)
	}
	defer ops.Close()
	ctx := context.Background()
	if uri, err := ops.conn.GetURI(); err != nil || uri != SystemURI {
		refuse("not connected to qemu:///system")
	}
	nd, nv, err := resourcesOf(ops, cfg.Pool, name, uuid)
	if err != nil {
		refuse("cannot enumerate resources")
	}
	if nd == 0 && nv == 0 {
		cleanupRunNetwork(ctx, ops, rec, refuse)
		rec.pass("cleanup", "nothing exists for this run (already clean)")
		return
	}
	if nd > 1 {
		refuse("more than one domain matches this run")
	}
	// Ownership proof: the marker must be well formed, carry this run's derived UUID and fingerprint, and the domain's disks must
	// be the derived volumes of that UUID. A same-name domain that fails any of these is NOT ours and is never touched.
	if nd == 1 {
		di, err := ops.LookupDomain(ctx, name)
		if err != nil || !di.Managed || di.UUID != uuid || di.Fingerprint != fp {
			refuse("the domain does not carry this run's ownership marker")
		}
	}
	root, rerr := ops.LookupVolume(ctx, cfg.Pool, provision.RootVolumeName(uuid))
	if rerr == nil {
		cat, err := provision.LoadTrustedCatalog(pol, cfg.CatalogDir)
		if err != nil || root.BackingPath == "" || filepath.Dir(root.BackingPath) != cat.StorePath() {
			refuse("the root volume is not backed by a managed store image")
		}
	}
	if nd == 1 {
		dom, err := ops.conn.LookupDomainByName(name)
		if err != nil {
			refuse("domain vanished")
		}
		if active, _ := dom.IsActive(); active {
			if err := dom.Destroy(); err != nil {
				refuse("cannot stop the qualification VM")
			}
		}
		if err := dom.UndefineFlags(libvirt.DOMAIN_UNDEFINE_NVRAM); err != nil {
			if err2 := dom.Undefine(); err2 != nil {
				_ = dom.Free()
				refuse("cannot undefine the qualification VM")
			}
		}
		_ = dom.Free()
	}
	p, err := ops.conn.LookupStoragePoolByName(cfg.Pool)
	if err != nil {
		refuse("pool vanished")
	}
	defer func() { _ = p.Free() }()
	for _, vn := range []string{provision.RootVolumeName(uuid), provision.SeedVolumeName(uuid)} { // exactly the two derived names
		v, err := p.LookupStorageVolByName(vn)
		if err != nil {
			continue
		}
		if err := v.Delete(0); err != nil {
			_ = v.Free()
			refuse("cannot delete " + vn)
		}
		_ = v.Free()
	}
	if nd, nv, err := resourcesOf(ops, cfg.Pool, name, uuid); err != nil || nd != 0 || nv != 0 {
		refuse("resources remain after cleanup")
	}
	cleanupRunNetwork(ctx, ops, rec, refuse)
	rec.pass("cleanup", "removed the run's VM and its two volumes (and its network, if the run made one); nothing else touched")
}

// cleanupRunNetwork removes the network a network-stage run derived from its run id, but only if it carries Svavyom's ownership marker with exactly that
// derived UUID and bridge and no VM is attached. A network of that name that fails any of these is NOT ours and is never touched.
func cleanupRunNetwork(ctx context.Context, ops *Ops, rec *recorder, refuse func(string)) {
	name, uuid := netIdentity(rec.res.RunID)
	n, err := ops.LookupNetwork(ctx, name)
	if hypervisor.CategoryOf(err) == hypervisor.NotFound {
		return
	}
	if err != nil || !n.Managed || n.UUID != uuid || n.Bridge != provision.BridgeName(uuid) {
		refuse("a network named " + name + " exists but does not carry this run's ownership marker")
	}
	if err := provision.NetworkDelete(ctx, ops, name, nil); err != nil {
		refuse("cannot remove this run's network: " + err.Error())
	}
}
