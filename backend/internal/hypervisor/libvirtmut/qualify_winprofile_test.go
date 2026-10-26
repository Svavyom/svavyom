//go:build libvirt && libvirt_test

package libvirtmut

// REAL-HOST qualification of the Windows guest profile (story M6-E01-S04, criterion AC07; DR-032, DR-033). It does nothing unless SVAVYOM_QUALIFY_WINDOWS=1, so
// `make check` never runs the system tests; the pure helpers at the top (windowsDefinitionProblems and the answer-disk naming) are ordinary tests and always run.
//
// Two stages, both keyed by one qualification RUN ID (qr-YYYYMMDD-xxxxxx), orchestrated by tools/qualify_windows.py:
//
//	create   provisions ONE VM with the production code path (profile windows, from the catalog's Windows installation ISO) on the real qemu:///system,
//	         checks the definition libvirt holds, attaches the catalog's driver ISO as the second medium, and only then adds the one HARNESS-ONLY device (a read-only
//	         removable USB disk holding the answer file, in a pool volume named for the run). It starts the VM, shows that the installer reads its CD under KVM, and
//	         hands over: the guest installs unattended and reports back to the orchestrator on the host.
//	cleanup  removes the run's VM and volumes, and only those whose ownership it can prove; it first re-checks that the definition is still the profile's and that no
//	         other VM and no catalog image changed.
//
// Evidence lines start with "QUALIFY ". The answer file contains a one-off administrator password for a VM that is deleted at the end; it is never printed.

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	libvirt "libvirt.org/go/libvirt"

	"example.invalid/dedicatedcloud/backend/internal/hypervisor"
	"example.invalid/dedicatedcloud/backend/internal/hypervisor/libvirtro"
	"example.invalid/dedicatedcloud/backend/internal/provision"
	"example.invalid/dedicatedcloud/backend/internal/qualify/unattend"
)

const (
	windowsVCPUs     = 4
	windowsMemoryMiB = 4096
	windowsDiskGiB   = 40
	// the installer must have read this much of its CD within windowsBootWait for "the installer boots from its CD under KVM" to be true
	windowsInstallerReadBytes = 150 << 20
	windowsBootWait           = 10 * time.Minute
	answerDev                 = "sdd" // the harness-only USB disk (the installer is sdb, the driver CD sdc)
)

// answerVolumeName is the pool volume that holds the answer disk of a run: derived from the run ID, so it can be proven to be the run's.
func answerVolumeName(runID string) string {
	return "svq-" + strings.TrimPrefix(runID, "qr-") + "-unattend.img"
}

// windowsDomain is the part of a libvirt definition the Windows profile is about. It is parsed, not matched as text, because libvirt rewrites the definition it
// stores (it adds PCI addresses and controllers, expands the machine type, changes quoting).
type windowsDomain struct {
	Metadata struct {
		Children []struct {
			XMLName xml.Name
			Attrs   []xml.Attr `xml:",any,attr"`
		} `xml:",any"`
	} `xml:"metadata"`
	OS struct {
		Type struct {
			Machine string `xml:"machine,attr"`
		} `xml:"type"`
		Loader *struct{} `xml:"loader"`
		NVRAM  *struct{} `xml:"nvram"`
	} `xml:"os"`
	Features struct {
		HyperV *struct {
			Relaxed struct {
				State string `xml:"state,attr"`
			} `xml:"relaxed"`
			VAPIC struct {
				State string `xml:"state,attr"`
			} `xml:"vapic"`
			Spinlocks struct {
				State   string `xml:"state,attr"`
				Retries string `xml:"retries,attr"`
			} `xml:"spinlocks"`
		} `xml:"hyperv"`
	} `xml:"features"`
	Clock struct {
		Offset string `xml:"offset,attr"`
		Timers []struct {
			Name    string `xml:"name,attr"`
			Present string `xml:"present,attr"`
		} `xml:"timer"`
	} `xml:"clock"`
	Devices struct {
		Disks []struct {
			Device string `xml:"device,attr"`
			Source struct {
				File string `xml:"file,attr"`
			} `xml:"source"`
			Target struct {
				Dev       string `xml:"dev,attr"`
				Bus       string `xml:"bus,attr"`
				Removable string `xml:"removable,attr"`
			} `xml:"target"`
			Boot struct {
				Order string `xml:"order,attr"`
			} `xml:"boot"`
			ReadOnly *struct{} `xml:"readonly"`
		} `xml:"disk"`
		Interfaces []struct {
			Model struct {
				Type string `xml:"type,attr"`
			} `xml:"model"`
		} `xml:"interface"`
		TPMs []struct{} `xml:"tpm"`
	} `xml:"devices"`
}

// windowsDefinitionProblems returns every way the definition x differs from the Windows profile (refinement M6-E01-S04 section 3.1) and from the media order
// (installer first, driver CD attached only); an empty result means it is the profile. wantMedia is the number of installation CDs it must hold (1, or 2 with the
// driver CD); withAnswerDisk is true after the harness-only USB disk was added (it must then be there, read-only, removable, and nothing else extra).
func windowsDefinitionProblems(x string, wantMedia int, withAnswerDisk bool) []string {
	var d windowsDomain
	if err := xml.Unmarshal([]byte(x), &d); err != nil {
		return []string{"the definition is not parseable XML"}
	}
	var p []string
	bad := func(format string, a ...any) { p = append(p, fmt.Sprintf(format, a...)) }

	profile := false
	for _, m := range d.Metadata.Children {
		if m.XMLName.Space == provision.MetadataNamespace && m.XMLName.Local == "managed" {
			for _, a := range m.Attrs {
				if a.Name.Local == "profile" && a.Value == provision.ProfileWindows {
					profile = true
				}
			}
		}
	}
	if !profile {
		bad("the ownership marker does not record profile='windows'")
	}
	if !strings.Contains(d.OS.Type.Machine, "q35") {
		bad("machine %q is not q35", d.OS.Type.Machine)
	}
	if d.OS.Loader != nil || d.OS.NVRAM != nil || len(d.Devices.TPMs) != 0 {
		bad("the definition carries UEFI firmware or a TPM, which version 1 of the profile does not have")
	}
	h := d.Features.HyperV
	switch {
	case h == nil:
		bad("no Hyper-V enlightenments")
	case h.Relaxed.State != "on" || h.VAPIC.State != "on" || h.Spinlocks.State != "on" || h.Spinlocks.Retries != "8191":
		bad("Hyper-V enlightenments are not relaxed=on, vapic=on, spinlocks=on retries=8191")
	}
	if d.Clock.Offset != "localtime" {
		bad("clock offset %q, want localtime", d.Clock.Offset)
	}
	timer := false
	for _, t := range d.Clock.Timers {
		timer = timer || (t.Name == "hypervclock" && t.Present == "yes")
	}
	if !timer {
		bad("no hypervclock timer")
	}

	var cds, others []string
	rootOK, installerOK, driversOK, answerOK := false, false, true, false
	for _, k := range d.Devices.Disks {
		switch {
		case k.Device == "disk" && k.Target.Dev == "sda":
			rootOK = k.Target.Bus == "sata" && k.Boot.Order == "2"
		case k.Device == "cdrom":
			cds = append(cds, k.Target.Dev)
			if k.Target.Dev == "sdb" {
				installerOK = k.Target.Bus == "sata" && k.Boot.Order == "1" && k.ReadOnly != nil
			} else if k.Boot.Order != "" || k.Target.Bus != "sata" || k.ReadOnly == nil {
				driversOK = false // a second medium is only attached: no boot order, read-only
			}
		case k.Device == "disk" && k.Target.Dev == answerDev:
			answerOK = k.Target.Bus == "usb" && k.Target.Removable == "on" && k.ReadOnly != nil && k.Boot.Order == ""
		default:
			others = append(others, k.Target.Dev)
		}
	}
	if !rootOK {
		bad("the root disk is not sda on bus sata with boot order 2")
	}
	if !installerOK {
		bad("the installer is not a read-only CD on sdb, bus sata, with boot order 1")
	}
	if !driversOK {
		bad("a second installation medium has a boot order, is not on SATA or is not read-only")
	}
	sort.Strings(cds)
	if len(cds) != wantMedia {
		bad("expected %d installation CDs, found %v", wantMedia, cds)
	}
	if withAnswerDisk != answerOK {
		bad("the harness-only answer disk (%s, removable USB, read-only) is %s", answerDev, map[bool]string{true: "missing or wrong", false: "present but should not be yet"}[withAnswerDisk])
	}
	if len(others) != 0 {
		bad("unexpected disks: %v", others)
	}
	if len(d.Devices.Interfaces) != 1 || d.Devices.Interfaces[0].Model.Type != "e1000e" {
		bad("the network card is not exactly one e1000e")
	}
	return p
}

func TestWindowsDefinitionProblemsAcceptsTheProductionTemplateAndNothingElse(t *testing.T) {
	root := filepath.Join("..", "..", "provision", "testdata")
	read := func(n string) string {
		b, err := os.ReadFile(filepath.Join(root, n))
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	win := read("iso-windows-kvm.golden.xml")
	if p := windowsDefinitionProblems(win, 1, false); len(p) != 0 {
		t.Fatalf("the Windows definition is refused: %v", p)
	}
	// every element of the profile is checked: the Linux definition fails on each of them
	lin := windowsDefinitionProblems(read("iso-linux-kvm.golden.xml"), 1, false)
	for _, want := range []string{"profile='windows'", "Hyper-V", "localtime", "hypervclock", "sda", "sdb", "e1000e"} {
		found := false
		for _, s := range lin {
			found = found || strings.Contains(s, want)
		}
		if !found {
			t.Errorf("the Linux definition is not refused for %q: %v", want, lin)
		}
	}
	// the media count and the answer disk are part of the check
	if p := windowsDefinitionProblems(win, 2, false); len(p) == 0 {
		t.Error("one CD accepted where two are required")
	}
	if p := windowsDefinitionProblems(win, 1, true); len(p) == 0 {
		t.Error("a missing answer disk accepted")
	}
	withAnswer := strings.Replace(win, "</devices>", "<disk type='file' device='disk'><driver name='qemu' type='raw'/><source file='/pool/a.img'/><target dev='sdd' bus='usb' removable='on'/><readonly/></disk></devices>", 1)
	if p := windowsDefinitionProblems(withAnswer, 1, true); len(p) != 0 {
		t.Errorf("the answer disk is refused: %v", p)
	}
	if p := windowsDefinitionProblems(withAnswer, 1, false); len(p) == 0 {
		t.Error("an unexpected answer disk accepted before it was added")
	}
	// a UEFI or TPM definition is not version 1 of the profile
	if p := windowsDefinitionProblems(strings.Replace(win, "</devices>", "<tpm model='tpm-crb'/></devices>", 1), 1, false); len(p) == 0 {
		t.Error("a TPM accepted")
	}
	if p := windowsDefinitionProblems("<domain", 1, false); len(p) == 0 {
		t.Error("garbage accepted")
	}
}

func TestTheAnswerVolumeIsNamedForTheRun(t *testing.T) {
	n := answerVolumeName("qr-20261026-a1b2c3")
	if n != "svq-20261026-a1b2c3-unattend.img" || !regexp.MustCompile(`^svq-[0-9]{8}-[0-9a-f]{6}-unattend\.img$`).MatchString(n) {
		t.Fatalf("%q", n)
	}
	if answerVolumeName("qr-20261026-a1b2c4") == n {
		t.Fatal("two runs share an answer volume")
	}
}

func windowsEnv(t *testing.T) (cfg provision.Config, pol provision.Policy, rec *recorder, name, uuid, fp string) {
	t.Helper()
	if os.Getenv("SVAVYOM_QUALIFY_WINDOWS") != "1" {
		t.Skip("NOT_RUN: set SVAVYOM_QUALIFY_WINDOWS=1 on an authorised disposable host (tools/qualify_windows.py, make docker-qualify-libvirt-windows)")
	}
	runID := os.Getenv("SVAVYOM_QUALIFY_RUN_ID")
	name, uuid, fp, err := qualIdentity(runID)
	if err != nil {
		t.Fatalf("SVAVYOM_QUALIFY_RUN_ID: %v", err)
	}
	cfg, err = provision.LoadConfig(os.Getenv("SVAVYOM_QUALIFY_CONFIG"))
	if err != nil || cfg.DomainType != "kvm" || cfg.LibvirtURI != SystemURI {
		t.Fatalf("SVAVYOM_QUALIFY_CONFIG must name a valid kvm/qemu:///system provisioning config: %v", err)
	}
	pol, err = cfg.TrustPolicy(false)
	if err != nil {
		t.Fatalf("the configuration has no valid trust declaration: %v", err)
	}
	rec = &recorder{t: t, out: os.Getenv("SVAVYOM_QUALIFY_OUT"), res: &result{RunID: runID, VMName: name, UUID: uuid, RootVolume: provision.RootVolumeName(uuid), Host: map[string]string{}}}
	return cfg, pol, rec, name, uuid, fp
}

// domainSnapshot lists every domain on the host with its state, for the "no other VM changed" criterion.
func domainSnapshot(ops *Ops, except string) (string, error) {
	doms, err := ops.conn.ListAllDomains(0)
	if err != nil {
		return "", err
	}
	var out []string
	for _, d := range doms {
		n, _ := d.GetName()
		st, _, _ := d.GetState()
		_ = d.Free()
		if n != except {
			out = append(out, fmt.Sprintf("%s=%d", n, st))
		}
	}
	sort.Strings(out)
	return strings.Join(out, ","), nil
}

const driverAnchorFile = "driver-anchor.json"

func TestSystemWindowsQualification(t *testing.T) {
	cfg, pol, rec, name, uuid, fp := windowsEnv(t)
	if os.Getenv("SVAVYOM_QUALIFY_STAGE") == "cleanup" {
		t.Skip("cleanup stage selected")
	}
	rec.res.Stage = "create"
	defer rec.flush()
	ctx := context.Background()
	runID := rec.res.RunID
	answer, err := os.ReadFile(os.Getenv("SVAVYOM_QUALIFY_ANSWER_FILE")) // #nosec G304 -- the orchestrator's file in this run's read-only mount
	if err != nil {
		t.Fatalf("no answer file: %v", err)
	}
	script, err := os.ReadFile(os.Getenv("SVAVYOM_QUALIFY_REPORT_SCRIPT")) // #nosec G304 -- the orchestrator's file in this run's read-only mount
	if err != nil {
		t.Fatalf("no guest script: %v", err)
	}

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
	media := func(envName, what string) provision.Image {
		im, err := cat.Usable(os.Getenv(envName))
		if err != nil || !im.IsISO() {
			rec.fail("managed-image", what+" is not a usable installation-media image in the catalog")
			t.Fatalf("%s: %v", what, err)
		}
		if _, err := cat.Verify(im); err != nil {
			rec.fail("managed-image", what+": digest verification failed")
			t.Fatal(err)
		}
		return im
	}
	inst, drv := media("SVAVYOM_QUALIFY_IMAGE_ID", "the Windows installer"), media("SVAVYOM_QUALIFY_DRIVER_IMAGE_ID", "the driver ISO")
	if inst.ID == drv.ID {
		rec.fail("managed-image", "the installer and the driver ISO are the same image")
		t.Fatal("same image")
	}
	rec.res.ImageID = inst.ID
	rec.pass("managed-image", fmt.Sprintf("installer %s sha256=%s; driver media %s sha256=%s (both verified, installation media)", inst.ID, inst.SHA256, drv.ID, drv.SHA256))

	// The two store files must be what the production policy requires before anything exists, and the same afterwards (cleanup stage).
	for _, a := range []struct {
		im   provision.Image
		file string
	}{{inst, anchorFile}, {drv, driverAnchorFile}} {
		want, err := anchorWantFor(pol, cat, a.im)
		if err != nil {
			rec.fail("image-immutable-before", "store path of "+a.im.ID+" not resolvable")
			t.Fatal(err)
		}
		base, line, err := checkAnchor(want, nil)
		if err != nil {
			rec.fail("image-immutable-before", fmt.Sprintf("%s is not the required root-owned read-only file: %v; %s", a.im.ID, err, line))
			t.Fatal(err)
		}
		if b, err := json.MarshalIndent(base, "", "  "); err == nil && rec.out != "" {
			_ = os.WriteFile(filepath.Join(rec.out, a.file), append(b, '\n'), 0o644) // #nosec G306 -- non-secret record: path, ids, mode, size, digest
		}
	}
	rec.pass("image-immutable-before", "installer and driver ISO: root:root 0444 regular files, recorded")

	ops, err := Open(SystemURI)
	if err != nil {
		rec.fail("real-libvirt", "cannot open qemu:///system read-write")
		t.Fatal(err)
	}
	defer ops.Close()
	var raw []string
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
	rec.pass("kvm-capable", "libvirt reports usable kvm domain capabilities")
	rec.pass("real-libvirt", "qemu:///system, driver QEMU")
	r := provision.Preflight(ctx, ops, cfg)
	if r.Network != "available" || r.Pool != "available" {
		rec.fail("host-ready", fmt.Sprintf("network=%s pool=%s", r.Network, r.Pool))
		t.Fatalf("host not ready: %+v", r)
	}
	rec.pass("host-ready", fmt.Sprintf("network=%s pool=%s", r.Network, r.Pool))
	before, err := domainSnapshot(ops, name)
	if err != nil {
		t.Fatal(err)
	}
	rec.res.Host["domains_before"] = before

	spec := provision.Spec{Name: name, UUID: uuid, Fingerprint: fp, VCPUs: windowsVCPUs, MemoryMiB: windowsMemoryMiB, ImageID: inst.ID, ImageSHA256: inst.SHA256,
		DiskGiB: windowsDiskGiB, Network: cfg.Network, Profile: provision.ProfileWindows}
	if err := spec.ValidateAnyMedia(); err != nil {
		rec.fail("profile-spec", "the qualification spec does not validate: "+err.Error())
		t.Fatal(err)
	}
	rec.pass("profile-spec", "the Windows-profile spec validates")
	var steps []string
	if err := provision.Provision(ctx, ops, cfg, cat, spec, t.TempDir(), func(s string) { steps = append(steps, s) }); err != nil {
		rec.fail("domain-defined", fmt.Sprintf("provision failed: %v; libvirt said: %s", err, strings.Join(raw, " | ")))
		t.Fatal(err)
	}
	if err := provision.Provision(ctx, ops, cfg, cat, spec, t.TempDir(), nil); err != nil { // an identical repeat is a no-op
		rec.fail("no-duplicates", fmt.Sprintf("repeat provision failed: %v", err))
		t.Fatal(err)
	}
	if nd, nv, err := resourcesOf(ops, cfg.Pool, name, uuid); err != nil || nd != 1 || nv != 1 {
		rec.fail("no-duplicates", fmt.Sprintf("expected 1 domain and 1 volume (the root: an installation-media VM has no seed), found %d and %d (%v)", nd, nv, err))
		t.Fatal("duplicate or missing resources")
	}
	rec.pass("domain-defined", "provisioned with profile windows from the installation ISO; steps="+strings.Join(steps, ","))
	rec.pass("no-duplicates", "1 domain and 1 volume after provision and an identical repeat")

	ro, err := libvirtro.Open(libvirtro.SystemURI)
	if err != nil {
		t.Fatal(err)
	}
	defer ro.Close()
	inactive := domainXML(ops, name, libvirt.DOMAIN_XML_INACTIVE)
	rec.evidence("domain-defined.xml", inactive)
	if p := windowsDefinitionProblems(inactive, 1, false); len(p) != 0 {
		rec.fail("profile-definition", "libvirt's stored definition is not the Windows profile: "+strings.Join(p, "; ")+" (domain-defined.xml)")
	} else {
		rec.pass("profile-definition", "libvirt's stored definition: BIOS q35, root disk sda on SATA (boot 2), installer CD sdb on SATA (boot 1), one e1000e NIC, clock localtime with the hypervclock timer, Hyper-V relaxed/vapic/spinlocks 8191, no UEFI, no TPM")
	}
	if d, err := ro.Lookup(ctx, name); err != nil || d.State != hypervisor.StateShutoff || !d.Managed || d.UUID != uuid || d.Profile != provision.ProfileWindows || d.Media != provision.MediaISO ||
		len(d.ISOSHA256s) != 1 || d.ISOSHA256s[0] != inst.SHA256 {
		rec.fail("profile-observed", fmt.Sprintf("the read-only observation does not report a stopped, managed, Windows-profile VM from this installer: %+v %v", d, err))
	} else {
		rec.pass("profile-observed", "the inventory path reports it stopped, managed, profile windows, from installation media, with exactly the installer attached")
	}
	if di, err := ops.LookupDomain(ctx, name); err != nil || !di.Managed || di.UUID != uuid || di.Fingerprint != fp || di.Profile != provision.ProfileWindows {
		rec.fail("svavyom-owned", "ownership marker does not match the run identity")
		t.Fatal("ownership")
	}
	rec.pass("svavyom-owned", "uuid and fingerprint recompute from the run id: ownership provable")

	// The second medium, through the production operation: only attached, never booting.
	if err := provision.ISOAttach(ctx, ops, cat, name, drv.ID, drv.SHA256, provision.BootDisk, nil); err != nil {
		rec.fail("second-medium", fmt.Sprintf("attaching the driver ISO failed: %v; libvirt said: %s", err, strings.Join(raw, " | ")))
		t.Fatal(err)
	}
	if err := provision.ISOAttach(ctx, ops, cat, name, drv.ID, drv.SHA256, provision.BootDisk, nil); err != nil {
		rec.fail("second-medium", "an identical repeat of the attach failed: "+err.Error())
		t.Fatal(err)
	}
	withDriver := domainXML(ops, name, libvirt.DOMAIN_XML_INACTIVE)
	rec.evidence("domain-with-driver-media.xml", withDriver)
	if p := windowsDefinitionProblems(withDriver, 2, false); len(p) != 0 {
		rec.fail("second-medium", "after the attach libvirt's definition is not installer-first with the driver CD only attached: "+strings.Join(p, "; "))
		t.Fatal("second medium")
	}
	if d, err := ro.Lookup(ctx, name); err != nil || len(d.ISOSHA256s) != 2 || d.ISOSHA256s[0] != inst.SHA256 || d.ISOSHA256s[1] != drv.SHA256 {
		rec.fail("second-medium", fmt.Sprintf("the observation does not list the installer then the driver ISO: %+v %v", d.ISOSHA256s, err))
	} else {
		rec.pass("second-medium", "the driver ISO is the second medium (sdc): read-only, no boot order, the installer still boots first; the observation lists both; a repeat changes nothing")
	}

	// HARNESS-ONLY from here: the answer file, as a read-only removable USB disk in a pool volume of this run. It is added after the checks above, which are
	// therefore about the Svavyom-managed definition alone; the definition checks after the run allow exactly this one extra disk.
	scratch := t.TempDir()
	img, err := unattend.BuildImage(answer, script, "UNATTEND", scratch)
	if err != nil {
		rec.fail("answer-disk", "cannot build the answer disk: "+err.Error())
		t.Fatal(err)
	}
	vol := answerVolumeName(runID)
	if err := ops.CreateSeedVolume(ctx, cfg.Pool, vol, int64(len(img))); err != nil {
		rec.fail("answer-disk", "cannot create the answer volume: "+err.Error())
		t.Fatal(err)
	}
	if err := ops.UploadSeed(ctx, cfg.Pool, vol, img); err != nil {
		rec.fail("answer-disk", "cannot upload the answer disk: "+err.Error())
		t.Fatal(err)
	}
	vi, err := ops.LookupVolume(ctx, cfg.Pool, vol)
	if err != nil || vi.Path == "" || !filepath.IsAbs(vi.Path) || filepath.Dir(vi.Path) != vi.PoolPath {
		rec.fail("answer-disk", fmt.Sprintf("the answer volume has no path inside the pool: %+v %v", vi, err))
		t.Fatal("answer volume path")
	}
	disk := fmt.Sprintf("    <disk type='file' device='disk'>\n      <driver name='qemu' type='raw'/>\n      <source file='%s'/>\n      <target dev='%s' bus='usb' removable='on'/>\n      <readonly/>\n    </disk>\n", vi.Path, answerDev)
	if !strings.Contains(withDriver, "</devices>") {
		t.Fatal("no devices section")
	}
	if err := ops.DefineDomain(ctx, strings.Replace(withDriver, "</devices>", disk+"  </devices>", 1)); err != nil {
		rec.fail("answer-disk", fmt.Sprintf("libvirt refused the definition with the answer disk: %v; %s", err, strings.Join(raw, " | ")))
		t.Fatal(err)
	}
	final := domainXML(ops, name, libvirt.DOMAIN_XML_INACTIVE)
	rec.evidence("domain-with-answer-disk.xml", final)
	if p := windowsDefinitionProblems(final, 2, true); len(p) != 0 {
		rec.fail("answer-disk", "after adding the answer disk: "+strings.Join(p, "; "))
		t.Fatal("answer disk")
	}
	rec.pass("answer-disk", "harness-only: the answer file is on a read-only removable USB disk (sdd) in pool volume "+vol+"; nothing else of the definition changed")

	if err := provision.Start(ctx, ops, name, nil); err != nil {
		rec.evidence("start-failure.txt", fmt.Sprintf("category: %v\nraw libvirt text:\n%s\n", err, strings.Join(raw, "\n")))
		rec.fail("vm-started", fmt.Sprintf("domain start failed (%v); libvirt said: %s", err, strings.Join(raw, " | ")))
		t.Fatalf("start: %v", err)
	}
	rec.pass("vm-started", "start accepted")
	dom, err := ops.conn.LookupDomainByName(name)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = dom.Free() }()
	if x, err := dom.GetXMLDesc(0); err == nil && strings.Contains(x, "<domain type='kvm'") {
		rec.pass("kvm-guest", "the running domain is type kvm")
	} else {
		rec.fail("kvm-guest", "the running domain is not type kvm")
	}
	rec.evidence("domain-running.xml", domainXML(ops, name, 0))

	// The installer boots from its CD (boot order, SATA CD, no driver needed) and runs under KVM: it reads its medium.
	var read uint64
	deadline := time.Now().Add(windowsBootWait)
	for time.Now().Before(deadline) {
		if st, err := dom.BlockStats("sdb"); err == nil && st.RdBytesSet {
			read = uint64(st.RdBytes)
			if read >= windowsInstallerReadBytes {
				break
			}
		}
		time.Sleep(5 * time.Second)
	}
	if read < windowsInstallerReadBytes {
		rec.fail("installer-boots", fmt.Sprintf("within %s the guest read only %d bytes of the installer CD (need %d)", windowsBootWait, read, windowsInstallerReadBytes))
	} else {
		rec.pass("installer-boots", fmt.Sprintf("the installer booted from its SATA CD (boot order 1) under KVM and had read %d MiB of it", read>>20))
	}
	if d, err := ro.Lookup(ctx, name); err != nil || d.State != hypervisor.StateRunning {
		rec.fail("vm-running", fmt.Sprintf("not running: %+v %v", d, err))
	} else {
		rec.pass("vm-running", "state Running")
	}
	fmt.Printf("QUALIFY handoff name=%s (the guest installs unattended and reports to the orchestrator on the host: tools/qualify_windows.py)\n", name)
	if rec.failed() {
		t.Fatal("one or more criteria failed")
	}
}

// TestSystemWindowsQualificationCleanup removes ONE run's resources, and only after proving every one of them is that run's.
func TestSystemWindowsQualificationCleanup(t *testing.T) {
	cfg, pol, rec, name, uuid, fp := windowsEnv(t)
	if os.Getenv("SVAVYOM_QUALIFY_STAGE") != "cleanup" {
		t.Skip("create stage selected")
	}
	rec.res.Stage = "cleanup"
	defer rec.flush()
	refuse := func(why string) {
		rec.fail("cleanup", "REFUSED, manual cleanup required: "+why)
		t.Fatalf("MANUAL CLEANUP REQUIRED: %s", why)
	}
	ops, err := Open(SystemURI)
	if err != nil {
		t.Fatal(err)
	}
	defer ops.Close()
	ctx := context.Background()
	if uri, err := ops.conn.GetURI(); err != nil || uri != SystemURI {
		refuse("not connected to qemu:///system")
	}

	// The two catalog images must be exactly what the create stage recorded, whatever else happens below.
	defer func() {
		cat, cerr := provision.LoadTrustedCatalog(pol, cfg.CatalogDir)
		for _, f := range []string{anchorFile, driverAnchorFile} {
			raw, err := os.ReadFile(filepath.Join(rec.out, f)) // #nosec G304 -- fixed names inside the run's output directory
			if err != nil {
				rec.add("image-immutable-after", "NOT_RUN", "no "+f+" from the create stage: nothing to compare with")
				return
			}
			var base provision.Anchor
			if json.Unmarshal(raw, &base) != nil || cerr != nil {
				rec.fail("image-immutable-after", "the base-image record or the catalog is unreadable")
				return
			}
			ok := false
			for _, im := range cat.Images {
				if p, perr := cat.Path(im); perr == nil && p == base.Path && im.SHA256 == base.SHA256 {
					want := provision.AnchorWant{Path: p, UID: pol.Owner, GID: 0, SHA256: im.SHA256, Size: im.SizeBytes}
					if _, line, err := checkAnchor(want, &base); err != nil {
						rec.fail("image-immutable-after", fmt.Sprintf("%s changed after the run: %v; %s", im.ID, err, line))
						return
					}
					ok = true
				}
			}
			if !ok {
				rec.fail("image-immutable-after", "a recorded image is not a catalog store image")
				return
			}
		}
		rec.pass("image-immutable-after", "installer and driver ISO: root:root 0444 regular files, identical to the baselines recorded before the run")
	}()

	nd, nv, err := resourcesOf(ops, cfg.Pool, name, uuid)
	if err != nil {
		refuse("cannot enumerate resources")
	}
	avol := answerVolumeName(rec.res.RunID)
	p, err := ops.conn.LookupStoragePoolByName(cfg.Pool)
	if err != nil {
		refuse("pool vanished")
	}
	defer func() { _ = p.Free() }()
	if nd == 0 && nv == 0 {
		if v, err := p.LookupStorageVolByName(avol); err == nil {
			_ = v.Free()
			refuse("the answer volume exists without its VM")
		}
		rec.pass("cleanup", "nothing exists for this run (already clean)")
		return
	}
	if nd > 1 {
		refuse("more than one domain matches this run")
	}
	if nd == 1 {
		di, err := ops.LookupDomain(ctx, name)
		if err != nil || !di.Managed || di.UUID != uuid || di.Fingerprint != fp || di.Profile != provision.ProfileWindows {
			refuse("the domain does not carry this run's ownership marker and the Windows profile")
		}
		// After the run the definition is still the profile's: the installer and the driver CD, and the one harness-only disk, nothing else.
		if p := windowsDefinitionProblems(domainXML(ops, name, libvirt.DOMAIN_XML_INACTIVE), 2, true); len(p) != 0 {
			rec.fail("profile-definition-after", "after the run libvirt's definition is no longer the profile: "+strings.Join(p, "; "))
		} else {
			rec.pass("profile-definition-after", "after the install the stored definition is still the Windows profile with both media and only the harness-only answer disk extra")
		}
	}
	root, rerr := ops.LookupVolume(ctx, cfg.Pool, provision.RootVolumeName(uuid))
	if rerr == nil && root.BackingPath != "" {
		refuse("the root volume has a backing file, which an installation-media VM never has")
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
	for _, vn := range []string{provision.RootVolumeName(uuid), avol} { // exactly the two names derived from the run
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
	if v, err := p.LookupStorageVolByName(avol); err == nil {
		_ = v.Free()
		refuse("the answer volume remains after cleanup")
	}
	// Nothing else on the host changed: every other domain is in the state the create stage found it.
	if want := os.Getenv("SVAVYOM_QUALIFY_DOMAINS_BEFORE"); want != "" {
		if got, err := domainSnapshot(ops, name); err != nil || got != want {
			rec.fail("other-domains-untouched", fmt.Sprintf("other domains differ from before the run: before=%q after=%q (%v)", want, got, err))
		} else {
			rec.pass("other-domains-untouched", "every other domain is exactly as the create stage found it")
		}
	} else {
		rec.add("other-domains-untouched", "NOT_RUN", "no record of the other domains from the create stage")
	}
	rec.pass("cleanup", "removed the run's VM and its two volumes (root, answer disk); nothing else touched")
}
