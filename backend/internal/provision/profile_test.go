package provision

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// DR-032: the Windows profile (version 1): hardware differences of an installation-media definition, observation of the marker, and no change to anything else.

const profileISOSum = "abababababababababababababababababababababababababababababababab"

func profileSpec(profile string) Spec {
	return Spec{Name: "inst-1", UUID: "11111111-2222-4333-8444-555555555555", Fingerprint: strings.Repeat("cd", 32), VCPUs: 2, MemoryMiB: 1024, ImageID: "alpine-iso",
		ImageSHA256: profileISOSum, DiskGiB: 20, Network: "svavyom-nat", Media: MediaISO, Profile: profile}
}

// renderKVM renders the template the way a real (kvm) host does: the kvm branch carries features, the host-model CPU and the random generator, and a real
// Config also needs a trust configuration that has nothing to do with rendering, so the template is executed with the data DomainXMLISO builds.
func renderKVM(t *testing.T, s Spec) string {
	t.Helper()
	var b bytes.Buffer
	err := isoTemplate.Execute(&b, map[string]any{
		"Type": "kvm", "Name": s.Name, "UUID": s.UUID, "Fingerprint": s.Fingerprint, "Image": s.ImageID, "Memory": s.MemoryMiB, "VCPUs": s.VCPUs,
		"Network": s.Network, "MAC": MAC(s.UUID), "NS": MetadataNamespace, "Ver": MetadataVersion, "Real": true,
		"RootPath": "/pool/" + RootVolumeName(s.UUID), "ISOPath": "/c/store/" + profileISOSum + ".iso", "Windows": s.IsWindows(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return b.String()
}

func renderTest(t *testing.T, s Spec) string {
	t.Helper()
	root := VolumeSource{Name: RootVolumeName(s.UUID), Path: "/pool/" + RootVolumeName(s.UUID), PoolPath: "/pool"}
	x, err := DomainXMLISO(testCfg(), s, ISOImage{Path: "/c/store/" + profileISOSum + ".iso", SHA256: profileISOSum}, root)
	if err != nil {
		t.Fatal(err)
	}
	return x
}

// golden compares got with testdata/<name>. To regenerate the files after a deliberate change to the templates, run the tests with UPDATE_GOLDEN=1 (for example
// `UPDATE_GOLDEN=1 go test ./internal/provision -run 'ISODefinition'`) and review the diff: it is the specification of the definitions, so a change is read, not accepted.
func golden(t *testing.T, name, got string) {
	t.Helper()
	if os.Getenv("UPDATE_GOLDEN") == "1" {
		if err := os.WriteFile("testdata/"+name, []byte(got), 0o644); err != nil { // #nosec G306 -- a non-secret test fixture
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	if got != string(want) {
		t.Fatalf("%s differs from its golden file:\n--- got ---\n%s\n--- want ---\n%s", name, got, want)
	}
}

// The profile changes nothing for a VM that does not ask for it: the definitions every Linux ISO VM had, byte for byte, on both domain types.
func TestLinuxISODefinitionIsByteForByteUnchanged(t *testing.T) {
	golden(t, "iso-linux.golden.xml", renderTest(t, profileSpec("")))
	golden(t, "iso-linux.golden.xml", renderTest(t, profileSpec(ProfileLinux)))
	golden(t, "iso-linux-kvm.golden.xml", renderKVM(t, profileSpec("")))
	golden(t, "iso-linux-kvm.golden.xml", renderKVM(t, profileSpec(ProfileLinux)))
}

// The Windows definition, as the refinement (3.1) lists it: SATA root disk, e1000e, local-time clock, Hyper-V enlightenments on a real host, installer CD first.
func TestWindowsISODefinitionIsTheGoldenOne(t *testing.T) {
	golden(t, "iso-windows.golden.xml", renderTest(t, profileSpec(ProfileWindows)))
	golden(t, "iso-windows-kvm.golden.xml", renderKVM(t, profileSpec(ProfileWindows)))
}

func TestWindowsDefinitionIsAcceptedByTheShapeChecksAndObserved(t *testing.T) {
	x := renderTest(t, profileSpec(ProfileWindows))
	root := VolumeSource{Name: RootVolumeName(profileSpec("").UUID), Path: "/pool/" + RootVolumeName(profileSpec("").UUID), PoolPath: "/pool"}
	if err := CheckDomainRootSource(x, root); err != nil {
		t.Fatalf("the root-disk check refuses the Windows definition: %v", err)
	}
	sha, _, dev, ok := ISODisk(x)
	if !ok || sha != profileISOSum || dev != "sdb" {
		t.Fatalf("the installer is the CD on sdb (the root disk holds sda): %s %s %v", sha, dev, ok)
	}
	pd, err := ParseDomain(x)
	if err != nil || !pd.Managed || pd.Media != MediaISO || pd.Profile != ProfileWindows || pd.Root != RootVolumeName(pd.UUID) || !pd.Graphics ||
		len(pd.ISOs) != 1 || pd.ISOs[0] != profileISOSum || pd.ISO != profileISOSum {
		t.Fatalf("%+v %v", pd, err)
	}
	// the Linux definition reads as linux
	if pd, _ := ParseDomain(renderTest(t, profileSpec(""))); pd.Profile != "" {
		t.Fatalf("a VM without a profile reads as linux: %+v", pd)
	}
	// only the one non-default profile is recorded: any other marker value reads as linux
	odd := strings.Replace(x, "profile='windows'", "profile='mac'", 1)
	if pd, _ := ParseDomain(odd); pd.Profile != "" {
		t.Fatalf("an unknown profile in the marker reads as linux: %+v", pd)
	}
	// a driver CD attached later takes the next free target, and the media operations keep working on this shape
	y, err := AttachISOXML(x, mediumPath(mediumB), BootDisk)
	if err != nil {
		t.Fatal(err)
	}
	if pd, _ := ParseDomain(y); len(pd.ISOs) != 2 || pd.Profile != ProfileWindows {
		t.Fatalf("%+v", pd)
	}
	if !strings.Contains(y, "<target dev='sdc' bus='sata'/>") {
		t.Fatalf("the driver CD goes on sdc:\n%s", y)
	}
	z, had, err := RemoveISOXML(y, mediumB)
	if err != nil || !had || z != x {
		t.Fatalf("eject of the driver CD gives the definition back exactly (%v %v)", had, err)
	}
	// rescue and unrescue give the Windows definition back exactly
	ejected, _, _ := RemoveISOXML(x, "")
	r, err := RescueXML(ejected, rescuePath(), rescueSum)
	if err != nil {
		t.Fatal(err)
	}
	if back, changed, err := UnrescueXML(r); err != nil || !changed || back != ejected {
		t.Fatalf("unrescue gives the definition back exactly (%v %v)", changed, err)
	}
}

func TestProfileValidation(t *testing.T) {
	for _, p := range []string{"", ProfileLinux, ProfileWindows} {
		s := profileSpec(p)
		if err := s.ValidateAnyMedia(); err != nil {
			t.Errorf("%q refused: %v", p, err)
		}
	}
	for _, p := range []string{"Windows", "WINDOWS", "mac", "windows ", "win", "../x", "windows'/><x", strings.Repeat("a", 64)} {
		s := profileSpec(p)
		if s.ValidateAnyMedia() == nil {
			t.Errorf("%q accepted", p)
		}
		if _, err := DomainXMLISO(testCfg(), s, ISOImage{Path: "/c/store/" + profileISOSum + ".iso", SHA256: profileISOSum}, VolumeSource{Name: RootVolumeName(s.UUID), Path: "/pool/" + RootVolumeName(s.UUID), PoolPath: "/pool"}); err == nil {
			t.Errorf("%q rendered", p)
		}
	}
	if !profileSpec(ProfileWindows).IsWindows() || profileSpec(ProfileLinux).IsWindows() || profileSpec("").IsWindows() {
		t.Error("IsWindows")
	}
}

// A profile never leaks into the JSON of a spec that has none (the helper request, the stored operation), so nothing recorded before changes.
func TestProfileIsAbsentFromASpecWithoutOne(t *testing.T) {
	for _, p := range []string{"", ProfileLinux} {
		b, err := json.Marshal(profileSpec(p))
		if err != nil || (p == "" && strings.Contains(string(b), "profile")) {
			t.Fatalf("%q: %s %v", p, b, err)
		}
	}
	b, err := json.Marshal(profileSpec(ProfileWindows))
	if err != nil || !strings.Contains(string(b), `"profile":"windows"`) {
		t.Fatalf("%s %v", b, err)
	}
	var back Spec
	if err := json.Unmarshal(b, &back); err != nil || back.Profile != ProfileWindows {
		t.Fatalf("%+v %v", back, err)
	}
}
