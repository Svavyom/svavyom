package provision

import (
	"strings"
	"testing"
)

const rescueSum = "ee11ee11ee11ee11ee11ee11ee11ee11ee11ee11ee11ee11ee11ee11ee11ee11"

func rescuePath() string { return "/c/store/" + rescueSum + ".iso" }

// cloudXML is a cloud-image VM definition with the boot device named in <os>.
func cloudXML(t *testing.T) string {
	x, _, _, _ := goodXML(t)
	return x
}

// isoXML is a VM created from installation media (per-device boot orders), then ejected, as such a VM is after its install.
func isoXML(t *testing.T) string {
	cfg := testCfg()
	sum := strings.Repeat("ab", 32)
	s := Spec{Name: "inst-1", UUID: "11111111-2222-4333-8444-555555555555", Fingerprint: strings.Repeat("cd", 32), VCPUs: 2, MemoryMiB: 1024, ImageID: "alpine-iso", ImageSHA256: sum, DiskGiB: 20, Network: "svavyom-nat", Media: MediaISO}
	root := VolumeSource{Name: RootVolumeName(s.UUID), Path: "/pool/" + RootVolumeName(s.UUID), PoolPath: "/pool"}
	x, err := DomainXMLISO(cfg, s, ISOImage{Path: "/c/store/" + sum + ".iso", SHA256: sum}, root)
	if err != nil {
		t.Fatal(err)
	}
	return x
}

func TestNewDefinitionsCarryAConsoleThatListensNowhere(t *testing.T) {
	for name, x := range map[string]string{"cloud": cloudXML(t), "iso": isoXML(t)} {
		if !HasGraphics(x) || strings.Count(x, "<graphics") != 1 || !strings.Contains(x, graphicsXML) || strings.Contains(x, "autoport") || strings.Contains(x, "passwd") || strings.Contains(x, "<graphics type='vnc' port") {
			t.Errorf("%s: %s", name, x)
		}
		if !strings.Contains(x, "<video>") || !strings.Contains(x, "type='tablet'") {
			t.Errorf("%s lacks the video adapter or the pointer", name)
		}
		if pd, err := ParseDomain(x); err != nil || !pd.Graphics || pd.Rescue != "" {
			t.Errorf("%s: %+v %v", name, pd, err)
		}
	}
}

func TestAddGraphicsGivesAnOldDefinitionTheDevicesOnceAndOnlyOnce(t *testing.T) {
	x := cloudXML(t)
	old := strings.Replace(strings.Replace(strings.Replace(x, "    "+graphicsXML+"\n", "", 1), "    "+videoXML+"\n", "", 1), "    "+tabletXML+"\n", "", 1)
	if HasGraphics(old) || strings.Contains(old, "<video") {
		t.Fatal("test setup")
	}
	y, err := AddGraphicsXML(old)
	if err != nil || y != x {
		t.Fatalf("adding the devices to an old definition must give the current template shape:\n%s\n%v", y, err)
	}
	again, err := AddGraphicsXML(y)
	if err != nil || again != y {
		t.Fatal("a second call changes nothing")
	}
	if _, err := AddGraphicsXML("<domain></domain>"); err == nil {
		t.Fatal("a definition without a devices section is refused")
	}
	// libvirt may already have given a video adapter: it is kept, not doubled
	withVideo := strings.Replace(old, "</devices>", "    <video><model type='cirrus'/></video>\n  </devices>", 1)
	z, _ := AddGraphicsXML(withVideo)
	if strings.Count(z, "<video") != 1 || !HasGraphics(z) {
		t.Fatalf("%s", z)
	}
}

func TestAttachISOAsABootDeviceAndEjectGivesTheOriginalBack(t *testing.T) {
	x := cloudXML(t)
	y, err := AttachISOXML(x, rescuePath(), BootCDROM)
	if err != nil {
		t.Fatal(err)
	}
	sha, path, dev, ok := ISODisk(y)
	if !ok || sha != rescueSum || path != rescuePath() || dev != "sdb" {
		t.Fatalf("the seed holds sda, so the media goes on sdb: %s %s %s %v", sha, path, dev, ok)
	}
	if strings.Contains(y, "<boot dev=") || !strings.Contains(y, "<boot order='1'/>") || !strings.Contains(y, "<boot order='2'/>") {
		t.Fatalf("boot choice must be per device with the media first:\n%s", y)
	}
	if pd, _ := ParseDomain(y); pd.ISO != rescueSum || pd.Seed != SeedVolumeName(pd.UUID) || !pd.Managed {
		t.Fatalf("the seed and the ownership survive: %+v", pd)
	}
	if same, err := AttachISOXML(y, rescuePath(), BootCDROM); err != nil || same != y {
		t.Fatal("the same media again is success and changes nothing")
	}
	if _, err := AttachISOXML(y, "/c/store/"+strings.Repeat("0", 64)+".iso", BootDisk); err != ErrISOPresent {
		t.Fatalf("other media while one is attached: %v", err)
	}
	back, had, err := RemoveISOXML(y, "")
	if err != nil || !had || back != x {
		t.Fatalf("eject must give back exactly the definition we started with (%v %v):\n%s", had, err, back)
	}
	if again, had, _ := RemoveISOXML(back, ""); had || again != back {
		t.Fatal("no media: nothing to do")
	}
}

func TestAttachISOWithoutBootingFromItLeavesTheBootChoiceAlone(t *testing.T) {
	x := cloudXML(t)
	y, err := AttachISOXML(x, rescuePath(), BootDisk)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(y, "<boot dev='hd'/>") || strings.Contains(y, "<boot order=") {
		t.Fatalf("the VM still boots from its disk:\n%s", y)
	}
	if back, _, _ := RemoveISOXML(y, ""); back != x {
		t.Fatal("eject is exact")
	}
}

func TestAttachISORefusesBadInput(t *testing.T) {
	x := cloudXML(t)
	for _, c := range []struct{ path, boot string }{{rescuePath(), "net"}, {rescuePath(), ""}, {"/tmp/x.iso", BootDisk}, {"/c/store/" + rescueSum + ".qcow2", BootDisk}, {"relative.iso", BootDisk}, {"/c/store/../x.iso", BootCDROM}} {
		if _, err := AttachISOXML(x, c.path, c.boot); err == nil {
			t.Errorf("%+v accepted", c)
		}
	}
}

func TestAnISOCreatedVMKeepsItsPerDeviceBootAfterMediaCome(t *testing.T) {
	x := isoXML(t)
	ejected, had, err := RemoveISOXML(x, "")
	if err != nil || !had || ISOPresent(ejected) {
		t.Fatalf("%v %v", had, err)
	}
	if !strings.Contains(ejected, "<boot order='2'/>") || strings.Contains(ejected, "<boot dev=") {
		t.Fatalf("an installed VM boots its disk by device order:\n%s", ejected)
	}
	y, err := AttachISOXML(ejected, rescuePath(), BootCDROM)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, dev, ok := ISODisk(y); !ok || dev != "sda" {
		t.Fatalf("the first CD slot is free again: %s", dev)
	}
	if back, _, _ := RemoveISOXML(y, ""); back != ejected {
		t.Fatalf("eject is exact:\n%s", back)
	}
}

// ISOPresent is a small test helper.
func ISOPresent(x string) bool { _, _, _, ok := ISODisk(x); return ok }

func TestRescueThenUnrescueIsExactForBothKindsOfVM(t *testing.T) {
	for name, x := range map[string]string{"cloud": cloudXML(t), "installed iso": func() string { y, _, _ := RemoveISOXML(isoXML(t), ""); return y }()} {
		r, err := RescueXML(x, rescuePath(), rescueSum)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		pd, _ := ParseDomain(r)
		if pd.Rescue != rescueSum || pd.ISO != rescueSum || !pd.Managed || RescueISO(r) != rescueSum {
			t.Fatalf("%s: %+v", name, pd)
		}
		if !strings.Contains(r, "<boot order='1'/>") {
			t.Fatalf("%s: the rescue media must boot first", name)
		}
		if _, err := RescueXML(r, rescuePath(), rescueSum); err != ErrRescued {
			t.Fatalf("%s: rescue twice: %v", name, err)
		}
		if _, err := AttachISOXML(r, "/c/store/"+strings.Repeat("0", 64)+".iso", BootDisk); err != ErrISOPresent {
			t.Fatalf("%s: other media in rescue mode: %v", name, err)
		}
		back, changed, err := UnrescueXML(r)
		if err != nil || !changed || back != x {
			t.Fatalf("%s: unrescue must give back exactly the definition we started with (%v %v):\n%s", name, changed, err, back)
		}
		if again, changed, _ := UnrescueXML(back); changed || again != back {
			t.Fatalf("%s: not in rescue mode: nothing to do", name)
		}
	}
}

func TestRescueNeedsAConsoleAndFreeMedia(t *testing.T) {
	x := cloudXML(t)
	noGfx := strings.Replace(x, "    "+graphicsXML+"\n", "", 1)
	if _, err := RescueXML(noGfx, rescuePath(), rescueSum); err != ErrNoGraphics {
		t.Fatalf("a rescue the person cannot see is no rescue: %v", err)
	}
	withISO, _ := AttachISOXML(x, rescuePath(), BootDisk)
	if _, err := RescueXML(withISO, rescuePath(), rescueSum); err != ErrISOPresent {
		t.Fatalf("media attached: %v", err)
	}
	if _, err := RescueXML(x, rescuePath(), "nothex"); err == nil {
		t.Fatal("a bad digest")
	}
	if _, err := RescueXML("<domain><devices>"+graphicsXML+"</devices></domain>", rescuePath(), rescueSum); err == nil {
		t.Fatal("a definition without metadata or disks is refused, not guessed at")
	}
}

func TestTheMarkerSurvivesWhatLibvirtDoesToADefinition(t *testing.T) {
	// libvirt re-serialises the definition: it adds aliases and addresses to devices and sorts attributes. The transformations only look for the
	// shapes below, so a definition with those additions still round-trips.
	x := cloudXML(t)
	noisy := strings.Replace(x, "<target dev='vda' bus='virtio'/>", "<target dev='vda' bus='virtio'/>\n      <alias name='virtio-disk0'/>\n      <address type='pci' domain='0x0000' bus='0x04' slot='0x00' function='0x0'/>", 1)
	r, err := RescueXML(noisy, rescuePath(), rescueSum)
	if err != nil {
		t.Fatal(err)
	}
	if back, ok, err := UnrescueXML(r); err != nil || !ok || back != noisy {
		t.Fatalf("%v %v\n%s", ok, err, back)
	}
}

// libvirt re-serialises the ownership marker with double quotes and keeps only ONE element per namespace in <metadata>: the rescue state must be an
// attribute of the marker, and must survive that re-serialisation (found on the real host, where a second element was silently dropped).
func TestRescueStateIsOnTheMarkerAndSurvivesLibvirtsQuoting(t *testing.T) {
	x := cloudXML(t)
	r, err := RescueXML(x, rescuePath(), rescueSum)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(r, "<svavyom:rescue") || strings.Count(r, "<svavyom:") != 1 || !strings.Contains(r, "rescue='"+rescueSum+"'/>") {
		t.Fatalf("one element in the namespace, the state an attribute of it:\n%s", r)
	}
	dq := managedRE.ReplaceAllStringFunc(r, func(m string) string { return strings.NewReplacer("'", `"`).Replace(m) })
	if RescueISO(dq) != rescueSum {
		t.Fatalf("double quotes: %q", RescueISO(dq))
	}
	if pd, _ := ParseDomain(dq); pd.Rescue != rescueSum || !pd.Managed {
		t.Fatalf("%+v", pd)
	}
	back, changed, err := UnrescueXML(dq)
	if err != nil || !changed || RescueISO(back) != "" || strings.Contains(back, "rescue=") {
		t.Fatalf("%v %v\n%s", changed, err, back)
	}
	if _, _, err := UnrescueXML("<domain></domain>"); err != nil {
		t.Fatalf("a definition not in rescue mode is untouched: %v", err)
	}
}
