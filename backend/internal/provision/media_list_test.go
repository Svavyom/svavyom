package provision

import (
	"errors"
	"strings"
	"testing"
)

// DR-031 slice 1: the list of attached installation media, its order, and removal of one medium by digest.

const (
	mediumA = "aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11"
	mediumB = "bb22bb22bb22bb22bb22bb22bb22bb22bb22bb22bb22bb22bb22bb22bb22bb22"
	mediumC = "cc33cc33cc33cc33cc33cc33cc33cc33cc33cc33cc33cc33cc33cc33cc33cc33"
)

func mediumPath(sha string) string { return "/c/store/" + sha + ".iso" }

// withMedium adds a read-only CD for the medium on the target, with a boot order when order > 0.
func withMedium(t *testing.T, x, sha, dev string, order int) string {
	t.Helper()
	y, ok := insertBeforeLast(x, "</devices>", "    "+cdromXML(mediumPath(sha), dev, order)+"\n")
	if !ok {
		t.Fatal("no devices section")
	}
	return y
}

// twoMedia is a cloud-image VM (so it has the seed CD on sda) with media A on sdb, which boots first, and B on sdc, in the per-device boot shape
// iso_attach produces.
func twoMedia(t *testing.T) string {
	t.Helper()
	x, err := toDeviceBoot(cloudXML(t))
	if err != nil {
		t.Fatal(err)
	}
	return withMedium(t, withMedium(t, x, mediumA, "sdb", 1), mediumB, "sdc", 0)
}

func TestParseListsEveryMediumInTargetOrder(t *testing.T) {
	pd, err := ParseDomain(cloudXML(t))
	if err != nil || pd.ISO != "" || len(pd.ISOs) != 0 {
		t.Fatalf("a cloud VM has no medium (its seed CD is not one): %+v %v", pd, err)
	}
	one := withMedium(t, cloudXML(t), mediumA, "sdb", 0)
	if pd, _ := ParseDomain(one); pd.ISO != mediumA || len(pd.ISOs) != 1 || pd.ISOs[0] != mediumA {
		t.Fatalf("one medium: %+v", pd)
	}
	// B is declared first in the document but sits on the later target: the list follows the guest target, not the document
	x := withMedium(t, withMedium(t, cloudXML(t), mediumB, "sdc", 0), mediumA, "sdb", 0)
	pd, _ = ParseDomain(x)
	if len(pd.ISOs) != 2 || pd.ISOs[0] != mediumA || pd.ISOs[1] != mediumB || pd.ISO != mediumA {
		t.Fatalf("target order, none boots: iso is the first: %+v", pd)
	}
	// the medium that boots next is the one reported as iso, wherever it sits
	y := withMedium(t, withMedium(t, cloudXML(t), mediumA, "sdb", 0), mediumB, "sdc", 1)
	if pd, _ = ParseDomain(y); pd.ISO != mediumB || pd.ISOs[0] != mediumA || pd.ISOs[1] != mediumB {
		t.Fatalf("the booting medium is iso: %+v", pd)
	}
	// three media (a CD added by hand): the first two are observed, nothing breaks
	z := withMedium(t, twoMedia(t), mediumC, "sdd", 0)
	if pd, _ = ParseDomain(z); len(pd.ISOs) != MaxMedia || pd.ISOs[0] != mediumA || pd.ISOs[1] != mediumB {
		t.Fatalf("at most %d: %+v", MaxMedia, pd)
	}
	// the same file on two targets is one medium to the person
	dup := withMedium(t, withMedium(t, cloudXML(t), mediumA, "sdb", 0), mediumA, "sdc", 0)
	if pd, _ = ParseDomain(dup); len(pd.ISOs) != 1 {
		t.Fatalf("duplicates collapse: %+v", pd)
	}
}

func TestRemoveOneMediumByDigest(t *testing.T) {
	x := twoMedia(t)
	if pd, _ := ParseDomain(x); pd.ISO != mediumA || len(pd.ISOs) != 2 {
		t.Fatalf("setup: %+v", pd)
	}
	// the booting medium goes: the other stays and does not inherit the boot order
	y, had, err := RemoveISOXML(x, mediumA)
	if err != nil || !had {
		t.Fatalf("%v %v", had, err)
	}
	pd, _ := ParseDomain(y)
	if len(pd.ISOs) != 1 || pd.ISOs[0] != mediumB || pd.ISO != mediumB || strings.Contains(y, "<boot order='1'/><boot") {
		t.Fatalf("B remains: %+v\n%s", pd, y)
	}
	if strings.Contains(y, "<boot order=") && !strings.Contains(y, "<boot dev='hd'/>") {
		t.Fatalf("no CD boots, so the disk does:\n%s", y)
	}
	// the other one goes: A stays and still boots
	y, had, err = RemoveISOXML(x, mediumB)
	if pd, _ = ParseDomain(y); err != nil || !had || len(pd.ISOs) != 1 || pd.ISOs[0] != mediumA || !strings.Contains(y, "<boot order='1'/>") {
		t.Fatalf("A remains and boots: %v %v %+v", had, err, pd)
	}
	// a medium that is not attached: success, nothing changed
	if same, had, err := RemoveISOXML(x, mediumC); err != nil || had || same != x {
		t.Fatalf("not attached: %v %v", had, err)
	}
	// two attached and no name: refused, nothing changed
	if same, had, err := RemoveISOXML(x, ""); !errors.Is(err, ErrMediaAmbiguous) || had || same != "" {
		t.Fatalf("ambiguous: %v %v %q", had, err, same)
	}
	// one attached and no name: that one goes, as before
	one := withMedium(t, cloudXML(t), mediumA, "sdb", 0)
	if back, had, err := RemoveISOXML(one, ""); err != nil || !had || back != cloudXML(t) {
		t.Fatalf("one medium, no name: %v %v", had, err)
	}
	// by name with one attached
	if back, had, err := RemoveISOXML(one, mediumA); err != nil || !had || back != cloudXML(t) {
		t.Fatalf("one medium, by name: %v %v", had, err)
	}
	// the seed CD is never touched
	if y, _, _ := RemoveISOXML(x, mediumA); !strings.Contains(y, "seed.iso") {
		t.Fatalf("the cloud-init seed stays:\n%s", y)
	}
}

func TestUnrescueRemovesOnlyTheRescueMedium(t *testing.T) {
	r, err := RescueXML(cloudXML(t), rescuePath(), rescueSum)
	if err != nil {
		t.Fatal(err)
	}
	// a CD added by hand next to the rescue medium survives unrescue
	r = withMedium(t, r, mediumB, "sdh", 0)
	back, changed, err := UnrescueXML(r)
	if err != nil || !changed {
		t.Fatalf("%v %v", changed, err)
	}
	if pd, _ := ParseDomain(back); len(pd.ISOs) != 1 || pd.ISOs[0] != mediumB || pd.Rescue != "" {
		t.Fatalf("only the rescue medium is removed: %+v", pd)
	}
}

// DR-031 slice 2: the attach matrix of the refinement (3.1) and the refusal of a definition with more than two media.
func TestAttachAMediumMatrix(t *testing.T) {
	cloud := cloudXML(t)
	// no medium: boots or not, as before
	for _, boot := range []string{BootCDROM, BootDisk} {
		y, err := AttachISOXML(cloud, mediumPath(mediumA), boot)
		if err != nil {
			t.Fatalf("first medium, %s: %v", boot, err)
		}
		if pd, _ := ParseDomain(y); len(pd.ISOs) != 1 || pd.ISOs[0] != mediumA {
			t.Fatalf("%s: %+v", boot, pd)
		}
		if (boot == BootCDROM) != strings.Contains(y, "<boot order='1'/>") {
			t.Fatalf("%s: boot order mismatch:\n%s", boot, y)
		}
	}
	// the driver medium attached first (just attached), then a booting second one: refused, nothing changed
	first, _ := AttachISOXML(cloud, mediumPath(mediumB), BootDisk)
	if _, err := AttachISOXML(first, mediumPath(mediumA), BootCDROM); err != ErrBoot {
		t.Fatalf("a second medium never boots, whichever order: %v", err)
	}
	// the installer first (boots), then the driver medium attached only
	inst, _ := AttachISOXML(cloud, mediumPath(mediumA), BootCDROM)
	both, err := AttachISOXML(inst, mediumPath(mediumB), BootDisk)
	if err != nil {
		t.Fatal(err)
	}
	pd, _ := ParseDomain(both)
	if len(pd.ISOs) != 2 || pd.ISO != mediumA || strings.Count(both, "device='cdrom'") != 3 {
		t.Fatalf("seed + two media; the installer still boots: %+v", pd)
	}
	for _, m := range attachedMedia(both) {
		if !strings.Contains(both, "<source file='"+m.path+"'>\n") && !strings.Contains(both, "<source file='"+m.path+"'><seclabel model='dac' relabel='no'/>") {
			t.Fatalf("each medium keeps the no-relabel directive: %s", m.path)
		}
	}
	// the same medium again and a third
	if same, err := AttachISOXML(both, mediumPath(mediumA), BootDisk); err != nil || same != both {
		t.Fatalf("the same medium again changes nothing: %v", err)
	}
	if _, err := AttachISOXML(both, mediumPath(mediumC), BootDisk); err != ErrISOPresent {
		t.Fatalf("a third: %v", err)
	}
	// a definition with more than two media is refused for attach and for eject, and left alone
	three := withMedium(t, both, mediumC, "sdh", 0)
	if _, err := AttachISOXML(three, mediumPath("dd44dd44dd44dd44dd44dd44dd44dd44dd44dd44dd44dd44dd44dd44dd44dd44"), BootDisk); !errors.Is(err, ErrTooManyMedia) {
		t.Fatalf("attach with three: %v", err)
	}
	if _, _, err := RemoveISOXML(three, mediumA); !errors.Is(err, ErrTooManyMedia) {
		t.Fatalf("eject with three: %v", err)
	}
	// in rescue mode nothing is attached
	r, err := RescueXML(cloud, rescuePath(), rescueSum)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := AttachISOXML(r, mediumPath(mediumA), BootDisk); !errors.Is(err, ErrRescued) {
		t.Fatalf("attach in rescue: %v", err)
	}
}
