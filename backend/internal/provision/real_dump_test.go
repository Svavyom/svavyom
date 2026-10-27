package provision

import (
	"errors"
	"os"
	"strings"
	"testing"
)

// A definition as libvirt itself writes it (testdata/libvirt-dump-two-cds.xml: a VM created from installation media, with a second CD added by hand
// next to the installer, as an operator did with virsh; only the pool path and the VM name were rewritten). Svavyom's own templates never produce this
// formatting (double-quoted metadata, PCI addresses, controllers), so this is the test that the media code reads and edits what a real host holds.
const (
	dumpInstaller = "6dae072e7f78f4ccab74a45341de0d6e2d45c39be25f1f5920a2ab4f51d7bcbb"
	dumpDrivers   = "303f7ae40dad495d6ae474fdc571df58958a4dbc5c37a522d80f9a203867949d"
)

func dumpXML(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile("testdata/libvirt-dump-two-cds.xml")
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestARealLibvirtDumpWithAHandAddedSecondCDIsReadAndEditedCorrectly(t *testing.T) {
	x := dumpXML(t)
	pd, err := ParseDomain(x)
	if err != nil || !pd.Managed || pd.Media != MediaISO || !pd.Graphics {
		t.Fatalf("%+v %v", pd, err)
	}
	if len(pd.ISOs) != 2 || pd.ISOs[0] != dumpInstaller || pd.ISOs[1] != dumpDrivers || pd.ISO != dumpInstaller {
		t.Fatalf("both CDs in target order, the installer (boot order 1) is the one that boots: %+v", pd)
	}
	if pd.Root != RootVolumeName(pd.UUID) {
		t.Fatalf("the root volume is recognised in a libvirt-formatted definition: %q", pd.Root)
	}

	// a third medium is refused; the second again changes nothing
	if _, err := AttachISOXML(x, "/var/lib/svavyom/images/store/"+strings.Repeat("0", 64)+".iso", BootDisk); !errors.Is(err, ErrISOPresent) {
		t.Fatalf("a third medium: %v", err)
	}
	if same, err := AttachISOXML(x, "/var/lib/svavyom/images/store/"+dumpDrivers+".iso", BootDisk); err != nil || same != x {
		t.Fatalf("the driver CD again: %v", err)
	}

	// eject by name: the driver CD goes, the installer stays and keeps booting; no name with two attached is refused
	if _, _, err := RemoveISOXML(x, ""); !errors.Is(err, ErrMediaAmbiguous) {
		t.Fatalf("two attached, no name: %v", err)
	}
	y, had, err := RemoveISOXML(x, dumpDrivers)
	if err != nil || !had {
		t.Fatalf("%v %v", had, err)
	}
	if pd, _ := ParseDomain(y); len(pd.ISOs) != 1 || pd.ISOs[0] != dumpInstaller || strings.Contains(y, dumpDrivers) || !strings.Contains(y, `<boot order='1'/>`) {
		t.Fatalf("the installer remains and still boots:\n%s", y)
	}
	// and the installer by name leaves the driver CD with no boot order and the disk to boot
	z, _, err := RemoveISOXML(x, dumpInstaller)
	if err != nil {
		t.Fatal(err)
	}
	if pd, _ := ParseDomain(z); len(pd.ISOs) != 1 || pd.ISOs[0] != dumpDrivers || strings.Contains(z, dumpInstaller) {
		t.Fatalf("%+v", pd)
	}
}
