package provision

import (
	"fmt"
	"regexp"
	"strings"
)

// Console, installation media and rescue on an existing VM (DR-026 D1, D2). Everything here is a pure transformation of a persistent domain
// definition: it adds or removes exactly the device elements named below, never anything a caller typed, and every result is checked by the
// caller against the postcondition before the operation is reported done. The definition goes back to the host through HostOps.DefineDomain,
// which libvirt applies to the persistent configuration of a stopped domain only.

const (
	graphicsXML = "<graphics type='vnc'><listen type='none'/></graphics>"
	videoXML    = "<video><model type='vga' vram='16384' heads='1'/></video>"
	tabletXML   = "<input type='tablet' bus='usb'/>"
)

// Errors of the device transformations (none carries caller input).
var (
	ErrISOPresent = fmt.Errorf("provision: installation media is already attached")
	ErrRescued    = fmt.Errorf("provision: the VM is in rescue mode")
	ErrNoGraphics = fmt.Errorf("provision: the VM has no graphical console")
	ErrDefinition = fmt.Errorf("provision: the domain definition has an unexpected shape")
	ErrBoot       = fmt.Errorf("provision: invalid boot choice")
)

// Boot choices of iso_attach.
const (
	BootCDROM = "cdrom"
	BootDisk  = "disk"
)

var (
	graphicsRE    = regexp.MustCompile(`<graphics\b[^>]*\btype=['"]vnc['"]`)
	tabletRE      = regexp.MustCompile(`<input\b[^>]*\btype=['"]tablet['"]`)
	diskRE        = regexp.MustCompile(`(?s)<disk\b.*?</disk>`)
	osBootDevRE   = regexp.MustCompile(`[ \t]*<boot dev=['"][a-z]+['"]\s*/>[ \t]*\n?`)
	diskBootRE    = regexp.MustCompile(`<boot order=['"][0-9]+['"]\s*/>`)
	targetDevRE   = regexp.MustCompile(`<target\b[^>]*\bdev=['"]([a-z0-9]+)['"]`)
	managedRE     = regexp.MustCompile(`<svavyom:managed\b[^>]*?/>`)
	rescueAttrRE  = regexp.MustCompile(`\s+rescue=['"][0-9a-f]{64}['"]`)
	rescueISORE   = regexp.MustCompile(`\brescue=['"]([0-9a-f]{64})['"]`)
	osSectionRE   = regexp.MustCompile(`(?s)<os\b.*?</os>`)
	osTypeCloseRE = regexp.MustCompile(`</type>`)
)

// HasGraphics reports whether the definition carries a VNC graphics device.
func HasGraphics(x string) bool { return graphicsRE.MatchString(x) }

// RescueISO returns the digest of the rescue media the definition records ("" when the VM is not in rescue mode).
func RescueISO(x string) string {
	if m := managedRE.FindString(x); m != "" {
		if r := rescueISORE.FindStringSubmatch(m); r != nil {
			return r[1]
		}
	}
	return ""
}

func insertBeforeLast(x, marker, text string) (string, bool) {
	i := strings.LastIndex(x, marker)
	if i < 0 {
		return x, false
	}
	for i > 0 && (x[i-1] == ' ' || x[i-1] == '\t') {
		i-- // the new lines go in front of the closing tag's own indentation
	}
	return x[:i] + text + x[i:], true
}

// AddGraphicsXML adds the graphical console devices (VNC with no listener, a VGA adapter so any installer can draw, and an absolute pointer) to a
// definition that has none. A definition that already has a VNC device is returned unchanged.
func AddGraphicsXML(x string) (string, error) {
	if HasGraphics(x) {
		return x, nil
	}
	add := "    " + graphicsXML + "\n"
	if !strings.Contains(x, "<video") {
		add += "    " + videoXML + "\n"
	}
	if !tabletRE.MatchString(x) {
		add += "    " + tabletXML + "\n"
	}
	y, ok := insertBeforeLast(x, "</devices>", add)
	if !ok {
		return "", ErrDefinition
	}
	return y, nil
}

func cdromXML(path, dev string, order int) string {
	boot := ""
	if order > 0 {
		boot = fmt.Sprintf("<boot order='%d'/>", order)
	}
	return "<disk type='file' device='cdrom'><driver name='qemu' type='raw'/><source file='" + path + "'><seclabel model='dac' relabel='no'/></source>" +
		"<target dev='" + dev + "' bus='sata'/><readonly/>" + boot + "</disk>"
}

func nextCDDev(x string) (string, error) {
	used := map[string]bool{}
	for _, m := range targetDevRE.FindAllStringSubmatch(x, -1) {
		used[m[1]] = true
	}
	for c := 'a'; c <= 'h'; c++ {
		if d := "sd" + string(c); !used[d] {
			return d, nil
		}
	}
	return "", ErrDefinition
}

// rootDiskSpan returns the byte span of the first non-CD disk (the VM's root disk).
func rootDiskSpan(x string) (int, int, bool) {
	for _, loc := range diskRE.FindAllStringIndex(x, -1) {
		if strings.Contains(x[loc[0]:loc[1]], "device='disk'") || strings.Contains(x[loc[0]:loc[1]], `device="disk"`) {
			return loc[0], loc[1], true
		}
	}
	return 0, 0, false
}

func withBootOrder(disk string, n int) string {
	if strings.Contains(disk, fmt.Sprintf("<boot order='%d'/>", n)) {
		return disk
	}
	disk = diskBootRE.ReplaceAllString(disk, "")
	i := strings.LastIndex(disk, "</disk>")
	if i < 0 {
		return disk
	}
	return disk[:i] + fmt.Sprintf("<boot order='%d'/>", n) + disk[i:]
}

// toDeviceBoot switches a definition that picks its boot device in <os> to per-device boot orders, the root disk second, so a CD can be first.
func toDeviceBoot(x string) (string, error) {
	s, e, ok := rootDiskSpan(x)
	if !ok {
		return "", ErrDefinition
	}
	x = x[:s] + withBootOrder(x[s:e], 2) + x[e:]
	if loc := osSectionRE.FindStringIndex(x); loc != nil {
		x = x[:loc[0]] + osBootDevRE.ReplaceAllString(x[loc[0]:loc[1]], "") + x[loc[1]:]
	}
	return x, nil
}

func hasCDBoot(x string) bool {
	for _, d := range diskRE.FindAllString(x, -1) {
		if strings.Contains(d, "device='cdrom'") && diskBootRE.MatchString(d) {
			return true
		}
	}
	return false
}

// normalizeBoot returns a definition that no longer has a bootable CD to the shape the cloud-image template has: the boot device named in <os>
// and no per-device orders. A VM created from installation media keeps per-device orders (its template uses them).
func normalizeBoot(x string) string {
	if strings.Contains(x, "media='iso'") || hasCDBoot(x) {
		return x
	}
	loc := osSectionRE.FindStringIndex(x)
	if loc == nil || strings.Contains(x[loc[0]:loc[1]], "<boot dev=") {
		return x
	}
	s, e, ok := rootDiskSpan(x)
	if !ok || !strings.Contains(x[s:e], "<boot order='2'/>") {
		return x
	}
	for _, d := range diskRE.FindAllString(x, -1) {
		if diskBootRE.MatchString(d) {
			x = strings.Replace(x, d, diskBootRE.ReplaceAllString(d, ""), 1)
		}
	}
	loc = osSectionRE.FindStringIndex(x)
	sec := x[loc[0]:loc[1]]
	t := osTypeCloseRE.FindStringIndex(sec)
	if t == nil {
		return x
	}
	sec = sec[:t[1]] + "\n    <boot dev='hd'/>" + sec[t[1]:]
	return x[:loc[0]] + sec + x[loc[1]:]
}

// AttachISOXML adds the installation media at path to the definition as a read-only CD on the first free SATA target. boot is BootCDROM (the VM boots
// from it next time) or BootDisk (it is just attached). Media already attached from the same path is success; other media is ErrISOPresent.
func AttachISOXML(x, path, boot string) (string, error) {
	if boot != BootCDROM && boot != BootDisk {
		return "", ErrBoot
	}
	if _, err := ISODiskXML(path, "sda"); err != nil {
		return "", ErrBacking
	}
	if _, have, _, ok := ISODisk(x); ok {
		if have == path {
			return x, nil
		}
		return "", ErrISOPresent
	}
	dev, err := nextCDDev(x)
	if err != nil {
		return "", err
	}
	order := 0
	if boot == BootCDROM {
		if x, err = toDeviceBoot(x); err != nil {
			return "", err
		}
		order = 1
	}
	y, ok := insertBeforeLast(x, "</devices>", "    "+cdromXML(path, dev, order)+"\n")
	if !ok {
		return "", ErrDefinition
	}
	return y, nil
}

// RemoveISOXML removes the installation media from the definition (none is success) and puts the boot choice back to the cloud-image shape when no CD boots.
func RemoveISOXML(x string) (string, bool, error) {
	for _, loc := range diskRE.FindAllStringIndex(x, -1) {
		var d sourceDiskDoc
		if !strings.Contains(x[loc[0]:loc[1]], "device='cdrom'") || xmlUnmarshalDisk(x[loc[0]:loc[1]], &d) != nil || !isISODisk(d) {
			continue
		}
		start := loc[0]
		for start > 0 && (x[start-1] == ' ' || x[start-1] == '\t') {
			start--
		}
		end := loc[1]
		if end < len(x) && x[end] == '\n' {
			end++
		}
		return normalizeBoot(x[:start] + x[end:]), true, nil
	}
	return x, false, nil
}

// RescueXML puts the VM in rescue mode: the rescue media is attached and boots first, with the original root disk kept as it is (the rescue system sees it
// as an additional disk), and a marker records the media. It needs a graphical console, no other media attached and no rescue in progress.
func RescueXML(x, path, sha string) (string, error) {
	if RescueISO(x) != "" {
		return "", ErrRescued
	}
	if !HasGraphics(x) {
		return "", ErrNoGraphics
	}
	if _, _, _, ok := ISODisk(x); ok {
		return "", ErrISOPresent
	}
	if !fingerprintRE.MatchString(sha) {
		return "", ErrBacking
	}
	y, err := AttachISOXML(x, path, BootCDROM)
	if err != nil {
		return "", err
	}
	// libvirt keeps at most one element per namespace in <metadata> (it silently drops a second one), so the rescue state is an attribute of the
	// ownership marker, which every definition of ours already carries.
	loc := managedRE.FindStringIndex(y)
	if loc == nil {
		return "", ErrDefinition
	}
	tag := y[loc[0]:loc[1]]
	return y[:loc[0]] + strings.TrimSuffix(tag, "/>") + " rescue='" + sha + "'/>" + y[loc[1]:], nil
}

// UnrescueXML takes the VM out of rescue mode: the marker and the rescue media go and the boot choice returns to the disk. A VM that is not in rescue
// mode is returned unchanged.
func UnrescueXML(x string) (string, bool, error) {
	if RescueISO(x) == "" {
		return x, false, nil
	}
	loc := managedRE.FindStringIndex(x)
	if loc == nil {
		return "", false, ErrDefinition
	}
	y := x[:loc[0]] + rescueAttrRE.ReplaceAllString(x[loc[0]:loc[1]], "") + x[loc[1]:]
	z, _, err := RemoveISOXML(y)
	if err != nil {
		return "", false, err
	}
	return z, true, nil
}
