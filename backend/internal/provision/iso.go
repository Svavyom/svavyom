package provision

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"path/filepath"
	"regexp"
	"text/template"
)

// Installation media (M1-E02-S05, DR-023 D3). A VM created from an ISO has a blank qcow2 root disk, the verified ISO attached read-only as a CD that is
// the first boot device, no seed volume and no cloud-init. The ownership marker carries media='iso' so a seedless definition is provably the right
// shape. eject_iso removes the CD from the persistent definition of a stopped VM, after which it boots from its disk.

// ISOImage is the verified installation media a VM boots from: produced by Catalog.Verify and re-checked when the definition is rendered.
type ISOImage struct {
	Path   string // "<catalog_dir>/store/<sha256>.iso"
	SHA256 string
}

var isoFileRE = regexp.MustCompile(`^([0-9a-f]{64})\.iso$`)

// ISOFileSHA256 recovers the digest from a store file name; ok is false for any other name.
func ISOFileSHA256(file string) (string, bool) {
	m := isoFileRE.FindStringSubmatch(file)
	if m == nil {
		return "", false
	}
	return m[1], true
}

func (m ISOImage) validateFor(cfg Config, s Spec) error {
	want := filepath.Join(cfg.CatalogDir, StoreDir, s.ImageSHA256+".iso")
	if m.Path != want || filepath.Clean(m.Path) != m.Path || !backingPathRE.MatchString(m.Path) || m.SHA256 != s.ImageSHA256 {
		return ErrBacking
	}
	return nil
}

// DomainXMLISO renders the definition of a VM created from installation media.
func DomainXMLISO(cfg Config, s Spec, iso ISOImage, root VolumeSource) (string, error) {
	if err := cfg.Validate(); err != nil {
		return "", err
	}
	if err := s.ValidateAnyMedia(); err != nil || s.SSHPublicKey != "" {
		return "", ErrInvalidSpec
	}
	if err := iso.validateFor(cfg, s); err != nil {
		return "", err
	}
	if err := root.validateAs(RootVolumeName(s.UUID)); err != nil {
		return "", err
	}
	var b bytes.Buffer
	err := isoTemplate.Execute(&b, map[string]any{
		"Type": cfg.DomainType, "Name": s.Name, "UUID": s.UUID, "Fingerprint": s.Fingerprint, "Image": s.ImageID,
		"Memory": s.MemoryMiB, "VCPUs": s.VCPUs,
		"Network": s.Network, "MAC": MAC(s.UUID), "NS": MetadataNamespace, "Ver": MetadataVersion, "Real": cfg.DomainType == "kvm",
		"RootPath": root.Path, "ISOPath": iso.Path, "Windows": s.IsWindows(),
	})
	if err != nil {
		return "", fmt.Errorf("provision: domain template: %w", err)
	}
	if err := CheckDomainRootSource(b.String(), root); err != nil {
		return "", err
	}
	if _, _, _, ok := ISODisk(b.String()); !ok {
		return "", ErrBacking
	}
	return b.String(), nil
}

var isoTemplate = template.Must(template.New("iso-domain").Funcs(template.FuncMap{"xml": xmlText}).Parse(`<domain type='{{.Type}}'>
  <name>{{.Name}}</name>
  <uuid>{{.UUID}}</uuid>
  <metadata>
    <svavyom:managed xmlns:svavyom='{{.NS}}' version='{{.Ver}}' uuid='{{.UUID}}' fingerprint='{{.Fingerprint}}' image='{{.Image}}' media='iso'{{if .Windows}} profile='windows'{{end}}/>
  </metadata>
  <memory unit='MiB'>{{.Memory}}</memory>
  <currentMemory unit='MiB'>{{.Memory}}</currentMemory>
  <vcpu placement='static'>{{.VCPUs}}</vcpu>
  <os>
    <type arch='x86_64' machine='{{if .Real}}q35{{else}}pc{{end}}'>hvm</type>
  </os>
{{- if .Real}}
  <features><acpi/><apic/>{{if .Windows}}<hyperv mode='custom'><relaxed state='on'/><vapic state='on'/><spinlocks state='on' retries='8191'/></hyperv>{{end}}</features>
  <cpu mode='host-model'/>
{{- end}}
{{- if and .Windows .Real}}
  <clock offset='localtime'><timer name='hypervclock' present='yes'/></clock>
{{- else if .Windows}}
  <clock offset='localtime'/>
{{- else}}
  <clock offset='utc'/>
{{- end}}
  <on_poweroff>destroy</on_poweroff>
  <on_reboot>restart</on_reboot>
  <on_crash>destroy</on_crash>
  <devices>
    <disk type='file' device='disk'>
      <driver name='qemu' type='qcow2'/>
      <source file='{{xml .RootPath}}'/>
      <target dev='{{if .Windows}}sda' bus='sata{{else}}vda' bus='virtio{{end}}'/>
      <boot order='2'/>
    </disk>
    <disk type='file' device='cdrom'>
      <driver name='qemu' type='raw'/>
      <source file='{{xml .ISOPath}}'>
        <seclabel model='dac' relabel='no'/>
      </source>
      <target dev='{{if .Windows}}sdb{{else}}sda{{end}}' bus='sata'/>
      <readonly/>
      <boot order='1'/>
    </disk>
    <interface type='network'>
      <source network='{{.Network}}'/>
      <mac address='{{.MAC}}'/>
      <model type='{{if .Windows}}e1000e{{else}}virtio{{end}}'/>
    </interface>
    <serial type='pty'><target port='0'/></serial>
    <console type='pty'><target type='serial' port='0'/></console>
    <graphics type='vnc'><listen type='none'/></graphics>
    <video><model type='vga' vram='16384' heads='1'/></video>
    <input type='tablet' bus='usb'/>
{{- if .Real}}
    <rng model='virtio'><backend model='random'>/dev/urandom</backend></rng>
{{- end}}
  </devices>
</domain>
`))

// isISODisk reports whether a disk of a definition is Svavyom's installation media: a read-only raw CD, a file named for a SHA-256 in the closed path alphabet,
// and exactly the one source directive that keeps libvirt from changing the owner of the immutable store file.
func isISODisk(d sourceDiskDoc) bool {
	f := d.Source.File
	if d.Device != "cdrom" || d.Type != "file" || d.Driver.Type != "raw" || d.ReadOnly == nil || !backingPathRE.MatchString(f) || filepath.Clean(f) != f {
		return false
	}
	if _, ok := ISOFileSHA256(filepath.Base(f)); !ok {
		return false
	}
	return len(d.Source.Seclabels) == 1 && d.Source.Seclabels[0].Model == "dac" && d.Source.Seclabels[0].Relabel == "no"
}

// ISODisk returns the installation media a definition carries (its digest, its file and the guest target).
func ISODisk(x string) (sha, path, dev string, ok bool) {
	var d struct {
		Disks []struct {
			sourceDiskDoc
			Target struct {
				Dev string `xml:"dev,attr"`
			} `xml:"target"`
		} `xml:"devices>disk"`
	}
	if len(x) > 1<<20 || xml.Unmarshal([]byte(x), &d) != nil {
		return "", "", "", false
	}
	for _, disk := range d.Disks {
		if isISODisk(disk.sourceDiskDoc) {
			s, _ := ISOFileSHA256(filepath.Base(disk.Source.File))
			return s, disk.Source.File, disk.Target.Dev, true
		}
	}
	return "", "", "", false
}

func xmlUnmarshalDisk(x string, d *sourceDiskDoc) error { return xml.Unmarshal([]byte(x), d) }

var isoDevRE = regexp.MustCompile(`^sd[a-z]$`)

// ISODiskXML renders the device element of the media, as the definition holds it (used to remove it).
func ISODiskXML(path, dev string) (string, error) {
	if !backingPathRE.MatchString(path) || filepath.Clean(path) != path || !isoDevRE.MatchString(dev) {
		return "", ErrVolumeSource
	}
	if _, ok := ISOFileSHA256(filepath.Base(path)); !ok {
		return "", ErrVolumeSource
	}
	return "<disk type='file' device='cdrom'><driver name='qemu' type='raw'/><source file='" + path + "'><seclabel model='dac' relabel='no'/></source>" +
		"<target dev='" + dev + "' bus='sata'/><readonly/></disk>", nil
}

// StepISOEjected is reported once the media is out of the definition.
const StepISOEjected = "iso-ejected"

// attachedMedium is one installation medium a definition carries.
type attachedMedium struct{ sha, path, dev string }

// attachedMedia returns every installation medium of a definition, in document order (ISODisk returns the first only).
func attachedMedia(x string) []attachedMedium {
	var d struct {
		Disks []struct {
			sourceDiskDoc
			Target struct {
				Dev string `xml:"dev,attr"`
			} `xml:"target"`
		} `xml:"devices>disk"`
	}
	if len(x) > 1<<20 || xml.Unmarshal([]byte(x), &d) != nil {
		return nil
	}
	var out []attachedMedium
	for _, disk := range d.Disks {
		if isISODisk(disk.sourceDiskDoc) {
			s, _ := ISOFileSHA256(filepath.Base(disk.Source.File))
			out = append(out, attachedMedium{sha: s, path: disk.Source.File, dev: disk.Target.Dev})
		}
	}
	return out
}
