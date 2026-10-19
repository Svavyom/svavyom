package provision

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"text/template"
)

// MetadataNamespace is the XML namespace of Svavyom's ownership marker inside a domain's <metadata>.
const MetadataNamespace = "https://svavyom.invalid/xml/1"

// MetadataVersion is the marker schema version.
const MetadataVersion = "1"

// DomainXML renders the libvirt domain definition for a validated spec from a fixed template. Every interpolated value has
// already passed a strict grammar (names, UUID, hex digests, bounded integers, a base64-free MAC), and the template emits
// them only as XML attribute or element text from that closed set, so no value can introduce markup. There is no
// caller-supplied XML anywhere on this path.
//
// The root disk declares its immutable base image explicitly (backingStore / format qcow2 / source file, ended by an empty
// backingStore) and marks ONLY that backing source <seclabel model='dac' relabel='no'/>, so libvirt's DAC driver never changes the
// owner of the root-owned base image (CT-PRODUCT-DELIVERY-008). The writable overlay keeps the default handling, and no
// domain-wide seclabel is emitted. Both the writable overlay and the NoCloud seed are file-backed disks at src.Root.Path and
// src.Seed.Path, the paths libvirt resolved for the volumes Svavyom created, so the per-guest AppArmor profile names exactly those
// files (CT-PRODUCT-DELIVERY-009 and its addendum); the seed is a readonly cdrom with no no-relabel directive.
// backing must be the catalog-qualified image of s (Catalog.Backing); anything else is refused,
// and the finished document is checked once more with CheckDomainBacking.
func DomainXML(cfg Config, s Spec, backing BackingImage, src DiskSources) (string, error) {
	return domainXML(cfg, s, backing, src, Spec.Validate)
}

// DomainXMLExisting renders the definition of a VM that already exists (reinstall, restore): identical, but the size limits are the hard
// ceilings instead of the create-time choice lists, because the VM's disk may have been grown.
func DomainXMLExisting(cfg Config, s Spec, backing BackingImage, src DiskSources) (string, error) {
	return domainXML(cfg, s, backing, src, Spec.ValidateExisting)
}

func domainXML(cfg Config, s Spec, backing BackingImage, src DiskSources, validate func(Spec) error) (string, error) {
	if err := cfg.Validate(); err != nil {
		return "", err
	}
	if err := validate(s); err != nil {
		return "", err
	}
	if err := backing.validateFor(cfg, s); err != nil {
		return "", err
	}
	if err := src.validateFor(s); err != nil {
		return "", err
	}
	var b bytes.Buffer
	err := domainTemplate.Execute(&b, map[string]any{
		"Type": cfg.DomainType, "Name": s.Name, "UUID": s.UUID, "Fingerprint": s.Fingerprint, "Image": s.ImageID,
		"Memory": s.MemoryMiB, "VCPUs": s.VCPUs,
		"Network": s.Network, "MAC": MAC(s.UUID), "NS": MetadataNamespace, "Ver": MetadataVersion, "Real": cfg.DomainType == "kvm",
		"RootPath": src.Root.Path, "SeedPath": src.Seed.Path, "SeedFormat": seedFormat, "BackingPath": backing.Path, "BackingFormat": backing.Format,
	})
	if err != nil {
		return "", fmt.Errorf("provision: domain template: %w", err)
	}
	if err := CheckDomainBacking(b.String(), backing); err != nil {
		return "", err
	}
	if err := CheckDomainSources(b.String(), src); err != nil {
		return "", err
	}
	return b.String(), nil
}

// xmlText escapes a value for an XML attribute or text position. The backing path already passes a closed alphabet; this keeps the
// template safe on its own.
func xmlText(v string) (string, error) {
	var b bytes.Buffer
	if err := xml.EscapeText(&b, []byte(v)); err != nil {
		return "", err
	}
	return b.String(), nil
}

var domainTemplate = template.Must(template.New("domain").Funcs(template.FuncMap{"xml": xmlText}).Parse(`<domain type='{{.Type}}'>
  <name>{{.Name}}</name>
  <uuid>{{.UUID}}</uuid>
  <metadata>
    <svavyom:managed xmlns:svavyom='{{.NS}}' version='{{.Ver}}' uuid='{{.UUID}}' fingerprint='{{.Fingerprint}}' image='{{.Image}}'/>
  </metadata>
  <memory unit='MiB'>{{.Memory}}</memory>
  <currentMemory unit='MiB'>{{.Memory}}</currentMemory>
  <vcpu placement='static'>{{.VCPUs}}</vcpu>
  <os>
    <type arch='x86_64' machine='{{if .Real}}q35{{else}}pc{{end}}'>hvm</type>
    <boot dev='hd'/>
  </os>
{{- if .Real}}
  <features><acpi/><apic/></features>
  <cpu mode='host-model'/>
{{- end}}
  <clock offset='utc'/>
  <on_poweroff>destroy</on_poweroff>
  <on_reboot>restart</on_reboot>
  <on_crash>destroy</on_crash>
  <devices>
    <disk type='file' device='disk'>
      <driver name='qemu' type='qcow2'/>
      <source file='{{xml .RootPath}}'/>
      <backingStore type='file'>
        <format type='{{.BackingFormat}}'/>
        <source file='{{xml .BackingPath}}'>
          <seclabel model='dac' relabel='no'/>
        </source>
        <backingStore/>
      </backingStore>
      <target dev='vda' bus='virtio'/>
    </disk>
    <disk type='file' device='cdrom'>
      <driver name='qemu' type='{{.SeedFormat}}'/>
      <source file='{{xml .SeedPath}}'/>
      <target dev='sda' bus='sata'/>
      <readonly/>
    </disk>
    <interface type='network'>
      <source network='{{.Network}}'/>
      <mac address='{{.MAC}}'/>
      <model type='virtio'/>
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
