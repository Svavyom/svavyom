package provision

import (
	"encoding/xml"
	"path"
	"strings"
)

// Domain is the part of a libvirt domain definition Svavyom reads back: identity, size and the ownership marker. Parsed with
// encoding/xml into typed fields; nothing is evaluated and no other element is retained.
type Domain struct {
	Name        string
	UUID        string
	VCPUs       int
	MemoryMiB   int
	Managed     bool       // the ownership marker is present, versioned, and its uuid matches the domain's
	Fingerprint string     // from the marker
	ImageID     string     // from the marker
	Root, Seed  string     // volume names of the first disk and of the cdrom
	Data        []DataDisk // Svavyom data volumes attached to the definition, in document order
	Media       string     // "iso" when the marker says the VM was created from installation media
	ISO         string     // the SHA-256 of the installation media attached now ("" when none)
	Network     string     // the libvirt network of the first network interface ("" when it has none)
	MAC         string     // that interface's MAC address, lower case
	Graphics    bool       // the definition carries a VNC graphical console (DR-026 D1)
	Rescue      string     // the SHA-256 of the rescue media when the VM is in rescue mode (DR-026 D2), else ""
}

// DataDisk is one standalone data volume attached to a domain: the volume's own name (not the pool file name) and the guest target device.
type DataDisk struct{ Volume, Dev string }

type domainDoc struct {
	Name   string `xml:"name"`
	UUID   string `xml:"uuid"`
	Memory struct {
		Unit  string `xml:"unit,attr"`
		Value int64  `xml:",chardata"`
	} `xml:"memory"`
	VCPU     int `xml:"vcpu"`
	Metadata struct {
		Children []struct {
			XMLName xml.Name
			Attrs   []xml.Attr `xml:",any,attr"`
		} `xml:",any"`
	} `xml:"metadata"`
	Disks []struct {
		Device string `xml:"device,attr"`
		Source struct {
			Volume string `xml:"volume,attr"`
			File   string `xml:"file,attr"`
		} `xml:"source"`
		Target struct {
			Dev string `xml:"dev,attr"`
		} `xml:"target"`
	} `xml:"devices>disk"`
	Interfaces []struct {
		Type   string `xml:"type,attr"`
		Source struct {
			Network string `xml:"network,attr"`
		} `xml:"source"`
		MAC struct {
			Address string `xml:"address,attr"`
		} `xml:"mac"`
	} `xml:"devices>interface"`
}

// ParseDomain parses a domain definition. The marker counts only if it is in Svavyom's namespace, has the current version, repeats
// the domain's UUID, and carries a well-formed fingerprint and image id; otherwise Managed is false (never an error: a foreign
// domain is a normal thing to read).
func ParseDomain(x string) (Domain, error) {
	var d domainDoc
	if len(x) > 1<<20 {
		return Domain{}, ErrInvalidSpec
	}
	if err := xml.Unmarshal([]byte(x), &d); err != nil {
		return Domain{}, ErrInvalidSpec
	}
	out := Domain{Name: d.Name, UUID: strings.ToLower(d.UUID), VCPUs: d.VCPU}
	switch d.Memory.Unit {
	case "", "KiB", "k", "KB":
		out.MemoryMiB = int(d.Memory.Value / 1024)
	case "MiB", "M":
		out.MemoryMiB = int(d.Memory.Value)
	case "GiB", "G":
		out.MemoryMiB = int(d.Memory.Value * 1024)
	}
	out.Graphics = HasGraphics(x)
	for _, m := range d.Metadata.Children {
		if m.XMLName.Space != MetadataNamespace || m.XMLName.Local != "managed" {
			continue
		}
		attr := map[string]string{}
		for _, a := range m.Attrs {
			attr[a.Name.Local] = a.Value
		}
		if attr["version"] == MetadataVersion && attr["uuid"] != "" && attr["uuid"] == out.UUID && fingerprintRE.MatchString(attr["fingerprint"]) &&
			(attr["image"] == "" || imageIDRE.MatchString(attr["image"])) {
			out.Managed, out.Fingerprint, out.ImageID = true, attr["fingerprint"], attr["image"]
			if attr["media"] == MediaISO {
				out.Media = MediaISO
			}
			if fingerprintRE.MatchString(attr["rescue"]) {
				out.Rescue = attr["rescue"] // rescue mode is recorded on the ownership marker (DR-026 D2)
			}
		}
	}
	// The logical volume names are recovered from the disks only if they are Svavyom's own for THIS domain: a pool/volume reference
	// must name RootVolumeName/SeedVolumeName of the domain's UUID, and a file-backed source must be a clean absolute path whose
	// final element is that name. Anything else (a foreign file, another VM's volume, a relative path) recovers nothing.
	named := func(vol, file, role string) string {
		// A disk counts as this VM's own if its name is a Svavyom volume name of THIS domain's UUID and of the right role (any generation).
		own := func(n string) bool {
			u, r, _, ok := ParseVolumeName(n)
			return ok && u == out.UUID && r == role && uuidRE.MatchString(out.UUID)
		}
		switch {
		case file == "" && own(vol):
			return vol
		case vol == "" && path.IsAbs(file) && path.Clean(file) == file && own(path.Base(file)):
			return path.Base(file)
		}
		return ""
	}
	for _, nic := range d.Interfaces {
		// A running domain on a bridge-mode network is reported by libvirt as type='bridge' with the network still named in <source network=...>.
		if (nic.Type == "network" || nic.Type == "bridge") && nic.Source.Network != "" {
			out.Network, out.MAC = nic.Source.Network, strings.ToLower(nic.MAC.Address)
			break
		}
	}
	for _, disk := range d.Disks {
		if disk.Device == "cdrom" {
			if out.Seed == "" {
				out.Seed = named(disk.Source.Volume, disk.Source.File, "seed")
			}
			if f := disk.Source.File; out.ISO == "" && f != "" && path.IsAbs(f) && path.Clean(f) == f {
				if sha, ok := ISOFileSHA256(path.Base(f)); ok {
					out.ISO = sha
				}
			}
		} else {
			if out.Root == "" {
				out.Root = named(disk.Source.Volume, disk.Source.File, "root")
			}
			// A data volume counts only as an absolute, clean file path whose last element is a Svavyom data volume name.
			if f := disk.Source.File; f != "" && disk.Source.Volume == "" && path.IsAbs(f) && path.Clean(f) == f && !(out.Root != "" && path.Base(f) == out.Root) {
				if n, ok := ParseDataVolumeName(path.Base(f)); ok && len(out.Data) < MaxDataDisks {
					out.Data = append(out.Data, DataDisk{Volume: n, Dev: disk.Target.Dev})
				}
			}
		}
	}
	return out, nil
}

// IsPrivateIPv4Lease reports whether s is a usable observation for the IP field: a dotted-quad IPv4 address. (The API shows it
// as information only.)
func IsIPv4(s string) bool {
	parts := strings.Split(s, ".")
	if len(parts) != 4 {
		return false
	}
	for _, p := range parts {
		if len(p) == 0 || len(p) > 3 {
			return false
		}
		n := 0
		for _, r := range p {
			if r < '0' || r > '9' {
				return false
			}
			n = n*10 + int(r-'0')
		}
		if n > 255 || (len(p) > 1 && p[0] == '0') {
			return false
		}
	}
	return true
}
