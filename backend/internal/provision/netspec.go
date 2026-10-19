package provision

import (
	"bytes"
	"encoding/binary"
	"encoding/xml"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"text/template"
)

// Managed NAT networks (M3). A Svavyom-managed network is one this product defined: it carries an ownership marker in its libvirt <metadata>, a
// server-derived bridge name and a gateway at the first address of its RFC 1918 subnet. Nothing the browser sends is ever XML; every value below has a
// closed grammar and the definition is rendered from a fixed template.

// NetworkNamespace is the XML namespace of Svavyom's ownership marker inside a network's <metadata>.
const NetworkNamespace = "https://svavyom.invalid/xml/net/1"

// NetworkMetadataVersion is the marker schema version.
const NetworkMetadataVersion = "1"

// ErrInvalidNetwork means a network specification is not acceptable.
var ErrInvalidNetwork = errors.New("provision: invalid network specification")

// Prefix length bounds of a managed network: large enough for a real network, small enough that it cannot swallow a /8.
const (
	MinNetPrefix = 16
	MaxNetPrefix = 29
)

var (
	netNameRE   = regexp.MustCompile(`^[a-z][a-z0-9-]{1,30}[a-z0-9]$`)
	macRE       = regexp.MustCompile(`^52:54:00:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}$`)
	rfc1918Nets = []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("172.16.0.0/12"), netip.MustParsePrefix("192.168.0.0/16")}
)

// NetworkSpec is the typed description of a managed NAT network. UUID is server generated.
type NetworkSpec struct {
	Name      string
	UUID      string
	Subnet    string // CIDR, canonical form (the network address)
	DHCPStart string
	DHCPEnd   string
	// HostBridge, when set, makes this a bridge-mode network on an existing host bridge (the one svavyom-ctl adopted or created, DR-024 D5): no
	// subnet and no DHCP range, because the host's own network addresses the guests. Libvirt does not create or change the bridge.
	HostBridge string
}

var hostBridgeRE = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9_.:-]{0,14}$`)

// HostBridgeOK reports whether name may be the host bridge of a bridge-mode network. libvirt's and Docker's own bridges, and the bridges that
// Svavyom derives for its NAT networks, are never one.
func HostBridgeOK(name string) bool {
	if !hostBridgeRE.MatchString(name) || strings.HasPrefix(name, "virbr") || strings.HasPrefix(name, "docker") || strings.HasPrefix(name, "br-") {
		return false
	}
	if len(name) == 12 && strings.HasPrefix(name, "svbr") && uuidHexRE.MatchString(name[4:]) {
		return false
	}
	return true
}

var uuidHexRE = regexp.MustCompile(`^[0-9a-f]{8}$`)

// ParseManagedSubnetOK reports whether an existing prefix falls in the managed-network grammar (RFC 1918, prefix 16 to 29); nil means yes.
func ParseManagedSubnetOK(p netip.Prefix) error {
	_, err := ParseManagedSubnet(p.String())
	return err
}

// NetNameOK reports whether s is an acceptable name for a managed network.
func NetNameOK(s string) bool { return netNameRE.MatchString(s) }

// ParsePrefixStrict parses a canonical IPv4 CIDR (the network address, no spaces).
func ParsePrefixStrict(s string) (netip.Prefix, error) {
	p, err := netip.ParsePrefix(s)
	if err != nil || !p.Addr().Is4() || p.Masked() != p || p.String() != s {
		return netip.Prefix{}, ErrInvalidNetwork
	}
	return p, nil
}

// BridgeName derives the bridge device name from the network UUID, so a retried create defines the identical network.
func BridgeName(uuid string) string {
	if len(uuid) < 8 {
		return ""
	}
	return "svbr" + strings.ToLower(uuid[:8])
}

// NetworkGateway returns the gateway (first host address) of a prefix.
func NetworkGateway(p netip.Prefix) netip.Addr { return p.Masked().Addr().Next() }

func lastAddr(p netip.Prefix) netip.Addr {
	a := p.Masked().Addr().As4()
	host := 32 - p.Bits()
	n := uint32(a[0])<<24 | uint32(a[1])<<16 | uint32(a[2])<<8 | uint32(a[3])
	n |= (1 << host) - 1
	return addr4(n)
}

// addr4 builds an IPv4 address from its big-endian integer value.
func addr4(n uint32) netip.Addr {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], n)
	return netip.AddrFrom4(b)
}

// ParseManagedSubnet checks that s is a canonical IPv4 CIDR entirely inside RFC 1918 space with a prefix length of 16 to 29.
func ParseManagedSubnet(s string) (netip.Prefix, error) {
	p, err := netip.ParsePrefix(s)
	if err != nil || !p.Addr().Is4() || p.Masked() != p || p.String() != s || p.Bits() < MinNetPrefix || p.Bits() > MaxNetPrefix {
		return netip.Prefix{}, ErrInvalidNetwork
	}
	for _, r := range rfc1918Nets {
		if r.Contains(p.Addr()) && p.Bits() >= r.Bits() {
			return p, nil
		}
	}
	return netip.Prefix{}, ErrInvalidNetwork
}

// Validate checks every field: the name, the UUID, an RFC 1918 subnet and a DHCP range of usable host addresses inside it (never the network
// address, the gateway or the broadcast address; start no later than end).
func (n NetworkSpec) Validate() error {
	if !netNameRE.MatchString(n.Name) || !uuidRE.MatchString(n.UUID) {
		return ErrInvalidNetwork
	}
	if n.HostBridge != "" {
		if !HostBridgeOK(n.HostBridge) || n.Subnet != "" || n.DHCPStart != "" || n.DHCPEnd != "" {
			return ErrInvalidNetwork
		}
		return nil
	}
	p, err := ParseManagedSubnet(n.Subnet)
	if err != nil {
		return err
	}
	return validateRange(p, n.DHCPStart, n.DHCPEnd)
}

func validateRange(p netip.Prefix, start, end string) error {
	a, err1 := netip.ParseAddr(start)
	b, err2 := netip.ParseAddr(end)
	if err1 != nil || err2 != nil || !a.Is4() || !b.Is4() || a.String() != start || b.String() != end {
		return ErrInvalidNetwork
	}
	gw, bc := NetworkGateway(p), lastAddr(p)
	if !p.Contains(a) || !p.Contains(b) || a.Less(gw.Next()) || bc.Prev().Less(b) || b.Less(a) {
		return ErrInvalidNetwork
	}
	return nil
}

// UsableHost reports whether ip is an address a guest may hold in p: inside it, and not the network address, the gateway or the broadcast address.
func UsableHost(p netip.Prefix, ip netip.Addr) bool {
	return ip.Is4() && p.Contains(ip) && ip != p.Masked().Addr() && ip != NetworkGateway(p) && ip != lastAddr(p)
}

// Overlaps reports whether two prefixes share any address.
func Overlaps(a, b netip.Prefix) bool {
	return a.Contains(b.Masked().Addr()) || b.Contains(a.Masked().Addr())
}

func netmaskOf(p netip.Prefix) string {
	m := ^uint32(0) << (32 - p.Bits())
	return addr4(m).String()
}

// NetworkXML renders the libvirt definition of a managed NAT network from a fixed template.
func NetworkXML(n NetworkSpec) (string, error) {
	if err := n.Validate(); err != nil {
		return "", err
	}
	if n.HostBridge != "" {
		var b bytes.Buffer
		if err := bridgeNetworkTemplate.Execute(&b, map[string]any{"Name": n.Name, "UUID": n.UUID, "Bridge": n.HostBridge, "NS": NetworkNamespace, "Ver": NetworkMetadataVersion}); err != nil {
			return "", ErrInvalidNetwork
		}
		return b.String(), nil
	}
	p, _ := ParseManagedSubnet(n.Subnet)
	var b bytes.Buffer
	err := networkTemplate.Execute(&b, map[string]any{
		"Name": n.Name, "UUID": n.UUID, "Bridge": BridgeName(n.UUID), "NS": NetworkNamespace, "Ver": NetworkMetadataVersion,
		"Gateway": NetworkGateway(p).String(), "Netmask": netmaskOf(p), "Start": n.DHCPStart, "End": n.DHCPEnd,
	})
	if err != nil {
		return "", ErrInvalidNetwork
	}
	return b.String(), nil
}

var bridgeNetworkTemplate = template.Must(template.New("bridge-network").Parse(`<network>
  <name>{{.Name}}</name>
  <uuid>{{.UUID}}</uuid>
  <metadata>
    <svavyom:network xmlns:svavyom='{{.NS}}' version='{{.Ver}}' uuid='{{.UUID}}'/>
  </metadata>
  <forward mode='bridge'/>
  <bridge name='{{.Bridge}}'/>
</network>
`))

var networkTemplate = template.Must(template.New("network").Parse(`<network>
  <name>{{.Name}}</name>
  <uuid>{{.UUID}}</uuid>
  <metadata>
    <svavyom:network xmlns:svavyom='{{.NS}}' version='{{.Ver}}' uuid='{{.UUID}}'/>
  </metadata>
  <forward mode='nat'/>
  <bridge name='{{.Bridge}}' stp='on' delay='0'/>
  <ip address='{{.Gateway}}' netmask='{{.Netmask}}'>
    <dhcp>
      <range start='{{.Start}}' end='{{.End}}'/>
    </dhcp>
  </ip>
</network>
`))

// NetworkInfo is what Svavyom reads back about a libvirt network (any network, managed or not).
type NetworkInfo struct {
	Name      string
	UUID      string
	Active    bool
	Autostart bool
	Managed   bool   // Svavyom's marker is present and its uuid matches the network's
	Mode      string // forward mode: nat, route, bridge, open, ... or "isolated" when there is no <forward>
	Bridge    string
	Subnet    netip.Prefix // zero when the network has no IPv4 address
	Gateway   string
	DHCPStart string
	DHCPEnd   string
	Hosts     []NetHost // static DHCP reservations
}

// NetHost is one static DHCP reservation of a network.
type NetHost struct {
	MAC, IP string
}

type networkDoc struct {
	Name     string `xml:"name"`
	UUID     string `xml:"uuid"`
	Metadata struct {
		Children []struct {
			XMLName xml.Name
			Attrs   []xml.Attr `xml:",any,attr"`
		} `xml:",any"`
	} `xml:"metadata"`
	Forward *struct {
		Mode string `xml:"mode,attr"`
	} `xml:"forward"`
	Bridge struct {
		Name string `xml:"name,attr"`
	} `xml:"bridge"`
	IPs []struct {
		Family  string `xml:"family,attr"`
		Address string `xml:"address,attr"`
		Netmask string `xml:"netmask,attr"`
		Prefix  string `xml:"prefix,attr"`
		DHCP    *struct {
			Range *struct {
				Start string `xml:"start,attr"`
				End   string `xml:"end,attr"`
			} `xml:"range"`
			Hosts []struct {
				MAC string `xml:"mac,attr"`
				IP  string `xml:"ip,attr"`
			} `xml:"host"`
		} `xml:"dhcp"`
	} `xml:"ip"`
}

// ParseNetwork parses a libvirt network definition into typed fields (nothing is evaluated; no other element is retained). The ownership
// marker counts only in Svavyom's namespace with the current version and the network's own UUID. active and autostart are the caller's
// observations.
func ParseNetwork(x string, active, autostart bool) (NetworkInfo, error) {
	var d networkDoc
	if len(x) > 1<<20 || xml.Unmarshal([]byte(x), &d) != nil {
		return NetworkInfo{}, ErrInvalidNetwork
	}
	out := NetworkInfo{Name: d.Name, UUID: strings.ToLower(d.UUID), Active: active, Autostart: autostart, Bridge: d.Bridge.Name, Mode: "isolated"}
	if d.Forward != nil {
		out.Mode = d.Forward.Mode
		if out.Mode == "" {
			out.Mode = "nat"
		}
	}
	for _, m := range d.Metadata.Children {
		if m.XMLName.Space != NetworkNamespace || m.XMLName.Local != "network" {
			continue
		}
		attr := map[string]string{}
		for _, a := range m.Attrs {
			attr[a.Name.Local] = a.Value
		}
		if attr["version"] == NetworkMetadataVersion && attr["uuid"] != "" && attr["uuid"] == out.UUID && uuidRE.MatchString(out.UUID) {
			out.Managed = true
		}
	}
	for _, ip := range d.IPs {
		if ip.Family != "" && ip.Family != "ipv4" {
			continue
		}
		a, err := netip.ParseAddr(ip.Address)
		if err != nil || !a.Is4() {
			continue
		}
		bits := -1
		if ip.Prefix != "" {
			if n, err := strconv.Atoi(ip.Prefix); err == nil {
				bits = n
			}
		} else if m, err := netip.ParseAddr(ip.Netmask); err == nil && m.Is4() {
			b := m.As4()
			n := uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
			ones := 0
			for n&0x80000000 != 0 {
				ones++
				n <<= 1
			}
			if n == 0 {
				bits = ones
			}
		}
		if bits < 0 || bits > 32 {
			continue
		}
		out.Subnet, out.Gateway = netip.PrefixFrom(a, bits).Masked(), a.String()
		if ip.DHCP != nil {
			if ip.DHCP.Range != nil {
				out.DHCPStart, out.DHCPEnd = ip.DHCP.Range.Start, ip.DHCP.Range.End
			}
			for _, h := range ip.DHCP.Hosts {
				out.Hosts = append(out.Hosts, NetHost{MAC: strings.ToLower(h.MAC), IP: h.IP})
			}
		}
		break
	}
	return out, nil
}

// HostEntryXML renders the <host> element of a static DHCP reservation for virNetworkUpdate. The MAC is the VM's derived MAC and the IP a
// validated host address, so neither can carry markup.
func HostEntryXML(mac, ip string) (string, error) {
	if !macRE.MatchString(mac) {
		return "", ErrInvalidNetwork
	}
	if a, err := netip.ParseAddr(ip); err != nil || !a.Is4() || a.String() != ip {
		return "", ErrInvalidNetwork
	}
	return fmt.Sprintf("<host mac='%s' ip='%s'/>", mac, ip), nil
}
