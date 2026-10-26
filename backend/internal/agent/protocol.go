// Package agent is the local host-agent boundary of the browser -> API -> agent -> libvirt chain (ADR-011): a small,
// closed, typed protocol over a Unix socket, and the client the unprivileged API uses.
//
// This slice is READ-ONLY: the only operations are `list` and `lookup`. There is no TCP listener, no shell, no XML, no
// client-supplied path, no generic RPC. Frames are length-prefixed JSON with hard size limits; both sides apply
// deadlines; the server checks the peer's uid (SO_PEERCRED) against an allowlist; errors cross the boundary as a closed
// category only, never as text from libvirt.
package agent

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"regexp"
	"strings"

	"example.invalid/dedicatedcloud/backend/internal/hypervisor"
	"example.invalid/dedicatedcloud/backend/internal/provision"
)

// Protocol limits.
const (
	Version         = 1
	MaxRequestBytes = 1 << 10
	MaxReplyBytes   = 256 << 10
	MaxDomains      = 1000
)

// Operations (closed set).
const (
	OpList     = "list"
	OpLookup   = "lookup"
	OpNetworks = "networks"
	OpVolumes  = "volumes"
)

// MaxNetworks bounds the networks (and MaxReservations the reservations of one network) the agent reports.
const (
	MaxNetworks     = 200
	MaxReservations = 256
)

// Request is the only message a client may send.
type Request struct {
	V    int    `json:"v"`
	Op   string `json:"op"`
	Name string `json:"name,omitempty"`
}

// Domain is the approved VM description: name, observed power state, size, Svavyom's ownership marker and an optional DHCP
// lease. Nothing else crosses the boundary: no XML, no paths, no host details.
type Domain struct {
	Name        string `json:"name"`
	Power       string `json:"power"`
	VCPUs       int    `json:"vcpus,omitempty"`
	MemoryMiB   int    `json:"memory_mib,omitempty"`
	UUID        string `json:"uuid,omitempty"`
	Managed     bool   `json:"managed,omitempty"`
	Fingerprint string `json:"fingerprint,omitempty"`
	ImageID     string `json:"image_id,omitempty"`
	IP          string `json:"ip,omitempty"`
	DiskBytes   int64  `json:"disk_bytes,omitempty"`
	Snapshots   []Snap `json:"snapshots,omitempty"`
	Network     string `json:"network,omitempty"`
	MAC         string `json:"mac,omitempty"`
	// CPUTimeNs is the cumulative CPU time of a running domain (DR-022); 0 and omitted otherwise.
	CPUTimeNs int64 `json:"cpu_time_ns,omitempty"`
	// MemUsedMiB, DiskIOBytes and NetIOBytes are the usage extras of DR-023 D5: guest memory in use and cumulative disk and network bytes of a running domain.
	MemUsedMiB  int64 `json:"mem_used_mib,omitempty"`
	DiskIOBytes int64 `json:"disk_io_bytes,omitempty"`
	NetIOBytes  int64 `json:"net_io_bytes,omitempty"`
	// DataVolumes are the standalone data volumes the definition carries (DR-023 D2).
	DataVolumes []string `json:"data_volumes,omitempty"`
	// Media is "iso" for a VM created from installation media; ISOSHA256 is the digest of the media attached now (DR-023 D3).
	Media     string `json:"media,omitempty"`
	ISOSHA256 string `json:"iso_sha256,omitempty"`
	// Profile is "windows" for a VM created with the Windows profile (DR-032); absent for every other VM.
	Profile string `json:"profile,omitempty"`
	// ISOSHA256s lists every installation medium attached, in guest target order, at most two (DR-031); ISOSHA256 is the one that boots next, else the first.
	ISOSHA256s []string `json:"iso_sha256s,omitempty"`
	// Graphics is true when the definition has the VNC console; RescueSHA256 is the rescue media's digest while the VM is in rescue mode (DR-026).
	Graphics     bool   `json:"graphics,omitempty"`
	RescueSHA256 string `json:"rescue_sha256,omitempty"`
}

// Net is the approved network description: identity, ownership, state and addressing. No XML, no host paths.
type Net struct {
	Name         string `json:"name"`
	UUID         string `json:"uuid,omitempty"`
	Managed      bool   `json:"managed,omitempty"`
	Active       bool   `json:"active,omitempty"`
	Autostart    bool   `json:"autostart,omitempty"`
	Mode         string `json:"mode"`
	Bridge       string `json:"bridge,omitempty"`
	Subnet       string `json:"subnet,omitempty"`
	Gateway      string `json:"gateway,omitempty"`
	DHCPStart    string `json:"dhcp_start,omitempty"`
	DHCPEnd      string `json:"dhcp_end,omitempty"`
	Attached     int    `json:"attached,omitempty"`
	Reservations []Res  `json:"reservations,omitempty"`
}

// Res is a static DHCP reservation.
type Res struct {
	MAC string `json:"mac"`
	IP  string `json:"ip"`
}

var (
	macRE    = regexp.MustCompile(`^([0-9a-f]{2}:){5}[0-9a-f]{2}$`)
	bridgeRE = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,15}$`)
	netModes = map[string]bool{"nat": true, "route": true, "open": true, "bridge": true, "private": true, "vepa": true, "passthrough": true, "hostdev": true, "isolated": true, "other": true}
)

// validNet checks a wire network (both sides apply it).
func validNet(n Net) bool {
	if !nameRE.MatchString(n.Name) || !netModes[n.Mode] || n.Attached < 0 || n.Attached > 100000 || len(n.Reservations) > MaxReservations {
		return false
	}
	if n.UUID != "" && !uuidRE.MatchString(n.UUID) {
		return false
	}
	if n.Bridge != "" && !bridgeRE.MatchString(n.Bridge) {
		return false
	}
	if n.Subnet != "" {
		if p, err := netip.ParsePrefix(n.Subnet); err != nil || !p.Addr().Is4() || p.Masked() != p || p.String() != n.Subnet {
			return false
		}
	}
	for _, a := range []string{n.Gateway, n.DHCPStart, n.DHCPEnd} {
		if a != "" && !provision.IsIPv4(a) {
			return false
		}
	}
	if n.Managed && n.UUID == "" {
		return false
	}
	for _, r := range n.Reservations {
		if !macRE.MatchString(r.MAC) || !provision.IsIPv4(r.IP) {
			return false
		}
	}
	return true
}

// Snap is one snapshot of a managed domain as the agent reports it.
type Snap struct {
	ID      string `json:"id"`
	Created int64  `json:"created"`
}

// MaxSnaps bounds the snapshots reported per domain.
const MaxSnaps = 16

var snapIDRE = regexp.MustCompile(`^snap-[0-9a-f]{12}$`)

// Reply is the only message the agent sends. On failure OK is false and Category is a hypervisor category.
type Reply struct {
	V        int      `json:"v"`
	OK       bool     `json:"ok"`
	Category string   `json:"category,omitempty"`
	Domains  []Domain `json:"domains,omitempty"`
	Networks []Net    `json:"networks,omitempty"`
	Volumes  []Vol    `json:"volumes,omitempty"`
}

// MaxVolumes bounds the data volumes of one reply; MaxDataVolumes the data volumes one domain reports.
const (
	MaxVolumes     = 512
	MaxDataVolumes = 8
)

// Vol is the approved data volume description: its name and virtual size. No path, no pool.
type Vol struct {
	Name     string `json:"name"`
	Capacity int64  `json:"capacity_bytes"`
}

var dataNameRE = regexp.MustCompile(`^[a-z][a-z0-9-]{1,30}[a-z0-9]$`)

func validDataName(n string) bool { return dataNameRE.MatchString(n) && !strings.HasSuffix(n, "-root") }

func validVol(v Vol) bool { return validDataName(v.Name) && v.Capacity > 0 && v.Capacity <= 1<<50 }

var nameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$`)

var (
	uuidRE        = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	fingerprintRE = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// validDetails checks the optional fields of a wire domain (both sides apply it).
func validDetails(d Domain) bool {
	if d.VCPUs < 0 || d.VCPUs > 4096 || d.MemoryMiB < 0 || d.MemoryMiB > 1<<24 || d.CPUTimeNs < 0 || d.CPUTimeNs > 1<<62 ||
		d.MemUsedMiB < 0 || d.MemUsedMiB > 1<<30 || d.DiskIOBytes < 0 || d.DiskIOBytes > 1<<62 || d.NetIOBytes < 0 || d.NetIOBytes > 1<<62 {
		return false
	}
	if d.UUID != "" && !uuidRE.MatchString(d.UUID) {
		return false
	}
	if d.Fingerprint != "" && !fingerprintRE.MatchString(d.Fingerprint) {
		return false
	}
	if d.ImageID != "" && !nameRE.MatchString(d.ImageID) {
		return false
	}
	if d.IP != "" && !provision.IsIPv4(d.IP) {
		return false
	}
	if (d.Network != "" && !nameRE.MatchString(d.Network)) || (d.MAC != "" && !macRE.MatchString(d.MAC)) {
		return false
	}
	if d.DiskBytes < 0 || d.DiskBytes > 1<<50 || len(d.Snapshots) > MaxSnaps || ((d.DiskBytes != 0 || len(d.Snapshots) != 0) && !d.Managed) {
		return false
	}
	for _, sn := range d.Snapshots {
		if !snapIDRE.MatchString(sn.ID) || sn.Created < 0 {
			return false
		}
	}
	if len(d.DataVolumes) > MaxDataVolumes || (len(d.DataVolumes) > 0 && !d.Managed) {
		return false
	}
	if (d.Media != "" && d.Media != "iso") || (d.ISOSHA256 != "" && !fingerprintRE.MatchString(d.ISOSHA256)) || ((d.Media != "" || d.ISOSHA256 != "") && !d.Managed) {
		return false
	}
	if !validMediaList(d) {
		return false
	}
	if !validProfile(d) {
		return false
	}
	if (d.RescueSHA256 != "" && (!fingerprintRE.MatchString(d.RescueSHA256) || d.RescueSHA256 != d.ISOSHA256)) || ((d.RescueSHA256 != "" || d.Graphics) && !d.Managed) {
		return false // rescue mode is the attached media, and only a Svavyom VM has either
	}
	for _, n := range d.DataVolumes {
		if !validDataName(n) {
			return false
		}
	}
	return !d.Managed || (d.UUID != "" && d.Fingerprint != "") // a managed marker needs both halves of the identity
}

var powers = map[hypervisor.State]bool{
	hypervisor.StateRunning: true, hypervisor.StateShutoff: true, hypervisor.StatePaused: true,
	hypervisor.StateCrashed: true, hypervisor.StateUnknown: true,
}

// errFrame is returned for any malformed or oversized frame.
var errFrame = errors.New("agent: bad frame")

// writeFrame writes a 4-byte big-endian length followed by the JSON encoding of v, refusing to exceed max.
func writeFrame(w io.Writer, v any, max int) error {
	body, err := json.Marshal(v)
	if err != nil || len(body) > max {
		return errFrame
	}
	buf := make([]byte, 4+len(body))
	binary.BigEndian.PutUint32(buf, uint32(len(body))) // #nosec G115 -- len <= max <= 256 KiB
	copy(buf[4:], body)
	_, err = w.Write(buf)
	return err
}

// readFrame reads one frame of at most max bytes and decodes it strictly into dst (no unknown fields, no trailing data).
func readFrame(r io.Reader, dst any, max int) error {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n == 0 || int64(n) > int64(max) {
		return errFrame
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(r, body); err != nil {
		return err
	}
	dec := json.NewDecoder(bytesReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return errFrame
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return errFrame
	}
	return nil
}

func validRequest(q Request) bool {
	if q.V != Version {
		return false
	}
	switch q.Op {
	case OpList, OpNetworks, OpVolumes:
		return q.Name == ""
	case OpLookup:
		return nameRE.MatchString(q.Name)
	}
	return false
}

// MaxMedia is the most installation media a domain reports (DR-031).
const MaxMedia = 2

// validMediaList checks the list of attached installation media: at most MaxMedia distinct digests, only on a Svavyom VM, and consistent with the
// single digest, which is one of them (the one that boots next, else the first).
func validMediaList(d Domain) bool {
	if len(d.ISOSHA256s) == 0 {
		return true
	}
	if len(d.ISOSHA256s) > MaxMedia || !d.Managed {
		return false
	}
	seen := map[string]bool{}
	hasSingle := d.ISOSHA256 == ""
	for _, s := range d.ISOSHA256s {
		if !fingerprintRE.MatchString(s) || seen[s] {
			return false
		}
		seen[s] = true
		if s == d.ISOSHA256 {
			hasSingle = true
		}
	}
	return hasSingle && d.ISOSHA256 != ""
}

// validProfile checks the profile of a frame: absent, or "windows" on a Svavyom VM created from installation media (DR-032). "linux" is never written.
func validProfile(d Domain) bool {
	return d.Profile == "" || (d.Profile == "windows" && d.Managed && d.Media == "iso")
}
