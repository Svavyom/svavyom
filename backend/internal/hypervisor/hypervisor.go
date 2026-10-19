// Package hypervisor defines the typed hypervisor interface used by the
// host agent (story M0-E02-S03, ADR-001, ADR-011).
//
// Callers describe domains with validated, typed fields only. Domain XML is
// generated internally from those fields; client-supplied XML is never
// accepted. Implementations: package fake (in-memory, T0) and package
// libvirttest (libvirt test:///default via cgo, T1, build tag libvirt_test).
// Neither is evidence of a real VM boot, storage or networking
// (TEST-STRATEGY); EnvironmentClass is always "simulated" for these.
package hypervisor

import (
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"regexp"
)

// EnvironmentClass tags every report produced with the fake or test driver.
const EnvironmentClass = "simulated"

// Category is a typed error category shared with the M0-E01-S01 contracts.
type Category string

// Error categories (subset of contracts/interfaces/errors.json).
const (
	Validation  Category = "validation"
	NotFound    Category = "not_found"
	Conflict    Category = "conflict"
	Prohibited  Category = "prohibited"
	Timeout     Category = "timeout"
	Unavailable Category = "unavailable"
	HostError   Category = "host_error"
)

// Error is the only error type returned by Hypervisor implementations.
type Error struct {
	Category Category
	Op       string
	Domain   string
	Msg      string
}

func (e *Error) Error() string {
	return fmt.Sprintf("%s %s %q: %s", e.Category, e.Op, e.Domain, e.Msg)
}

// Retryable reports whether the caller may retry the operation later.
func (e *Error) Retryable() bool {
	return e.Category == Timeout || e.Category == Unavailable
}

// CategoryOf returns the category of a hypervisor error, or "" for others.
func CategoryOf(err error) Category {
	var he *Error
	if errors.As(err, &he) {
		return he.Category
	}
	return ""
}

// NewError builds a typed error.
func NewError(c Category, op, domain, msg string) *Error {
	return &Error{Category: c, Op: op, Domain: domain, Msg: msg}
}

// State is the observed state of a domain.
type State string

// Domain states.
const (
	StateShutoff State = "shutoff"
	StateRunning State = "running"
	// Read-only observation states (VM inventory); the lifecycle adapters only produce shutoff and running.
	StatePaused  State = "paused"
	StateCrashed State = "crashed"
	StateUnknown State = "unknown"
)

// Reader is the read-only half of Hypervisor: everything the VM inventory may ask of a host. It has no mutating
// method, so a holder of a Reader cannot define, start, stop or remove anything.
type Reader interface {
	Lookup(ctx context.Context, name string) (Domain, error)
	List(ctx context.Context) ([]Domain, error)
}

// DomainSpec is the typed, validated description of a domain. The first three fields are the minimal definition used by the
// simulation adapters. The rest are the Svavyom-owned identity and provisioning inputs of a production create (all server
// generated or validated; never browser paths or XML): UUID and Fingerprint become the ownership metadata, ImageID and
// ImageSHA256 select a catalog image, DiskGiB sizes the root volume, SSHPublicKey is the one normalised authorised key.
type DomainSpec struct {
	Name           string
	VCPUs          int
	MemoryMiB      int
	UUID           string
	Fingerprint    string
	ImageID        string
	ImageSHA256    string
	DiskGiB        int
	SSHPublicKey   string
	SSHFingerprint string
	Network        string
}

// Domain is an observed domain. VCPUs and MemoryMiB are the observed definition (the configured maximum), 0 when the
// implementation could not establish them; callers must treat 0 as "unknown", never as a match.
//
// UUID, Fingerprint, Managed and ImageID come from Svavyom's ownership metadata in the domain definition: Managed is true
// only when that marker is present and well formed. A domain without it (or an adapter that cannot read it) is not proof of
// anything. IPv4 is an observation (a DHCP lease) and may be empty.
type Domain struct {
	Name        string
	State       State
	VCPUs       int
	MemoryMiB   int
	UUID        string
	Fingerprint string
	Managed     bool
	ImageID     string
	IPv4        string
	// DiskBytes is the virtual size of the root disk and Snapshots its snapshots, both observed only for a Svavyom-managed domain (0 / none otherwise).
	DiskBytes int64
	Snapshots []Snapshot
	// Network is the libvirt network of the domain's first interface and MAC its address (both from the stored definition; empty when unknown).
	Network string
	MAC     string
	// CPUTimeNs is the cumulative CPU time the guest has used (0 unless the domain is running); the usage sampler turns two readings into a percentage.
	CPUTimeNs int64
	// MemUsedMiB is the guest memory in use (0 when the balloon driver reports nothing); DiskIOBytes and NetIOBytes are cumulative bytes read plus written
	// and received plus transmitted of a running domain (DR-023 D5). The sampler turns two readings into KiB per second; 0 means "no figure".
	MemUsedMiB  int64
	DiskIOBytes int64
	NetIOBytes  int64
	// DataVolumes are the names of the standalone data volumes the definition carries (DR-023 D2), in document order.
	DataVolumes []string
	// Media is "iso" for a VM created from installation media; ISOSHA256 is the digest of the media attached now ("" when none) (DR-023 D3).
	Media     string
	ISOSHA256 string
	// Graphics is true when the definition carries the VNC console; RescueSHA256 is the rescue media's digest while the VM is in rescue mode (DR-026).
	Graphics     bool
	RescueSHA256 string
}

// Network is an observed libvirt network. Managed is true only for a network carrying Svavyom's ownership marker; every other network is foreign
// and read-only to Svavyom. Subnet, Gateway and the DHCP range are empty when the network has no IPv4 address.
type Network struct {
	Name         string
	UUID         string
	Managed      bool
	Active       bool
	Autostart    bool
	Mode         string // nat | route | bridge | open | isolated | ...
	Bridge       string
	Subnet       string
	Gateway      string
	DHCPStart    string
	DHCPEnd      string
	AttachedVMs  int // domains whose first interface uses the network
	Reservations []Reservation
}

// Reservation is a static DHCP reservation of a network.
type Reservation struct{ MAC, IP string }

// NetworkReader is implemented by readers that can also describe networks (the read-only agent path). It is separate from Reader so that a reader
// without network knowledge still satisfies Reader.
type NetworkReader interface {
	Networks(ctx context.Context) ([]Network, error)
}

// DataVolume is a Svavyom data volume as the read-only view describes it: its own name and virtual size. Where it is attached comes from the
// domains' DataVolumes.
type DataVolume struct {
	Name          string
	CapacityBytes int64
}

// DataVolumeReader is implemented by readers that can list the data volumes of the host's storage pools (the read-only agent path).
type DataVolumeReader interface {
	DataVolumes(ctx context.Context) ([]DataVolume, error)
}

// Snapshot is one of a managed domain's own snapshots.
type Snapshot struct {
	ID      string // snap-<12 hex>
	Created int64  // unix seconds
}

var nameRE = regexp.MustCompile(`^[a-z][a-z0-9-]{0,62}$`)

// ValidateName enforces a conservative domain name grammar (no path
// separators, shell metacharacters or markup).
func ValidateName(op, name string) error {
	if !nameRE.MatchString(name) {
		return NewError(Validation, op, truncate(name), "name must match ^[a-z][a-z0-9-]{0,62}$")
	}
	return nil
}

// Validate checks a domain spec.
func (s DomainSpec) Validate() error {
	if err := ValidateName("define", s.Name); err != nil {
		return err
	}
	if s.VCPUs < 1 || s.VCPUs > 64 {
		return NewError(Validation, "define", s.Name, "vcpus must be between 1 and 64")
	}
	if s.MemoryMiB < 64 || s.MemoryMiB > 1048576 {
		return NewError(Validation, "define", s.Name, "memory must be between 64 and 1048576 MiB")
	}
	return nil
}

type domainXML struct {
	XMLName xml.Name `xml:"domain"`
	Type    string   `xml:"type,attr"`
	Name    string   `xml:"name"`
	Memory  struct {
		Unit  string `xml:"unit,attr"`
		Value int    `xml:",chardata"`
	} `xml:"memory"`
	VCPU int `xml:"vcpu"`
	OS   struct {
		Type string `xml:"type"`
	} `xml:"os"`
}

// DomainXML generates the libvirt domain definition from a validated spec.
// It is the only producer of domain XML in the product.
func DomainXML(s DomainSpec) (string, error) {
	if err := s.Validate(); err != nil {
		return "", err
	}
	d := domainXML{Type: "test", Name: s.Name, VCPU: s.VCPUs}
	d.Memory.Unit = "MiB"
	d.Memory.Value = s.MemoryMiB
	d.OS.Type = "hvm"
	out, err := xml.Marshal(d)
	if err != nil {
		return "", NewError(HostError, "define", s.Name, "cannot render definition")
	}
	return string(out), nil
}

// CallRecord is one entry of the harness call audit log. It carries no
// secret-bearing field (M0-E01-S01 redaction rules).
type CallRecord struct {
	Op      string
	Domain  string
	Outcome string
}

// Hypervisor is the typed lifecycle interface. All errors are *Error.
// Start, Stop, Destroy and Undefine are idempotent: repeating a completed
// action is a no-op that never repeats a destructive side effect.
type Hypervisor interface {
	Define(ctx context.Context, spec DomainSpec) (Domain, error)
	Start(ctx context.Context, name string) error
	Stop(ctx context.Context, name string) error
	Destroy(ctx context.Context, name string) error
	Undefine(ctx context.Context, name string) error
	Lookup(ctx context.Context, name string) (Domain, error)
	List(ctx context.Context) ([]Domain, error)
	Calls() []CallRecord
}

func truncate(s string) string {
	if len(s) > 64 {
		return s[:64] + "..."
	}
	return s
}
