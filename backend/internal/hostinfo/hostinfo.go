// Package hostinfo builds the read-only host summary of the dashboard (story M1-E04-S01, DR-015 D3) from the existing
// read-only capability checker. It adds no probe of its own beyond the memory total, exposes only the explicitly
// approved fields below, and never returns paths, environment, user names, command output or raw probe details.
package hostinfo

import (
	"context"
	_ "embed" // support-matrix.json
	"errors"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"example.invalid/dedicatedcloud/backend/internal/capability"
)

// supportMatrix is a byte-identical copy of the pinned docs-repo matrix (tests/fixtures/distribution); a test compares
// them and capability.LoadMatrix pins its digest, so this repository cannot widen what is supported.
//
//go:embed support-matrix.json
var supportMatrix []byte

// State is a three-valued availability.
type State string

// States.
const (
	Available   State = "available"
	Unavailable State = "unavailable"
	Unknown     State = "unknown"
)

// Finding is a closed reason code with the checker's remediation sentence (never command output).
type Finding struct {
	Code        string
	Remediation string
}

// Info is the complete set of fields the browser may see.
type Info struct {
	ID, Name        string
	AgentVersion    string
	CPUCount        int
	MemoryMiB       int64
	Verdict         string // supported | unsupported | unknown: matrix conformance only, not host qualification
	Hardware        State  // CPU virtualization extensions
	KVMDevice       State  // /dev/kvm present
	LibvirtPackages State  // libvirt installed (the daemon is not contacted)
	QEMUPackages    State
	DistroID        string
	DistroVersion   string
	Findings        []Finding
}

// Config configures a Provider.
type Config struct {
	Root         string // filesystem root to inspect, default "/"
	Name         string // display name of the host, default "This host"
	AgentVersion string // build version of this service
	CPUs         int    // override for tests; default runtime.NumCPU()
	TTL          time.Duration
	Clock        func() time.Time
}

// Provider returns the host summary, re-evaluating at most once per TTL.
type Provider struct {
	cfg    Config
	matrix *capability.Matrix
	mu     sync.Mutex
	cached Info
	at     time.Time
}

var nameRE = regexp.MustCompile(`^[\x21-\x7e][\x20-\x7e]{0,62}$`)

// ErrUnavailable means the host could not be inspected at all.
var ErrUnavailable = errors.New("hostinfo: host cannot be inspected")

// New builds a Provider.
func New(cfg Config) (*Provider, error) {
	if cfg.Root == "" {
		cfg.Root = "/"
	}
	if cfg.Name == "" {
		cfg.Name = "This host"
	}
	if !nameRE.MatchString(cfg.Name) {
		return nil, errors.New("hostinfo: invalid host name")
	}
	if cfg.TTL <= 0 {
		cfg.TTL = 30 * time.Second
	}
	if cfg.Clock == nil {
		cfg.Clock = time.Now
	}
	if cfg.CPUs <= 0 {
		cfg.CPUs = runtime.NumCPU()
	}
	if len(cfg.AgentVersion) > 64 || !regexp.MustCompile(`^[A-Za-z0-9._+-]*$`).MatchString(cfg.AgentVersion) {
		return nil, errors.New("hostinfo: invalid agent version")
	}
	if cfg.AgentVersion == "" {
		cfg.AgentVersion = "dev"
	}
	m, err := capability.LoadMatrix(supportMatrix)
	if err != nil {
		return nil, err
	}
	return &Provider{cfg: cfg, matrix: m}, nil
}

// Host returns the summary of the one managed host.
func (p *Provider) Host(ctx context.Context) (Info, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	now := p.cfg.Clock()
	if !p.at.IsZero() && now.Sub(p.at) < p.cfg.TTL {
		return p.cached, nil
	}
	if err := ctx.Err(); err != nil {
		return Info{}, err
	}
	fsys, closeFS, err := capability.OpenRoot(p.cfg.Root)
	if err != nil {
		return Info{}, ErrUnavailable
	}
	defer func() { _ = closeFS() }()
	rep := capability.Check(fsys, p.matrix)
	info := fromReport(rep)
	info.ID, info.Name, info.AgentVersion, info.CPUCount = "local", p.cfg.Name, p.cfg.AgentVersion, p.cfg.CPUs
	mem, err := memoryMiB(fsys)
	if err != nil {
		return Info{}, ErrUnavailable
	}
	info.MemoryMiB = mem
	p.cached, p.at = info, now
	return info, nil
}

var codeRE = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,39}$`)

func fromReport(rep capability.Report) Info {
	by := map[string]capability.ProbeResult{}
	for _, pr := range rep.Probes {
		by[pr.ID] = pr
	}
	info := Info{Verdict: rep.Verdict, DistroID: rep.Distribution.ID, DistroVersion: rep.Distribution.VersionID,
		Hardware: Unknown, KVMDevice: Unknown, LibvirtPackages: Unknown, QEMUPackages: Unknown}
	switch by["cpu_virt"].Result {
	case capability.Pass:
		info.Hardware = Available
	case capability.Fail:
		info.Hardware = Unavailable
	}
	switch by["dev_kvm"].Reason {
	case "PRESENT":
		info.KVMDevice = Available
	case "ABSENT_OR_UNREADABLE", "NOT_A_CHAR_DEVICE":
		info.KVMDevice = Unavailable
	}
	pkg := func(id string) State {
		switch by[id].Reason {
		case "INSTALLED":
			return Available
		case "NOT_INSTALLED":
			return Unavailable
		}
		return Unknown
	}
	info.LibvirtPackages, info.QEMUPackages = pkg("libvirt_packages"), pkg("qemu_packages")
	seen := map[string]bool{}
	add := func(code string) {
		if codeRE.MatchString(code) && !seen[code] && len(info.Findings) < 16 {
			seen[code] = true
			info.Findings = append(info.Findings, Finding{Code: code, Remediation: capability.Remediations[code]})
		}
	}
	for _, r := range rep.Reasons {
		add(r)
	}
	for _, pr := range rep.Probes {
		if pr.Required && pr.Result == capability.Fail {
			add(pr.Reason)
		}
	}
	return info
}

// memoryMiB reads MemTotal from proc/meminfo through the capability checker's confined, bounded reader.
func memoryMiB(fsys capability.FS) (int64, error) {
	data, err := fsys.ReadRegular("proc/meminfo", 64<<10)
	if err != nil {
		return 0, err
	}
	for _, line := range strings.Split(string(data), "\n") {
		rest, ok := strings.CutPrefix(line, "MemTotal:")
		if !ok {
			continue
		}
		f := strings.Fields(rest)
		if len(f) != 2 || f[1] != "kB" {
			break
		}
		kb, err := strconv.ParseInt(f[0], 10, 64)
		if err != nil || kb < 1024 || kb > 1<<40 {
			break
		}
		return kb / 1024, nil
	}
	return 0, errors.New("hostinfo: MemTotal unreadable")
}
