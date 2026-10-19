package capability

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
)

// RequiredProbes and InformationalProbes are the probe sets this checker
// implements; the matrix must list exactly these (DR-007 D2 = A).
var (
	RequiredProbes      = []string{"os_release", "arch", "cpu_virt", "kernel_floor", "cgroup_v2", "systemd", "nftables_kernel", "lsm", "containment"}
	InformationalProbes = []string{"dev_kvm", "nftables_userspace", "libvirt_packages", "qemu_packages"}
)

// Entry is one support-matrix row.
type Entry struct {
	ID          string  `json:"id"`
	VersionID   *string `json:"version_id"`
	Arch        *string `json:"arch"`
	Status      string  `json:"status"`
	RequiredLSM string  `json:"required_lsm"`
	SupportEnds *string `json:"support_ends"`
}

// ProbeDef documents a probe's sources and rule (informative for readers).
type ProbeDef struct {
	Sources []string `json:"sources"`
	Rule    string   `json:"rule"`
}

// Matrix is the docs-repo support matrix (contracts/support-matrix.json).
type Matrix struct {
	Schema              int                 `json:"schema"`
	Description         string              `json:"description"`
	KernelFloor         string              `json:"kernel_floor"`
	Entries             []Entry             `json:"entries"`
	RequiredProbes      []string            `json:"required_probes"`
	InformationalProbes []string            `json:"informational_probes"`
	Probes              map[string]ProbeDef `json:"probes"`
	ReadLimits          map[string]int64    `json:"read_limits"`
	DeadlinesMs         struct {
		Probe int `json:"probe"`
		Run   int `json:"run"`
	} `json:"deadlines_ms"`

	digest string
	floor  [2]int
}

// ErrMatrix marks a contract error: the CLI exits 2 and gives no verdict.
var ErrMatrix = errors.New("invalid support matrix")

// PinnedMatrixSHA256 is the digest of the docs-repo support matrix approved
// under DR-007 D2 = A (contracts/support-matrix.json at the pinned docs
// commit). A different matrix is a contract error: cloud-platform cannot
// widen support (implementation review M1). Changing the matrix needs an
// approved docs decision, a docs-lock bump and a reviewed change here.
const PinnedMatrixSHA256 = "95a244835db2d8e11c254cc72b7a376fa56433bd68070ce99d000ae450534256"

// The approved M0 content, pinned as defence in depth (mirrors the docs
// repo's tools/validate_support_matrix.py).
var (
	approvedSupported = map[string]bool{"ubuntu|24.04|x86_64": true, "ubuntu|26.04|x86_64": true, "debian|13|x86_64": true}
	approvedPlanned   = map[string]bool{"almalinux": true, "rocky": true}
	approvedFloor     = "6.8"
	topKeys           = []string{"schema", "description", "kernel_floor", "entries", "required_probes", "informational_probes", "probes", "read_limits", "deadlines_ms"}
	entryKeys         = []string{"id", "version_id", "arch", "status", "required_lsm", "support_ends"}
)

var floorRE = regexp.MustCompile(`^(\d+)\.(\d+)$`)

// LoadMatrix strictly decodes and validates the matrix, which must be the
// pinned approved matrix.
func LoadMatrix(data []byte) (*Matrix, error) { return decodeMatrix(data, true) }

// exactKeys rejects any key not spelled exactly as allowed (Go's JSON decoder
// matches field names case-insensitively).
func exactKeys(raw json.RawMessage, allowed []string) error {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil {
		return err
	}
	if len(obj) != len(allowed) {
		return errors.New("unexpected keys")
	}
	for _, k := range allowed {
		if _, ok := obj[k]; !ok {
			return fmt.Errorf("missing or misspelled key %q", k)
		}
	}
	return nil
}

func decodeMatrix(data []byte, pinDigest bool) (*Matrix, error) {
	sum := sha256.Sum256(data)
	digest := hex.EncodeToString(sum[:])
	if pinDigest && digest != PinnedMatrixSHA256 {
		return nil, fmt.Errorf("%w: digest %s is not the pinned approved matrix", ErrMatrix, digest)
	}
	if err := exactKeys(data, topKeys); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMatrix, err)
	}
	var rawEntries struct {
		Entries []json.RawMessage `json:"entries"`
	}
	if err := json.Unmarshal(data, &rawEntries); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMatrix, err)
	}
	for _, e := range rawEntries.Entries {
		if err := exactKeys(e, entryKeys); err != nil {
			return nil, fmt.Errorf("%w: entry: %v", ErrMatrix, err)
		}
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var m Matrix
	if err := dec.Decode(&m); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMatrix, err)
	}
	if dec.More() {
		return nil, fmt.Errorf("%w: trailing data", ErrMatrix)
	}
	if m.Schema != 1 {
		return nil, fmt.Errorf("%w: schema must be 1", ErrMatrix)
	}
	if !slices.Equal(m.RequiredProbes, RequiredProbes) || !slices.Equal(m.InformationalProbes, InformationalProbes) {
		return nil, fmt.Errorf("%w: probe sets differ from the implemented probes", ErrMatrix)
	}
	for _, id := range append(slices.Clone(RequiredProbes), InformationalProbes...) {
		if def, ok := m.Probes[id]; !ok || len(def.Sources) == 0 {
			return nil, fmt.Errorf("%w: probe %s undefined", ErrMatrix, id)
		}
	}
	if len(m.Probes) != len(RequiredProbes)+len(InformationalProbes) {
		return nil, fmt.Errorf("%w: unknown probe definitions", ErrMatrix)
	}
	f := floorRE.FindStringSubmatch(m.KernelFloor)
	if f == nil || m.KernelFloor != approvedFloor {
		return nil, fmt.Errorf("%w: kernel_floor", ErrMatrix)
	}
	_, _ = fmt.Sscan(f[1], &m.floor[0])
	_, _ = fmt.Sscan(f[2], &m.floor[1])
	if m.ReadLimits["default"] <= 0 {
		return nil, fmt.Errorf("%w: read_limits.default", ErrMatrix)
	}
	for _, v := range m.ReadLimits {
		if v <= 0 || v > 64<<20 {
			return nil, fmt.Errorf("%w: read limit out of range", ErrMatrix)
		}
	}
	if m.DeadlinesMs.Probe <= 0 || m.DeadlinesMs.Run <= 0 || m.DeadlinesMs.Probe > m.DeadlinesMs.Run || m.DeadlinesMs.Run > 60000 {
		return nil, fmt.Errorf("%w: deadlines", ErrMatrix)
	}
	seen := map[string]bool{}
	planned := map[string]bool{}
	supported := 0
	for _, e := range m.Entries {
		key := fmt.Sprintf("%s|%v|%v", e.ID, deref(e.VersionID), deref(e.Arch))
		if e.ID == "" || seen[key] {
			return nil, fmt.Errorf("%w: empty or duplicate entry %s", ErrMatrix, key)
		}
		seen[key] = true
		switch e.Status {
		case "supported":
			if e.VersionID == nil || *e.VersionID == "" || e.Arch == nil || *e.Arch == "" || e.RequiredLSM != "apparmor" ||
				e.SupportEnds == nil || *e.SupportEnds == "" || !approvedSupported[key] {
				return nil, fmt.Errorf("%w: supported entry %s is not in the approved set (DR-007 D2)", ErrMatrix, key)
			}
			supported++
		case "planned":
			if !approvedPlanned[e.ID] {
				return nil, fmt.Errorf("%w: planned entry %s is not approved", ErrMatrix, e.ID)
			}
			planned[e.ID] = true
		default:
			return nil, fmt.Errorf("%w: status %q", ErrMatrix, e.Status)
		}
	}
	for _, e := range m.Entries {
		if e.Status == "supported" && planned[e.ID] {
			return nil, fmt.Errorf("%w: planned distribution %s marked supported", ErrMatrix, e.ID)
		}
	}
	if supported != len(approvedSupported) || len(planned) != len(approvedPlanned) {
		return nil, fmt.Errorf("%w: entries must be exactly the approved supported and planned sets", ErrMatrix)
	}
	m.digest = digest
	return &m, nil
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// limit returns the read cap for a source path.
func (m *Matrix) limit(source string) int64 {
	if v, ok := m.ReadLimits[source]; ok {
		return v
	}
	return m.ReadLimits["default"]
}

// match returns the supported entry for (id, version, arch), the supported
// entries for (id, version) regardless of arch, and whether id is planned.
func (m *Matrix) match(id, version, arch string) (hit *Entry, sameDistro []Entry, planned bool) {
	for i := range m.Entries {
		e := &m.Entries[i]
		if e.ID != id {
			continue
		}
		if e.Status == "planned" {
			planned = true
			continue
		}
		if deref(e.VersionID) == version {
			sameDistro = append(sameDistro, *e)
			if arch != "" && deref(e.Arch) == arch {
				hit = e
			}
		}
	}
	return hit, sameDistro, planned
}

// supportedArches is the set of arches any supported entry names.
func (m *Matrix) supportedArches() map[string]bool {
	out := map[string]bool{}
	for _, e := range m.Entries {
		if e.Status == "supported" {
			out[deref(e.Arch)] = true
		}
	}
	return out
}
