package capability

import (
	"encoding/json"
	"strings"
	"time"
)

// CheckerVersion is recorded in every report.
const CheckerVersion = "1"

// Verdicts.
const (
	Supported   = "supported"
	Unsupported = "unsupported"
	UnknownV    = "unknown"
)

// Report is the checker output: allowlisted fields only, no timestamps or
// host identifiers. "supported" means matrix conformance only.
type Report struct {
	Schema         int           `json:"schema"`
	CheckerVersion string        `json:"checker_version"`
	MatrixSHA256   string        `json:"matrix_sha256"`
	Qualification  string        `json:"qualification"`
	Meaning        string        `json:"meaning"`
	Distribution   Distribution  `json:"distribution"`
	Verdict        string        `json:"verdict"`
	Reasons        []string      `json:"reasons"`
	Probes         []ProbeResult `json:"probes"`
}

// Distribution identifies the os-release ID/VERSION_ID (sanitised, capped).
type Distribution struct {
	ID        string `json:"id"`
	VersionID string `json:"version_id"`
}

// Remediations never suggest weakening a security control (tested).
var Remediations = map[string]string{
	"NO_HW_VIRT":          "Enable hardware virtualization (Intel VT-x / AMD-V) in the system firmware.",
	"KERNEL_BELOW_FLOOR":  "Use the distribution's supported kernel at or above the matrix floor.",
	"CGROUP_NOT_UNIFIED":  "Boot with the unified cgroup v2 hierarchy (the distribution default).",
	"CGROUP_NOT_MOUNTED":  "Boot with the unified cgroup v2 hierarchy (the distribution default).",
	"SYSTEMD_NOT_RUNNING": "Run on a host where systemd is the init system.",
	"APPARMOR_DISABLED":   "Enable AppArmor (the distribution default) and keep its profiles enforcing.",
	"APPARMOR_ABSENT":     "Enable AppArmor (the distribution default) and keep its profiles enforcing.",
	"APPARMOR_NOT_ACTIVE": "Enable AppArmor (the distribution default) and keep its profiles enforcing.",
	"ARCH_UNSUPPORTED":    "Use an x86_64 host; other architectures are not in the M0 support matrix.",
	"VIRTUALIZED_HOST":    "Use a dedicated (bare-metal) host; virtual machines are not in the M0 support matrix.",
}

type probeFn func(*env) (Result, string, string)

// Options are test-only hooks; the zero value is the production behaviour.
type Options struct {
	// Hook is called before each probe (used to inject delays).
	Hook func(id string)
}

// run executes one probe on a private copy of env with a deadline. A probe
// that times out keeps no access to shared state (its copy is discarded), so
// late completions cannot race with later probes; facts it established are
// returned only when it finished in time.
func run(e *env, id string, required bool, fn probeFn, hook func(string), deadline time.Duration) (ProbeResult, *env) {
	type out struct {
		r            Result
		reason, info string
		facts        *env
	}
	ch := make(chan out, 1)
	local := *e
	go func() {
		if hook != nil {
			hook(id)
		}
		r, reason, info := fn(&local)
		ch <- out{r, reason, info, &local}
	}()
	select {
	case o := <-ch:
		return ProbeResult{ID: id, Required: required, Result: o.r, Reason: o.reason, Detail: sanitize(o.info)}, o.facts
	case <-time.After(deadline):
		if required {
			return ProbeResult{ID: id, Required: true, Result: Unknown, Reason: "TIMEOUT"}, nil
		}
		return ProbeResult{ID: id, Result: Info, Reason: "TIMEOUT"}, nil
	}
}

// sanitize keeps printable ASCII only and caps the length.
func sanitize(s string) string {
	var b strings.Builder
	for _, r := range s {
		if b.Len() >= 64 {
			break
		}
		if r >= 0x20 && r < 0x7f {
			b.WriteRune(r)
		} else {
			b.WriteByte('?')
		}
	}
	return b.String()
}

// Check evaluates the root against the matrix. It is deterministic for a
// given root and matrix.
func Check(fsys FS, m *Matrix) Report { return CheckWith(fsys, m, Options{}) }

// CheckWith is Check with test hooks.
func CheckWith(fsys FS, m *Matrix, opts Options) Report {
	probeDeadline := time.Duration(m.DeadlinesMs.Probe) * time.Millisecond
	runDeadline := time.Now().Add(time.Duration(m.DeadlinesMs.Run) * time.Millisecond)
	e := &env{fsys: fsys, m: m}
	step := func(id string, required bool, fn probeFn) ProbeResult {
		left := time.Until(runDeadline)
		if left <= 0 {
			if required {
				return ProbeResult{ID: id, Required: true, Result: Unknown, Reason: "TIMEOUT"}
			}
			return ProbeResult{ID: id, Result: Info, Reason: "TIMEOUT"}
		}
		d := probeDeadline
		if left < d {
			d = left
		}
		res, facts := run(e, id, required, fn, opts.Hook, d)
		if facts != nil { // adopt facts only from probes that completed in time
			e.osID, e.osVersion, e.kernel = facts.osID, facts.osVersion, facts.kernel
		}
		return res
	}
	results := map[string]ProbeResult{}
	// os_release and kernel facts first; containment is evaluated first for the verdict.
	results["containment"] = step("containment", true, probeContainment)
	results["os_release"] = step("os_release", true, probeOSRelease)
	if results["os_release"].Result != Pass {
		e.osID, e.osVersion = "", ""
	}
	results["arch"] = step("arch", true, probeArch)
	archValue := ""
	if results["arch"].Result == Pass || results["arch"].Result == Fail {
		archValue = results["arch"].Detail
	}
	hit, sameDistro, planned := m.match(e.osID, e.osVersion, archValue)
	switch {
	case hit != nil:
		e.requiredLSM = hit.RequiredLSM
	case len(sameDistro) > 0:
		e.requiredLSM = sameDistro[0].RequiredLSM
	case planned:
		e.requiredLSM = "selinux"
	}
	results["cpu_virt"] = step("cpu_virt", true, probeCPUVirt)
	results["kernel_floor"] = step("kernel_floor", true, probeKernelFloor)
	results["cgroup_v2"] = step("cgroup_v2", true, probeCgroupV2)
	results["systemd"] = step("systemd", true, probeSystemd)
	results["nftables_kernel"] = step("nftables_kernel", true, probeNftablesKernel)
	results["lsm"] = step("lsm", true, probeLSM)
	results["dev_kvm"] = step("dev_kvm", false, probeDevKVM)
	results["nftables_userspace"] = step("nftables_userspace", false, probeNftUserspace)
	results["libvirt_packages"] = step("libvirt_packages", false, func(e *env) (Result, string, string) {
		return packageVersion(e, "libvirt-daemon-system")
	})
	results["qemu_packages"] = step("qemu_packages", false, func(e *env) (Result, string, string) {
		return packageVersion(e, "qemu-system-x86")
	})

	rep := Report{Schema: 1, CheckerVersion: CheckerVersion, MatrixSHA256: m.digest, Qualification: "none",
		Meaning: "matrix conformance only; not host qualification", Reasons: []string{}}
	if results["os_release"].Result == Pass {
		rep.Distribution = Distribution{ID: sanitize(e.osID), VersionID: sanitize(e.osVersion)}
	}
	for _, id := range append(append([]string{}, RequiredProbes...), InformationalProbes...) {
		p := results[id]
		if p.Result == Fail {
			p.Remediation = Remediations[p.Reason]
		}
		rep.Probes = append(rep.Probes, p)
	}
	rep.Verdict, rep.Reasons = verdict(results, hit, sameDistro, planned, results["os_release"].Result == Pass, archValue)
	return rep
}

// verdict is the exhaustive, fail-closed verdict function (refinement r2 +
// erratum r2a): containment first; supported only if every required probe
// passes for an exactly matching supported entry.
func verdict(results map[string]ProbeResult, hit *Entry, sameDistro []Entry, planned, osOK bool, arch string) (string, []string) {
	c := results["containment"]
	if c.Result == Unknown && c.Reason == "CONTAINERIZED" {
		return UnknownV, []string{"CONTAINERIZED"}
	}
	if c.Result == Fail && c.Reason == "VIRTUALIZED_HOST" {
		return Unsupported, []string{"VIRTUALIZED_HOST"}
	}
	var reasons []string
	allPass := true
	anyFail := false
	for _, id := range RequiredProbes {
		p := results[id]
		switch p.Result {
		case Pass:
		case Fail:
			anyFail = true
			allPass = false
			reasons = append(reasons, id+":"+p.Reason)
		default: // unknown, not_applicable on a required probe, info
			allPass = false
			reasons = append(reasons, id+":"+p.Reason)
		}
	}
	distroUnsupported := false
	if osOK && len(sameDistro) == 0 {
		distroUnsupported = true
		if planned {
			reasons = append([]string{"DISTRIBUTION_PLANNED_NOT_SUPPORTED"}, reasons...)
		} else {
			reasons = append([]string{"DISTRIBUTION_NOT_IN_MATRIX"}, reasons...)
		}
	}
	if osOK && len(sameDistro) > 0 && arch != "" && hit == nil {
		distroUnsupported = true
		reasons = append([]string{"ARCH_NOT_IN_MATRIX"}, reasons...)
	}
	switch {
	case osOK && hit != nil && allPass:
		return Supported, []string{}
	case anyFail || distroUnsupported:
		return Unsupported, reasons
	default:
		return UnknownV, reasons
	}
}

// JSON renders the report deterministically.
func (r Report) JSON() []byte {
	out, _ := json.MarshalIndent(r, "", "  ")
	return append(out, '\n')
}
