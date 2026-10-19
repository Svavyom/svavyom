package capability

import (
	"bufio"
	"bytes"
	"io/fs"
	"regexp"
	"strconv"
	"strings"
)

// Result is a probe outcome.
type Result string

// Probe outcomes.
const (
	Pass          Result = "pass"
	Fail          Result = "fail"
	Unknown       Result = "unknown"
	NotApplicable Result = "not_applicable"
	Info          Result = "info"
)

// ProbeResult is one probe's typed outcome. Detail is capped and sanitised.
type ProbeResult struct {
	ID          string `json:"id"`
	Required    bool   `json:"required"`
	Result      Result `json:"result"`
	Reason      string `json:"reason"`
	Detail      string `json:"detail,omitempty"`
	Remediation string `json:"remediation,omitempty"`
}

// env carries what probes need: the filesystem, the matrix and the facts
// established by earlier probes.
type env struct {
	fsys        FS
	m           *Matrix
	osID        string
	osVersion   string
	requiredLSM string
	kernel      string
}

func unknownErr(err error) (Result, string) { return Unknown, reasonFor(err) }

// exists reports a marker file: (true,nil) present, (false,nil) provably
// absent, (false,err) undeterminable.
func exists(fsys FS, name string) (bool, error) {
	_, err := lstatResolved(fsys, name)
	if err == nil {
		return true, nil
	}
	if reasonFor(err) == "MISSING" {
		return false, nil
	}
	return false, err
}

// markerPresent lstats a marker without following it: a dangling or escaping
// symlink named like a marker still counts as present (review N4).
func markerPresent(fsys FS, name string) (bool, error) {
	_, err := fsys.Lstat(name)
	if err == nil {
		return true, nil
	}
	if reasonFor(err) == "MISSING" {
		return false, nil
	}
	return false, err
}

func probeOSRelease(e *env) (Result, string, string) {
	data, err := read(e.fsys, "etc/os-release", e.m.limit("etc/os-release"))
	if err != nil && reasonFor(err) == "MISSING" {
		data, err = read(e.fsys, "usr/lib/os-release", e.m.limit("usr/lib/os-release"))
	}
	if err != nil {
		r, why := unknownErr(err)
		return r, why, ""
	}
	kv, err := parseOSRelease(data)
	if err != nil {
		return Unknown, "OSRELEASE_MALFORMED", ""
	}
	e.osID = kv["ID"]
	if e.osID == "" {
		e.osID = "linux" // os-release(5) default
	}
	e.osVersion = kv["VERSION_ID"]
	return Pass, "PARSED", e.osID + " " + e.osVersion
}

func probeArch(e *env) (Result, string, string) {
	data, err := read(e.fsys, "proc/sys/kernel/arch", e.m.limit("proc/sys/kernel/arch"))
	if err != nil {
		r, why := unknownErr(err)
		return r, why, ""
	}
	arch := strings.TrimSpace(string(data))
	if arch == "" {
		return Unknown, "EMPTY", ""
	}
	if hit, _, _ := e.m.match(e.osID, e.osVersion, arch); hit != nil || e.m.supportedArches()[arch] {
		return Pass, "ARCH_OK", arch
	}
	return Fail, "ARCH_UNSUPPORTED", arch
}

func cpuFlags(e *env) (map[string]bool, error) {
	data, err := read(e.fsys, "proc/cpuinfo", e.m.limit("proc/cpuinfo"))
	if err != nil {
		return nil, err
	}
	var flags map[string]bool
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64*1024), len(data)+1)
	for sc.Scan() {
		k, v, ok := strings.Cut(sc.Text(), ":")
		if ok && strings.TrimSpace(k) == "flags" {
			if flags == nil {
				flags = map[string]bool{}
			}
			for _, f := range strings.Fields(v) {
				flags[f] = true
			}
		}
	}
	return flags, nil
}

func probeCPUVirt(e *env) (Result, string, string) {
	flags, err := cpuFlags(e)
	if err != nil {
		r, why := unknownErr(err)
		return r, why, ""
	}
	if flags == nil {
		return Unknown, "NO_FLAGS", ""
	}
	if flags["vmx"] || flags["svm"] {
		return Pass, "HW_VIRT", ""
	}
	return Fail, "NO_HW_VIRT", ""
}

// kernelRE: MAJOR.MINOR without leading zeros, then end or a release suffix of
// printable characters (review N6).
var kernelRE = regexp.MustCompile(`^(0|[1-9][0-9]{0,3})\.(0|[1-9][0-9]{0,3})(?:[.+~_-][\x21-\x7e]*)?$`)

func probeKernelFloor(e *env) (Result, string, string) {
	data, err := read(e.fsys, "proc/sys/kernel/osrelease", e.m.limit("proc/sys/kernel/osrelease"))
	if err != nil {
		r, why := unknownErr(err)
		return r, why, ""
	}
	rel := strings.TrimSpace(string(data))
	mm := kernelRE.FindStringSubmatch(rel)
	if mm == nil {
		return Unknown, "KERNEL_UNPARSEABLE", ""
	}
	e.kernel = rel
	major, err1 := strconv.Atoi(mm[1])
	minor, err2 := strconv.Atoi(mm[2])
	if err1 != nil || err2 != nil {
		return Unknown, "KERNEL_UNPARSEABLE", ""
	}
	if major > e.m.floor[0] || (major == e.m.floor[0] && minor >= e.m.floor[1]) {
		return Pass, "KERNEL_OK", mm[1] + "." + mm[2]
	}
	return Fail, "KERNEL_BELOW_FLOOR", mm[1] + "." + mm[2]
}

// mounts returns (mountpoint -> fstype) from mountinfo.
func mounts(e *env) (map[string]string, error) {
	data, err := read(e.fsys, "proc/self/mountinfo", e.m.limit("proc/self/mountinfo"))
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	for _, line := range strings.Split(string(data), "\n") {
		pre, post, ok := strings.Cut(line, " - ")
		fields, after := strings.Fields(pre), strings.Fields(post)
		if !ok || len(fields) < 5 || len(after) < 1 {
			continue
		}
		out[fields[4]] = after[0]
	}
	return out, nil
}

func probeCgroupV2(e *env) (Result, string, string) {
	mt, err := mounts(e)
	if err != nil {
		r, why := unknownErr(err)
		return r, why, ""
	}
	fstype, mounted := mt["/sys/fs/cgroup"]
	if mounted && fstype != "cgroup2" {
		return Fail, "CGROUP_NOT_UNIFIED", fstype
	}
	if !mounted {
		return Fail, "CGROUP_NOT_MOUNTED", ""
	}
	_, err = read(e.fsys, "sys/fs/cgroup/cgroup.controllers", e.m.limit("sys/fs/cgroup/cgroup.controllers"))
	if err != nil {
		if reasonFor(err) == "MISSING" {
			return Fail, "CGROUP_CONTROLLERS_MISSING", ""
		}
		r, why := unknownErr(err)
		return r, why, ""
	}
	return Pass, "CGROUP_V2", ""
}

func probeSystemd(e *env) (Result, string, string) {
	fi, err := lstatResolved(e.fsys, "run/systemd/system")
	if err != nil {
		if reasonFor(err) == "MISSING" {
			return Fail, "SYSTEMD_NOT_RUNNING", ""
		}
		r, why := unknownErr(err)
		return r, why, ""
	}
	if fi.IsDir() {
		return Pass, "SYSTEMD", ""
	}
	return Fail, "SYSTEMD_NOT_RUNNING", ""
}

func probeNftablesKernel(e *env) (Result, string, string) {
	if fi, err := lstatResolved(e.fsys, "sys/module/nf_tables"); err == nil && fi.IsDir() {
		return Pass, "NF_TABLES_LOADED", ""
	}
	if data, err := read(e.fsys, "proc/modules", e.m.limit("proc/modules")); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			if strings.HasPrefix(line, "nf_tables ") {
				return Pass, "NF_TABLES_LOADED", ""
			}
		}
	}
	if e.kernel != "" && !strings.ContainsAny(e.kernel, "/\\") && e.kernel != "." && e.kernel != ".." {
		for _, f := range []string{"modules.builtin", "modules.dep"} {
			p := "lib/modules/" + e.kernel + "/" + f
			data, err := read(e.fsys, p, e.m.limit(p))
			if err == nil && bytes.Contains(data, []byte("/nf_tables.ko")) {
				return Pass, "NF_TABLES_AVAILABLE", ""
			}
		}
	}
	// Never fail: availability could not be established (erratum r2a, note 5).
	return Unknown, "NF_TABLES_UNDETERMINED", ""
}

func probeLSM(e *env) (Result, string, string) {
	switch e.requiredLSM {
	case "apparmor":
		lsm, err := read(e.fsys, "sys/kernel/security/lsm", e.m.limit("sys/kernel/security/lsm"))
		if err != nil {
			r, why := unknownErr(err)
			return r, "LSM_LIST_" + why, ""
		}
		enabled, err := read(e.fsys, "sys/module/apparmor/parameters/enabled", e.m.limit("sys/module/apparmor/parameters/enabled"))
		if err != nil {
			if reasonFor(err) == "MISSING" {
				if ok, err2 := exists(e.fsys, "sys/module/apparmor"); err2 == nil && !ok {
					return Fail, "APPARMOR_ABSENT", ""
				}
			}
			r, why := unknownErr(err)
			return r, why, ""
		}
		listed := false
		for _, name := range strings.Split(strings.TrimSpace(string(lsm)), ",") {
			listed = listed || name == "apparmor"
		}
		switch strings.TrimSpace(string(enabled)) {
		case "Y":
			if listed {
				return Pass, "APPARMOR_ENABLED", ""
			}
			return Fail, "APPARMOR_NOT_ACTIVE", ""
		case "N":
			return Fail, "APPARMOR_DISABLED", ""
		default:
			return Unknown, "APPARMOR_STATE_UNPARSEABLE", ""
		}
	case "selinux":
		data, err := read(e.fsys, "sys/fs/selinux/enforce", e.m.limit("sys/fs/selinux/enforce"))
		if err != nil {
			if reasonFor(err) == "MISSING" {
				return Fail, "SELINUX_ABSENT", ""
			}
			r, why := unknownErr(err)
			return r, why, ""
		}
		if strings.TrimSpace(string(data)) == "1" {
			return Pass, "SELINUX_ENFORCING", ""
		}
		return Fail, "SELINUX_NOT_ENFORCING", ""
	default:
		return NotApplicable, "NO_MATRIX_ENTRY", ""
	}
}

var guestVendors = []string{"qemu", "vmware", "innotek", "xen", "microsoft corporation", "amazon ec2", "google", "digitalocean", "hetzner", "openstack", "parallels", "bhyve", "kvm", "red hat", "bochs", "ovirt", "nutanix", "proxmox", "apple virtualization"}

// probeContainment is evaluated first. pass only when every container source
// is readable (marker files provably absent) and shows no marker and no guest
// marker is present (erratum r2a, M1/M2).
func probeContainment(e *env) (Result, string, string) {
	for _, marker := range []string{".dockerenv", "run/.containerenv", "run/systemd/container"} {
		ok, err := markerPresent(e.fsys, marker)
		if err != nil {
			return Unknown, "CONTAINMENT_UNDETERMINED", marker
		}
		if ok {
			return Unknown, "CONTAINERIZED", marker
		}
	}
	envData, err := read(e.fsys, "proc/1/environ", e.m.limit("proc/1/environ"))
	if err != nil {
		return Unknown, "CONTAINMENT_UNDETERMINED", "proc/1/environ"
	}
	for _, kv := range bytes.Split(envData, []byte{0}) {
		if bytes.HasPrefix(kv, []byte("container=")) {
			return Unknown, "CONTAINERIZED", "proc/1/environ"
		}
	}
	uidMap, err := read(e.fsys, "proc/self/uid_map", e.m.limit("proc/self/uid_map"))
	if err != nil {
		return Unknown, "CONTAINMENT_UNDETERMINED", "proc/self/uid_map"
	}
	if f := strings.Fields(string(uidMap)); len(f) != 3 || f[0] != "0" || f[1] != "0" || f[2] != "4294967295" {
		return Unknown, "CONTAINERIZED", "proc/self/uid_map"
	}
	cg, err := read(e.fsys, "proc/1/cgroup", e.m.limit("proc/1/cgroup"))
	if err != nil {
		return Unknown, "CONTAINMENT_UNDETERMINED", "proc/1/cgroup"
	}
	for _, w := range []string{"docker", "containerd", "kubepods", "lxc", "libpod", "machine.slice"} {
		if bytes.Contains(cg, []byte(w)) {
			return Unknown, "CONTAINERIZED", "proc/1/cgroup"
		}
	}
	mt, err := mounts(e)
	if err != nil {
		return Unknown, "CONTAINMENT_UNDETERMINED", "proc/self/mountinfo"
	}
	if t := mt["/"]; t == "overlay" || t == "aufs" || t == "fuse-overlayfs" {
		return Unknown, "CONTAINERIZED", "proc/self/mountinfo"
	}
	flags, err := cpuFlags(e)
	if err != nil || flags == nil {
		return Unknown, "CONTAINMENT_UNDETERMINED", "proc/cpuinfo"
	}
	if flags["hypervisor"] {
		return Fail, "VIRTUALIZED_HOST", "cpuinfo"
	}
	if data, err := read(e.fsys, "sys/hypervisor/type", e.m.limit("sys/hypervisor/type")); err == nil && strings.TrimSpace(string(data)) != "" {
		return Fail, "VIRTUALIZED_HOST", "sys/hypervisor/type"
	} else if err != nil && reasonFor(err) != "MISSING" {
		return Unknown, "CONTAINMENT_UNDETERMINED", "sys/hypervisor/type"
	}
	if data, err := read(e.fsys, "sys/class/dmi/id/sys_vendor", e.m.limit("sys/class/dmi/id/sys_vendor")); err == nil {
		vendor := strings.ToLower(strings.TrimSpace(string(data)))
		for _, g := range guestVendors {
			if strings.HasPrefix(vendor, g) {
				return Fail, "VIRTUALIZED_HOST", "dmi"
			}
		}
	}
	return Pass, "BARE_HOST", ""
}

func probeDevKVM(e *env) (Result, string, string) {
	fi, err := lstatResolved(e.fsys, "dev/kvm") // lstat only; never opened
	switch {
	case err != nil:
		return Info, "ABSENT_OR_UNREADABLE", ""
	case fi.Mode()&fs.ModeCharDevice != 0:
		return Info, "PRESENT", ""
	default:
		return Info, "NOT_A_CHAR_DEVICE", ""
	}
}

func probeNftUserspace(e *env) (Result, string, string) {
	if _, err := lstatResolved(e.fsys, "usr/sbin/nft"); err == nil {
		return Info, "PRESENT", ""
	}
	return Info, "ABSENT_OR_UNREADABLE", ""
}

func packageVersion(e *env, pkg string) (Result, string, string) {
	data, err := read(e.fsys, "var/lib/dpkg/status", e.m.limit("var/lib/dpkg/status"))
	if err != nil {
		return Info, "DPKG_STATUS_" + reasonFor(err), ""
	}
	for _, stanza := range strings.Split(string(data), "\n\n") {
		var name, status, version string
		for _, line := range strings.Split(stanza, "\n") {
			k, v, _ := strings.Cut(line, ":")
			switch k {
			case "Package":
				name = strings.TrimSpace(v)
			case "Status":
				status = strings.TrimSpace(v)
			case "Version":
				version = strings.TrimSpace(v)
			}
		}
		if name == pkg && status == "install ok installed" {
			return Info, "INSTALLED", version
		}
	}
	return Info, "NOT_INSTALLED", ""
}
