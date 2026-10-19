package ctl

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"

	"example.invalid/dedicatedcloud/backend/internal/provision"
)

// PreflightOptions are the inputs of the read-only host preflight.
type PreflightOptions struct {
	// ConfigPath, when set, adds the checks of the configured network and pool.
	ConfigPath string
	// MinFreeGiB is the free space the state directory's file system must offer (default 30).
	MinFreeGiB int
	// Arch is the machine architecture (default: runtime).
	Arch string
}

var osReleaseKV = regexp.MustCompile(`^([A-Z_]+)=(.*)$`)

// parseOSRelease reads KEY=VALUE lines of /etc/os-release.
func parseOSRelease(b []byte) map[string]string {
	out := map[string]string{}
	for _, l := range strings.Split(string(b), "\n") {
		if m := osReleaseKV.FindStringSubmatch(strings.TrimSpace(l)); m != nil {
			out[m[1]] = strings.Trim(m[2], `"'`)
		}
	}
	return out
}

// Preflight answers one question without changing anything: can this machine run a Svavyom Development Preview? It reads /proc, /sys and the
// installation, dials the read-only libvirt socket and asks `virsh -r` for the state of the configured network and pool; it creates, writes and
// starts nothing. READY is not qualification.
func Preflight(ctx context.Context, e *Env, o PreflightOptions) Report {
	if o.MinFreeGiB == 0 {
		o.MinFreeGiB = 30
	}
	var list []Finding
	add := func(f Finding) { f.Detail = clean(f.Detail); list = append(list, f) }
	req := func(id, status, code, detail, remedy string) {
		add(Finding{ID: id, Status: status, Required: true, Code: code, Detail: detail, Remediation: remedy})
	}

	// 1. Distribution.
	if b, err := e.ReadFile(e.P("/etc/os-release")); err != nil {
		req("ubuntu-release", NotReady, "OS_UNREADABLE", "cannot read /etc/os-release", "Run on Ubuntu 24.04 LTS.")
	} else if kv := parseOSRelease(b); kv["ID"] != "ubuntu" || (kv["VERSION_ID"] != "24.04") {
		req("ubuntu-release", Fail, "OS_UNSUPPORTED", "found "+kv["ID"]+" "+kv["VERSION_ID"], "Use Ubuntu 24.04 LTS (the only Development Preview host).")
	} else {
		req("ubuntu-release", Pass, "", "Ubuntu "+kv["VERSION_ID"], "")
	}
	// 2. Architecture.
	arch := o.Arch
	if arch == "" {
		arch = hostArch()
	}
	if arch != "x86_64" && arch != "amd64" {
		req("architecture", Fail, "ARCH_UNSUPPORTED", arch, "Use an x86_64 host.")
	} else {
		req("architecture", Pass, "", "x86_64", "")
	}
	// 3. systemd.
	if _, err := e.Lstat(e.P("/run/systemd/system")); err != nil {
		req("systemd", Fail, "SYSTEMD_NOT_RUNNING", "/run/systemd/system is absent", "Run on a host where systemd is the init system.")
	} else {
		req("systemd", Pass, "", "systemd is running", "")
	}
	// 4. Hardware virtualisation.
	if b, err := e.ReadFile(e.P("/proc/cpuinfo")); err != nil {
		req("cpu-virtualization", NotReady, "CPUINFO_UNREADABLE", "cannot read /proc/cpuinfo", "Run on the host itself.")
	} else if !regexp.MustCompile(`(?m)^flags\s*:.*\b(vmx|svm)\b`).Match(b) {
		req("cpu-virtualization", Fail, "NO_HW_VIRT", "no vmx/svm CPU flag", "Enable Intel VT-x / AMD-V in the firmware; a virtual machine without nested virtualisation is not supported.")
	} else {
		req("cpu-virtualization", Pass, "", "vmx or svm present", "")
	}
	// 5. /dev/kvm and the KVM modules.
	if fi, err := e.Lstat(e.P("/dev/kvm")); err != nil || fi.Mode()&fs.ModeCharDevice == 0 {
		req("dev-kvm", Fail, "NO_DEV_KVM", "/dev/kvm is not a character device", "Load the KVM modules (modprobe kvm_intel or kvm_amd) and check the firmware setting.")
	} else {
		req("dev-kvm", Pass, "", "/dev/kvm present", "")
	}
	if b, err := e.ReadFile(e.P("/proc/modules")); err != nil {
		req("kvm-modules", NotReady, "MODULES_UNREADABLE", "cannot read /proc/modules", "Run on the host itself.")
	} else if s := string(b); !regexp.MustCompile(`(?m)^kvm `).MatchString(s) || !regexp.MustCompile(`(?m)^kvm_(intel|amd) `).MatchString(s) {
		req("kvm-modules", Fail, "KVM_MODULES_MISSING", "kvm and kvm_intel/kvm_amd are not both loaded", "Load the KVM modules.")
	} else {
		req("kvm-modules", Pass, "", "kvm and the vendor module are loaded", "")
	}
	// 6. QEMU and libvirt packages.
	if _, err := e.LookPath("qemu-system-x86_64"); err != nil {
		req("qemu", NotReady, "QEMU_MISSING", "qemu-system-x86_64 not found", "apt install qemu-system-x86")
	} else {
		req("qemu", Pass, "", "qemu-system-x86_64 found", "")
	}
	_, e1 := e.LookPath("libvirtd")
	_, e2 := e.LookPath("virtqemud")
	if e1 != nil && e2 != nil {
		req("libvirt-installed", NotReady, "LIBVIRT_MISSING", "no libvirt daemon found", "apt install libvirt-daemon-system libvirt-clients")
	} else {
		req("libvirt-installed", Pass, "", "libvirt daemon found", "")
	}
	// 7. The libvirt sockets (Ubuntu's libvirtd: libvirt-sock root:libvirt 0660 and libvirt-sock-ro).
	rw, ro := "/run/libvirt/libvirt-sock", "/run/libvirt/libvirt-sock-ro"
	if _, err := e.Lstat(e.P(ro)); err != nil {
		rw, ro = "/run/libvirt/virtqemud-sock", "/run/libvirt/virtqemud-sock-ro"
	}
	missing := []string{}
	for _, p := range []string{rw, ro} {
		if fi, err := e.Lstat(e.P(p)); err != nil || fi.Mode()&fs.ModeSocket == 0 {
			missing = append(missing, p)
		}
	}
	if len(missing) > 0 {
		req("libvirt-sockets", NotReady, "LIBVIRT_SOCKET_MISSING", strings.Join(missing, ", ")+" not a socket", "Start libvirt: systemctl enable --now libvirtd")
	} else {
		req("libvirt-sockets", Pass, "", "read-write and read-only sockets present", "")
		if err := e.Dial(e.P(ro)); err != nil {
			req("libvirt-reachable", NotReady, "LIBVIRT_UNREACHABLE", "cannot connect to the read-only socket", "Run this command with sudo or as a member of the libvirt group, and check that libvirtd runs.")
		} else {
			req("libvirt-reachable", Pass, "", "qemu:///system answers on the read-only socket", "")
		}
	}
	// 8. The configured network and pool.
	if o.ConfigPath != "" {
		cfg, err := provision.LoadConfig(o.ConfigPath)
		if err != nil {
			req("config", Fail, "CONFIG_INVALID", "the provisioning configuration does not validate", "Run svavyom-ctl validate-config for the reason.")
		} else {
			for _, r := range []struct{ kind, name, id string }{{"net", cfg.Network, "network"}, {"pool", cfg.Pool, "pool"}} {
				req(r.id+"-ready", virshState(ctx, e, r.kind, r.name), codeFor(r.id, virshState(ctx, e, r.kind, r.name)), "libvirt "+r.id+" "+r.name, remedyFor(r.id, r.name))
			}
		}
	}
	// 9. Space for the state and the VM disks.
	probe := e.P(LibDir)
	for probe != "/" && probe != "." {
		if _, err := e.Lstat(probe); err == nil {
			break
		}
		probe = filepath.Dir(probe)
	}
	if free, err := e.Statfs(probe); err != nil {
		req("free-space", NotReady, "SPACE_UNKNOWN", "cannot read the free space", "Check the file system of /var/lib.")
	} else if free < uint64(o.MinFreeGiB)<<30 { // #nosec G115 -- MinFreeGiB is a small positive option
		req("free-space", Fail, "LOW_SPACE", fmt.Sprintf("%d GiB free, %d GiB wanted", free>>30, o.MinFreeGiB), "Free space on the file system of /var/lib/svavyom or choose another pool location.")
	} else {
		req("free-space", Pass, "", fmt.Sprintf("%d GiB free", free>>30), "")
	}
	// 10. Trust anchors can be root-owned.
	bad := []string{}
	for _, p := range []string{LibexecDir, ConfigDir, LibDir} {
		if why := anchorFeasible(e, p); why != "" {
			bad = append(bad, why)
		}
	}
	if len(bad) > 0 {
		req("trust-anchors", Fail, "TRUST_ANCHOR_PATH", strings.Join(bad, "; "), "The directories above the trust anchors must be owned by root and closed to group and other writes, with no symlink in the path.")
	} else {
		req("trust-anchors", Pass, "", "the anchor paths are (or can be made) root-owned with no writable ancestor", "")
	}
	// 11. AppArmor.
	if b, err := e.ReadFile(e.P("/sys/module/apparmor/parameters/enabled")); err != nil {
		req("apparmor", Fail, "APPARMOR_ABSENT", "AppArmor is not enabled in the kernel", "Enable AppArmor (the Ubuntu default) and keep its profiles enforcing.")
	} else if strings.TrimSpace(string(b)) != "Y" {
		req("apparmor", Fail, "APPARMOR_DISABLED", "AppArmor is not enabled", "Enable AppArmor (the Ubuntu default) and keep its profiles enforcing.")
	} else {
		req("apparmor", Pass, "", "AppArmor is enabled", "")
	}
	// Informational.
	if _, err := e.LookPath("docker"); err != nil {
		add(Finding{ID: "docker", Status: Info, Detail: "not installed (needed only to build or qualify, not to run)"})
	} else {
		add(Finding{ID: "docker", Status: Info, Detail: "present (build and qualification only)"})
	}
	return NewReport("preflight", list)
}

func hostArch() string {
	var u syscall.Utsname
	if err := syscall.Uname(&u); err != nil {
		return ""
	}
	var b []byte
	for _, c := range u.Machine {
		if c == 0 {
			break
		}
		b = append(b, byte(c)) // #nosec G115 -- a uname field holds ASCII
	}
	return string(b)
}

// virshState asks the read-only libvirt client whether a network or pool exists and is active. Without the client the answer is NOT_READY, never PASS.
func virshState(ctx context.Context, e *Env, kind, name string) string {
	if _, err := e.LookPath("virsh"); err != nil {
		return NotReady
	}
	out, err := e.Run.Run(ctx, "virsh", "-r", "-c", "qemu:///system", kind+"-info", "--", name)
	if err != nil {
		return NotReady
	}
	if regexp.MustCompile(`(?m)^Active:\s+yes`).MatchString(out) {
		return Pass
	}
	return NotReady
}

func codeFor(id, status string) string {
	if status == Pass {
		return ""
	}
	return strings.ToUpper(id) + "_NOT_READY"
}

func remedyFor(id, name string) string {
	if id == "network" {
		return "Define and start the libvirt network " + name + " (virsh net-start / net-autostart)."
	}
	return "Define and start the libvirt pool " + name + " (packages/ubuntu/libvirt/pool-svavyom.xml)."
}

// anchorFeasible reports why the path (or, if it does not exist yet, its nearest existing ancestor) cannot hold a root-owned trust anchor. "" means it can.
func anchorFeasible(e *Env, p string) string {
	cur := e.P(p)
	for {
		fi, err := e.Lstat(cur)
		if err == nil {
			if fi.Mode()&fs.ModeSymlink != 0 {
				return p + ": a path component is a symlink"
			}
			if st, ok := fi.Sys().(*syscall.Stat_t); ok && (e.Root == "/" || e.Root == "") {
				if st.Uid != 0 {
					return p + ": " + cur + " is not owned by root"
				}
				if fi.Mode().Perm()&0o022 != 0 && fi.Mode()&fs.ModeSticky == 0 {
					return p + ": " + cur + " is writable by group or others"
				}
			}
			if cur == e.P(p) {
				return ""
			}
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			return ""
		}
		cur = parent
	}
}

var _ = os.Getpid
