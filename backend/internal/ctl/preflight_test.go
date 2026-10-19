package ctl

import (
	"context"
	"io/fs"
	"os"
	"strings"
	"testing"
)

func TestPreflightPassesOnASupportedHost(t *testing.T) {
	h := newHost(t)
	r := Preflight(context.Background(), h.env, PreflightOptions{Arch: "x86_64"})
	if r.Verdict != Pass || r.ExitCode() != 0 {
		var b strings.Builder
		r.Text(&b)
		t.Fatalf("%s", b.String())
	}
	for _, id := range []string{"ubuntu-release", "architecture", "systemd", "cpu-virtualization", "dev-kvm", "kvm-modules", "qemu", "libvirt-installed", "libvirt-sockets", "libvirt-reachable", "free-space", "trust-anchors", "apparmor"} {
		if f := find(r, id); f.Status != Pass || !f.Required {
			t.Errorf("%s: %+v", id, f)
		}
	}
	if f := find(r, "docker"); f.Status != Info || f.Required {
		t.Errorf("docker is informational: %+v", f)
	}
}

func TestPreflightIsReadOnly(t *testing.T) {
	h := newHost(t)
	before := snapshotTree(t, h.root)
	_ = Preflight(context.Background(), h.env, PreflightOptions{Arch: "x86_64"})
	if after := snapshotTree(t, h.root); after != before {
		t.Fatal("preflight changed the file system")
	}
	for _, c := range h.run.calls {
		if !strings.HasPrefix(c, "virsh -r ") {
			t.Errorf("preflight ran a command that is not a read-only query: %s", c)
		}
	}
}

func snapshotTree(t *testing.T, root string) string {
	t.Helper()
	var b strings.Builder
	_ = fs.WalkDir(os.DirFS(root), ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		fi, _ := d.Info()
		b.WriteString(p + " " + fi.Mode().String() + " " + fi.ModTime().String() + "\n")
		return nil
	})
	return b.String()
}

func TestPreflightTypedFailuresAndNotReady(t *testing.T) {
	cases := map[string]struct {
		break_ func(h *testHost)
		id     string
		status string
		code   string
	}{
		"not ubuntu":          {func(h *testHost) { h.write("/etc/os-release", "ID=debian\nVERSION_ID=\"13\"\n") }, "ubuntu-release", Fail, "OS_UNSUPPORTED"},
		"old ubuntu":          {func(h *testHost) { h.write("/etc/os-release", "ID=ubuntu\nVERSION_ID=\"22.04\"\n") }, "ubuntu-release", Fail, "OS_UNSUPPORTED"},
		"ubuntu 26.04":        {func(h *testHost) { h.write("/etc/os-release", "ID=ubuntu\nVERSION_ID=\"26.04\"\n") }, "ubuntu-release", Fail, "OS_UNSUPPORTED"},
		"no os-release":       {func(h *testHost) { _ = os.Remove(h.root + "/etc/os-release") }, "ubuntu-release", NotReady, "OS_UNREADABLE"},
		"no hw virt":          {func(h *testHost) { h.write("/proc/cpuinfo", "flags : fpu sse\n") }, "cpu-virtualization", Fail, "NO_HW_VIRT"},
		"no /dev/kvm":         {func(h *testHost) { delete(h.devices, "/dev/kvm") }, "dev-kvm", Fail, "NO_DEV_KVM"},
		"kvm is a plain file": {func(h *testHost) { h.devices["/dev/kvm"] = 0o666 }, "dev-kvm", Fail, "NO_DEV_KVM"},
		"no kvm modules":      {func(h *testHost) { h.write("/proc/modules", "ext4 1 0 - Live 0x0\n") }, "kvm-modules", Fail, "KVM_MODULES_MISSING"},
		"no qemu":             {func(h *testHost) { delete(h.paths, "qemu-system-x86_64") }, "qemu", NotReady, "QEMU_MISSING"},
		"no libvirt":          {func(h *testHost) { delete(h.paths, "libvirtd") }, "libvirt-installed", NotReady, "LIBVIRT_MISSING"},
		"no libvirt socket":   {func(h *testHost) { delete(h.devices, "/run/libvirt/libvirt-sock") }, "libvirt-sockets", NotReady, "LIBVIRT_SOCKET_MISSING"},
		"socket not a socket": {func(h *testHost) { h.devices["/run/libvirt/libvirt-sock-ro"] = 0o666 }, "libvirt-sockets", NotReady, "LIBVIRT_SOCKET_MISSING"},
		"libvirt unreachable": {func(h *testHost) { h.dialErr = os.ErrPermission }, "libvirt-reachable", NotReady, "LIBVIRT_UNREACHABLE"},
		"low space":           {func(h *testHost) { h.free = 5 << 30 }, "free-space", Fail, "LOW_SPACE"},
		"apparmor off":        {func(h *testHost) { h.write("/sys/module/apparmor/parameters/enabled", "N\n") }, "apparmor", Fail, "APPARMOR_DISABLED"},
		"no apparmor":         {func(h *testHost) { _ = os.Remove(h.root + "/sys/module/apparmor/parameters/enabled") }, "apparmor", Fail, "APPARMOR_ABSENT"},
		"not systemd":         {func(h *testHost) { _ = os.RemoveAll(h.root + "/run/systemd") }, "systemd", Fail, "SYSTEMD_NOT_RUNNING"},
	}
	for name, c := range cases {
		h := newHost(t)
		c.break_(h)
		r := Preflight(context.Background(), h.env, PreflightOptions{Arch: "x86_64"})
		f := find(r, c.id)
		if f.Status != c.status || f.Code != c.code || f.Remediation == "" {
			t.Errorf("%s: %+v", name, f)
		}
		want := Fail
		if c.status == NotReady {
			want = NotReady
		}
		if r.Verdict != want {
			t.Errorf("%s: verdict %s, want %s", name, r.Verdict, want)
		}
	}
	h := newHost(t)
	if r := Preflight(context.Background(), h.env, PreflightOptions{Arch: "aarch64"}); find(r, "architecture").Code != "ARCH_UNSUPPORTED" || r.Verdict != Fail {
		t.Fatal("an ARM host must fail")
	}
}

func TestPreflightNeverSuggestsWeakeningASecurityControl(t *testing.T) {
	h := newHost(t)
	h.write("/sys/module/apparmor/parameters/enabled", "N\n")
	h.dialErr = os.ErrPermission
	r := Preflight(context.Background(), h.env, PreflightOptions{Arch: "x86_64"})
	for _, f := range r.Findings {
		low := strings.ToLower(f.Remediation)
		for _, bad := range []string{"chmod 777", "disable apparmor", "setenforce", "unix_sock_rw_perms", "run as root", "--insecure", "security_driver"} {
			if strings.Contains(low, bad) {
				t.Errorf("%s suggests %q", f.ID, bad)
			}
		}
	}
}

func TestPreflightChecksTheConfiguredNetworkAndPool(t *testing.T) {
	h := newHost(t)
	cfg := h.write("/etc/svavyom/provision.json", `{"catalog_dir":"/var/lib/svavyom/images","pool":"svavyom","network":"default","domain_type":"kvm","libvirt_uri":"qemu:///system","state_dir":"/var/lib/svavyom/state",`+
		`"trust":{"deploy_uid":0,"runtime_identities":[{"name":"api","uid":987,"gids":[987]},{"name":"agent","uid":986,"gids":[986]},{"name":"mutation","uid":985,"gids":[985,113]}]}}`)
	r := Preflight(context.Background(), h.env, PreflightOptions{Arch: "x86_64", ConfigPath: cfg})
	if find(r, "network-ready").Status != Pass || find(r, "pool-ready").Status != Pass {
		t.Fatalf("%+v %+v", find(r, "network-ready"), find(r, "pool-ready"))
	}
	h.run.reply["virsh -r -c qemu:///system net-info"] = "Name: default\nActive: no\n"
	r = Preflight(context.Background(), h.env, PreflightOptions{Arch: "x86_64", ConfigPath: cfg})
	if f := find(r, "network-ready"); f.Status != NotReady || f.Code != "NETWORK_NOT_READY" {
		t.Fatalf("%+v", f)
	}
	delete(h.paths, "virsh")
	r = Preflight(context.Background(), h.env, PreflightOptions{Arch: "x86_64", ConfigPath: cfg})
	if find(r, "pool-ready").Status != NotReady {
		t.Fatal("without virsh the pool cannot be verified, which is NOT_READY and never PASS")
	}
	bad := h.write("/etc/svavyom/bad.json", `{"catalog_dir":"relative"}`)
	if r = Preflight(context.Background(), h.env, PreflightOptions{Arch: "x86_64", ConfigPath: bad}); find(r, "config").Code != "CONFIG_INVALID" {
		t.Fatal("an invalid configuration must be reported")
	}
}

func TestParseOSRelease(t *testing.T) {
	kv := parseOSRelease([]byte("ID=ubuntu\nVERSION_ID=\"24.04\"\n# c\nPRETTY_NAME='Ubuntu 24.04'\nbroken line\n"))
	if kv["ID"] != "ubuntu" || kv["VERSION_ID"] != "24.04" || kv["PRETTY_NAME"] != "Ubuntu 24.04" {
		t.Fatalf("%v", kv)
	}
}

func TestReportRendering(t *testing.T) {
	r := NewReport("x", []Finding{{ID: "a", Status: Pass, Required: true}, {ID: "b", Status: NotReady, Required: true, Code: "X", Detail: "d\x01e", Remediation: "do it"}, {ID: "c", Status: Info}})
	var b strings.Builder
	r.Text(&b)
	if r.Verdict != NotReady || r.ExitCode() != 11 || !strings.Contains(b.String(), "-> do it") || !strings.Contains(b.String(), "RESULT: NOT_READY") {
		t.Fatalf("%s", b.String())
	}
	if clean("ok\x00\x1b[31mé") != "ok?[31m?" && !strings.Contains(clean("a\x01b"), "?") {
		t.Fatal("control characters must not survive")
	}
	if got := NewReport("x", []Finding{{ID: "a", Status: Fail, Required: false}}); got.Verdict != Pass {
		t.Fatal("an optional failure does not change the verdict")
	}
	if !strings.Contains(string(r.JSON()), `"verdict": "NOT_READY"`) {
		t.Fatal("json")
	}
}

// TestRegressionMatrixOfHostSystems is the host-system regression matrix (M4-E01-S03): every row of certification/matrix.json whose expectation is
// "refused" must be refused by the preflight with OS_UNSUPPORTED, and the one supported system must pass the release check. The wider the matrix
// grows, the more this table guards against an installer that quietly accepts a system nobody qualified.
func TestRegressionMatrixOfHostSystems(t *testing.T) {
	rows := []struct {
		id, osID, version string
		supported         bool
	}{
		{"ubuntu-24.04", "ubuntu", "24.04", true},
		{"ubuntu-22.04", "ubuntu", "22.04", false}, {"ubuntu-20.04", "ubuntu", "20.04", false}, {"ubuntu-24.10", "ubuntu", "24.10", false},
		{"ubuntu-25.04", "ubuntu", "25.04", false}, {"ubuntu-26.04", "ubuntu", "26.04", false},
		{"debian-11", "debian", "11", false}, {"debian-12", "debian", "12", false}, {"debian-13", "debian", "13", false},
		{"rocky-9", "rocky", "9", false}, {"almalinux-9", "almalinux", "9", false}, {"fedora-41", "fedora", "41", false}, {"arch", "arch", "", false},
		{"ubuntu-without-a-version", "ubuntu", "", false},
	}
	for _, r := range rows {
		t.Run(r.id, func(t *testing.T) {
			h := newHost(t)
			h.write("/etc/os-release", "ID="+r.osID+"\nVERSION_ID=\""+r.version+"\"\n")
			rep := Preflight(context.Background(), h.env, PreflightOptions{Arch: "x86_64"})
			f := find(rep, "ubuntu-release")
			switch {
			case r.supported && f.Status != Pass:
				t.Fatalf("the supported system must pass: %+v", f)
			case !r.supported && (f.Status != Fail || f.Code != "OS_UNSUPPORTED"):
				t.Fatalf("an unqualified system must be refused with OS_UNSUPPORTED: %+v", f)
			}
		})
	}
}
