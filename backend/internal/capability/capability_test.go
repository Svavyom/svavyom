package capability

import (
	"bytes"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"testing"
	"time"
)

var fixtures = filepath.Join("..", "..", "..", "tests", "fixtures", "distribution")

var supportedFixtures = []string{"debian-13", "ubuntu-24.04", "ubuntu-26.04", "proxmox-like", "nftables-builtin"}

func loadMatrix(t *testing.T, mutate func(map[string]any)) *Matrix {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(fixtures, "support-matrix.json"))
	if err != nil {
		t.Fatal(err)
	}
	if mutate != nil {
		var doc map[string]any
		if err := json.Unmarshal(raw, &doc); err != nil {
			t.Fatal(err)
		}
		mutate(doc)
		raw, _ = json.Marshal(doc)
	}
	pin := mutate == nil
	m, err := decodeMatrix(raw, pin) // mutated (e.g. shorter deadlines) test matrices skip only the digest pin
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func openFixture(t *testing.T, name string) FS {
	t.Helper()
	f, closeFn, err := OpenRoot(filepath.Join(fixtures, "roots", name))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = closeFn() })
	return f
}

// copyRoot copies a fixture root (preserving symlinks) into a temp dir.
func copyRoot(t *testing.T, name string) string {
	t.Helper()
	src := filepath.Join(fixtures, "roots", name)
	dst := t.TempDir()
	err := filepath.WalkDir(src, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		out := filepath.Join(dst, rel)
		switch {
		case d.Type()&fs.ModeSymlink != 0:
			target, err := os.Readlink(p)
			if err != nil {
				return err
			}
			return os.Symlink(target, out)
		case d.IsDir():
			return os.MkdirAll(out, 0o755)
		default:
			data, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			return os.WriteFile(out, data, 0o644)
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	return dst
}

func checkDir(t *testing.T, dir string, m *Matrix) Report {
	t.Helper()
	f, closeFn, err := OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = closeFn() }()
	return Check(f, m)
}

func probe(r Report, id string) ProbeResult {
	for _, p := range r.Probes {
		if p.ID == id {
			return p
		}
	}
	return ProbeResult{}
}

func TestRunsAsNonRoot(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Fatal("capability tests must run as a non-root user (chmod-000 fixtures are meaningless as root)")
	}
}

func TestFixtureVerdicts(t *testing.T) {
	m := loadMatrix(t, nil)
	raw, err := os.ReadFile(filepath.Join(fixtures, "expected-verdicts.json"))
	if err != nil {
		t.Fatal(err)
	}
	var expected map[string]string
	if err := json.Unmarshal(raw, &expected); err != nil {
		t.Fatal(err)
	}
	if len(expected) < 30 {
		t.Fatalf("only %d fixtures", len(expected))
	}
	for name, want := range expected {
		t.Run(name, func(t *testing.T) {
			rep := Check(openFixture(t, name), m)
			if rep.Verdict != want {
				t.Fatalf("verdict %s, want %s (reasons %v)", rep.Verdict, want, rep.Reasons)
			}
			if rep.Qualification != "none" || rep.Meaning != "matrix conformance only; not host qualification" {
				t.Fatal("report must state qualification none")
			}
		})
	}
}

// TestFixtureReasons asserts the documented first typed reason of every
// unsupported/unknown fixture (AC02 "documented verdict and typed reasons").
func TestFixtureReasons(t *testing.T) {
	m := loadMatrix(t, nil)
	raw, err := os.ReadFile(filepath.Join(fixtures, "expected-reasons.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Reasons map[string]string `json:"reasons"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil || len(doc.Reasons) < 30 {
		t.Fatalf("expected-reasons.json: %v (%d)", err, len(doc.Reasons))
	}
	for name, want := range doc.Reasons {
		rep := Check(openFixture(t, name), m)
		if len(rep.Reasons) == 0 || rep.Reasons[0] != want {
			t.Errorf("%s: reasons %v, want first %s", name, rep.Reasons, want)
		}
	}
}

func TestSupportedReportsAreGoldenAndDeterministic(t *testing.T) {
	m := loadMatrix(t, nil)
	for _, name := range supportedFixtures {
		t.Run(name, func(t *testing.T) {
			want, err := os.ReadFile(filepath.Join(fixtures, "expected-reports", name+".json"))
			if err != nil {
				t.Fatal(err)
			}
			a := Check(openFixture(t, name), m).JSON()
			b := Check(openFixture(t, name), m).JSON()
			if !bytes.Equal(a, want) || !bytes.Equal(a, b) {
				t.Fatalf("report differs from golden or between runs:\n%s", a)
			}
		})
	}
}

func TestContainerAndGuestPrecedence(t *testing.T) {
	m := loadMatrix(t, nil)
	cases := map[string][2]string{
		"docker-container": {UnknownV, "CONTAINERIZED"},
		"lxc-container":    {UnknownV, "CONTAINERIZED"},
		"userns-container": {UnknownV, "CONTAINERIZED"},
		"vm-guest":         {Unsupported, "VIRTUALIZED_HOST"},
		"dmi-guest":        {Unsupported, "VIRTUALIZED_HOST"},
	}
	for name, want := range cases {
		rep := Check(openFixture(t, name), m)
		if rep.Verdict != want[0] || len(rep.Reasons) != 1 || rep.Reasons[0] != want[1] {
			t.Errorf("%s: %s %v, want %v", name, rep.Verdict, rep.Reasons, want)
		}
	}
	// A container that also lacks systemd is still unknown/CONTAINERIZED (erratum r2a, M1).
	dir := copyRoot(t, "docker-container")
	if err := os.RemoveAll(filepath.Join(dir, "run", "systemd")); err != nil {
		t.Fatal(err)
	}
	if rep := checkDir(t, dir, m); rep.Verdict != UnknownV || rep.Reasons[0] != "CONTAINERIZED" {
		t.Fatalf("container without systemd: %s %v", rep.Verdict, rep.Reasons)
	}
}

// mutFS makes one path behave as missing, unreadable, over-limit, garbage or present.
type mutFS struct {
	FS
	path, kind string
}

type fakeInfo struct {
	name string
	mode fs.FileMode
}

func (f fakeInfo) Name() string       { return f.name }
func (f fakeInfo) Size() int64        { return 0 }
func (f fakeInfo) Mode() fs.FileMode  { return f.mode }
func (f fakeInfo) ModTime() time.Time { return time.Time{} }
func (f fakeInfo) IsDir() bool        { return f.mode.IsDir() }
func (f fakeInfo) Sys() any           { return nil }

func (m mutFS) hit(name string) bool { return name == m.path || strings.HasPrefix(name, m.path+"/") }

func (m mutFS) Lstat(name string) (fs.FileInfo, error) {
	if m.hit(name) {
		switch m.kind {
		case "missing":
			return nil, fs.ErrNotExist
		case "unreadable":
			return nil, fs.ErrPermission
		case "present":
			return fakeInfo{name, 0}, nil
		}
	}
	return m.FS.Lstat(name)
}

func (m mutFS) ReadRegular(name string, limit int64) ([]byte, error) {
	if m.hit(name) {
		switch m.kind {
		case "missing":
			return nil, fs.ErrNotExist
		case "unreadable":
			return nil, fs.ErrPermission
		case "too_large":
			return nil, ErrTooLarge
		case "garbage":
			return []byte("\x00\xffgarbage"), nil
		case "present":
			return []byte("x"), nil
		}
	}
	return m.FS.ReadRegular(name, limit)
}

// TestPropertyNeverSupported: for every supported fixture, each required
// probe's input replaced by a failing, unknown, missing, unreadable,
// over-limit or slow input never yields "supported" (review F7, AC02).
func TestPropertyNeverSupported(t *testing.T) {
	m := loadMatrix(t, func(d map[string]any) { d["deadlines_ms"] = map[string]any{"probe": 200, "run": 5000} })
	all := []string{"missing", "unreadable", "too_large", "garbage"}
	type target struct {
		probe string
		paths []string
		kinds []string
	}
	targets := []target{
		{"os_release", []string{"usr/lib/os-release"}, all},
		// etc/os-release is a relative link here; a missing link legitimately falls back to usr/lib (os-release(5)).
		{"os_release", []string{"etc/os-release"}, []string{"unreadable"}},
		{"arch", []string{"proc/sys/kernel/arch"}, all},
		{"cpu_virt", []string{"proc/cpuinfo"}, all},
		{"kernel_floor", []string{"proc/sys/kernel/osrelease"}, all},
		{"cgroup_v2", []string{"proc/self/mountinfo"}, all},
		{"cgroup_v2", []string{"sys/fs/cgroup/cgroup.controllers"}, []string{"missing", "unreadable", "too_large"}},
		{"systemd", []string{"run/systemd/system"}, []string{"missing", "unreadable"}},
		{"lsm", []string{"sys/module/apparmor/parameters/enabled", "sys/kernel/security/lsm"}, all},
		{"containment", []string{"proc/1/environ", "proc/1/cgroup"}, []string{"missing", "unreadable", "too_large"}},
		{"containment", []string{"proc/self/uid_map"}, all},
		{"containment", []string{".dockerenv", "run/.containerenv", "run/systemd/container"}, []string{"present", "unreadable"}},
	}
	for _, name := range supportedFixtures {
		base := openFixture(t, name)
		for _, tg := range targets {
			for _, path := range tg.paths {
				for _, kind := range tg.kinds {
					rep := Check(mutFS{base, path, kind}, m)
					if rep.Verdict == Supported {
						t.Errorf("%s: %s %s=%s still supported", name, tg.probe, path, kind)
					}
				}
			}
		}
		// nftables: both load sources must be lost (either alone still proves it), and no module list exists.
		for _, kind := range []string{"missing", "unreadable"} {
			f := mutFS{mutFS{base, "sys/module/nf_tables", kind}, "proc/modules", kind}
			if name == "nftables-builtin" {
				f = mutFS{f, "lib/modules", kind}
			}
			if rep := Check(f, m); rep.Verdict == Supported {
				t.Errorf("%s: nftables %s still supported", name, kind)
			}
		}
		// slow: each required probe past its deadline.
		for _, id := range RequiredProbes {
			rep := CheckWith(base, m, Options{Hook: func(p string) {
				if p == id {
					time.Sleep(400 * time.Millisecond)
				}
			}})
			if rep.Verdict == Supported || probe(rep, id).Reason != "TIMEOUT" {
				t.Errorf("%s: slow %s -> %s / %s", name, id, rep.Verdict, probe(rep, id).Reason)
			}
		}
	}
}

func TestSpecialFilesAreNeverOpened(t *testing.T) {
	m := loadMatrix(t, nil)
	for _, kind := range []string{"fifo", "socket"} {
		t.Run(kind, func(t *testing.T) {
			dir := copyRoot(t, "debian-13")
			p := filepath.Join(dir, "proc", "cpuinfo")
			if err := os.Remove(p); err != nil {
				t.Fatal(err)
			}
			if kind == "fifo" {
				if err := syscall.Mkfifo(p, 0o644); err != nil {
					t.Fatal(err)
				}
			} else {
				fd, err := syscall.Socket(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
				if err != nil {
					t.Fatal(err)
				}
				defer func() { _ = syscall.Close(fd) }()
				if err := syscall.Bind(fd, &syscall.SockaddrUnix{Name: p}); err != nil {
					t.Skipf("cannot bind unix socket here: %v", err)
				}
			}
			start := time.Now()
			rep := checkDir(t, dir, m)
			if time.Since(start) > 5*time.Second {
				t.Fatal("special file made the checker hang")
			}
			if rep.Verdict == Supported || probe(rep, "cpu_virt").Reason != "NOT_REGULAR_FILE" {
				t.Fatalf("%s: %s %+v", kind, rep.Verdict, probe(rep, "cpu_virt"))
			}
		})
	}
	// A character device is rejected by type before any open.
	f, closeFn, err := OpenRoot("/")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = closeFn() }()
	if _, err := f.ReadRegular("dev/null", 10); !errors.Is(err, ErrNotRegular) {
		t.Fatalf("dev/null: %v", err)
	}
}

// recFS records every ReadRegular call.
type recFS struct {
	FS
	reads *[]string
}

func (r recFS) ReadRegular(name string, limit int64) ([]byte, error) {
	*r.reads = append(*r.reads, name)
	return r.FS.ReadRegular(name, limit)
}

func TestDevKVMIsNeverOpened(t *testing.T) {
	var reads []string
	Check(recFS{openFixture(t, "debian-13"), &reads}, loadMatrix(t, nil))
	for _, r := range reads {
		if strings.HasPrefix(r, "dev/") {
			t.Fatalf("opened %s", r)
		}
	}
}

func TestUnreadableAndOversizedInputs(t *testing.T) {
	m := loadMatrix(t, nil)
	dir := copyRoot(t, "debian-13")
	if err := os.Chmod(filepath.Join(dir, "proc", "1", "environ"), 0); err != nil {
		t.Fatal(err)
	}
	rep := checkDir(t, dir, m)
	if rep.Verdict != UnknownV || probe(rep, "containment").Reason != "CONTAINMENT_UNDETERMINED" {
		t.Fatalf("unreadable environ: %s %+v", rep.Verdict, probe(rep, "containment"))
	}
	dir = copyRoot(t, "debian-13")
	big := bytes.Repeat([]byte("flags\t\t: vmx\n"), 400000) // > 4 MiB cap
	if err := os.WriteFile(filepath.Join(dir, "proc", "cpuinfo"), big, 0o644); err != nil {
		t.Fatal(err)
	}
	rep = checkDir(t, dir, m)
	if rep.Verdict == Supported || probe(rep, "cpu_virt").Reason != "INPUT_TOO_LARGE" {
		t.Fatalf("oversized cpuinfo: %s %+v", rep.Verdict, probe(rep, "cpu_virt"))
	}
}

func TestMatrixContract(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(fixtures, "support-matrix.json"))
	if err != nil {
		t.Fatal(err)
	}
	mutations := map[string]func(map[string]any){
		"planned marked supported": func(d map[string]any) {
			d["entries"] = append(d["entries"].([]any), map[string]any{"id": "rocky", "version_id": "9", "arch": "x86_64", "status": "supported", "required_lsm": "apparmor", "support_ends": "2030-01-01"})
		},
		"unknown probe": func(d map[string]any) {
			d["probes"].(map[string]any)["magic"] = map[string]any{"sources": []any{"x"}, "rule": "y"}
		},
		"required probe missing":  func(d map[string]any) { d["required_probes"] = []any{"os_release"} },
		"bad floor":               func(d map[string]any) { d["kernel_floor"] = "six" },
		"duplicate entry":         func(d map[string]any) { d["entries"] = append(d["entries"].([]any), d["entries"].([]any)[0]) },
		"selinux on supported":    func(d map[string]any) { d["entries"].([]any)[0].(map[string]any)["required_lsm"] = "selinux" },
		"unknown field":           func(d map[string]any) { d["hosted"] = true },
		"probe deadline over run": func(d map[string]any) { d["deadlines_ms"] = map[string]any{"probe": 9000, "run": 100} },
		"huge read limit":         func(d map[string]any) { d["read_limits"].(map[string]any)["default"] = 1 << 40 },
		"schema 2":                func(d map[string]any) { d["schema"] = 2 },
	}
	// Widening mutations (implementation review M1): rejected by content pins even without the digest pin.
	widen := map[string]func(map[string]any){
		"rocky planned replaced by supported": func(d map[string]any) {
			var es []any
			for _, e := range d["entries"].([]any) {
				if e.(map[string]any)["id"] != "rocky" {
					es = append(es, e)
				}
			}
			d["entries"] = append(es, map[string]any{"id": "rocky", "version_id": "9.4", "arch": "x86_64", "status": "supported", "required_lsm": "apparmor", "support_ends": "2032-01-01"})
		},
		"kernel floor lowered": func(d map[string]any) { d["kernel_floor"] = "0.0" },
		"derivative added": func(d map[string]any) {
			d["entries"] = append(d["entries"].([]any), map[string]any{"id": "pop", "version_id": "24.04", "arch": "x86_64", "status": "supported", "required_lsm": "apparmor", "support_ends": nil})
		},
		"planned dropped":   func(d map[string]any) { d["entries"] = d["entries"].([]any)[:3] },
		"supported dropped": func(d map[string]any) { d["entries"] = d["entries"].([]any)[1:] },
		"null support_ends": func(d map[string]any) { d["entries"].([]any)[0].(map[string]any)["support_ends"] = nil },
		"arm64 entry":       func(d map[string]any) { d["entries"].([]any)[0].(map[string]any)["arch"] = "aarch64" },
	}
	for name, mutate := range mutations {
		widen[name] = mutate
	}
	for name, mutate := range widen {
		var doc map[string]any
		_ = json.Unmarshal(raw, &doc)
		mutate(doc)
		data, _ := json.Marshal(doc)
		if _, err := LoadMatrix(data); !errors.Is(err, ErrMatrix) {
			t.Errorf("%s: accepted by LoadMatrix (%v)", name, err)
		}
		if _, err := decodeMatrix(data, false); !errors.Is(err, ErrMatrix) {
			t.Errorf("%s: accepted by content pins (%v)", name, err)
		}
	}
	// Case-variant and Unicode-folded keys (Go JSON matches case-insensitively).
	for _, variant := range [][2]string{{`"status"`, `"STATUS"`}, {`"kernel_floor"`, "\"\u212aernel_floor\""}} {
		data := []byte(strings.Replace(string(raw), variant[0], variant[1], 1))
		if _, err := decodeMatrix(data, false); !errors.Is(err, ErrMatrix) {
			t.Errorf("key variant %s accepted", variant[1])
		}
	}
	// The pinned matrix itself, re-serialised (same content, different bytes), fails the digest pin.
	var doc map[string]any
	_ = json.Unmarshal(raw, &doc)
	data, _ := json.Marshal(doc)
	if _, err := LoadMatrix(data); !errors.Is(err, ErrMatrix) {
		t.Error("digest pin not enforced")
	}
	if _, err := LoadMatrix(raw); err != nil {
		t.Fatalf("pinned matrix rejected: %v", err)
	}
	if _, err := LoadMatrix(append(raw, []byte("{}")...)); !errors.Is(err, ErrMatrix) {
		t.Error("trailing data accepted")
	}
}

// TestNoProcessOrNetworkPackages enforces "no processes, no network" on the
// library and CLI (import allowlist; gosec runs in make check).
func TestNoProcessOrNetworkPackages(t *testing.T) {
	out, err := exec.Command("go", "list", "-deps", "-f", "{{.ImportPath}}", ".", "../../cmd/capability-check").Output()
	if err != nil {
		t.Fatalf("go list failed: %v", err) // never skip a security check (review N5)
	}
	forbidden := regexp.MustCompile(`^(os/exec|net|net/.*|plugin|os/signal|syscall/js|crypto/tls)$`)
	for _, pkg := range strings.Fields(string(out)) {
		if forbidden.MatchString(pkg) {
			t.Errorf("forbidden dependency %s", pkg)
		}
	}
}

func TestRemediationsNeverWeakenControls(t *testing.T) {
	bad := regexp.MustCompile(`(?i)disabl|permissive|complain|setenforce|aa-teardown|apparmor=0|selinux=0|enforcing=0|remove .*profile`)
	for reason, text := range Remediations {
		if bad.MatchString(text) {
			t.Errorf("%s: %q", reason, text)
		}
	}
}

func TestReportFieldsAreAllowlisted(t *testing.T) {
	m := loadMatrix(t, nil)
	entries, err := os.ReadDir(filepath.Join(fixtures, "roots"))
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		out := Check(openFixture(t, e.Name()), m).JSON()
		for _, marker := range []string{"fixture-secret-hostname", "fixture-machine-id-not-real", "BOOT_IMAGE", "Dell"} {
			if bytes.Contains(out, []byte(marker)) {
				t.Errorf("%s: report leaks %q", e.Name(), marker)
			}
		}
		var top map[string]any
		_ = json.Unmarshal(out, &top)
		keys := map[string]bool{}
		for k := range top {
			keys[k] = true
		}
		for _, k := range []string{"schema", "checker_version", "matrix_sha256", "qualification", "meaning", "distribution", "verdict", "reasons", "probes"} {
			delete(keys, k)
		}
		if len(keys) != 0 {
			t.Errorf("%s: unexpected report keys %v", e.Name(), keys)
		}
	}
}

func TestRunDeadline(t *testing.T) {
	m := loadMatrix(t, func(d map[string]any) { d["deadlines_ms"] = map[string]any{"probe": 100, "run": 300} })
	start := time.Now()
	rep := CheckWith(openFixture(t, "debian-13"), m, Options{Hook: func(string) { time.Sleep(time.Second) }})
	if el := time.Since(start); el > 2*time.Second {
		t.Fatalf("run took %v", el)
	}
	if rep.Verdict != UnknownV {
		t.Fatalf("verdict %s", rep.Verdict)
	}
}

func TestParseOSRelease(t *testing.T) {
	good := map[string]map[string]string{
		"ID=debian\nVERSION_ID=\"13\"\n":     {"ID": "debian", "VERSION_ID": "13"},
		"# c\n\nNAME='Ubuntu'\nID=ubuntu\n":  {"NAME": "Ubuntu", "ID": "ubuntu"},
		"PRETTY_NAME=\"A \\\"q\\\" \\$x\"\n": {"PRETTY_NAME": "A \"q\" $x"},
	}
	for in, want := range good {
		got, err := parseOSRelease([]byte(in))
		if err != nil || len(got) != len(want) {
			t.Fatalf("%q: %v %v", in, got, err)
		}
		for k, v := range want {
			if got[k] != v {
				t.Fatalf("%q: %s=%q", in, k, got[k])
			}
		}
	}
	for _, bad := range []string{"ID=a\nID=b\n", "ID=\"x\n", "ID=a b\n", "lower=x\n", "ID=\"a\\n\"\n", "ID='a'b'\n", "ID=\x00\n",
		"ID=\xff\n", "X=" + strings.Repeat("a", 5000) + "\n", "ID=\"$(id)\"\n", "noequals\n", "X=a\u0085b\nID=debian\n", "\ufeffID=debian\n"} {
		if _, err := parseOSRelease([]byte(bad)); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}

func TestHardeningFromReview(t *testing.T) {
	m := loadMatrix(t, nil)
	// N2: ".." after a symlinked parent is refused (kernel vs lexical resolution).
	dir := copyRoot(t, "debian-13")
	if err := os.MkdirAll(filepath.Join(dir, "sub", "etc"), 0o755); err != nil {
		t.Fatal(err)
	}
	_ = os.Remove(filepath.Join(dir, "etc", "os-release"))
	if err := os.Rename(filepath.Join(dir, "etc"), filepath.Join(dir, "sub", "etcold")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("sub/etc", filepath.Join(dir, "etc")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../usr/lib/os-release", filepath.Join(dir, "sub", "etc", "os-release")); err != nil {
		t.Fatal(err)
	}
	if p := probe(checkDir(t, dir, m), "os_release"); p.Reason != "PATH_ESCAPE" {
		t.Errorf("N2: %+v", p)
	}
	// N4: a dangling marker symlink is a marker.
	dir = copyRoot(t, "debian-13")
	if err := os.Symlink("nowhere", filepath.Join(dir, ".dockerenv")); err != nil {
		t.Fatal(err)
	}
	if rep := checkDir(t, dir, m); rep.Verdict != UnknownV || rep.Reasons[0] != "CONTAINERIZED" {
		t.Errorf("N4 dangling marker: %s %v", rep.Verdict, rep.Reasons)
	}
	// N4: DMI vendor matching is case-insensitive and covers Red Hat / Bochs.
	for _, vendor := range []string{"Red Hat\n", "BOCHS\n", "qemu\n"} {
		dir = copyRoot(t, "debian-13")
		if err := os.WriteFile(filepath.Join(dir, "sys", "class", "dmi", "id", "sys_vendor"), []byte(vendor), 0o644); err != nil {
			t.Fatal(err)
		}
		if rep := checkDir(t, dir, m); rep.Verdict != Unsupported {
			t.Errorf("N4 vendor %q: %s", vendor, rep.Verdict)
		}
	}
	// N6: loose kernel strings are unknown.
	for _, rel := range []string{"6.8\x00garbage", "06.08", "6.8 x", "6", "v6.8"} {
		dir = copyRoot(t, "debian-13")
		if err := os.WriteFile(filepath.Join(dir, "proc", "sys", "kernel", "osrelease"), []byte(rel), 0o644); err != nil {
			t.Fatal(err)
		}
		if p := probe(checkDir(t, dir, m), "kernel_floor"); p.Result != Unknown {
			t.Errorf("N6 kernel %q: %+v", rel, p)
		}
	}
	// N1: a file that vanishes after lstat is unknown (VANISHED), not absent.
	rep := Check(vanishFS{openFixture(t, "debian-13"), "sys/fs/cgroup/cgroup.controllers"}, m)
	if p := probe(rep, "cgroup_v2"); p.Result != Unknown || p.Reason != "VANISHED" || rep.Verdict != UnknownV {
		t.Errorf("N1: %s %+v", rep.Verdict, p)
	}
}

// vanishFS: lstat succeeds but the read finds the file gone.
type vanishFS struct {
	FS
	path string
}

func (v vanishFS) ReadRegular(name string, limit int64) ([]byte, error) {
	if name == v.path {
		return nil, ErrVanished
	}
	return v.FS.ReadRegular(name, limit)
}

func TestSymlinkResolution(t *testing.T) {
	m := loadMatrix(t, nil)
	for name, reason := range map[string]string{"symlink-escape": "PATH_ESCAPE", "symlink-absolute": "PATH_ESCAPE", "symlink-loop": "PATH_LOOP"} {
		if p := probe(Check(openFixture(t, name), m), "os_release"); p.Result != Unknown || p.Reason != reason {
			t.Errorf("%s: %+v", name, p)
		}
	}
	// The supported fixtures resolve a relative in-root etc/os-release link.
	if p := probe(Check(openFixture(t, "debian-13"), m), "os_release"); p.Result != Pass {
		t.Fatalf("relative link: %+v", p)
	}
}
