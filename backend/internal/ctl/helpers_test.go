package ctl

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeRunner records every command and answers from a table (longest-prefix match on "name arg arg").
type fakeRunner struct {
	mu    sync.Mutex
	calls []string
	reply map[string]string
	fail  map[string]bool
	// failN makes the first N matching commands fail (a transient or version-specific failure).
	failN map[string]int
	hook  func(cmd string)
	// stdins are the standard-input texts passed through RunStdin, in order.
	stdins []string
}

func (f *fakeRunner) Run(_ context.Context, name string, args ...string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	cmd := strings.TrimSpace(name + " " + strings.Join(args, " "))
	f.calls = append(f.calls, cmd)
	if f.hook != nil {
		f.hook(cmd)
	}
	for k, n := range f.failN {
		if n > 0 && strings.HasPrefix(cmd, k) {
			f.failN[k] = n - 1
			return "failed: " + cmd, os.ErrInvalid
		}
	}
	best := ""
	for k := range f.fail {
		if strings.HasPrefix(cmd, k) && len(k) > len(best) {
			best = k
		}
	}
	if best != "" {
		return "failed: " + cmd, os.ErrInvalid
	}
	best = ""
	for k := range f.reply {
		if strings.HasPrefix(cmd, k) && len(k) > len(best) {
			best = k
		}
	}
	if best != "" {
		return f.reply[best], nil
	}
	if strings.HasPrefix(cmd, "systemctl is-active") {
		return "active\n", nil
	}
	if strings.HasPrefix(cmd, "systemctl is-enabled") {
		return "enabled\n", nil
	}
	return "", nil
}

func (f *fakeRunner) called(prefix string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, c := range f.calls {
		if strings.HasPrefix(c, prefix) {
			n++
		}
	}
	return n
}

type fakeInfo struct {
	name string
	mode fs.FileMode
}

func (i fakeInfo) Name() string      { return i.name }
func (fakeInfo) Size() int64         { return 0 }
func (i fakeInfo) Mode() fs.FileMode { return i.mode }
func (fakeInfo) ModTime() time.Time  { return time.Time{} }
func (i fakeInfo) IsDir() bool       { return i.mode.IsDir() }
func (fakeInfo) Sys() any            { return nil }

// testHost is a temporary root that looks like a supported Ubuntu host; each field can be broken by a test.
type testHost struct {
	t       *testing.T
	root    string
	run     *fakeRunner
	devices map[string]fs.FileMode // absolute path -> faked mode (devices and sockets cannot be created in a temp dir)
	paths   map[string]string      // LookPath
	free    uint64
	dialErr error
	now     time.Time
	env     *Env
}

func newHost(t *testing.T) *testHost {
	t.Helper()
	root := t.TempDir()
	h := &testHost{t: t, root: root, run: &fakeRunner{reply: map[string]string{}, fail: map[string]bool{}, failN: map[string]int{}}, free: 500 << 30, now: time.Date(2026, 10, 12, 9, 0, 0, 0, time.UTC),
		devices: map[string]fs.FileMode{}, paths: map[string]string{"qemu-system-x86_64": "/usr/bin/qemu-system-x86_64", "libvirtd": "/usr/sbin/libvirtd", "virsh": "/usr/bin/virsh"}}
	h.write("/etc/os-release", "ID=ubuntu\nVERSION_ID=\"24.04\"\nPRETTY_NAME=\"Ubuntu 24.04.3 LTS\"\n")
	h.write("/proc/cpuinfo", "processor\t: 0\nflags\t\t: fpu vme vmx sse\n")
	h.write("/proc/modules", "kvm_intel 1 0 - Live 0x0\nkvm 2 1 kvm_intel, Live 0x0\n")
	h.write("/sys/module/apparmor/parameters/enabled", "Y\n")
	if err := os.MkdirAll(filepath.Join(root, "run/systemd/system"), 0o755); err != nil {
		t.Fatal(err)
	}
	h.devices["/dev/kvm"] = fs.ModeDevice | fs.ModeCharDevice | 0o666
	h.devices["/run/libvirt/libvirt-sock"] = fs.ModeSocket | 0o660
	h.devices["/run/libvirt/libvirt-sock-ro"] = fs.ModeSocket | 0o666
	h.run.reply["virsh -r -c qemu:///system net-info"] = "Name: default\nActive: yes\n"
	h.run.reply["virsh -r -c qemu:///system pool-info"] = "Name: svavyom\nActive: yes\n"
	uids := map[string][2]int{"svavyom-api": {987, 987}, "svavyom-ro": {986, 986}, "svavyom-mut": {985, 985}, "svavyom-con": {984, 984}}
	h.env = &Env{Root: root, Run: h.run, Now: func() time.Time { return h.now }, Sleep: func(_ context.Context, d time.Duration) error { h.now = h.now.Add(d); return nil }, Euid: func() int { return 0 }, Chown: func(string, int, int) error { return nil },
		Lstat: func(p string) (fs.FileInfo, error) {
			if m, ok := h.devices[strings.TrimPrefix(p, root)]; ok {
				return fakeInfo{name: filepath.Base(p), mode: m}, nil
			}
			return os.Lstat(p)
		},
		ReadFile: os.ReadFile, Statfs: func(string) (uint64, error) { return h.free, nil },
		LookPath: func(n string) (string, error) {
			if p, ok := h.paths[n]; ok {
				return p, nil
			}
			return "", os.ErrNotExist
		},
		Dial: func(string) error { return h.dialErr },
		Getpw: func(n string) (int, int, error) {
			if v, ok := uids[n]; ok {
				return v[0], v[1], nil
			}
			return 0, 0, os.ErrNotExist
		},
		Getgr: func(n string) (int, error) {
			if n == "libvirt" {
				return 113, nil
			}
			return 0, os.ErrNotExist
		}}
	return h
}

func (h *testHost) write(p, body string) string {
	h.t.Helper()
	full := filepath.Join(h.root, strings.TrimPrefix(p, "/"))
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		h.t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(body), 0o644); err != nil {
		h.t.Fatal(err)
	}
	return full
}

func (h *testHost) read(p string) (string, bool) {
	b, err := os.ReadFile(filepath.Join(h.root, strings.TrimPrefix(p, "/")))
	return string(b), err == nil
}

func (h *testHost) exists(p string) bool {
	_, err := os.Lstat(filepath.Join(h.root, strings.TrimPrefix(p, "/")))
	return err == nil
}

func find(r Report, id string) Finding {
	for _, f := range r.Findings {
		if f.ID == id {
			return f
		}
	}
	return Finding{ID: "(missing) " + id}
}

// makeArtifact builds a release artifact directory with a manifest. mut may change files before the manifest is computed.
func makeArtifact(t *testing.T, version string, schema map[string]int, mut func(files map[string][]byte)) string {
	t.Helper()
	dir := t.TempDir()
	files := map[string][]byte{}
	for _, b := range Binaries {
		files["bin/"+b] = []byte("#!/bin/sh\n# " + b + " " + version + "\n")
	}
	files["web/index.html"] = []byte("<html>" + version + "</html>")
	files["web/assets/app.js"] = []byte("console.log('" + version + "')")
	for _, u := range Units {
		files["packages/ubuntu/systemd/"+u+".in"] = []byte("[Service]\nUser=@SVAVYOM_API_UID@\nGroup=@SVAVYOM_API_GID@\n" + unitExec(u))
	}
	files["packages/ubuntu/sysusers.d/svavyom.conf"] = []byte("u svavyom-api - \"Svavyom API\" /var/lib/svavyom/api /usr/sbin/nologin\n")
	files["packages/ubuntu/tmpfiles.d/svavyom.conf"] = []byte("d /etc/svavyom 0755 root root -\n")
	files["packages/ubuntu/etc/provision.json.in"] = []byte(`{"catalog_dir":"/var/lib/svavyom/images","pool":"svavyom","network":"default","domain_type":"kvm","libvirt_uri":"qemu:///system","state_dir":"/var/lib/svavyom/state",` +
		`"trust":{"deploy_uid":0,"runtime_identities":[{"name":"api","uid":@SVAVYOM_API_UID@,"gids":[@SVAVYOM_API_GID@]},{"name":"agent","uid":@SVAVYOM_RO_UID@,"gids":[@SVAVYOM_RO_GID@]},` +
		`{"name":"mutation","uid":@SVAVYOM_MUT_UID@,"gids":[@SVAVYOM_MUT_GID@,@LIBVIRT_GID@]},{"name":"console","uid":@SVAVYOM_CON_UID@,"gids":[@SVAVYOM_CON_GID@,@LIBVIRT_GID@]}]}}` + "\n")
	files["packages/ubuntu/libvirt/pool-svavyom.xml"] = []byte("<pool type='dir'><name>svavyom</name><target><path>/var/lib/svavyom/pool</path></target></pool>\n")
	files["docs/INSTALL.md"] = []byte("install " + version + "\n")
	if mut != nil {
		mut(files)
	}
	var m Manifest
	m.Schema, m.Product, m.Version, m.Classification, m.BuiltFrom, m.SchemaVersions = 1, "svavyom", version, "Development Preview / Pre-Alpha", "test", schema
	var names []string
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		p := filepath.Join(dir, filepath.FromSlash(n))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, files[n], 0o644); err != nil {
			t.Fatal(err)
		}
		s := sha256.Sum256(files[n])
		aud := "public"
		if strings.HasPrefix(n, "packages/") && false {
			aud = "private"
		}
		m.Files = append(m.Files, ArtifactFile{Path: n, SHA256: hex.EncodeToString(s[:]), Size: int64(len(files[n])), Mode: 0o644, Audience: aud})
	}
	b, _ := json.MarshalIndent(m, "", "  ")
	if err := os.WriteFile(filepath.Join(dir, ManifestName), b, 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

func unitExec(u string) string {
	if u == "svavyom-api.service" {
		return "ExecStart=/usr/libexec/svavyom/api serve \\\n    --db /var/lib/svavyom/api/svavyom.db \\\n    --listen 0.0.0.0:8443 \\\n    --tls-cert /etc/svavyom/tls/cert.pem --tls-key /etc/svavyom/tls/key.pem \\\n    --static-dir /usr/share/svavyom/web\n"
	}
	return "ExecStart=/usr/libexec/svavyom/" + strings.TrimSuffix(strings.TrimPrefix(u, "svavyom-"), ".service") + "\n"
}

// RunStdin records the standard input and then answers like Run.
func (f *fakeRunner) RunStdin(ctx context.Context, stdin, name string, args ...string) (string, error) {
	f.mu.Lock()
	f.stdins = append(f.stdins, stdin)
	f.mu.Unlock()
	return f.Run(ctx, name, args...)
}
