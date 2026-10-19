package hostinfo

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const fixtures = "../../../tests/fixtures/distribution/"

func root(t *testing.T, name, meminfo string) string {
	t.Helper()
	dst := filepath.Join(t.TempDir(), "root")
	if err := os.CopyFS(dst, os.DirFS(filepath.Join(fixtures, "roots", name))); err != nil {
		t.Fatal(err)
	}
	if meminfo != "" {
		if err := os.MkdirAll(filepath.Join(dst, "proc"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dst, "proc/meminfo"), []byte(meminfo), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dst
}

const mem = "MemTotal:       16384000 kB\nMemFree:         1000 kB\n"

func provider(t *testing.T, rootDir string) *Provider {
	t.Helper()
	p, err := New(Config{Root: rootDir, Name: "lab-host", AgentVersion: "1.2.3", CPUs: 8})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestEmbeddedMatrixIsTheFixtureCopy(t *testing.T) {
	want, err := os.ReadFile(fixtures + "support-matrix.json")
	if err != nil || !bytes.Equal(want, supportMatrix) {
		t.Fatalf("embedded matrix differs from the byte-identical fixture copy: %v", err)
	}
}

func TestSupportedHostReportsCapacityAndReadiness(t *testing.T) {
	info, err := provider(t, root(t, "debian-13", mem)).Host(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if info.ID != "local" || info.Name != "lab-host" || info.AgentVersion != "1.2.3" || info.CPUCount != 8 || info.MemoryMiB != 16000 {
		t.Fatalf("%+v", info)
	}
	if info.Verdict != "supported" || info.Hardware != Available || info.DistroID != "debian" || info.DistroVersion != "13" {
		t.Fatalf("%+v", info)
	}
	// Fixture roots hold no /dev/kvm and no dpkg status for libvirt: absent or unknown, never invented.
	if info.KVMDevice == Available || info.LibvirtPackages == Available {
		t.Fatalf("invented availability: %+v", info)
	}
}

func TestNoHardwareVirtualizationIsUnavailableWithRemediation(t *testing.T) {
	info, err := provider(t, root(t, "no-cpu-virt", mem)).Host(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if info.Verdict != "unsupported" || info.Hardware != Unavailable {
		t.Fatalf("%+v", info)
	}
	found := false
	for _, f := range info.Findings {
		if f.Code == "NO_HW_VIRT" && strings.Contains(f.Remediation, "VT-x") {
			found = true
		}
	}
	if !found {
		t.Fatalf("no NO_HW_VIRT finding: %+v", info.Findings)
	}
}

func TestContainerIsUnknownNeverSupported(t *testing.T) {
	info, err := provider(t, root(t, "docker-container", mem)).Host(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if info.Verdict != "unknown" || len(info.Findings) == 0 || info.Findings[0].Code != "CONTAINERIZED" {
		t.Fatalf("%+v", info)
	}
}

func TestUnreadableMemoryIsUnavailableNotZero(t *testing.T) {
	for _, bad := range []string{"", "MemTotal: lots kB\n", "MemTotal: 12 MB\n", "MemTotal: 0 kB\n", "Other: 5 kB\n"} {
		if _, err := provider(t, root(t, "debian-13", bad)).Host(context.Background()); err != ErrUnavailable {
			t.Errorf("%q: %v", bad, err)
		}
	}
}

func TestCachedWithinTTL(t *testing.T) {
	now := time.Unix(1000, 0)
	dir := root(t, "debian-13", mem)
	p, _ := New(Config{Root: dir, CPUs: 2, TTL: time.Minute, Clock: func() time.Time { return now }})
	a, _ := p.Host(context.Background())
	if err := os.WriteFile(filepath.Join(dir, "proc/meminfo"), []byte("MemTotal: 2048 kB\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	b, _ := p.Host(context.Background())
	if a.MemoryMiB != b.MemoryMiB {
		t.Fatal("not cached")
	}
	now = now.Add(2 * time.Minute)
	c, _ := p.Host(context.Background())
	if c.MemoryMiB != 2 {
		t.Fatalf("not refreshed: %d", c.MemoryMiB)
	}
}

func TestConfigValidation(t *testing.T) {
	for _, c := range []Config{{Name: "bad\nname"}, {Name: strings.Repeat("x", 64)}, {AgentVersion: "v 1;rm"}, {AgentVersion: strings.Repeat("1", 65)}} {
		if _, err := New(c); err == nil {
			t.Errorf("%+v accepted", c)
		}
	}
}

func TestInfoExposesOnlyApprovedFields(t *testing.T) {
	// A change to Info must be a deliberate, reviewed one (DR-015 D3 host information boundary).
	info, _ := provider(t, root(t, "debian-13", mem)).Host(context.Background())
	got := strings.Fields(fieldNames(info))
	want := "ID Name AgentVersion CPUCount MemoryMiB Verdict Hardware KVMDevice LibvirtPackages QEMUPackages DistroID DistroVersion Findings"
	if strings.Join(got, " ") != want {
		t.Fatalf("Info fields changed: %v", got)
	}
}
