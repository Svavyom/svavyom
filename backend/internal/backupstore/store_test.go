package backupstore

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func newStore(t *testing.T) *Store {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "backups")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	real, _ := filepath.EvalSymlinks(dir)
	s, err := Open(real)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func manifest() Manifest {
	return Manifest{CreatedAt: "2026-10-11T10:00:00Z", Tool: "svavyom test", VM: VM{Name: "web-1", UUID: "9a9a9a9a-2222-4333-8444-5555555555ab", Fingerprint: strings.Repeat("ab", 32),
		ImageID: "ubuntu-24.04", ImageSHA256: strings.Repeat("cd", 32), LoginUser: "ubuntu", VCPUs: 1, MemoryMiB: 1024, DiskGiB: 10, Network: "default"},
		Root: Root{VirtualSizeBytes: 10 << 30}}
}

func write(t *testing.T, s *Store, id, body string) Manifest {
	t.Helper()
	w, err := s.Begin(id, int64(len(body)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte(body)); err != nil {
		t.Fatal(err)
	}
	m, err := w.Commit(manifest())
	if err != nil {
		t.Fatal(err)
	}
	return m
}

const id1 = "bk-0123456789abcdef"

func TestWriteVerifyListDelete(t *testing.T) {
	s := newStore(t)
	m := write(t, s, id1, "overlay-bytes")
	if m.Root.Size != 13 || len(m.Root.SHA256) != 64 || m.Root.Format != "qcow2-overlay" {
		t.Fatalf("%+v", m.Root)
	}
	b, err := s.Verify(id1)
	if err != nil || b.Manifest.VM.Name != "web-1" {
		t.Fatalf("%v", err)
	}
	f, _ := b.OpenRoot()
	got := make([]byte, 64)
	n, _ := f.Read(got)
	_ = f.Close()
	if string(got[:n]) != "overlay-bytes" {
		t.Fatalf("%q", got[:n])
	}
	l, _ := s.List()
	if len(l) != 1 || !l[0].Valid || l[0].Manifest.BackupID != id1 || s.UsageBytes() != 13 {
		t.Fatalf("%+v %d", l, s.UsageBytes())
	}
	if err := s.Delete(id1); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Verify(id1); err != ErrNotFound {
		t.Fatalf("%v", err)
	}
	if err := s.Delete(id1); err != nil {
		t.Fatalf("deleting twice: %v", err)
	}
}

func TestAnIncompleteBackupIsNeverVisible(t *testing.T) {
	s := newStore(t)
	w, err := s.Begin(id1, 10)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = w.Write([]byte("half"))
	// crash here: nothing was committed
	if l, _ := s.List(); len(l) != 0 {
		t.Fatalf("a partial backup is listed: %+v", l)
	}
	if _, err := s.Verify(id1); err != ErrNotFound {
		t.Fatalf("a partial backup verifies: %v", err)
	}
	w.Abort()
	if ents, _ := os.ReadDir(s.Dir()); len(ents) != 0 {
		t.Fatalf("abort left %v", ents)
	}
	// a leftover partial of the same id is replaced by the next attempt
	w, _ = s.Begin(id1, 10)
	_, _ = w.Write([]byte("x"))
	w2, err := s.Begin(id1, 10)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = w2.Write([]byte("fresh"))
	if _, err := w2.Commit(manifest()); err != nil {
		t.Fatal(err)
	}
	if b, err := s.Verify(id1); err != nil || b.Manifest.Root.Size != 5 {
		t.Fatalf("%v", err)
	}
}

func TestCorruptionIsDetected(t *testing.T) {
	for name, damage := range map[string]func(dir string){
		"root byte flipped": func(d string) { flip(t, filepath.Join(d, RootFile), 3) },
		"root truncated":    func(d string) { _ = os.Truncate(filepath.Join(d, RootFile), 4) },
		"manifest edited":   func(d string) { flip(t, filepath.Join(d, ManifestFile), 40) },
		"checksum edited":   func(d string) { flip(t, filepath.Join(d, ChecksumFile), 2) },
		"extra file":        func(d string) { _ = os.WriteFile(filepath.Join(d, "extra"), []byte("x"), 0o600) },
		"manifest missing":  func(d string) { _ = os.Remove(filepath.Join(d, ManifestFile)) },
		"root is symlink": func(d string) {
			_ = os.Remove(filepath.Join(d, RootFile))
			_ = os.Symlink("/etc/hostname", filepath.Join(d, RootFile))
		},
	} {
		s := newStore(t)
		write(t, s, id1, "overlay-bytes")
		damage(filepath.Join(s.Dir(), id1))
		if _, err := s.Verify(id1); err != ErrCorrupt {
			t.Errorf("%s: %v", name, err)
		}
	}
	// a backup whose manifest names another id is refused
	s := newStore(t)
	write(t, s, id1, "x")
	if err := os.Rename(filepath.Join(s.Dir(), id1), filepath.Join(s.Dir(), "bk-ffffffffffffffff")); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Verify("bk-ffffffffffffffff"); err != ErrCorrupt {
		t.Errorf("renamed backup: %v", err)
	}
}

func flip(t *testing.T, path string, at int) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	b[at] ^= 0xff
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestDirectoryAndIDGrammar(t *testing.T) {
	base := t.TempDir()
	real, _ := filepath.EvalSymlinks(base)
	good := filepath.Join(real, "b")
	_ = os.Mkdir(good, 0o700)
	link := filepath.Join(real, "link")
	_ = os.Symlink(good, link)
	wide := filepath.Join(real, "wide")
	_ = os.Mkdir(wide, 0o700)
	_ = os.Chmod(wide, 0o755)
	file := filepath.Join(real, "file")
	_ = os.WriteFile(file, nil, 0o600)
	for name, d := range map[string]string{"relative": "backups", "traversal": good + "/../b", "symlink": link, "group readable": wide, "a file": file, "root": "/", "missing": real + "/nope",
		"odd chars": real + "/a b", "empty": ""} {
		if _, err := Open(d); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	if _, err := Open(good); err != nil {
		t.Fatal(err)
	}
	s := newStore(t)
	for _, bad := range []string{"", "bk-1", "../x", "bk-0123456789abcdeg", "bk-0123456789abcdef/../x", "BK-0123456789abcdef", ".partial-bk-0123456789abcdef"} {
		if _, err := s.Begin(bad, 1); err == nil {
			t.Errorf("Begin(%q)", bad)
		}
		if _, err := s.Verify(bad); err == nil {
			t.Errorf("Verify(%q)", bad)
		}
		if err := s.Delete(bad); err == nil {
			t.Errorf("Delete(%q)", bad)
		}
	}
}

func TestRefusesWithoutSpaceAndWithoutOverwriting(t *testing.T) {
	s := newStore(t)
	if _, err := s.Begin(id1, 1<<60); err != ErrSpace {
		t.Fatalf("%v", err)
	}
	write(t, s, id1, "x")
	if _, err := s.Begin(id1, 1); err != ErrExists {
		t.Fatalf("a finished backup must never be overwritten: %v", err)
	}
	if _, err := s.Begin(id1, -1); err == nil {
		t.Fatal("negative size")
	}
}

func TestManifestValidation(t *testing.T) {
	good := manifest()
	good.BackupID, good.Schema = id1, Schema
	good.Root = Root{File: RootFile, Size: 5, SHA256: strings.Repeat("a", 64), Format: "qcow2-overlay", VirtualSizeBytes: 10 << 30}
	if err := good.Validate(); err != nil {
		t.Fatal(err)
	}
	for name, mut := range map[string]func(*Manifest){
		"schema": func(m *Manifest) { m.Schema = 2 }, "id": func(m *Manifest) { m.BackupID = "x" }, "time": func(m *Manifest) { m.CreatedAt = "yesterday" },
		"name": func(m *Manifest) { m.VM.Name = "Web" }, "uuid": func(m *Manifest) { m.VM.UUID = "nope" }, "disk": func(m *Manifest) { m.VM.DiskGiB = 0 },
		"disk size mismatch": func(m *Manifest) { m.Root.VirtualSizeBytes = 11 << 30 }, "root file": func(m *Manifest) { m.Root.File = "../x" }, "format": func(m *Manifest) { m.Root.Format = "raw" },
		"digest": func(m *Manifest) { m.Root.SHA256 = "zz" }, "login user": func(m *Manifest) { m.VM.LoginUser = "ro ot" }, "fingerprint newline": func(m *Manifest) { m.VM.SSHFingerprint = "SHA256:x\ny" },
	} {
		m := good
		mut(&m)
		if m.Validate() == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestCleanPartialsAndBytes(t *testing.T) {
	s := newStore(t)
	w, _ := s.Begin(id1, 1)
	_, _ = w.Write(bytes.Repeat([]byte("a"), 10))
	if n := s.CleanPartials(time.Hour); n != 0 {
		t.Fatalf("a fresh partial must survive: %d", n)
	}
	_ = os.Chtimes(filepath.Join(s.Dir(), partialPref+id1), time.Now().Add(-2*time.Hour), time.Now().Add(-2*time.Hour))
	if n := s.CleanPartials(time.Hour); n != 1 {
		t.Fatalf("%d", n)
	}
	if free, err := s.FreeBytes(); err != nil || free <= 0 {
		t.Fatalf("%d %v", free, err)
	}
}
