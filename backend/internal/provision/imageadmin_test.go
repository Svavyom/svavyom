package provision

import (
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// overlayBytes is a minimal qcow2 v3 header with a backing file, like the overlays libvirt creates.
func overlayBytes(backing string) []byte {
	h := make([]byte, qcow2HeaderBytes+len(backing))
	copy(h, []byte{'Q', 'F', 'I', 0xfb})
	binary.BigEndian.PutUint32(h[4:], 3)
	binary.BigEndian.PutUint64(h[8:], qcow2HeaderBytes)
	binary.BigEndian.PutUint32(h[16:], uint32(len(backing)))
	binary.BigEndian.PutUint32(h[20:], 16)
	binary.BigEndian.PutUint64(h[24:], 1<<30)
	copy(h[qcow2HeaderBytes:], backing)
	return h
}

type removeRig struct {
	dir, pool string
	im        Image
}

func newRemoveRig(t *testing.T, state string) *removeRig {
	t.Helper()
	dir := catalogDir(t)
	im, err := Register(DevPolicy(), dir, reg(source(t, "d.qcow2", qcow2Bytes("payload"))))
	if err != nil {
		t.Fatal(err)
	}
	if state == StateQualified {
		im, err = SetState(DevPolicy(), dir, im.ID, state, "qr-20261011-aaaaaa")
	} else {
		im, err = SetState(DevPolicy(), dir, im.ID, state, "")
	}
	if err != nil {
		t.Fatal(err)
	}
	pool := filepath.Join(t.TempDir(), "pool")
	if err := os.Mkdir(pool, 0o750); err != nil {
		t.Fatal(err)
	}
	real, _ := filepath.EvalSymlinks(pool)
	return &removeRig{dir: dir, pool: real, im: im}
}

func (r *removeRig) remove(t *testing.T) error {
	t.Helper()
	_, err := RemoveImage(DevPolicy(), r.dir, r.im.ID, func(c *Catalog, im Image) ([]string, error) { return ImageReferences(c, im, r.pool, nil) },
		func() time.Time { return time.Date(2026, 10, 11, 9, 0, 0, 0, time.UTC) })
	return err
}

func TestRemoveImageNeedsADisabledImage(t *testing.T) {
	r := newRemoveRig(t, StateQualified)
	if err := r.remove(t); !errors.Is(err, ErrImageNotDisabled) {
		t.Fatalf("%v", err)
	}
	if _, err := os.Stat(storeFile(r.dir, r.im)); err != nil {
		t.Fatal("the file must still be there")
	}
}

func TestRemoveImageRefusesWhileAnOverlayUsesIt(t *testing.T) {
	r := newRemoveRig(t, StateDisabled)
	cat, _ := LoadCatalog(r.dir)
	p, _ := cat.Path(r.im)
	if err := os.WriteFile(filepath.Join(r.pool, "svavyom-x-root.qcow2"), overlayBytes(p), 0o600); err != nil {
		t.Fatal(err)
	}
	// an overlay of ANOTHER image and a non-qcow2 file do not count
	if err := os.WriteFile(filepath.Join(r.pool, "svavyom-y-root.qcow2"), overlayBytes("/elsewhere/other.qcow2"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(r.pool, "svavyom-z-seed.iso"), []byte("iso"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := r.remove(t); !errors.Is(err, ErrImageInUse) {
		t.Fatalf("%v", err)
	}
	if _, err := os.Stat(storeFile(r.dir, r.im)); err != nil {
		t.Fatal("a referenced image must keep its file")
	}
	if _, ok := mustCatalog(t, r.dir).Get(r.im.ID); !ok {
		t.Fatal("a referenced image must stay in the catalog")
	}
	// once the overlay is gone the removal goes through
	_ = os.Remove(filepath.Join(r.pool, "svavyom-x-root.qcow2"))
	if err := r.remove(t); err != nil {
		t.Fatal(err)
	}
}

func mustCatalog(t *testing.T, dir string) *Catalog {
	t.Helper()
	c, err := LoadCatalog(dir)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestRemoveImageRefusesWhatItCannotJudge(t *testing.T) {
	r := newRemoveRig(t, StateDisabled)
	// a symlink named like a volume is ambiguous
	if err := os.Symlink("/etc/passwd", filepath.Join(r.pool, "svavyom-link-root.qcow2")); err != nil {
		t.Fatal(err)
	}
	if err := r.remove(t); !errors.Is(err, ErrImageAmbiguous) {
		t.Fatalf("%v", err)
	}
	_ = os.Remove(filepath.Join(r.pool, "svavyom-link-root.qcow2"))
	// a pool directory that is itself reached through a symlink, or relative, is refused
	link := filepath.Join(t.TempDir(), "poollink")
	if err := os.Symlink(r.pool, link); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{link, "relative/pool", "/", r.pool + "/../" + filepath.Base(r.pool)} {
		cat := mustCatalog(t, r.dir)
		if _, err := ImageReferences(cat, r.im, bad, nil); !errors.Is(err, ErrImageAmbiguous) {
			t.Errorf("%q: %v", bad, err)
		}
	}
	// a store file that is not the regular file named for its digest is ambiguous too
	f := storeFile(r.dir, r.im)
	if err := os.Chmod(filepath.Dir(f), 0o750); err != nil {
		t.Fatal(err)
	}
	_ = os.Remove(f)
	if err := os.Symlink("/etc/passwd", f); err != nil {
		t.Fatal(err)
	}
	if err := r.remove(t); !errors.Is(err, ErrImageAmbiguous) {
		t.Fatalf("%v", err)
	}
	if _, err := os.Lstat("/etc/passwd"); err != nil {
		t.Fatal("never touch what a symlink points at")
	}
}

func TestRemoveImageDeletesOnlyThatFileAndRecordsIt(t *testing.T) {
	r := newRemoveRig(t, StateDisabled)
	other, err := Register(DevPolicy(), r.dir, RegisterRequest{ID: "other-1", DisplayName: "Other", Distribution: "Other", Version: "1", Source: source(t, "o.qcow2", qcow2Bytes("different")), LoginUser: "admin", MinDiskGiB: 3, CloudInit: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := r.remove(t); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(storeFile(r.dir, r.im)); !os.IsNotExist(err) {
		t.Fatalf("the image file must be gone: %v", err)
	}
	if _, err := os.Lstat(storeFile(r.dir, other)); err != nil {
		t.Fatal("another image must be untouched")
	}
	c := mustCatalog(t, r.dir)
	if _, ok := c.Get(r.im.ID); ok {
		t.Fatal("the catalog must no longer list the removed image")
	}
	if _, ok := c.Get(other.ID); !ok {
		t.Fatal("the other image must remain listed")
	}
	log, err := os.ReadFile(filepath.Join(r.dir, RemovalLog))
	if err != nil || !strings.Contains(string(log), `"id":"debian-13"`) || !strings.Contains(string(log), r.im.SHA256) || !strings.Contains(string(log), "2026-10-11T09:00:00Z") {
		t.Fatalf("%q %v", log, err)
	}
	if err := r.remove(t); !errors.Is(err, ErrImageNotFound) {
		t.Fatalf("a second removal: %v", err)
	}
}
