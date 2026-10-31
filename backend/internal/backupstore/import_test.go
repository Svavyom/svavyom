package backupstore

import (
	"errors"
	"io"
	"os"
	"strings"
	"testing"
)

// fetchFrom reads the three files of backup id from the store src, the way an off-host target serves them.
func fetchFrom(src *Store, id string) func(name string, w io.Writer) error {
	return func(name string, w io.Writer) error {
		f, err := os.Open(src.path(id, name))
		if err != nil {
			return err
		}
		defer f.Close()
		_, err = io.Copy(w, f)
		return err
	}
}

func rootSize(t *testing.T, s *Store, id string) int64 {
	t.Helper()
	fi, err := os.Stat(s.path(id, RootFile))
	if err != nil {
		t.Fatal(err)
	}
	return fi.Size()
}

func listedIDs(t *testing.T, s *Store) map[string]bool {
	t.Helper()
	l, err := s.List()
	if err != nil {
		t.Fatal(err)
	}
	m := map[string]bool{}
	for _, b := range l {
		m[b.Manifest.BackupID] = b.Valid
	}
	return m
}

// An off-host stream past the declared size aborts at the bound, leaves nothing in the store, and returns a typed failure (M0-E01-S09). The root-file cap used to be
// 64 TiB, whatever the target had reported.
func TestImportStopsAtTheDeclaredSize(t *testing.T) {
	src, dst := newStore(t), newStore(t)
	write(t, src, id1, strings.Repeat("x", 1<<20))
	need := rootSize(t, src, id1)
	var accepted int64
	err := dst.ImportFrom(id1, need, func(name string, w io.Writer) error {
		if name != RootFile {
			return fetchFrom(src, id1)(name, w)
		}
		chunk := make([]byte, 64<<10)
		for { // a hostile target keeps streaming
			n, werr := w.Write(chunk)
			accepted += int64(n)
			if werr != nil {
				return werr
			}
			if accepted > need+(64<<20) {
				t.Fatalf("the import accepted %d bytes for a root copy declared as %d", accepted, need)
			}
		}
	})
	if err == nil {
		t.Fatal("an import that streamed past the declared size succeeded")
	}
	if accepted > need+importSlackBytes {
		t.Fatalf("accepted %d bytes, the bound is %d", accepted, need+importSlackBytes)
	}
	if ids := listedIDs(t, dst); len(ids) != 0 {
		t.Fatalf("a refused import left a backup: %v", ids)
	}
	ents, _ := os.ReadDir(dst.dir)
	if len(ents) != 0 {
		t.Fatalf("a refused import left %d entries in the store", len(ents))
	}
}

// A backup is not listed, as valid or at all, until its hash has been verified: during the import the store lists nothing of it, a root copy that does not match its
// manifest is refused without ever having been visible, and a good import appears whole and valid (M0-E01-S09).
func TestImportIsNotListedUntilVerified(t *testing.T) {
	src, dst := newStore(t), newStore(t)
	write(t, src, id1, strings.Repeat("y", 300<<10))
	need := rootSize(t, src, id1)
	seen := func(when string) {
		t.Helper()
		if ids := listedIDs(t, dst); len(ids) != 0 {
			t.Fatalf("%s: a backup that is still being imported is listed: %v", when, ids)
		}
	}

	// a root copy with the right size and a wrong hash: refused, never listed
	err := dst.ImportFrom(id1, need, func(name string, w io.Writer) error {
		seen("before " + name)
		if name == RootFile {
			_, err := w.Write([]byte(strings.Repeat("z", int(need)))) // same size, other content
			seen("after the root copy was written")
			return err
		}
		return fetchFrom(src, id1)(name, w)
	})
	if !errors.Is(err, ErrCorrupt) {
		t.Fatalf("a root copy that does not match its manifest: %v, want ErrCorrupt", err)
	}
	seen("after the refused import")
	if ents, _ := os.ReadDir(dst.dir); len(ents) != 0 {
		t.Fatalf("a refused import left %d entries", len(ents))
	}

	// the good import: nothing is listed until it is whole, then it is listed and valid
	err = dst.ImportFrom(id1, need, func(name string, w io.Writer) error {
		seen("before " + name)
		return fetchFrom(src, id1)(name, w)
	})
	if err != nil {
		t.Fatal(err)
	}
	if ids := listedIDs(t, dst); !ids[id1] {
		t.Fatalf("a verified import is not listed as valid: %v", ids)
	}
	if _, err := dst.Verify(id1); err != nil {
		t.Fatal(err)
	}
}
