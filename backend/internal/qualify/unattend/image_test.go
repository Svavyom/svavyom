package unattend

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf16"

	"github.com/diskfs/go-diskfs/backend/file"
	"github.com/diskfs/go-diskfs/filesystem/fat32"
)

const answer = `<?xml version="1.0" encoding="utf-8"?><unattend xmlns="urn:schemas-microsoft-com:unattend"></unattend>`

// Windows Setup finds the answer file only by its exact long name, so the image must hold real long-filename entries and the file must read back whole.
func TestTheImageHoldsTheAnswerFileUnderItsLongName(t *testing.T) {
	img, err := BuildImage([]byte(answer), "UNATTEND", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if len(img) != ImageSize {
		t.Fatalf("size %d", len(img))
	}
	// a FAT32 volume: boot sector signature, the FAT32 type string, the label
	if img[510] != 0x55 || img[511] != 0xAA || !bytes.Contains(img[:512], []byte("FAT32")) || !bytes.Contains(img[:512], []byte("UNATTEND")) {
		t.Fatalf("not a FAT32 boot sector: % x", img[:64])
	}
	// the long name is stored as UTF-16 long-filename entries (attribute 0x0F), not only as an 8.3 alias
	name := utf16.Encode([]rune(FileName))
	lfn := 0
	for off := 0; off+32 <= len(img) && off < 8<<20; off += 32 {
		if img[off+11] == 0x0F && img[off] != 0xE5 && img[off] != 0 {
			lfn++
		}
	}
	if lfn < (len(name)+12)/13 {
		t.Fatalf("expected at least %d long-filename entries, found %d", (len(name)+12)/13, lfn)
	}
	// read it back with the same library: the name and the content survive
	p := filepath.Join(t.TempDir(), "back.img")
	if err := os.WriteFile(p, img, 0o600); err != nil {
		t.Fatal(err)
	}
	be, err := file.OpenFromPath(p, true)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = be.Close() }()
	fs, err := fat32.Read(be, ImageSize, 0, 512)
	if err != nil {
		t.Fatal(err)
	}
	entries, err := fs.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	found := false
	for _, n := range names {
		found = found || n == FileName
	}
	if !found {
		t.Fatalf("the root has %v, not %s", names, FileName)
	}
	f, err := fs.OpenFile(FileName, os.O_RDONLY)
	if err != nil {
		t.Fatal(err)
	}
	var got bytes.Buffer
	if _, err := got.ReadFrom(f); err != nil || got.String() != answer {
		t.Fatalf("content: %q %v", got.String(), err)
	}
}

func TestBuildImageRefusesWhatIsNotAnAnswerFile(t *testing.T) {
	for name, c := range map[string]struct {
		answer []byte
		label  string
	}{
		"empty":       {nil, "UNATTEND"},
		"not xml":     {[]byte("echo hello"), "UNATTEND"},
		"too large":   {bytes.Repeat([]byte("a"), MaxAnswer+1), "UNATTEND"},
		"lower case":  {[]byte(answer), "unattend"},
		"a space":     {[]byte(answer), "UN ATTEND"},
		"too long":    {[]byte(answer), strings.Repeat("A", 12)},
		"empty label": {[]byte(answer), ""},
		"punctuation": {[]byte(answer), "UN.ATTEND"},
	} {
		if _, err := BuildImage(c.answer, c.label, t.TempDir()); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}
