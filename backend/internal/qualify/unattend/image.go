// Package unattend builds the small disk that carries a Windows answer file (Autounattend.xml) to Windows Setup in a qualification run.
//
// Windows Setup looks for Autounattend.xml, by that exact long name, in the root of removable media. The qualification harness (tools/qualify_windows.py and the
// Go stage in internal/hypervisor/libvirtmut) attaches this image to a disposable VM as a removable USB disk, after the Svavyom-managed definition has been
// checked, so the install needs no person at the console. It is harness-only code: nothing in the product's services uses it.
package unattend

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/diskfs/go-diskfs/backend/file"
	"github.com/diskfs/go-diskfs/filesystem/fat32"
)

// FileName is the exact name Windows Setup searches for.
const FileName = "Autounattend.xml"

// ImageSize is the size of the image: the smallest a FAT32 volume can reasonably be (FAT32 needs at least 65525 clusters).
const ImageSize = 64 << 20

// MaxAnswer bounds the answer file; a real one is a few KiB.
const MaxAnswer = 256 << 10

// BuildImage returns a FAT32 volume (no partition table, like a floppy or a freshly formatted stick) whose root holds the answer file as Autounattend.xml.
// scratchDir must be a directory the caller owns; the scratch file inside it is removed before return.
func BuildImage(answer []byte, label, scratchDir string) ([]byte, error) {
	if len(answer) == 0 || len(answer) > MaxAnswer {
		return nil, errors.New("unattend: the answer file is empty or too large")
	}
	if !strings.HasPrefix(strings.TrimSpace(string(answer)), "<?xml") {
		return nil, errors.New("unattend: the answer file is not XML")
	}
	if l := len(label); l < 1 || l > 11 || strings.ToUpper(label) != label || strings.ContainsAny(label, " .\\/:*?\"<>|") {
		return nil, errors.New("unattend: the volume label must be 1 to 11 upper-case characters without spaces or punctuation")
	}
	work, err := os.MkdirTemp(scratchDir, "unattend-")
	if err != nil {
		return nil, fmt.Errorf("unattend: scratch: %w", err)
	}
	defer func() { _ = os.RemoveAll(work) }()
	path := filepath.Join(work, "unattend.img")
	backend, err := file.CreateFromPath(path, ImageSize)
	if err != nil {
		return nil, fmt.Errorf("unattend: image: %w", err)
	}
	defer func() { _ = backend.Close() }()
	fs, err := fat32.Create(backend, ImageSize, 0, 512, label, true)
	if err != nil {
		return nil, fmt.Errorf("unattend: filesystem: %w", err)
	}
	w, err := fs.OpenFile("/"+FileName, os.O_CREATE|os.O_RDWR)
	if err != nil {
		return nil, fmt.Errorf("unattend: file: %w", err)
	}
	if _, err := w.Write(answer); err != nil {
		return nil, fmt.Errorf("unattend: write: %w", err)
	}
	if err := fs.Close(); err != nil {
		return nil, fmt.Errorf("unattend: close: %w", err)
	}
	b, err := os.ReadFile(filepath.Clean(path)) // #nosec G304 -- the scratch file this function created
	if err != nil {
		return nil, fmt.Errorf("unattend: read: %w", err)
	}
	return b, nil
}
