package provision

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/diskfs/go-diskfs/backend/file"
	"github.com/diskfs/go-diskfs/filesystem/iso9660"
)

// seedWorkSize is the size of the scratch ISO image; the finalised ISO is a few tens of KiB.
const seedWorkSize = 1 << 20

// BuildSeed produces the NoCloud "cidata" seed ISO (volume label cidata, files user-data and meta-data, Rock Ridge names)
// natively in Go, with no shell, no mount and no external tool. scratchDir must be a server-owned directory (mode 0700); the
// scratch file inside it is removed before return. The bytes returned are what is uploaded into the seed volume.
func BuildSeed(s Spec, scratchDir string) ([]byte, error) {
	user, err := UserData(s)
	if err != nil {
		return nil, err
	}
	meta, err := MetaData(s)
	if err != nil {
		return nil, err
	}
	work, err := os.MkdirTemp(scratchDir, "seed-") // mode 0700; holds both the ISO workspace and the output image
	if err != nil {
		return nil, fmt.Errorf("provision: seed scratch: %w", err)
	}
	defer func() { _ = os.RemoveAll(work) }()
	if err := os.Mkdir(filepath.Join(work, "ws"), 0o700); err != nil {
		return nil, fmt.Errorf("provision: seed scratch: %w", err)
	}
	path := filepath.Join(work, "seed.iso")
	backend, err := file.CreateFromPath(path, seedWorkSize)
	if err != nil {
		return nil, fmt.Errorf("provision: seed image: %w", err)
	}
	defer func() { _ = backend.Close() }()
	fs, err := iso9660.Create(backend, seedWorkSize, 0, 2048, filepath.Join(work, "ws"))
	if err != nil {
		return nil, fmt.Errorf("provision: seed filesystem: %w", err)
	}
	for name, content := range map[string]string{"/user-data": user, "/meta-data": meta} {
		w, err := fs.OpenFile(name, os.O_CREATE|os.O_RDWR)
		if err != nil {
			return nil, fmt.Errorf("provision: seed file: %w", err)
		}
		if _, err := w.Write([]byte(content)); err != nil {
			return nil, fmt.Errorf("provision: seed write: %w", err)
		}
	}
	if err := fs.Finalize(iso9660.FinalizeOptions{RockRidge: true, VolumeIdentifier: "cidata"}); err != nil {
		return nil, fmt.Errorf("provision: seed finalize: %w", err)
	}
	if err := fs.Close(); err != nil {
		return nil, fmt.Errorf("provision: seed close: %w", err)
	}
	b, err := os.ReadFile(filepath.Clean(path)) // #nosec G304 -- the scratch file this function created
	if err != nil {
		return nil, fmt.Errorf("provision: seed read: %w", err)
	}
	if len(b) == 0 || len(b) > SeedCapacityBytes || len(b) < pvdOffset+2048 {
		return nil, fmt.Errorf("provision: seed size")
	}
	padPVD(b)
	return b, nil
}

const pvdOffset = 16 * 2048 // the primary volume descriptor is logical sector 16

// padPVD rewrites the text identifier fields of the primary volume descriptor so that unused bytes are spaces, as ECMA-119
// requires for d-/a-characters. The library pads with NUL, which blkid-style label matching ("cidata") must not depend on.
func padPVD(iso []byte) {
	pvd := iso[pvdOffset : pvdOffset+2048]
	for _, f := range [][2]int{{8, 40}, {40, 72}, {190, 318}, {318, 446}, {446, 574}, {574, 702}, {702, 739}, {739, 776}, {776, 813}} {
		for i := f[0]; i < f[1]; i++ {
			if pvd[i] == 0 {
				pvd[i] = ' '
			}
		}
	}
}
