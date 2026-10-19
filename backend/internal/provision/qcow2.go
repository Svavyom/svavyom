package provision

import (
	"bytes"
	"errors"
	"io"
)

// ErrOverlay means a file is not an acceptable Svavyom root overlay (a qcow2 whose only backing file is the expected managed image).
var ErrOverlay = errors.New("provision: not an acceptable root overlay")

// Overlay is what the header of a root overlay says. Only the facts Svavyom compares are kept.
type Overlay struct {
	Version     uint32
	VirtualSize uint64
	BackingPath string
	Snapshots   uint32 // internal snapshots stored in the file
}

const qcow2HeaderBytes = 104

// ParseOverlay reads the qcow2 header and the embedded backing-file name from r (size bytes long). It accepts only a version 2 or 3
// qcow2 with a backing file, no encryption, a sane cluster size and a bounded virtual size; the backing name is read from where the header says it
// is and must lie inside the file. Nothing is evaluated: the result is compared with what the catalog says it must be.
func ParseOverlay(r io.ReaderAt, size int64) (Overlay, error) {
	h := make([]byte, qcow2HeaderBytes)
	if size < qcow2HeaderBytes {
		return Overlay{}, ErrOverlay
	}
	if _, err := r.ReadAt(h, 0); err != nil {
		return Overlay{}, ErrOverlay
	}
	if !bytes.Equal(h[:4], []byte{'Q', 'F', 'I', 0xfb}) {
		return Overlay{}, ErrOverlay
	}
	be32 := func(b []byte) uint32 { return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3]) }
	be64 := func(b []byte) uint64 { return uint64(be32(b))<<32 | uint64(be32(b[4:])) }
	o := Overlay{Version: be32(h[4:]), VirtualSize: be64(h[24:]), Snapshots: be32(h[60:])}
	if o.Version != 2 && o.Version != 3 {
		return Overlay{}, ErrOverlay
	}
	if cb := be32(h[20:]); cb < 9 || cb > 21 {
		return Overlay{}, ErrOverlay
	}
	if o.VirtualSize == 0 || o.VirtualSize > 1<<50 || be32(h[32:]) != 0 { // crypt_method
		return Overlay{}, ErrOverlay
	}
	off, n := be64(h[8:]), be32(h[16:])
	if off == 0 || n == 0 || n > 1023 || off+uint64(n) > uint64(size) { // #nosec G115 -- size is a file size, never negative here
		return Overlay{}, ErrOverlay
	}
	name := make([]byte, n)
	if _, err := r.ReadAt(name, int64(off)); err != nil { // #nosec G115 -- off is bounded by size above
		return Overlay{}, ErrOverlay
	}
	o.BackingPath = string(name)
	return o, nil
}

// CheckOverlay requires r to be a root overlay of exactly the given backing image and virtual size (GiB). A different backing file,
// a different size or any stored internal snapshot is refused.
func CheckOverlay(r io.ReaderAt, size int64, backing BackingImage, diskGiB int) (Overlay, error) {
	o, err := ParseOverlay(r, size)
	if err != nil {
		return Overlay{}, err
	}
	if diskGiB < 1 || o.BackingPath != backing.Path || o.VirtualSize != uint64(diskGiB)<<30 || o.Snapshots != 0 { // #nosec G115 -- diskGiB is positive
		return Overlay{}, ErrOverlay
	}
	return o, nil
}
