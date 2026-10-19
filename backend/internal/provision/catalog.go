package provision

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
)

// CatalogFile is the catalog inside the catalog directory.
const CatalogFile = "catalog.json"

// StoreDir is the Svavyom-managed, content-addressed, immutable image store inside the catalog directory. A registered image is
// COPIED here (never referenced where the operator had it); the file is named by its SHA-256 and is mode 0444.
const StoreDir = "store"

// Qualification states of an image. They are deliberately separate claims:
//
//	registered  imported and hashed; nothing else is asserted.
//	verified    the operator explicitly accepted its metadata (cloud-init support, login user) through the supported workflow.
//	qualified   a real-host test booted this image and proved the access flow (never set from simulation or unit tests).
//	disabled    withdrawn; never offered.
const (
	StateRegistered = "registered"
	StateVerified   = "verified"
	StateQualified  = "qualified"
	StateDisabled   = "disabled"
)

const catalogSchema = 2

// Image is one operator-registered image. The browser can only ever name one by ID.
type Image struct {
	ID           string `json:"id"`
	DisplayName  string `json:"display_name"`
	Distribution string `json:"distribution"`
	Version      string `json:"version"`
	Architecture string `json:"architecture"` // x86_64 only in this slice
	File         string `json:"file"`         // always "<sha256>.qcow2" (or ".iso" for installation media) inside the store directory
	Format       string `json:"format"`       // qcow2, or iso for installation media
	// Media is "disk" (a bootable cloud image, the default) or "iso" (installation media: DR-023 D3). An ISO is verified by its SHA-256, never has
	// cloud-init, and is attached to a new VM as a read-only CD.
	Media      string `json:"media,omitempty"`
	SHA256     string `json:"sha256"`
	SizeBytes  int64  `json:"size_bytes"`
	MinDiskGiB int    `json:"min_disk_gib"`
	CloudInit  bool   `json:"cloud_init"` // the operator's assertion that the image reads a NoCloud seed
	LoginUser  string `json:"login_user"` // the operator's assertion of the image's default account
	State      string `json:"state"`
	Evidence   string `json:"evidence,omitempty"` // reference to the real-host qualification record (qualified only)
}

var (
	loginUserRE = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)
	textRE      = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9 ._()+-]{0,62}$`)
)

// Errors of the catalog (no caller text).
var (
	ErrCatalog = errors.New("provision: image catalog problem")
	// ErrCatalogSchema: the catalog was written by an older Development Preview build. There is no migration for a pre-public
	// experimental catalog; images are re-imported through the managed workflow.
	ErrCatalogSchema = fmt.Errorf("%w: the catalog uses an older format; re-import the images with `api register-image` (Development Preview catalogs are not migrated)", ErrCatalog)
	ErrImageNotFound = errors.New("provision: image not in the catalog")
	ErrImageDisabled = errors.New("provision: image disabled")
	ErrImageNotReady = errors.New("provision: image registered but not verified")
	ErrImageChanged  = errors.New("provision: image file does not match its catalog hash")
)

// IsISO reports whether the image is installation media.
func (i Image) IsISO() bool { return i.Media == MediaISO }

// Media kinds of an image.
const (
	MediaDisk = "disk"
	MediaISO  = "iso"
)

// storeExt is the extension of the image's file in the store.
func (i Image) storeExt() string {
	if i.IsISO() {
		return ".iso"
	}
	return ".qcow2"
}

func (i Image) validate() error {
	if i.Media != "" && i.Media != MediaDisk && i.Media != MediaISO {
		return ErrCatalog
	}
	if i.IsISO() {
		// Installation media: no cloud-init, no login user, never "qualified" (a real-host boot of a cloud image is what qualification means).
		if !imageIDRE.MatchString(i.ID) || !textRE.MatchString(i.DisplayName) || !textRE.MatchString(i.Distribution) || !textRE.MatchString(i.Version) ||
			i.Architecture != "x86_64" || i.Format != "iso" || !fingerprintRE.MatchString(i.SHA256) || i.File != i.SHA256+".iso" ||
			i.SizeBytes <= 0 || i.MinDiskGiB < 1 || i.MinDiskGiB > 4096 || i.CloudInit || i.LoginUser != "" || i.Evidence != "" {
			return ErrCatalog
		}
		if i.State != StateVerified && i.State != StateDisabled {
			return ErrCatalog
		}
		return nil
	}
	if !imageIDRE.MatchString(i.ID) || !textRE.MatchString(i.DisplayName) || !textRE.MatchString(i.Distribution) || !textRE.MatchString(i.Version) ||
		i.Architecture != "x86_64" || i.Format != "qcow2" || !fingerprintRE.MatchString(i.SHA256) || i.File != i.SHA256+".qcow2" ||
		i.SizeBytes <= 0 || i.MinDiskGiB < 1 || i.MinDiskGiB > 4096 || !loginUserRE.MatchString(i.LoginUser) {
		return ErrCatalog
	}
	switch i.State {
	case StateRegistered, StateDisabled:
	case StateVerified, StateQualified:
		if !i.CloudInit {
			return ErrCatalog
		}
	default:
		return ErrCatalog
	}
	if (i.State == StateQualified) != (i.Evidence != "") || (i.Evidence != "" && !textRE.MatchString(i.Evidence)) {
		return ErrCatalog
	}
	return nil
}

// Catalog is the loaded catalog.
type Catalog struct {
	Dir    string
	Images []Image
	trust  Policy // set by LoadTrustedCatalog; the zero value is the strict production policy
}

type catalogDoc struct {
	Schema int     `json:"schema"`
	Images []Image `json:"images"`
}

// LoadCatalog reads dir/catalog.json. The directory must be absolute and clean; the catalog file must be a regular file, not
// a symlink, and not writable by group or others. A missing catalog is an empty one (no images registered yet).
func LoadCatalog(dir string) (*Catalog, error) {
	if !filepath.IsAbs(dir) || filepath.Clean(dir) != dir {
		return nil, ErrCatalog
	}
	p := filepath.Join(dir, CatalogFile)
	fi, err := os.Lstat(p)
	if errors.Is(err, os.ErrNotExist) {
		return &Catalog{Dir: dir}, nil
	}
	if err != nil || !fi.Mode().IsRegular() || fi.Mode().Perm()&0o022 != 0 || fi.Size() > 1<<20 {
		return nil, ErrCatalog
	}
	b, err := os.ReadFile(p) // #nosec G304 -- fixed name inside the server-owned directory, checked above
	if err != nil {
		return nil, ErrCatalog
	}
	var head struct {
		Schema int `json:"schema"`
	}
	if json.Unmarshal(b, &head) == nil && head.Schema > 0 && head.Schema < catalogSchema {
		return nil, ErrCatalogSchema
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var d catalogDoc
	if err := dec.Decode(&d); err != nil || d.Schema != catalogSchema {
		return nil, ErrCatalog
	}
	seen := map[string]bool{}
	for _, im := range d.Images {
		if err := im.validate(); err != nil || seen[im.ID] {
			return nil, ErrCatalog
		}
		seen[im.ID] = true
	}
	return &Catalog{Dir: dir, Images: d.Images}, nil
}

// Get returns an image by ID.
func (c *Catalog) Get(id string) (Image, bool) {
	for _, im := range c.Images {
		if im.ID == id {
			return im, true
		}
	}
	return Image{}, false
}

// Usable returns the image if it can be used to create a VM: verified or qualified, with cloud-init support. A merely registered
// image is listed to the operator but cannot be chosen.
func (c *Catalog) Usable(id string) (Image, error) {
	im, ok := c.Get(id)
	switch {
	case !ok:
		return Image{}, ErrImageNotFound
	case im.State == StateDisabled:
		return Image{}, ErrImageDisabled
	case im.IsISO():
		return im, nil // installation media is usable once verified by its digest; it has no cloud-init to assert
	case im.State == StateRegistered || !im.CloudInit:
		return Image{}, ErrImageNotReady
	}
	return im, nil
}

// StorePath is the managed store directory.
func (c *Catalog) StorePath() string { return filepath.Join(c.Dir, StoreDir) }

// Path resolves the managed image file: "<sha256>.qcow2" directly inside the store, a regular non-symlink file.
func (c *Catalog) Path(im Image) (string, error) {
	if im.File != im.SHA256+im.storeExt() || !fingerprintRE.MatchString(im.SHA256) {
		return "", ErrCatalog
	}
	p := filepath.Join(c.StorePath(), im.File)
	fi, err := os.Lstat(p)
	if err != nil || !fi.Mode().IsRegular() {
		return "", ErrImageChanged
	}
	return p, nil
}

// Verify is run by the mutation helper just before an image becomes a backing file. It requires the store directory, its
// ancestors and the image to be trusted (not symlinks, owned by root or the service identity, not writable by group/others, the
// image not writable at all), then recomputes the size and SHA-256 over ONE open descriptor. Hashing alone cannot close the gap
// between this check and libvirt opening the path later; the protection is that the published file is immutable to every identity
// that is not root or the service identity (docs/VM-CREATION.md).
func (c *Catalog) Verify(im Image) (string, error) {
	p, err := c.Path(im)
	if err != nil {
		return "", err
	}
	if c.trust.Dir(c.StorePath()) != nil || c.trust.File(p, true) != nil {
		return "", ErrImageChanged
	}
	f, err := os.OpenFile(p, os.O_RDONLY|syscall.O_NOFOLLOW, 0) // #nosec G304 -- path produced by Catalog.Path and checked above
	if err != nil {
		return "", ErrImageChanged
	}
	defer f.Close()
	if fi, err := f.Stat(); err != nil || !fi.Mode().IsRegular() || fi.Size() != im.SizeBytes {
		return "", ErrImageChanged
	}
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil || hex.EncodeToString(h.Sum(nil)) != im.SHA256 {
		return "", ErrImageChanged
	}
	return p, nil
}

// LoadTrustedCatalog is LoadCatalog for the mutation helper: the catalog directory and file must also be trusted (owner and
// ancestors), because they decide which file becomes a backing image.
func LoadTrustedCatalog(pol Policy, dir string) (*Catalog, error) {
	if err := pol.Dir(dir); err != nil {
		return nil, ErrCatalog
	}
	if _, err := os.Lstat(filepath.Join(dir, CatalogFile)); err == nil && pol.File(filepath.Join(dir, CatalogFile), false) != nil {
		return nil, ErrCatalog
	}
	cat, err := LoadCatalog(dir)
	if err != nil {
		return nil, err
	}
	cat.trust = pol
	return cat, nil
}

// maxImageBytes bounds one import (a cloud image is a few hundred MiB; 32 GiB is far above any real one).
const maxImageBytes = 32 << 30

// checkQcow2Header validates the qcow2 header at the level this slice supports: version 2 or 3, no backing file of its own (a
// base image that points at another file would escape the store), no encryption, a sane cluster size and a non-zero virtual size.
func checkQcow2Header(h []byte) error {
	if len(h) < 36 || !bytes.Equal(h[:4], []byte{'Q', 'F', 'I', 0xfb}) {
		return ErrCatalog
	}
	be32 := func(b []byte) uint32 { return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3]) }
	be64 := func(b []byte) uint64 { return uint64(be32(b))<<32 | uint64(be32(b[4:])) }
	if v := be32(h[4:]); v != 2 && v != 3 {
		return ErrCatalog
	}
	if be64(h[8:]) != 0 || be32(h[16:]) != 0 { // backing_file_offset / backing_file_size
		return ErrCatalog
	}
	if cb := be32(h[20:]); cb < 9 || cb > 21 {
		return ErrCatalog
	}
	if sz := be64(h[24:]); sz == 0 || sz > 1<<50 {
		return ErrCatalog
	}
	if be32(h[32:]) != 0 { // crypt_method
		return ErrCatalog
	}
	return nil
}

// checkISOHeader requires the ISO 9660 primary volume descriptor identifier "CD001" at byte 32769 (sector 16, after its type byte). That is all this slice
// asserts about the content of installation media: the operator's SHA-256 of record and the immutable store protect its integrity.
func checkISOHeader(h []byte) error {
	if len(h) < 32774 || !bytes.Equal(h[32769:32774], []byte("CD001")) {
		return ErrCatalog
	}
	return nil
}

// RegisterRequest is the operator's description of an image to IMPORT. Source is an absolute path chosen by the operator on the
// host; it is read once and never referenced again. CloudInit is the operator's explicit assertion that the image reads a NoCloud
// seed and has LoginUser as its default account; with it the image is "verified", without it only "registered".
type RegisterRequest struct {
	ID, DisplayName, Distribution, Version, Source, LoginUser string
	MinDiskGiB                                                int
	CloudInit                                                 bool
	// Media is "" or "disk" for a cloud image, "iso" for installation media (no cloud-init, no login user).
	Media string
}

// importImage copies the source into the store as a new, immutable, content-addressed file and returns its digest and size.
// The copy goes to a temporary ".import-*" name (never a valid published name, and never referenced by a catalog), is fsynced,
// made read-only, and published with a non-overwriting link; a crash leaves at most a stray temporary file.
func importImage(pol Policy, source, store, media string) (sum string, size int64, err error) {
	ext := ".qcow2"
	if media == MediaISO {
		ext = ".iso"
	}
	if !filepath.IsAbs(source) || filepath.Clean(source) != source {
		return "", 0, ErrCatalog
	}
	src, err := os.OpenFile(source, os.O_RDONLY|syscall.O_NOFOLLOW, 0) // #nosec G304 -- operator-supplied import source; O_NOFOLLOW, regular-file check below
	if err != nil {
		return "", 0, ErrCatalog
	}
	defer src.Close()
	if fi, err := src.Stat(); err != nil || !fi.Mode().IsRegular() || fi.Size() <= 0 || fi.Size() > maxImageBytes {
		return "", 0, ErrCatalog
	}
	if media == MediaISO {
		header := make([]byte, 32774)
		if _, err := io.ReadFull(src, header); err != nil || checkISOHeader(header) != nil {
			return "", 0, ErrCatalog
		}
	} else {
		header := make([]byte, 72)
		if _, err := io.ReadFull(src, header); err != nil || checkQcow2Header(header) != nil {
			return "", 0, ErrCatalog
		}
	}
	if _, err := src.Seek(0, io.SeekStart); err != nil {
		return "", 0, ErrCatalog
	}
	if err := os.MkdirAll(store, 0o755); err != nil { // #nosec G301 -- the helper identity must be able to read the store
		return "", 0, ErrCatalog
	}
	if err := pol.Dir(store); err != nil {
		return "", 0, ErrCatalog
	}
	tmp, err := os.CreateTemp(store, ".import-*")
	if err != nil {
		return "", 0, ErrCatalog
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }() // after a successful link the temporary name simply disappears
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(tmp, h), io.LimitReader(src, maxImageBytes+1))
	if err != nil || n <= 0 || n > maxImageBytes || tmp.Sync() != nil || tmp.Chmod(0o444) != nil || tmp.Close() != nil {
		_ = tmp.Close()
		return "", 0, ErrCatalog
	}
	sum = hex.EncodeToString(h.Sum(nil))
	final := filepath.Join(store, sum+ext)
	if err := os.Link(tmpName, final); err != nil {
		if !errors.Is(err, os.ErrExist) {
			return "", 0, ErrCatalog
		}
		// The same content is already published: accept it only if it really is that content.
		if pol.File(final, true) != nil {
			return "", 0, ErrCatalog
		}
		if s2, n2, err := hashFile(final); err != nil || s2 != sum || n2 != n {
			return "", 0, ErrCatalog
		}
	}
	if d, err := os.Open(store); err == nil { // #nosec G304 -- the store directory checked above
		_ = d.Sync()
		_ = d.Close()
	}
	return sum, n, nil
}

func hashFile(p string) (string, int64, error) {
	f, err := os.Open(p) // #nosec G304 -- path inside the trusted store
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}

func writeCatalog(dir string, images []Image) error {
	out, err := json.MarshalIndent(catalogDoc{Schema: catalogSchema, Images: images}, "", "  ")
	if err != nil {
		return ErrCatalog
	}
	tmp, err := os.CreateTemp(dir, ".catalog-*")
	if err != nil {
		return ErrCatalog
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	if _, err := tmp.Write(append(out, '\n')); err != nil || tmp.Chmod(0o644) != nil || tmp.Sync() != nil || tmp.Close() != nil {
		return ErrCatalog
	}
	if err := os.Rename(tmp.Name(), filepath.Join(dir, CatalogFile)); err != nil {
		return ErrCatalog
	}
	return nil
}

// Register imports an image into the managed store and adds it to the catalog. It runs on the host, explicitly, as the deployment owner
// (root); the runtime services only ever read the result. An existing ID is refused. The catalog is rewritten atomically.
func Register(pol Policy, dir string, r RegisterRequest) (Image, error) {
	if err := pol.RequireAdministrator(); err != nil {
		return Image{}, err
	}
	cat, err := LoadCatalog(dir)
	if err != nil {
		return Image{}, err
	}
	if err := pol.Dir(dir); err != nil {
		return Image{}, ErrCatalog
	}
	im := Image{ID: r.ID, DisplayName: r.DisplayName, Distribution: r.Distribution, Version: r.Version, Architecture: "x86_64",
		Format: "qcow2", MinDiskGiB: r.MinDiskGiB, CloudInit: r.CloudInit, LoginUser: r.LoginUser, State: StateRegistered}
	if r.CloudInit {
		im.State = StateVerified
	}
	if r.Media != "" && r.Media != MediaDisk && r.Media != MediaISO {
		return Image{}, ErrCatalog
	}
	if r.Media == MediaISO {
		im.Media, im.Format, im.CloudInit, im.LoginUser, im.State = MediaISO, "iso", false, "", StateVerified
		if r.CloudInit || r.LoginUser != "" {
			return Image{}, fmt.Errorf("%w: installation media has no cloud-init and no login user", ErrCatalog)
		}
	}
	if _, dup := cat.Get(r.ID); dup {
		return Image{}, fmt.Errorf("%w: id %s is already registered", ErrCatalog, r.ID)
	}
	pre := im // validate the operator's metadata BEFORE anything is copied, so a refused registration leaves nothing behind
	pre.SHA256, pre.SizeBytes, pre.File = strings.Repeat("0", 64), 1, strings.Repeat("0", 64)+im.storeExt()
	if err := pre.validate(); err != nil {
		return Image{}, err
	}
	sum, size, err := importImage(pol, r.Source, filepath.Join(dir, StoreDir), r.Media)
	if err != nil {
		if r.Media == MediaISO {
			return Image{}, fmt.Errorf("%w: the source is not an importable ISO 9660 image", ErrCatalog)
		}
		return Image{}, fmt.Errorf("%w: the source is not an importable qcow2 image", ErrCatalog)
	}
	im.SHA256, im.SizeBytes, im.File = sum, size, sum+im.storeExt()
	if err := im.validate(); err != nil {
		return Image{}, err
	}
	if err := writeCatalog(dir, append(append([]Image(nil), cat.Images...), im)); err != nil {
		return Image{}, err
	}
	return im, nil
}

// SetState changes the qualification state of a registered image. Moving to "verified" needs the cloud-init assertion;
// "qualified" needs a reference to the real-host qualification record and must never be set from simulation. Images are
// append-only: nothing here removes an image or its file (docs/VM-CREATION.md "Image lifetime").
func SetState(pol Policy, dir, id, state, evidence string) (Image, error) {
	if err := pol.RequireAdministrator(); err != nil {
		return Image{}, err
	}
	if err := pol.Dir(dir); err != nil {
		return Image{}, ErrCatalog
	}
	cat, err := LoadCatalog(dir)
	if err != nil {
		return Image{}, err
	}
	out := append([]Image(nil), cat.Images...)
	for i := range out {
		if out[i].ID != id {
			continue
		}
		out[i].State, out[i].Evidence = state, ""
		if state == StateQualified {
			out[i].Evidence = evidence
		}
		if err := out[i].validate(); err != nil {
			return Image{}, err
		}
		if err := writeCatalog(dir, out); err != nil {
			return Image{}, err
		}
		return out[i], nil
	}
	return Image{}, ErrImageNotFound
}
