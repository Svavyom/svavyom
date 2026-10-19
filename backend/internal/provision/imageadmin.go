package provision

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"example.invalid/dedicatedcloud/backend/internal/backupstore"
)

// Operator image retirement (M2-S02). It is a host-administrator operation run explicitly as the deployment owner (root); no service does it. It refuses unless the
// image is disabled, nothing references it and every doubt is resolved by refusing. It deletes exactly one regular file, never follows a symlink and never removes a directory.

// Errors of image removal. All are refusals; none leaves the catalog changed.
var (
	ErrImageInUse       = errors.New("provision: image is still referenced")
	ErrImageNotDisabled = errors.New("provision: disable the image before removing it")
	ErrImageAmbiguous   = errors.New("provision: cannot prove the image is unreferenced")
)

// RemovalLog is the append-only evidence file of removals, kept next to the catalog.
const RemovalLog = "removals.jsonl"

// ImageReferences lists what still depends on the image: root overlays in the pool directory whose backing file is the image, and backups whose base is its digest. A directory
// entry that is a symlink, an overlay that cannot be read, or a backup that cannot be judged makes the answer ambiguous: ErrImageAmbiguous. poolDir must be the pool's target
// directory (absolute, no symlink); bk may be nil when no backup store is configured.
func ImageReferences(c *Catalog, im Image, poolDir string, bk *backupstore.Store) ([]string, error) {
	if im.IsISO() {
		return nil, ErrImageAmbiguous // an ISO is named by VM definitions, which this check does not read: its removal is not offered (docs/VM-CREATION.md)
	}
	want, err := c.Path(im)
	if err != nil {
		return nil, ErrImageAmbiguous
	}
	if !filepath.IsAbs(poolDir) || filepath.Clean(poolDir) != poolDir || poolDir == "/" {
		return nil, ErrImageAmbiguous
	}
	if fi, err := os.Lstat(poolDir); err != nil || !fi.IsDir() {
		return nil, ErrImageAmbiguous
	}
	if real, err := filepath.EvalSymlinks(poolDir); err != nil || real != poolDir {
		return nil, ErrImageAmbiguous
	}
	ents, err := os.ReadDir(poolDir)
	if err != nil {
		return nil, ErrImageAmbiguous
	}
	var refs []string
	for _, e := range ents {
		if !strings.HasSuffix(e.Name(), ".qcow2") {
			continue
		}
		p := filepath.Join(poolDir, e.Name())
		fi, err := os.Lstat(p)
		if err != nil || !fi.Mode().IsRegular() {
			return nil, ErrImageAmbiguous // a symlink or special file named like a volume
		}
		f, err := os.Open(p) // #nosec G304 -- a regular file directly inside the operator-supplied pool directory
		if err != nil {
			return nil, ErrImageAmbiguous
		}
		o, perr := ParseOverlay(f, fi.Size())
		_ = f.Close()
		if perr != nil {
			continue // not a backed overlay (for example a standalone disk): it cannot depend on the image
		}
		if o.BackingPath == want {
			refs = append(refs, "volume "+e.Name())
		}
	}
	if bk != nil {
		l, err := bk.List()
		if err != nil {
			return nil, ErrImageAmbiguous
		}
		for _, s := range l {
			if !s.Valid {
				return nil, ErrImageAmbiguous // a damaged backup cannot be judged
			}
			if s.Manifest.VM.ImageSHA256 == im.SHA256 {
				refs = append(refs, "backup "+s.Manifest.BackupID)
			}
		}
	}
	sort.Strings(refs)
	return refs, nil
}

// RemoveImage retires one disabled, unreferenced image. The catalog is rewritten atomically WITHOUT the image first, so nothing can start using it; then its store file is
// removed (that single regular file); then the removal is recorded. A failure after the catalog rewrite leaves an unreferenced file in the store, which is harmless and is
// reported. references is called with the catalog and the image and must list everything that depends on it; any error from it, or a non-empty list, refuses.
func RemoveImage(pol Policy, dir, id string, references func(*Catalog, Image) ([]string, error), now func() time.Time) (Image, error) {
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
	im, ok := cat.Get(id)
	if !ok {
		return Image{}, ErrImageNotFound
	}
	if im.State != StateDisabled {
		return Image{}, ErrImageNotDisabled
	}
	file, err := cat.Path(im) // a regular file named for its own digest, not a symlink; anything else refuses
	if err != nil {
		return Image{}, ErrImageAmbiguous
	}
	refs, err := references(cat, im)
	if err != nil {
		return Image{}, ErrImageAmbiguous
	}
	if len(refs) > 0 {
		return Image{}, ErrImageInUse
	}
	rest := make([]Image, 0, len(cat.Images))
	for _, x := range cat.Images {
		if x.ID != id {
			rest = append(rest, x)
		}
	}
	// Two images may share one file (the same digest registered twice): the file stays while another entry names it.
	shared := false
	for _, x := range rest {
		shared = shared || x.SHA256 == im.SHA256
	}
	if err := writeCatalog(dir, rest); err != nil {
		return Image{}, err
	}
	var rmErr error
	if !shared {
		rmErr = os.Remove(file)
	}
	ev, _ := json.Marshal(struct {
		At     string `json:"at"`
		ID     string `json:"id"`
		SHA256 string `json:"sha256"`
		File   string `json:"file_removed"`
	}{now().UTC().Format(time.RFC3339), im.ID, im.SHA256, map[bool]string{true: "kept (shared)", false: im.File}[shared]})
	logPath := filepath.Join(dir, RemovalLog)
	if fi, err := os.Lstat(logPath); err == nil && !fi.Mode().IsRegular() {
		return im, ErrCatalog // never append through a symlink or special file; the removal itself is done
	}
	if f, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644); err == nil { // #nosec G302 G304 -- like catalog.json, a root-owned evidence file readable by the services; fixed name in the trusted catalog directory, checked above
		_, _ = f.Write(append(ev, '\n'))
		_ = f.Close()
	}
	if rmErr != nil {
		return im, rmErr
	}
	return im, nil
}
