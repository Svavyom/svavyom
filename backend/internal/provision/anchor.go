package provision

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"syscall"
)

// ErrAnchorChanged means the managed base image is not what the trust model requires, or differs from an earlier record.
var ErrAnchorChanged = errors.New("provision: managed base image trust anchor changed")

// Anchor is the recorded state of one managed base image, the immutable trust anchor of every VM overlay (DR-017). The
// qualification takes it before the domain exists, while the guest runs and after cleanup, and any difference is a FAIL. Names are
// the lookups of the process that took the record and are informational next to the numeric ids.
type Anchor struct {
	Path    string `json:"path"` // canonical: equal to its own EvalSymlinks
	UID     uint32 `json:"uid"`
	Owner   string `json:"owner"`
	GID     uint32 `json:"gid"`
	Group   string `json:"group"`
	Mode    string `json:"mode"` // full mode string of the Lstat, e.g. "-r--r--r--"
	Size    int64  `json:"size"`
	SHA256  string `json:"sha256"`
	Regular bool   `json:"regular"`
	Symlink bool   `json:"symlink"`
}

// TakeAnchor records path without following a symlink: Lstat for type, ownership and mode, then the size and SHA-256 over one
// descriptor opened with O_NOFOLLOW. A symlink, a non-regular file or a path that is not canonical is returned as recorded (so the
// caller can report it), with the digest left empty; only an unreadable file is an error.
func TakeAnchor(path string) (Anchor, error) {
	var a Anchor
	fi, err := os.Lstat(path)
	if err != nil {
		return a, ErrAnchorChanged
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return a, ErrAnchorChanged
	}
	a = Anchor{Path: path, UID: st.Uid, GID: st.Gid, Mode: fi.Mode().String(), Size: fi.Size(), Regular: fi.Mode().IsRegular(), Symlink: fi.Mode()&os.ModeSymlink != 0}
	a.Owner, a.Group = idName(st.Uid, st.Gid)
	if real, err := filepath.EvalSymlinks(path); err != nil || real != path {
		a.Path = "(not canonical) " + path
	}
	if !a.Regular || a.Symlink {
		return a, nil
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0) // #nosec G304 -- the managed store path, Lstat-checked above
	if err != nil {
		return a, ErrAnchorChanged
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return a, ErrAnchorChanged
	}
	a.Size, a.SHA256 = n, hex.EncodeToString(h.Sum(nil))
	return a, nil
}

func idName(uid, gid uint32) (owner, group string) {
	owner, group = "uid:"+strconv.FormatUint(uint64(uid), 10), "gid:"+strconv.FormatUint(uint64(gid), 10)
	if u, err := user.LookupId(owner[4:]); err == nil {
		owner = u.Username
	}
	if g, err := user.LookupGroupId(group[4:]); err == nil {
		group = g.Name
	}
	return owner, group
}

// AnchorWant is what the trust model requires of a managed base image.
type AnchorWant struct {
	Path   string // the catalog-qualified store path
	UID    uint32 // the deployment owner: 0
	GID    uint32 // 0 (root:root)
	SHA256 string
	Size   int64
}

// anchorMode is the only acceptable mode of a published base image: a regular file, read-only for everybody.
const anchorMode = "-r--r--r--"

// Violations lists, as short labels, every way a deviates from want: type, symlink, canonical path, owner, group, mode, size or
// digest. An empty result means the anchor is exactly the root-owned, read-only, digest-stable image the catalog qualifies.
func (a Anchor) Violations(want AnchorWant) []string {
	var v []string
	if a.Symlink {
		v = append(v, "symlink")
	}
	if !a.Regular {
		v = append(v, "not-a-regular-file")
	}
	if a.Path != want.Path {
		v = append(v, "path")
	}
	if a.UID != want.UID {
		v = append(v, "owner-uid")
	}
	if a.GID != want.GID {
		v = append(v, "group-gid")
	}
	if a.Mode != anchorMode {
		v = append(v, "mode")
	}
	if a.Size != want.Size {
		v = append(v, "size")
	}
	if a.SHA256 != want.SHA256 {
		v = append(v, "sha256")
	}
	return v
}

// Diff lists the fields in which a differs from the earlier record base (owner and group names included).
func (a Anchor) Diff(base Anchor) []string {
	var d []string
	for _, c := range []struct {
		name string
		same bool
	}{
		{"path", a.Path == base.Path}, {"owner-uid", a.UID == base.UID}, {"owner-name", a.Owner == base.Owner}, {"group-gid", a.GID == base.GID},
		{"group-name", a.Group == base.Group}, {"mode", a.Mode == base.Mode}, {"size", a.Size == base.Size}, {"sha256", a.SHA256 == base.SHA256},
		{"regular", a.Regular == base.Regular}, {"symlink", a.Symlink == base.Symlink},
	} {
		if !c.same {
			d = append(d, c.name)
		}
	}
	return d
}

// String is the one-line evidence form (no secrets: a path, ids, names, mode, size, digest).
func (a Anchor) String() string {
	return fmt.Sprintf("path=%s owner=%s(%d) group=%s(%d) mode=%s size=%d sha256=%s regular=%t symlink=%t", a.Path, a.Owner, a.UID, a.Group, a.GID, a.Mode, a.Size, a.SHA256, a.Regular, a.Symlink)
}

// CheckAnchor takes the anchor at path and judges it against want and, when base is not nil, against the earlier record. It
// returns the record taken and an error naming every violated field (never file content).
func CheckAnchor(want AnchorWant, base *Anchor) (Anchor, error) {
	a, err := TakeAnchor(want.Path)
	if err != nil {
		return a, fmt.Errorf("%w: cannot be read", ErrAnchorChanged)
	}
	bad := a.Violations(want)
	if base != nil {
		bad = append(bad, prefixed("changed-", a.Diff(*base))...)
	}
	if len(bad) > 0 {
		return a, fmt.Errorf("%w: %v", ErrAnchorChanged, bad)
	}
	return a, nil
}

func prefixed(p string, in []string) []string {
	out := make([]string, len(in))
	for i, s := range in {
		out[i] = p + s
	}
	return out
}
