package provision

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"syscall"
)

// ErrUntrusted means a security-critical file or directory (the managed image store, the catalog, the mutation helper, its
// provisioning configuration, or any directory above them) could be changed by an identity that must not change it, or is not what
// it must be (a symlink, not a regular file). Callers fail closed; the reason is deliberately not included.
var ErrUntrusted = errors.New("provision: untrusted file or directory")

// ErrNotAdministrator means an image-administration command was run by an identity other than the deployment owner.
var ErrNotAdministrator = errors.New("provision: image administration must be run by the deployment owner (root)")

// The trust model (docs/VM-CREATION.md "Trust anchors", DR-017 as amended): the mutation helper, the provisioning configuration,
// the image catalog, the managed image store and the published backing images are OPERATOR-OWNED. They belong to the deployment
// owner (root in production), are not writable by group or others, and no Svavyom runtime identity (API, read-only agent,
// mutation supervisor/helper) may own them or be able to write them or any directory above them. Runtime identities get read
// and execute access only. Runtime state (SQLite, sockets, scratch, VM provisioning state) is separate and stays writable. A
// malicious root administrator is out of scope.

// Identity is one declared runtime service identity: a user and the groups it holds.
type Identity struct {
	Name string
	UID  uint32
	GIDs []uint32
}

// Policy says who owns the trust anchors and which identities must not be able to change them. The zero Policy is the strict
// production policy with no declared identity; it accepts nothing owned by a non-root user and is not usable by tests.
type Policy struct {
	Owner   uint32     // deployment owner: 0 (root) in production
	Runtime []Identity // identities that must not be able to write any anchor
	dev     bool
	// floor is a test seam (unexported, so no deployment can set it): when non-empty the ancestor walk stops at this directory,
	// and the process-self write check is skipped. Docker tests run as an unprivileged user and cannot create a root-owned tree.
	floor string
}

// DevPolicy is the INSECURE development/test policy (Docker end-to-end tests, single-identity runs): anchors may be owned by
// root or by the current process identity, and a sticky world-writable ancestor such as /tmp is accepted. It enforces no
// separation between runtime identities. It is never the policy of a production deployment (docs/VM-CREATION.md).
func DevPolicy() Policy { return Policy{dev: true} }

// Insecure reports whether this is the development/test policy.
func (p Policy) Insecure() bool { return p.dev }

func (p Policy) ownerOK(fi os.FileInfo) bool {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return false
	}
	if p.dev {
		return st.Uid == 0 || st.Uid == uint32(os.Geteuid()) // #nosec G115 -- euid is non-negative
	}
	return st.Uid == p.Owner
}

// runtimeCanWrite evaluates, for each declared runtime identity, whether it could modify the object (or, for a directory, add,
// rename or remove entries in it) under POSIX owner/group/other rules. Owning the object counts as being able to modify it:
// an owner can always chmod it. ACLs and capabilities are not evaluated (documented limit).
func (p Policy) runtimeCanWrite(fi os.FileInfo) bool {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return true
	}
	perm := fi.Mode().Perm()
	for _, id := range p.Runtime {
		switch {
		case st.Uid == id.UID:
			return true
		case slices.Contains(id.GIDs, st.Gid):
			if perm&0o020 != 0 {
				return true
			}
		default:
			if perm&0o002 != 0 {
				return true
			}
		}
	}
	return false
}

// File requires path to be a regular file (Lstat: a symlink is refused) with the right owner, no group/other write, not
// modifiable by any runtime identity. With readOnly, no write bit at all may be set (published base images are 0444).
func (p Policy) File(path string, readOnly bool) error {
	fi, err := os.Lstat(path)
	if err != nil || !fi.Mode().IsRegular() || !p.ownerOK(fi) || fi.Mode().Perm()&0o022 != 0 || (readOnly && fi.Mode().Perm()&0o222 != 0) || p.runtimeCanWrite(fi) {
		return ErrUntrusted
	}
	return nil
}

// Dir requires path itself to be a real directory (not a symlink) with the right owner, no group/other write and not modifiable
// by a runtime identity, and every ancestor of its real location likewise. Only the development policy accepts a sticky
// world-writable ancestor such as /tmp: production trust never rests on /tmp semantics.
func (p Policy) Dir(path string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return ErrUntrusted
	}
	fi, err := os.Lstat(path)
	if err != nil || !fi.IsDir() || !p.ownerOK(fi) || fi.Mode().Perm()&0o022 != 0 || p.runtimeCanWrite(fi) {
		return ErrUntrusted
	}
	real, err := filepath.EvalSymlinks(filepath.Dir(path))
	if err != nil {
		return ErrUntrusted
	}
	for d := real; ; d = filepath.Dir(d) {
		st, err := os.Lstat(d)
		if err != nil || !st.IsDir() || !p.ownerOK(st) {
			return ErrUntrusted
		}
		if st.Mode().Perm()&0o022 != 0 && !(p.dev && st.Mode()&os.ModeSticky != 0) {
			return ErrUntrusted
		}
		if !(p.dev && st.Mode()&os.ModeSticky != 0) && p.runtimeCanWrite(st) {
			return ErrUntrusted
		}
		if d == "/" || (p.floor != "" && d == p.floor) {
			return nil
		}
	}
}

// Asset checks a file together with its parent directory chain.
func (p Policy) Asset(path string, readOnly bool) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return ErrUntrusted
	}
	if err := p.File(path, readOnly); err != nil {
		return err
	}
	return p.Dir(filepath.Dir(path))
}

// RequireAdministrator refuses image administration (register-image, image-state) unless this process runs as the deployment
// owner. The development policy accepts any identity.
func (p Policy) RequireAdministrator() error {
	if p.dev || uint32(os.Geteuid()) == p.Owner { // #nosec G115 -- euid is non-negative
		return nil
	}
	return ErrNotAdministrator
}

// WritableByMe reports whether the current process identity could modify path (access(2) W_OK). Every Svavyom runtime process
// uses it to refuse to start when it could rewrite a trust anchor, which also catches a deployment whose declared identities
// differ from the identity the process really runs as.
func WritableByMe(path string) bool {
	return syscall.Access(path, 2) == nil
}

// CheckDeployment returns generic labels (never paths) for every trust anchor of the deployment that violates the policy or
// that the calling process itself could write (the check of the process's own writes is skipped for root, the trusted owner). An empty result means the supported production layout is in place. Used by the
// API, the supervisor (at start and before every helper run) and the qualification preflight.
func (p Policy) CheckDeployment(cfgPath string, c Config) []string {
	var bad []string
	check := func(label string, err error, path string) {
		if err != nil || (!p.dev && p.floor == "" && os.Geteuid() != 0 && WritableByMe(path)) {
			bad = append(bad, label)
		}
	}
	store := filepath.Join(c.CatalogDir, StoreDir)
	catalog := filepath.Join(c.CatalogDir, CatalogFile)
	check("provisioning configuration", p.Asset(cfgPath, false), cfgPath)
	check("catalog directory", p.Dir(c.CatalogDir), c.CatalogDir)
	if _, err := os.Lstat(store); err == nil {
		check("image store", p.Dir(store), store)
	}
	if _, err := os.Lstat(catalog); err == nil {
		check("catalog", p.File(catalog, false), catalog)
		if cat, err := LoadCatalog(c.CatalogDir); err == nil {
			for _, im := range cat.Images {
				if ip, err := cat.Path(im); err == nil {
					check("published image", p.File(ip, true), ip)
				}
			}
		}
	}
	return slices.Compact(bad)
}
