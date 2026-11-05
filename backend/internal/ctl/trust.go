package ctl

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path/filepath"
	"strings"
	"syscall"
)

// How install and upgrade come to trust an artifact (DR: finding F-02 of the second review, M0-E01-S13).
//
// An artifact directory checked against the manifest inside it authenticates nothing: whoever can write the directory can change the files and the manifest together. So,
// before a root-run install or upgrade uses anything from it:
//  1. the artifact must carry a valid signature under a public key the operator obtained out of band (--signatures DIR --public-key FILE), unless --allow-unsigned is
//     given; the ed25519 signature is checked over the MANIFEST.json and SHA256SUMS bytes read once, and the manifest that is then parsed must have exactly the digest
//     that was signed;
//  2. with --allow-unsigned the artifact must sit where nobody but root can change it: every directory above it and every file in it owned by root and not writable by
//     group or others, because without a signature that is the only thing that stops a swap;
//  3. every file the installation uses is then read ONCE from the directory, hashed against the manifest and installed from that same buffer (trustedArtifact), so a file
//     swapped between the check and the use is refused instead of installed.

// trustedArtifact reads artifact files once and only if they are what the verified manifest says.
type trustedArtifact struct {
	dir   string
	files map[string]ArtifactFile
}

func newTrusted(dir string, m Manifest) *trustedArtifact {
	t := &trustedArtifact{dir: dir, files: map[string]ArtifactFile{}}
	for _, f := range m.Files {
		t.files[f.Path] = f
	}
	return t
}

// read returns the bytes of rel, read once, after checking them against the manifest's size and digest. A file the manifest does not list is refused.
func (t *trustedArtifact) read(rel string) ([]byte, error) {
	f, ok := t.files[rel]
	if !ok {
		return nil, fmt.Errorf("%w: %s is not listed in the manifest", errBadArtf, rel)
	}
	data, err := readRegular(filepath.Join(t.dir, filepath.FromSlash(rel)), 64<<20)
	if err != nil {
		return nil, fmt.Errorf("%w: %s cannot be read", errBadArtf, rel)
	}
	if int64(len(data)) != f.Size || digestOf(data) != f.SHA256 {
		return nil, fmt.Errorf("%w: %s changed after it was verified; nothing was installed from it", errBadArtf, rel)
	}
	return data, nil
}

// ownerOf is how the trust checks see who owns a file; tests replace it (a temporary directory is not root's).
func realOwner(fi fs.FileInfo) (int, bool) {
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		return int(st.Uid), true
	}
	return 0, false
}

// treeProblems lists why an artifact directory is not safe to trust without a signature: a directory above it, or the artifact tree itself, that is not owned by root or
// that group or others can write.
func (e *Env) treeProblems(dir string) []string {
	owner := e.OwnerOf
	if owner == nil {
		owner = realOwner
	}
	var bad []string
	check := func(p string, fi fs.FileInfo, ancestor bool) {
		uid, known := owner(fi)
		sticky := ancestor && fi.Mode()&fs.ModeSticky != 0 // a sticky directory (/tmp): others cannot rename or remove what root owns inside it
		if !known || uid != 0 {
			bad = append(bad, p+" is not owned by root")
		} else if fi.Mode().Perm()&0o022 != 0 && !sticky {
			bad = append(bad, p+" can be written by group or others")
		}
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return []string{"the artifact path cannot be resolved"}
	}
	for p := abs; ; p = filepath.Dir(p) {
		fi, err := e.Lstat(p)
		if err != nil {
			bad = append(bad, p+" cannot be examined")
		} else {
			check(p, fi, p != abs)
		}
		if p == filepath.Dir(p) {
			break
		}
	}
	_ = filepath.WalkDir(abs, func(p string, d fs.DirEntry, err error) error {
		if err != nil || p == abs {
			return nil
		}
		if fi, ierr := d.Info(); ierr == nil {
			check(p, fi, false)
		}
		return nil
	})
	if len(bad) > 6 {
		bad = append(bad[:6], fmt.Sprintf("and %d more", len(bad)-6))
	}
	return bad
}

// establishTrust verifies the artifact and decides whether it may be installed (see the comment at the top of this file). It returns the manifest and the reader to
// install from.
func (e *Env) establishTrust(ctx context.Context, o InstallOptions, w io.Writer) (Manifest, *trustedArtifact, error) {
	m, digest, err := VerifyArtifactDigest(o.Artifact)
	if err != nil {
		return m, nil, err
	}
	if o.AllowUnsigned {
		if (o.Signatures != "") != (o.PublicKey != "") {
			return m, nil, errors.New("--signatures and --public-key go together")
		}
	}
	if o.Signatures != "" || o.PublicKey != "" {
		res, serr := VerifySignatures(ctx, e, o.Artifact, SignatureOptions{Dir: o.Signatures, PublicKey: o.PublicKey})
		if serr != nil {
			return m, nil, serr
		}
		if res.ManifestSHA256 != digest {
			return m, nil, fmt.Errorf("%w: the manifest changed while it was being verified", errBadSig)
		}
		_, _ = fmt.Fprintf(w, "signature: valid (%s, %s, signed %s); the files were verified against the signed manifest\n", res.Method, res.KeyDetail, res.SignedAt)
		return m, newTrusted(o.Artifact, m), nil
	}
	if !o.AllowUnsigned {
		return m, nil, errors.New("this artifact is not authenticated: pass --signatures DIR --public-key FILE (the key obtained out of band, see ci/sign/README.md), or --allow-unsigned to install an artifact you have checked yourself from a directory only root can write")
	}
	if bad := e.treeProblems(o.Artifact); len(bad) > 0 {
		return m, nil, fmt.Errorf("refusing an unsigned artifact that others could change: %s. Copy it to a root-owned directory first (for example: sudo install -d -m 0755 /opt/svavyom-artifacts && sudo cp -a %s /opt/svavyom-artifacts/ && sudo chown -R root:root /opt/svavyom-artifacts), or sign it", strings.Join(bad, "; "), filepath.Base(filepath.Clean(o.Artifact)))
	}
	_, _ = fmt.Fprintf(w, "WARNING: --allow-unsigned: the artifact is not authenticated; it is in a directory only root can change, and its files are checked against its own manifest. Prefer a signed release.\n")
	return m, newTrusted(o.Artifact, m), nil
}
