package ctl

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// ManifestName is the release manifest at the root of an artifact directory.
const ManifestName = "MANIFEST.json"

// ArtifactFile is one file of a release artifact.
type ArtifactFile struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
	Mode   uint32 `json:"mode"`
	// Audience is "public" (safe to publish with the release) or "private" (stays with the operator/maintainers): the public/private snapshot manifest.
	Audience string `json:"audience"`
}

// Manifest describes a release artifact exactly: every file with its digest, so an installer can refuse anything that is not what the release says.
type Manifest struct {
	Schema         int            `json:"schema"`
	Product        string         `json:"product"`
	Version        string         `json:"version"`
	Classification string         `json:"classification"`
	License        string         `json:"license,omitempty"`
	BuiltFrom      string         `json:"built_from"`
	SchemaVersions map[string]int `json:"schema_versions"`
	Files          []ArtifactFile `json:"files"`
}

var (
	versionRE  = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$`)
	relPathRE  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._@+-]*(/[A-Za-z0-9][A-Za-z0-9._@+-]*)*$`)
	hexSHA256  = regexp.MustCompile(`^[0-9a-f]{64}$`)
	errBadArtf = errors.New("ctl: the release artifact does not match its manifest")
)

// VerifyArtifact checks an artifact directory against its manifest: strict JSON, safe relative paths, regular files only (no symlink, no special file),
// every digest and size, and no file that the manifest does not list. It reads, and changes nothing.
func VerifyArtifact(dir string) (Manifest, error) {
	var m Manifest
	raw, err := readRegular(filepath.Join(dir, ManifestName), 4<<20)
	if err != nil {
		return m, fmt.Errorf("%w: no readable %s", errBadArtf, ManifestName)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&m); err != nil || m.Schema != 1 || m.Product != "svavyom" || !versionRE.MatchString(m.Version) || len(m.Files) == 0 || len(m.Files) > 5000 {
		return m, fmt.Errorf("%w: the manifest is malformed", errBadArtf)
	}
	listed := map[string]bool{ManifestName: true, "SHA256SUMS": true}
	for _, f := range m.Files {
		if !relPathRE.MatchString(f.Path) || strings.Contains(f.Path, "..") || !hexSHA256.MatchString(f.SHA256) || f.Size < 0 || (f.Audience != "public" && f.Audience != "private") || f.Mode&^0o777 != 0 {
			return m, fmt.Errorf("%w: an entry of the manifest is malformed", errBadArtf)
		}
		if listed[f.Path] {
			return m, fmt.Errorf("%w: duplicate or reserved entry %s", errBadArtf, f.Path)
		}
		listed[f.Path] = true
		p := filepath.Join(dir, filepath.FromSlash(f.Path))
		fi, err := os.Lstat(p)
		if err != nil || !fi.Mode().IsRegular() {
			return m, fmt.Errorf("%w: %s is missing or not a regular file", errBadArtf, f.Path)
		}
		if fi.Size() != f.Size {
			return m, fmt.Errorf("%w: %s has the wrong size", errBadArtf, f.Path)
		}
		sum, err := fileSHA256(p)
		if err != nil || sum != f.SHA256 {
			return m, fmt.Errorf("%w: %s does not match its digest", errBadArtf, f.Path)
		}
	}
	var extra []string
	_ = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		rel, _ := filepath.Rel(dir, p)
		if !listed[filepath.ToSlash(rel)] {
			extra = append(extra, filepath.ToSlash(rel))
		}
		return nil
	})
	if len(extra) > 0 {
		sort.Strings(extra)
		return m, fmt.Errorf("%w: files the manifest does not list: %s", errBadArtf, strings.Join(extra[:min(len(extra), 5)], ", "))
	}
	for _, b := range Binaries {
		if !listed["bin/"+b] {
			return m, fmt.Errorf("%w: the artifact has no bin/%s", errBadArtf, b)
		}
	}
	if err := checkAttestation(dir, m); err != nil {
		return m, err
	}
	return m, nil
}

// File returns the manifest entry for path.
func (m Manifest) File(path string) (ArtifactFile, bool) {
	for _, f := range m.Files {
		if f.Path == path {
			return f, true
		}
	}
	return ArtifactFile{}, false
}

func readRegular(path string, limit int64) ([]byte, error) {
	fi, err := os.Lstat(path)
	if err != nil || !fi.Mode().IsRegular() || fi.Size() > limit {
		return nil, errors.New("not a regular file within the size limit")
	}
	return os.ReadFile(path) // #nosec G304 -- a path the caller checked above
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path) // #nosec G304 -- operator-supplied artifact path, regular file checked by the caller
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// AttestationName is the release's SBOM attestation: an in-toto style statement, listed in the manifest (so SHA256SUMS and its signature cover it), that
// names the shipped programs by digest and binds them to the SBOM and licence inventory they were built with. It is made by tools/make_release.py.
const AttestationName = "ATTESTATION.json"

type attestation struct {
	Type          string `json:"_type"`
	PredicateType string `json:"predicateType"`
	Subject       []struct {
		Name   string            `json:"name"`
		Digest map[string]string `json:"digest"`
	} `json:"subject"`
	Predicate struct {
		Version   string `json:"version"`
		BuiltFrom string `json:"built_from"`
		SBOM      struct {
			Path   string `json:"path"`
			SHA256 string `json:"sha256"`
		} `json:"sbom"`
		Licenses struct {
			Path   string `json:"path"`
			SHA256 string `json:"sha256"`
		} `json:"licenses"`
		Note string `json:"note"`
	} `json:"predicate"`
}

// checkAttestation verifies a listed attestation against the manifest: same version and commit, every shipped program and both inventories named by the
// digests the manifest holds. An artifact built before attestations existed has none and is not affected.
func checkAttestation(dir string, m Manifest) error {
	_, ok := m.File(AttestationName)
	if !ok {
		return nil
	}
	raw, err := readRegular(filepath.Join(dir, AttestationName), 1<<20)
	if err != nil {
		return fmt.Errorf("%w: the attestation cannot be read", errBadArtf)
	}
	var a attestation
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&a); err != nil || a.Type != "https://in-toto.io/Statement/v1" || a.PredicateType != "https://svavyom.invalid/attestation/sbom/v1" {
		return fmt.Errorf("%w: the attestation is malformed", errBadArtf)
	}
	if a.Predicate.Version != m.Version || a.Predicate.BuiltFrom != m.BuiltFrom {
		return fmt.Errorf("%w: the attestation is about another version or commit than the manifest", errBadArtf)
	}
	same := func(path, sum string) bool {
		f, ok := m.File(path)
		return ok && f.SHA256 == sum
	}
	if !same(a.Predicate.SBOM.Path, a.Predicate.SBOM.SHA256) || !same(a.Predicate.Licenses.Path, a.Predicate.Licenses.SHA256) {
		return fmt.Errorf("%w: the attestation names an SBOM or licence inventory that is not the shipped one", errBadArtf)
	}
	seen := map[string]bool{}
	for _, s := range a.Subject {
		if !same(s.Name, s.Digest["sha256"]) {
			return fmt.Errorf("%w: the attestation names %s with a digest the manifest does not hold", errBadArtf, clean(s.Name))
		}
		seen[s.Name] = true
	}
	for _, b := range Binaries {
		if !seen["bin/"+b] {
			return fmt.Errorf("%w: the attestation does not cover bin/%s", errBadArtf, b)
		}
	}
	return nil
}
