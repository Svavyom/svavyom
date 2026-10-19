package ctl

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"example.invalid/dedicatedcloud/backend/internal/auth"
	"example.invalid/dedicatedcloud/backend/internal/operation"
	"example.invalid/dedicatedcloud/backend/internal/provision"
	"example.invalid/dedicatedcloud/backend/internal/sqlitedb"
)

// BundleOptions are the inputs of the support bundle.
type BundleOptions struct {
	// OutDir receives the bundle (created 0700 if absent); the file is 0600.
	OutDir string
	// ConfigPath overrides the installed configuration path.
	ConfigPath string
	// LogLines is how many recent journal lines per unit to include (default 300, at most 2000).
	LogLines int
	// Version is the product version recorded in the bundle.
	Version string
}

// BundleEntry is one file of a bundle, as listed in its manifest.
type BundleEntry struct {
	Name       string `json:"name"`
	Bytes      int    `json:"bytes"`
	SHA256     string `json:"sha256"`
	Redactions int    `json:"redactions"`
	Note       string `json:"note,omitempty"`
}

// BundleManifest is the first file of every bundle. It states what is inside and, as plainly, what is deliberately not.
type BundleManifest struct {
	Schema     int           `json:"schema"`
	Product    string        `json:"product"`
	Version    string        `json:"version"`
	CreatedAt  string        `json:"created_at"`
	Entries    []BundleEntry `json:"entries"`
	Excluded   []string      `json:"excluded"`
	Redactions int           `json:"redactions_total"`
}

// bundleExcluded is printed into every manifest.
var bundleExcluded = []string{
	"passwords and password hashes", "session cookies and CSRF tokens", "console tickets", "idempotency keys", "private SSH keys and SSH public key bodies",
	"TLS private keys and certificates", "the database file itself (only schema versions and recent operation states)", "VM disk, seed and backup contents",
	"unrelated host files (the bundle reads a fixed list of sources and never a glob)",
}

type bundleFile struct {
	name string
	body string
	note string
}

// SupportBundle collects a scrubbed diagnostic archive. Every text passes through Redact; a file that still looks like it holds a credential is replaced by
// a stub instead of being written. The result is a .tar.gz in OutDir, mode 0600, and the manifest.
func SupportBundle(ctx context.Context, e *Env, o BundleOptions) (string, BundleManifest, error) {
	if o.OutDir == "" || !filepath.IsAbs(o.OutDir) {
		return "", BundleManifest{}, errors.New("the output directory must be an absolute path")
	}
	if o.LogLines <= 0 {
		o.LogLines = 300
	}
	if o.LogLines > 2000 {
		o.LogLines = 2000
	}
	var files []bundleFile
	add := func(name, body, note string) { files = append(files, bundleFile{name: name, body: body, note: note}) }
	run := func(name string, args ...string) string {
		out, err := e.Run.Run(ctx, name, args...)
		if err != nil && strings.TrimSpace(out) == "" {
			return "(not available: " + clean(err.Error()) + ")\n"
		}
		return out
	}

	add("product.txt", fmt.Sprintf("product: Svavyom (Development Preview / Pre-Alpha)\nversion: %s\nbundle created: %s\nschema versions of this build: operation=%d accounts=%d\n",
		o.Version, e.Now().UTC().Format(time.RFC3339), operation.SchemaVersion(), auth.SchemaVersion()), "")
	if b, err := e.ReadFile(e.P(VersionFile)); err == nil {
		add("installed-version.txt", string(b), "")
	}
	osr := ""
	if b, err := e.ReadFile(e.P("/etc/os-release")); err == nil {
		kv := parseOSRelease(b)
		osr = fmt.Sprintf("ID=%s\nVERSION_ID=%s\nPRETTY_NAME=%s\n", kv["ID"], kv["VERSION_ID"], kv["PRETTY_NAME"])
	}
	add("os.txt", osr+run("uname", "-srm"), "")
	// Service states: a fixed property list, never the unit's environment.
	var svc strings.Builder
	for _, u := range Units {
		svc.WriteString("== " + u + "\n")
		svc.WriteString(run("systemctl", "show", "-p", "ActiveState,SubState,UnitFileState,NRestarts,Result,ExecMainStatus,ActiveEnterTimestamp", "--", u))
	}
	add("services.txt", svc.String(), "")
	add("config-validation.txt", textOf(ValidateConfig(ctx, e, ValidateOptions{ConfigPath: o.ConfigPath})), "")
	add("status.txt", textOf(Status(ctx, e, StatusOptions{})), "")
	for _, u := range Units {
		add("logs/"+strings.TrimSuffix(u, ".service")+".txt", run("journalctl", "-u", u, "-n", fmt.Sprint(o.LogLines), "--no-pager", "-o", "short-iso"), "recent journal lines, redacted")
	}
	add("versions.txt", "libvirt: "+firstLine(run("virsh", "--version"))+"\nqemu: "+firstLine(run("qemu-system-x86_64", "--version"))+"\n", "")
	add("libvirt-summary.txt", run("virsh", "-r", "-c", "qemu:///system", "net-list", "--all")+run("virsh", "-r", "-c", "qemu:///system", "pool-list", "--all")+
		run("virsh", "-r", "-c", "qemu:///system", "list", "--all"), "names and states only")

	cfgPath := o.ConfigPath
	if cfgPath == "" {
		cfgPath = e.P(ConfigFile)
	}
	if cfg, err := provision.LoadConfig(cfgPath); err == nil {
		add("provision-config.txt", fmt.Sprintf("pool=%s\nnetwork=%s\ndomain_type=%s\nlibvirt_uri=%s\nbackup_configured=%v\n", cfg.Pool, cfg.Network, cfg.DomainType, cfg.LibvirtURI, cfg.BackupDir != ""), "")
		if cat, cerr := provision.LoadCatalog(e.P(cfg.CatalogDir)); cerr == nil {
			type im struct {
				ID, Distribution, Version, SHA256, State, Evidence string
				SizeBytes                                          int64
			}
			var l []im
			for _, x := range cat.Images {
				l = append(l, im{x.ID, x.Distribution, x.Version, x.SHA256, x.State, x.Evidence, x.SizeBytes})
			}
			b, _ := json.MarshalIndent(l, "", "  ")
			add("image-catalog.json", string(b), "metadata and digests; no paths")
		}
	}
	add("database.txt", databaseSummary(ctx, e), "schema versions and recent operation states; the database file is not included")

	// Redact, refuse leaks, assemble.
	man := BundleManifest{Schema: 1, Product: "svavyom", Version: o.Version, CreatedAt: e.Now().UTC().Format(time.RFC3339), Excluded: bundleExcluded}
	var out []bundleFile
	for _, f := range files {
		clean, n := Redact(f.body)
		if MentionsSecret(clean) {
			clean, f.note = "[withheld: the redactor could not make this file safe]\n", "withheld"
		}
		man.Redactions += n
		sum := sha256.Sum256([]byte(clean))
		man.Entries = append(man.Entries, BundleEntry{Name: f.name, Bytes: len(clean), SHA256: hex.EncodeToString(sum[:]), Redactions: n, Note: f.note})
		out = append(out, bundleFile{name: f.name, body: clean})
	}
	sort.Slice(man.Entries, func(i, j int) bool { return man.Entries[i].Name < man.Entries[j].Name })
	mb, _ := json.MarshalIndent(man, "", "  ")
	out = append([]bundleFile{{name: "MANIFEST.json", body: string(mb) + "\n"}}, out...)

	if err := os.MkdirAll(o.OutDir, 0o700); err != nil {
		return "", man, err
	}
	var path string
	var f *os.File
	var err error
	for i := 0; i < 100; i++ {
		suffix := ""
		if i > 0 {
			suffix = fmt.Sprintf("-%d", i+1)
		}
		path = filepath.Join(o.OutDir, "svavyom-support-"+e.Now().UTC().Format("20060102T150405Z")+suffix+".tar.gz")
		f, err = os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) // #nosec G304 -- operator-supplied output directory, new file only
		if err == nil || !os.IsExist(err) {
			break
		}
	}
	if err != nil {
		return "", man, err
	}
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)
	for _, bf := range out {
		hdr := &tar.Header{Name: "svavyom-support/" + bf.name, Mode: 0o600, Size: int64(len(bf.body)), ModTime: e.Now().Truncate(time.Second), Typeflag: tar.TypeReg}
		if err := tw.WriteHeader(hdr); err != nil {
			_ = f.Close()
			return "", man, err
		}
		if _, err := tw.Write([]byte(bf.body)); err != nil {
			_ = f.Close()
			return "", man, err
		}
	}
	if err := tw.Close(); err != nil {
		_ = f.Close()
		return "", man, err
	}
	if err := gz.Close(); err != nil {
		_ = f.Close()
		return "", man, err
	}
	return path, man, f.Close()
}

func textOf(r Report) string {
	var b strings.Builder
	r.Text(&b)
	return b.String()
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	return clean(s)
}

// databaseSummary reads the API database read-only: the recorded schema versions against this build's, and the 50 newest operations (id, kind, type,
// status, attempts, error category, created time). Not the idempotency key, not who requested it, not any parameter.
func databaseSummary(ctx context.Context, e *Env) string {
	dbPath := e.P(LibDir + "/api/svavyom.db")
	db, err := sqlitedb.OpenReadOnly(dbPath)
	if err != nil {
		return "(no readable database at the installed location)\n"
	}
	defer db.Close()
	var b strings.Builder
	vs, _ := sqlitedb.Versions(ctx, db)
	fmt.Fprintf(&b, "recorded schema versions: %v\nthis build expects: operation=%d accounts=%d\n", vs, operation.SchemaVersion(), auth.SchemaVersion())
	b.WriteString(recentOperations(ctx, db))
	return b.String()
}

func recentOperations(ctx context.Context, db *sql.DB) string {
	rows, err := db.QueryContext(ctx, `SELECT id, resource_kind, type, status, attempts, error_category, created_at FROM operations ORDER BY seq DESC LIMIT 50`)
	if err != nil {
		return "(no operations table)\n"
	}
	defer rows.Close()
	var b strings.Builder
	b.WriteString("id kind type status attempts error_category created_at\n")
	for rows.Next() {
		var id, kind, typ, status, cat string
		var attempts int
		var created int64
		if err := rows.Scan(&id, &kind, &typ, &status, &attempts, &cat, &created); err != nil {
			break
		}
		fmt.Fprintf(&b, "%s %s %s %s %d %s %s\n", id, kind, typ, status, attempts, cat, time.Unix(created, 0).UTC().Format(time.RFC3339))
	}
	return b.String()
}
