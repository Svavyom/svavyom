package provision

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"example.invalid/dedicatedcloud/backend/internal/alerts"
)

// Config is the server-owned provisioning configuration (a JSON file the operator writes; never anything a browser sends).
// Storage locations are separated: the image catalog directory holds base images (read by the mutation helper), the libvirt
// pool holds VM root volumes and seed volumes, StateDir holds runtime scratch state.
type Config struct {
	CatalogDir string `json:"catalog_dir"` // absolute: base images and catalog.json
	Pool       string `json:"pool"`        // libvirt storage pool owned by Svavyom
	Network    string `json:"network"`     // the single libvirt NAT network profile
	DomainType string `json:"domain_type"` // "kvm" (production) or "test" (libvirt test driver)
	LibvirtURI string `json:"libvirt_uri"` // qemu:///system or test:///default
	StateDir   string `json:"state_dir"`   // absolute, owner-only
	// BackupDir is where stopped-VM backups are written (M2-S07): absolute, owned by the mutation identity, closed to others, outside the pool, the
	// catalog and the state directory. Empty means backups are not configured and every backup operation is refused.
	BackupDir string `json:"backup_dir,omitempty"`
	// Trust declares who owns the trust anchors and which runtime identities must not be able to write them (DR-017). Required
	// for the production domain type (kvm); a test-driver configuration may omit it only when run with the insecure dev policy.
	Trust *TrustSpec `json:"trust,omitempty"`
	// BackupTargets are the off-host places a backup can be copied to (M2-E01-S01, DR-023 D4). Like the rest of this file they are a trust
	// anchor: only the operator (root) writes them, and no request can name anything but one of these ids.
	BackupTargets []BackupTarget `json:"backup_targets,omitempty"`
	// Alerts are the operator's alert settings (DR-024 D2). They are written only by the operator: the browser cannot change a threshold or the webhook.
	Alerts *AlertSettings `json:"alerts,omitempty"`
	// Schedule is the operator's policy for scheduled backups (DR-024 D3).
	Schedule *ScheduleSettings `json:"schedule,omitempty"`
}

// AlertSettings: free-space thresholds in percent free (warning above critical) and one webhook.
type AlertSettings struct {
	DiskWarnPercent int      `json:"disk_warn_percent,omitempty"` // default 20
	DiskCritPercent int      `json:"disk_crit_percent,omitempty"` // default 10
	Webhook         *Webhook `json:"webhook,omitempty"`
}

// Webhook is the one destination of alert notifications. AllowInternal permits http and addresses on loopback or private ranges.
type Webhook struct {
	URL           string `json:"url"`
	AllowInternal bool   `json:"allow_internal,omitempty"`
}

// ScheduleSettings: Disabled turns the backup scheduler off for the whole host (schedules stay stored and show as paused).
type ScheduleSettings struct {
	Disabled bool `json:"disabled,omitempty"`
}

// BackupTarget is one off-host backup target. Kind "path" is a directory the operator mounted (a network share, a USB disk); kind "ssh" is a
// directory on another host reached over SSH with a key file and a PINNED host key (no trust on first use).
type BackupTarget struct {
	ID      string `json:"id"`
	Kind    string `json:"kind"`               // ssh | path
	Dir     string `json:"dir"`                // absolute directory (the mounted path, or the remote directory)
	Host    string `json:"host,omitempty"`     // ssh: DNS name or IPv4 address
	Port    int    `json:"port,omitempty"`     // ssh: default 22
	User    string `json:"user,omitempty"`     // ssh: remote account
	KeyFile string `json:"key_file,omitempty"` // ssh: absolute path of the client private key, readable by the offsite service only
	HostKey string `json:"host_key,omitempty"` // ssh: the server's public key, one line: "ssh-ed25519 AAAA..."
}

// MaxBackupTargets bounds the declared targets.
const MaxBackupTargets = 8

var (
	targetIDRE   = regexp.MustCompile(`^[a-z][a-z0-9-]{1,30}[a-z0-9]$`)
	targetHostRE = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$`)
	targetUserRE = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)
	targetDirRE  = regexp.MustCompile(`^/[A-Za-z0-9._/-]{1,198}$`)
	hostKeyRE    = regexp.MustCompile(`^(ssh-ed25519|ecdsa-sha2-nistp(256|384|521)|ssh-rsa) [A-Za-z0-9+/]{20,1000}={0,2}$`)
)

// ValidTargetID reports whether id has the grammar of a backup target id.
func ValidTargetID(id string) bool { return targetIDRE.MatchString(id) }

func (t BackupTarget) validate(c Config) error {
	if !targetIDRE.MatchString(t.ID) || !targetDirRE.MatchString(t.Dir) || filepath.Clean(t.Dir) != t.Dir || t.Dir == "/" || strings.Contains(t.Dir, "..") {
		return ErrInvalidConfig
	}
	switch t.Kind {
	case "path":
		if t.Host != "" || t.Port != 0 || t.User != "" || t.KeyFile != "" || t.HostKey != "" {
			return ErrInvalidConfig
		}
		within := func(p, dir string) bool {
			return dir != "" && (p == dir || strings.HasPrefix(p, dir+"/") || strings.HasPrefix(dir, p+"/"))
		}
		// A "path" target must be somewhere else than Svavyom's own storage: a copy next to the original is not off-host.
		for _, own := range []string{c.CatalogDir, c.StateDir, c.BackupDir, "/var/lib/svavyom", "/etc/svavyom"} {
			if within(t.Dir, own) {
				return ErrInvalidConfig
			}
		}
	case "ssh":
		port := t.Port
		if port == 0 {
			port = 22
		}
		if !targetHostRE.MatchString(t.Host) || port < 1 || port > 65535 || !targetUserRE.MatchString(t.User) ||
			!targetDirRE.MatchString(t.KeyFile) || filepath.Clean(t.KeyFile) != t.KeyFile || !hostKeyRE.MatchString(t.HostKey) {
			return ErrInvalidConfig
		}
	default:
		return ErrInvalidConfig
	}
	return nil
}

// TrustSpec is the operator-declared ownership model of the deployment.
type TrustSpec struct {
	DeployUID uint32          `json:"deploy_uid"` // owner of helper, config, catalog, store and images; 0 (root) for kvm
	Runtime   []TrustIdentity `json:"runtime_identities"`
}

// TrustIdentity is one runtime service identity; Name is one of api, agent, mutation, console.
type TrustIdentity struct {
	Name string   `json:"name"`
	UID  uint32   `json:"uid"`
	GIDs []uint32 `json:"gids"`
}

// ErrNoTrust means production mutation mode was configured without a valid trust declaration.
var ErrNoTrust = errors.New("provision: the configuration has no valid \"trust\" section (deploy_uid and the api, agent and mutation runtime identities)")

// TrustPolicy builds the trust policy. insecureDev selects the development/test policy and is the only way to run without a
// trust declaration. Otherwise the declaration must name exactly the api, agent and mutation identities, none of which may be
// the deployment owner, and kvm requires the owner to be root. The console broker identity is declared too when the deployment has one
// (every identity that runs beside the trust anchors must be declared, so none of them can be left able to write one).
func (c Config) TrustPolicy(insecureDev bool) (Policy, error) {
	if insecureDev {
		return DevPolicy(), nil
	}
	t := c.Trust
	if t == nil || len(t.Runtime) < 3 || len(t.Runtime) > 4 || (c.DomainType == "kvm" && t.DeployUID != 0) {
		return Policy{}, ErrNoTrust
	}
	seen := map[string]bool{}
	var ids []Identity
	for _, r := range t.Runtime {
		if (r.Name != "api" && r.Name != "agent" && r.Name != "mutation" && r.Name != "console") || seen[r.Name] || r.UID == t.DeployUID || len(r.GIDs) > 32 {
			return Policy{}, ErrNoTrust
		}
		seen[r.Name] = true
		ids = append(ids, Identity(r))
	}
	if !seen["api"] || !seen["agent"] || !seen["mutation"] {
		return Policy{}, ErrNoTrust
	}
	return Policy{Owner: t.DeployUID, Runtime: ids}, nil
}

var nameTokenRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$`)

// Validate checks every field: paths absolute and clean, names in the id grammar, a closed set for the type and URI.
func (c Config) Validate() error {
	for _, p := range []string{c.CatalogDir, c.StateDir} {
		if !filepath.IsAbs(p) || filepath.Clean(p) != p || len(p) > 200 {
			return ErrInvalidConfig
		}
	}
	if !nameTokenRE.MatchString(c.Pool) || !nameTokenRE.MatchString(c.Network) {
		return ErrInvalidConfig
	}
	if c.BackupDir != "" {
		within := func(p, dir string) bool {
			return p == dir || strings.HasPrefix(p, dir+"/") || strings.HasPrefix(dir, p+"/")
		}
		if !filepath.IsAbs(c.BackupDir) || filepath.Clean(c.BackupDir) != c.BackupDir || len(c.BackupDir) > 200 || c.BackupDir == "/" ||
			within(c.BackupDir, c.CatalogDir) || within(c.BackupDir, c.StateDir) {
			return ErrInvalidConfig
		}
	}
	if len(c.BackupTargets) > MaxBackupTargets || (len(c.BackupTargets) > 0 && c.BackupDir == "") {
		return ErrInvalidConfig // a target is a place to copy local backups to: without a local store there is nothing to copy
	}
	seen := map[string]bool{}
	for _, t := range c.BackupTargets {
		if err := t.validate(c); err != nil || seen[t.ID] {
			return ErrInvalidConfig
		}
		seen[t.ID] = true
	}
	if a := c.Alerts; a != nil {
		th := alerts.Thresholds{WarnPercent: a.DiskWarnPercent, CritPercent: a.DiskCritPercent}.WithDefaults()
		if !th.Valid() {
			return ErrInvalidConfig
		}
		if a.Webhook != nil && alerts.ValidateWebhook(a.Webhook.URL, a.Webhook.AllowInternal) != nil {
			return ErrInvalidConfig
		}
	}
	if c.DomainType == "kvm" && c.Trust == nil {
		return ErrInvalidConfig
	}
	switch c.DomainType + "|" + c.LibvirtURI {
	case "kvm|qemu:///system", "test|test:///default":
	default:
		return ErrInvalidConfig
	}
	return nil
}

// LoadConfig reads and validates the configuration file. Unknown fields are refused.
func LoadConfig(path string) (Config, error) {
	b, err := os.ReadFile(filepath.Clean(path)) // #nosec G304 -- operator-supplied configuration path
	if err != nil || len(b) > 16<<10 {
		return Config{}, ErrInvalidConfig
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var c Config
	if err := dec.Decode(&c); err != nil {
		return Config{}, ErrInvalidConfig
	}
	if err := c.Validate(); err != nil {
		return Config{}, err
	}
	return c, nil
}

func (c Config) String() string {
	return fmt.Sprintf("provision config (pool %s, network %s)", c.Pool, c.Network)
}
