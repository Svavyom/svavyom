package ctl

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"

	"example.invalid/dedicatedcloud/backend/internal/fwstatus"
	"example.invalid/dedicatedcloud/backend/internal/provision"
)

// ServiceUsers maps the runtime identity names of the trust declaration to the system accounts that must back them.
var ServiceUsers = map[string]string{"api": "svavyom-api", "agent": "svavyom-ro", "mutation": "svavyom-mut", "console": "svavyom-con"}

// ValidateOptions are the inputs of configuration validation.
type ValidateOptions struct {
	ConfigPath string
	// Deep also re-hashes every catalog image (slow for large images).
	Deep bool
	// Online also asks the running system: the read-only libvirt client for the pool and network, and the agent socket.
	Online bool
}

func ownerOf(fi fs.FileInfo) (uid int, ok bool) {
	st, k := fi.Sys().(*syscall.Stat_t)
	if !k {
		return 0, false
	}
	return int(st.Uid), true // #nosec G115 -- a uid fits int
}

func gidOf(fi fs.FileInfo) (gid int, ok bool) {
	st, k := fi.Sys().(*syscall.Stat_t)
	if !k {
		return 0, false
	}
	return int(st.Gid), true // #nosec G115 -- a gid fits int
}

// ValidateConfig checks the installation's configuration without changing anything and returns typed, actionable findings. It never prints a secret:
// TLS files are checked for presence and mode only.
func ValidateConfig(ctx context.Context, e *Env, o ValidateOptions) Report {
	var list []Finding
	add := func(id, status, code, detail, remedy string) {
		list = append(list, Finding{ID: id, Status: status, Required: true, Code: code, Detail: clean(detail), Remediation: remedy})
	}
	real := e.Root == "/" || e.Root == ""
	path := o.ConfigPath
	if path == "" {
		path = e.P(ConfigFile)
	}

	// 1. Syntax: strict JSON, the known fields, the grammars.
	raw, err := e.ReadFile(path)
	if err != nil {
		add("config-file", Fail, "CONFIG_MISSING", "cannot read the provisioning configuration", "Install the configuration (svavyom-ctl install) or pass --config.")
		return NewReport("validate-config", list)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var probe provision.Config
	if err := dec.Decode(&probe); err != nil {
		add("config-syntax", Fail, "CONFIG_SYNTAX", "not valid JSON for the provisioning configuration: "+clean(err.Error()), "Fix the syntax; unknown fields are refused.")
		return NewReport("validate-config", list)
	}
	cfg, err := provision.LoadConfig(path)
	if err != nil {
		add("config-syntax", Fail, "CONFIG_INVALID", "a field is outside its allowed grammar (paths absolute and clean, names valid, domain type and URI paired)", "Compare with packages/ubuntu/etc/provision.json.in.")
		return NewReport("validate-config", list)
	}
	add("config-syntax", Pass, "", "syntax and grammars are valid", "")

	// 2. The file itself and its directory are root-owned and closed to writes (a trust anchor).
	if fi, err := e.Lstat(path); err == nil && real {
		if uid, ok := ownerOf(fi); ok && (uid != 0 || fi.Mode().Perm()&0o022 != 0 || fi.Mode()&fs.ModeSymlink != 0) {
			add("config-ownership", Fail, "CONFIG_NOT_ROOT_OWNED", "the configuration is not a root-owned regular file closed to group and other writes", "chown root:root and chmod 0644 the file.")
		} else {
			add("config-ownership", Pass, "", "root-owned, mode "+fmt.Sprintf("%04o", fi.Mode().Perm()), "")
		}
	}

	// 3. Required paths.
	for _, r := range []struct{ id, p string }{{"catalog-dir", cfg.CatalogDir}, {"state-dir", cfg.StateDir}} {
		fi, err := e.Lstat(e.P(r.p))
		switch {
		case err != nil:
			add(r.id, Fail, "PATH_MISSING", r.p+" does not exist", "Create it (systemd-tmpfiles --create after installing packages/ubuntu/tmpfiles.d/svavyom.conf).")
		case !fi.IsDir():
			add(r.id, Fail, "PATH_NOT_DIR", r.p+" is not a directory", "")
		default:
			add(r.id, Pass, "", r.p, "")
		}
	}
	if real {
		if fi, err := e.Lstat(e.P(cfg.StateDir)); err == nil {
			uid, _ := ownerOf(fi)
			want, _, perr := e.Getpw(ServiceUsers["mutation"])
			if perr == nil && (uid != want || fi.Mode().Perm()&0o077 != 0) {
				add("state-dir-owner", Fail, "STATE_DIR_OWNER", "the state directory must be owned by "+ServiceUsers["mutation"]+" with mode 0700", "chown svavyom-mut:svavyom-mut and chmod 0700.")
			}
		}
	}

	// 4. Service identities: the declared uids/gids are the system accounts' (a stale rendering after a user was recreated is caught here).
	if cfg.Trust == nil {
		add("trust-declaration", Fail, "TRUST_MISSING", "no trust declaration (required for the kvm domain type)", "Add the trust section (see provision.json.in).")
	} else {
		seen := map[string]bool{}
		okAll := true
		for _, id := range cfg.Trust.Runtime {
			seen[id.Name] = true
			acct, known := ServiceUsers[id.Name]
			if !known {
				add("service-"+id.Name, Fail, "IDENTITY_UNKNOWN", "unknown runtime identity "+id.Name, "Use api, agent, mutation and console.")
				okAll = false
				continue
			}
			uid, gid, perr := e.Getpw(acct)
			switch {
			case perr != nil:
				add("service-"+id.Name, Fail, "SERVICE_USER_MISSING", "account "+acct+" does not exist", "systemd-sysusers packages/ubuntu/sysusers.d/svavyom.conf")
				okAll = false
			case uid == 0 || gid == 0:
				add("service-"+id.Name, Fail, "SERVICE_USER_ROOT", acct+" resolves to uid or gid 0", "A Svavyom service never runs as root.")
				okAll = false
			case uid != int(id.UID) || !containsU32(id.GIDs, gid): // #nosec G115 -- ids are small
				add("service-"+id.Name, Fail, "SERVICE_ID_MISMATCH", acct+" has uid "+fmt.Sprint(uid)+" gid "+fmt.Sprint(gid)+", the configuration says otherwise", "Re-render the configuration (svavyom-ctl install) after the users exist.")
				okAll = false
			}
		}
		for n := range ServiceUsers {
			if !seen[n] && n != "console" {
				add("service-"+n, Fail, "IDENTITY_MISSING", "the trust declaration has no "+n+" identity", "Add it (see provision.json.in).")
				okAll = false
			}
		}
		if okAll {
			add("service-ids", Pass, "", "every declared runtime identity matches a non-root system account", "")
		}
		if pol, perr := cfg.TrustPolicy(false); perr != nil {
			add("trust-policy", Fail, "TRUST_POLICY", "the trust declaration is not acceptable (root deploy owner, distinct non-root identities)", "")
		} else if real {
			if bad := pol.CheckDeployment(path, cfg); len(bad) > 0 {
				add("trust-anchors", Fail, "TRUST_ANCHOR_WRITABLE", "not operator-owned and read-only for the runtime identities: "+strings.Join(bad, ", "), "Make these root-owned and closed to group and other writes; never loosen a mode to make a service start.")
			} else {
				add("trust-anchors", Pass, "", "configuration, catalog, image store and published images are operator-owned and not writable by any runtime identity", "")
			}
		}
	}

	// 5. Image catalog and store.
	if cat, err := provision.LoadCatalog(e.P(cfg.CatalogDir)); err != nil {
		if os.IsNotExist(err) || strings.Contains(err.Error(), "no such file") {
			list = append(list, Finding{ID: "image-catalog", Status: Info, Code: "CATALOG_EMPTY", Detail: "no catalog yet: import an image with api register-image"})
		} else {
			add("image-catalog", Fail, "CATALOG_INVALID", "the image catalog cannot be read or has an unknown format", "Re-import the images with api register-image.")
		}
	} else {
		states := map[string]int{}
		bad := 0
		for _, im := range cat.Images {
			states[im.State]++
			if o.Deep {
				if _, verr := cat.Verify(im); verr != nil {
					bad++
				}
			}
		}
		if len(cat.Images) == 0 {
			list = append(list, Finding{ID: "image-catalog", Status: Info, Code: "CATALOG_EMPTY", Detail: "no image imported yet: import one with api register-image"})
		} else if bad > 0 {
			add("image-catalog", Fail, "IMAGE_CHANGED", fmt.Sprintf("%d image(s) do not match their recorded digest", bad), "Do not use these images; re-import them.")
		} else {
			add("image-catalog", Pass, "", fmt.Sprintf("%d image(s): %v%s", len(cat.Images), states, map[bool]string{true: ", digests re-checked", false: ""}[o.Deep]), "")
		}
	}

	// 6. Backup store (optional).
	if cfg.BackupDir != "" {
		fi, err := e.Lstat(e.P(cfg.BackupDir))
		switch {
		case err != nil || !fi.IsDir():
			add("backup-dir", Fail, "BACKUP_DIR_MISSING", cfg.BackupDir+" is not a directory", "Create it owned by svavyom-mut with mode 0700.")
		case real && fi.Mode().Perm()&0o077 != 0:
			add("backup-dir", Fail, "BACKUP_DIR_MODE", "the backup directory must be closed to group and others (0700)", "chmod 0700 and chown svavyom-mut:svavyom-mut.")
		default:
			add("backup-dir", Pass, "", cfg.BackupDir, "")
		}
	} else {
		list = append(list, Finding{ID: "backup-dir", Status: Info, Code: "BACKUPS_NOT_CONFIGURED", Detail: "no backup_dir: backups are refused"})
	}

	// 7. The API unit: the listener and the TLS requirement; the console broker unit.
	unit, uerr := e.ReadFile(e.P(UnitDir + "/svavyom-api.service"))
	if uerr != nil {
		list = append(list, Finding{ID: "api-unit", Status: Info, Code: "UNIT_NOT_INSTALLED", Detail: "svavyom-api.service is not installed"})
	} else {
		validateListener(e, string(unit), real, add)
	}
	if _, err := e.ReadFile(e.P(UnitDir + "/svavyom-console.service")); err == nil && cfg.Trust != nil {
		has := false
		for _, id := range cfg.Trust.Runtime {
			has = has || id.Name == "console"
		}
		if !has {
			add("console-broker", Fail, "CONSOLE_IDENTITY_MISSING", "the console unit is installed but the trust declaration has no console identity", "Add the console identity and re-render.")
		} else {
			add("console-broker", Pass, "", "the console identity is declared", "")
		}
	}

	// 8. Online: the running libvirt objects and the agent.
	if o.Online {
		for _, r := range []struct{ kind, name, id string }{{"net", cfg.Network, "libvirt-network"}, {"pool", cfg.Pool, "libvirt-pool"}} {
			st := virshState(ctx, e, r.kind, r.name)
			if st == Pass {
				add(r.id, Pass, "", r.name+" is active", "")
			} else {
				add(r.id, NotReady, strings.ToUpper(strings.ReplaceAll(r.id, "-", "_"))+"_NOT_READY", r.name+" is not active or cannot be queried", remedyFor(map[string]string{"net": "network", "pool": "pool"}[r.kind], r.name))
			}
		}
		if err := e.Dial(e.P("/run/svavyom/agent/agent.sock")); err != nil {
			add("agent-socket", NotReady, "AGENT_UNREACHABLE", "the read-only agent socket does not answer", "systemctl start svavyom-agent")
		} else {
			add("agent-socket", Pass, "", "the read-only agent answers", "")
		}
	}
	// The last firewall check recorded by install, upgrade or `firewall-check --write` (advisory: it never changes the verdict).
	if r, ok := fwstatus.Read(e.ReadFile, e.P(FirewallStatusFile), e.Now(), 7*24*time.Hour); ok {
		f := firewallFinding(r)
		f.Required = false
		list = append(list, f)
	}
	return NewReport("validate-config", list)
}

func containsU32(l []uint32, v int) bool {
	for _, x := range l {
		if int(x) == v { // #nosec G115 -- small ids
			return true
		}
	}
	return false
}

var flagRE = func(name string) *regexp.Regexp {
	return regexp.MustCompile(`(?m)--` + regexp.QuoteMeta(name) + `[ =]+([^\s\\]+)`)
}

// validateListener enforces the native TLS rule: a listener that is not loopback needs a certificate and key, the key closed to everyone but root and the API group.
func validateListener(e *Env, unit string, real bool, add func(id, status, code, detail, remedy string)) {
	m := flagRE("listen").FindStringSubmatch(unit)
	if m == nil {
		add("api-listener", Fail, "LISTEN_MISSING", "the API unit has no --listen", "")
		return
	}
	host, _, err := net.SplitHostPort(m[1])
	if err != nil {
		add("api-listener", Fail, "LISTEN_INVALID", "--listen is not host:port", "")
		return
	}
	ip := net.ParseIP(host)
	loop := host == "localhost" || (ip != nil && ip.IsLoopback())
	cert, key := flagRE("tls-cert").FindStringSubmatch(unit), flagRE("tls-key").FindStringSubmatch(unit)
	if loop {
		add("api-listener", Pass, "", "loopback listener "+m[1]+" (put a TLS-terminating proxy in front for remote access)", "")
		return
	}
	if cert == nil || key == nil {
		add("api-listener", Fail, "TLS_REQUIRED", "a non-loopback listener needs --tls-cert and --tls-key", "Provide a certificate and key; the API refuses plain HTTP on a non-loopback address.")
		return
	}
	for _, p := range []string{cert[1], key[1]} {
		fi, err := e.Lstat(e.P(p))
		if err != nil || !fi.Mode().IsRegular() {
			add("api-tls", Fail, "TLS_FILE_MISSING", filepath.Base(p)+" is missing or not a regular file", "Install the certificate and key (svavyom-ctl install --tls-self-signed HOSTNAME for a Development Preview certificate).")
			return
		}
		if real && p == key[1] && fi.Mode().Perm()&0o007 != 0 {
			add("api-tls", Fail, "TLS_KEY_MODE", "the TLS private key is readable by others", "chmod 0640 and chown root:svavyom-api.")
			return
		}
	}
	add("api-listener", Pass, "", "non-loopback listener "+m[1]+" with TLS", "")
}
