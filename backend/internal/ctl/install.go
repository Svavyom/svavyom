package ctl

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"example.invalid/dedicatedcloud/backend/internal/provision"
)

// InstallOptions are the inputs of install and upgrade.
type InstallOptions struct {
	// Artifact is the release artifact directory.
	Artifact string
	// Apply performs the plan; without it only the plan is printed.
	Apply bool
	// AllowNotReady proceeds when the preflight is NOT_READY (never when it FAILs); for a clean-room install where libvirt hardware is absent on purpose.
	AllowNotReady bool
	// TLSSelfSigned, when set, creates a Development Preview certificate for this host name if none exists.
	TLSSelfSigned string
	// Pool and Network name the libvirt pool and network the configuration uses (defaults svavyom and default).
	Pool, Network string
	// BackupDir, when set, configures the local backup store (created 0700, owned by the mutation identity) and lets the mutation unit write there.
	BackupDir string
	// CreatePool defines, starts and autostarts the libvirt pool from the artifact's template when it does not exist.
	CreatePool bool
	// EnableMutation and EnableConsole install the Development Preview feature switches as an API drop-in.
	EnableMutation, EnableConsole bool
	// MinFreeGiB is the free space the preflight wants on the state file system (default 30; a small lab host may lower it, a FAIL is still a FAIL).
	MinFreeGiB int
	// EnableNightlyBoot ("HH:MM") installs the nightly real guest boot check (DR-024 D4): a service account of the operator role, a service and a timer.
	// DisableNightlyBoot removes the timer and the service.
	EnableNightlyBoot  string
	DisableNightlyBoot bool
	// Listen is the API listen address (default 0.0.0.0:8443; it must come with TLS unless loopback).
	Listen string
}

// placeholderRE matches a template placeholder such as @SVAVYOM_API_UID@ (a comment may mention the pattern, e.g. "@SVAVYOM_..._UID@", without being one).
var placeholderRE = regexp.MustCompile(`@[A-Z][A-Z0-9_]*@`)

var hostNameRE = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9.-]{0,61}[A-Za-z0-9])?$`)

func (o *InstallOptions) defaults() {
	if o.Pool == "" {
		o.Pool = "svavyom"
	}
	if o.Network == "" {
		o.Network = "default"
	}
	if o.Listen == "" {
		o.Listen = "0.0.0.0:8443"
	}
}

func (o InstallOptions) validate() error {
	nameRE := regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$`)
	if !nameRE.MatchString(o.Pool) || !nameRE.MatchString(o.Network) {
		return errors.New("--pool and --network must be libvirt object names")
	}
	if o.TLSSelfSigned != "" && !hostNameRE.MatchString(o.TLSSelfSigned) {
		return errors.New("--tls-self-signed needs a host name")
	}
	if o.BackupDir != "" && (!filepath.IsAbs(o.BackupDir) || filepath.Clean(o.BackupDir) != o.BackupDir || len(o.BackupDir) > 200) {
		return errors.New("--backup-dir must be a clean absolute path")
	}
	if _, _, err := net.SplitHostPort(o.Listen); err != nil {
		return errors.New("--listen must be host:port")
	}
	if o.EnableNightlyBoot != "" && !hhmmRE.MatchString(o.EnableNightlyBoot) {
		return errors.New("--enable-nightly-boot needs a time of day written HH:MM, for example 02:30")
	}
	if o.EnableNightlyBoot != "" && o.DisableNightlyBoot {
		return errors.New("--enable-nightly-boot and --disable-nightly-boot exclude each other")
	}
	return nil
}

// loopbackListen reports whether the listen address is loopback only.
func loopbackListen(addr string) bool {
	h, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	ip := net.ParseIP(h)
	return h == "localhost" || (ip != nil && ip.IsLoopback())
}

type ids struct{ apiU, apiG, roU, roG, mutU, mutG, conU, conG, lvG int }

func (e *Env) serviceIDs() (ids, error) {
	var d ids
	var err error
	if d.apiU, d.apiG, err = e.Getpw("svavyom-api"); err != nil {
		return d, errors.New("the account svavyom-api does not exist")
	}
	if d.roU, d.roG, err = e.Getpw("svavyom-ro"); err != nil {
		return d, errors.New("the account svavyom-ro does not exist")
	}
	if d.mutU, d.mutG, err = e.Getpw("svavyom-mut"); err != nil {
		return d, errors.New("the account svavyom-mut does not exist")
	}
	if d.conU, d.conG, err = e.Getpw("svavyom-con"); err != nil {
		return d, errors.New("the account svavyom-con does not exist")
	}
	if d.lvG, err = e.Getgr("libvirt"); err != nil {
		return d, errors.New("the group libvirt does not exist (install the libvirt packages first)")
	}
	for _, v := range []int{d.apiU, d.apiG, d.roU, d.roG, d.mutU, d.mutG, d.conU, d.conG, d.lvG} {
		if v == 0 {
			return d, errors.New("a service identity resolves to uid or gid 0; refusing")
		}
	}
	return d, nil
}

func (d ids) subst() map[string]string {
	return map[string]string{
		"@SVAVYOM_API_UID@": fmt.Sprint(d.apiU), "@SVAVYOM_API_GID@": fmt.Sprint(d.apiG), "@SVAVYOM_RO_UID@": fmt.Sprint(d.roU), "@SVAVYOM_RO_GID@": fmt.Sprint(d.roG),
		"@SVAVYOM_MUT_UID@": fmt.Sprint(d.mutU), "@SVAVYOM_MUT_GID@": fmt.Sprint(d.mutG), "@LIBVIRT_GID@": fmt.Sprint(d.lvG),
		"@SVAVYOM_CON_UID@": fmt.Sprint(d.conU), "@SVAVYOM_CON_GID@": fmt.Sprint(d.conG),
	}
}

func readArtifact(dir, rel string) ([]byte, error) {
	return readRegular(filepath.Join(dir, filepath.FromSlash(rel)), 64<<20)
}

// installSteps adds the steps that put the artifact's files in place (binaries, web assets, units, drop-ins, VERSION). They are shared by install and upgrade.
func (e *Env) installSteps(p *Plan, m Manifest, o InstallOptions, w io.Writer) {
	p.add("install the "+fmt.Sprint(len(Binaries))+" binaries into "+LibexecDir+" (root:root 0755, replaced atomically)", func() error {
		if err := e.ensureDir(e.P(LibexecDir), 0o755, 0, 0); err != nil {
			return err
		}
		for _, b := range Binaries {
			data, err := readArtifact(o.Artifact, "bin/"+b)
			if err != nil {
				return err
			}
			changed, err := e.writeAtomic(e.P(LibexecDir+"/"+b), data, 0o755, 0, 0)
			if err != nil {
				return err
			}
			if !changed {
				_, _ = fmt.Fprintf(w, "      %s unchanged\n", b)
			}
		}
		return nil
	})
	p.add("install the web assets into "+ShareDir+"/web (root:root, read-only)", func() error {
		if err := e.ensureDir(e.P(ShareDir+"/web"), 0o755, 0, 0); err != nil {
			return err
		}
		var want []string
		for _, f := range m.Files {
			if !strings.HasPrefix(f.Path, "web/") {
				continue
			}
			want = append(want, strings.TrimPrefix(f.Path, "web/"))
			data, err := readArtifact(o.Artifact, f.Path)
			if err != nil {
				return err
			}
			dst := e.P(ShareDir + "/web/" + strings.TrimPrefix(f.Path, "web/"))
			if err := e.ensureDir(filepath.Dir(dst), 0o755, 0, 0); err != nil {
				return err
			}
			if _, err := e.writeAtomic(dst, data, 0o644, 0, 0); err != nil {
				return err
			}
		}
		if len(want) == 0 {
			return errors.New("the artifact carries no web assets")
		}
		return nil
	})
	p.add("render and install the five systemd units into "+UnitDir+" (root:root 0644)", func() error {
		d, err := e.serviceIDs()
		if err != nil {
			return err
		}
		for _, u := range Units {
			tpl, err := readArtifact(o.Artifact, "packages/ubuntu/systemd/"+u+".in")
			if err != nil {
				return err
			}
			text := sub(string(tpl), d.subst())
			text = strings.ReplaceAll(text, "--listen 0.0.0.0:8443", "--listen "+o.Listen)
			if u == "svavyom-api.service" && loopbackListen(o.Listen) {
				// A loopback listener is plain HTTP (the same rule the feature drop-in follows).
				text = strings.ReplaceAll(text, "    --tls-cert /etc/svavyom/tls/cert.pem --tls-key /etc/svavyom/tls/key.pem \\\n", "")
			}
			if placeholderRE.MatchString(text) {
				return errors.New("an unreplaced placeholder is left in " + u)
			}
			if _, err := e.writeAtomic(e.P(UnitDir+"/"+u), []byte(text), 0o644, 0, 0); err != nil {
				return err
			}
		}
		return nil
	})
	p.add("install the Development Preview feature switches and the backup path as systemd drop-ins (only what was asked for)", func() error { return e.dropIns(o) })
	p.add("record the installed version "+m.Version, func() error {
		_, err := e.writeAtomic(e.P(VersionFile), []byte(m.Version+"\n"), 0o644, 0, 0)
		return err
	})
}

// dropIns writes (or removes) the API feature drop-in and the mutation backup drop-in so that the units match the options exactly.
func (e *Env) dropIns(o InstallOptions) error {
	apiDir := e.P(UnitDir + "/svavyom-api.service.d")
	feat := apiDir + "/features.conf"
	if !o.EnableMutation && !o.EnableConsole {
		if err := os.Remove(feat); err != nil && !os.IsNotExist(err) {
			return err
		}
	} else {
		if err := e.ensureDir(apiDir, 0o755, 0, 0); err != nil {
			return err
		}
		flags := ""
		if o.EnableMutation {
			flags += " \\\n    --experimental-mutation"
		}
		if o.EnableConsole {
			flags += " \\\n    --experimental-console"
		}
		tls := ""
		if !loopbackListen(o.Listen) {
			tls = " \\\n    --tls-cert /etc/svavyom/tls/cert.pem --tls-key /etc/svavyom/tls/key.pem"
		}
		body := "# Written by svavyom-ctl install: the Development Preview feature switches (default closed). A drop-in replaces ExecStart, so it repeats the full command.\n" +
			"[Service]\nExecStart=\nExecStart=/usr/libexec/svavyom/api serve \\\n    --db /var/lib/svavyom/api/svavyom.db \\\n    --listen " + o.Listen + tls +
			" \\\n    --static-dir /usr/share/svavyom/web \\\n    --agent-socket /run/svavyom/agent/agent.sock \\\n    --mutation-socket /run/svavyom/mutation/mutation.sock \\\n    --offsite-socket /run/svavyom/offsite/offsite.sock \\\n" +
			"    --console-socket /run/svavyom/console/console.sock \\\n    --provision-config /etc/svavyom/provision.json" + flags + "\n"
		if _, err := e.writeAtomic(feat, []byte(body), 0o644, 0, 0); err != nil {
			return err
		}
	}
	mutDir := e.P(UnitDir + "/svavyom-mutation.service.d")
	bk := mutDir + "/backup.conf"
	offDir := e.P(UnitDir + "/svavyom-offsite.service.d")
	offBk, offTargets := offDir+"/backup.conf", offDir+"/targets.conf"
	if o.BackupDir == "" {
		for _, f := range []string{bk, offBk, offTargets} {
			if err := os.Remove(f); err != nil && !os.IsNotExist(err) {
				return err
			}
		}
		return nil
	}
	if err := e.ensureDir(mutDir, 0o755, 0, 0); err != nil {
		return err
	}
	if _, err := e.writeAtomic(bk, []byte("# Written by svavyom-ctl install: the local backup store is the only extra place the mutation service may write.\n[Service]\nReadWritePaths="+o.BackupDir+"\n"), 0o644, 0, 0); err != nil {
		return err
	}
	// The off-host copy service reads the same store (read-only) and may write the "path" targets the operator declared (DR-023 D4).
	if err := e.ensureDir(offDir, 0o755, 0, 0); err != nil {
		return err
	}
	if _, err := e.writeAtomic(offBk, []byte("# Written by svavyom-ctl install: the off-host copy service may only READ the local backup store.\n[Service]\nReadOnlyPaths="+o.BackupDir+"\n"), 0o644, 0, 0); err != nil {
		return err
	}
	var rw []string
	if pc, err := provision.LoadConfig(e.P(ConfigFile)); err == nil {
		for _, t := range pc.BackupTargets {
			if t.Kind == "path" {
				rw = append(rw, t.Dir)
			}
		}
	}
	if len(rw) == 0 {
		if err := os.Remove(offTargets); err != nil && !os.IsNotExist(err) {
			return err
		}
		return nil
	}
	_, err := e.writeAtomic(offTargets, []byte("# Written by svavyom-ctl install from the \"path\" backup targets in "+ConfigFile+": the only places the off-host copy service may write.\n[Service]\nReadWritePaths="+strings.Join(rw, " ")+"\n"), 0o644, 0, 0)
	return err
}

// renderConfig renders the provisioning configuration from the artifact's template and the options.
func (e *Env) renderConfig(o InstallOptions, d ids) ([]byte, error) {
	tpl, err := readArtifact(o.Artifact, "packages/ubuntu/etc/provision.json.in")
	if err != nil {
		return nil, err
	}
	var cfg provision.Config
	if err := json.Unmarshal([]byte(sub(string(tpl), d.subst())), &cfg); err != nil {
		return nil, errors.New("the configuration template is not valid JSON after substitution")
	}
	cfg.Pool, cfg.Network, cfg.BackupDir = o.Pool, o.Network, o.BackupDir
	b, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

// Install puts a verified release artifact on this host. Without o.Apply it prints the plan and changes nothing. It never overwrites an existing
// provisioning configuration or TLS key, never loosens a mode, never runs a service as root and never touches libvirt networks, pools or VMs (except to
// define the pool when asked with CreatePool).
func Install(ctx context.Context, e *Env, o InstallOptions, w io.Writer) error {
	o.defaults()
	if err := o.validate(); err != nil {
		return err
	}
	m, err := VerifyArtifact(o.Artifact)
	if err != nil {
		return err
	}
	_, _ = fmt.Fprintf(w, "artifact: svavyom %s (%s), %d files, every digest verified\n", m.Version, m.Classification, len(m.Files))
	if o.Apply && e.Euid() != 0 {
		return errors.New("--apply needs root (run with sudo); the plan can be printed without it")
	}
	pf := Preflight(ctx, e, PreflightOptions{MinFreeGiB: o.MinFreeGiB})
	pf.Text(w)
	if pf.Verdict == Fail || (pf.Verdict == NotReady && !o.AllowNotReady) {
		return fmt.Errorf("the host preflight is %s; fix the findings above (or, for a clean-room check, pass --allow-not-ready for NOT_READY only)", pf.Verdict)
	}
	if !loopbackListen(o.Listen) && o.TLSSelfSigned == "" {
		if _, err := e.ReadFile(e.P(ConfigDir + "/tls/cert.pem")); err != nil {
			return errors.New("a non-loopback --listen needs TLS: install /etc/svavyom/tls/cert.pem and key.pem or pass --tls-self-signed HOSTNAME")
		}
	}
	p := &Plan{}
	p.add("install the account and directory definitions ("+SysusersFile+", "+TmpfilesFile+") and create the service accounts and directories (root-owned trust anchors, separate runtime state)", func() error { return e.installAccounts(ctx, o.Artifact) })
	e.installSteps(p, m, o, w)
	p.add("write "+ConfigFile+" if it does not exist (an existing configuration is kept and validated, never overwritten)", func() error {
		d, err := e.serviceIDs()
		if err != nil {
			return err
		}
		if fi, err := os.Lstat(e.P(ConfigFile)); err == nil && fi.Mode().IsRegular() {
			return nil
		}
		b, err := e.renderConfig(o, d)
		if err != nil {
			return err
		}
		if err := e.ensureDir(e.P(ConfigDir), 0o755, 0, 0); err != nil {
			return err
		}
		_, err = e.writeAtomic(e.P(ConfigFile), b, 0o644, 0, 0)
		return err
	})
	if o.BackupDir != "" {
		p.add("create the backup store "+o.BackupDir+" (owner svavyom-mut, mode 0700)", func() error {
			d, err := e.serviceIDs()
			if err != nil {
				return err
			}
			return e.ensureDir(e.P(o.BackupDir), 0o700, d.mutU, d.mutG)
		})
	}
	if o.TLSSelfSigned != "" {
		p.add("create a Development Preview self-signed certificate for "+o.TLSSelfSigned+" if none exists (key root:svavyom-api 0640)", func() error { return e.selfSignedTLS(o.TLSSelfSigned) })
	}
	if o.CreatePool {
		p.add("define, start and autostart the libvirt pool "+o.Pool+" if it does not exist", func() error { return e.createPool(ctx, o) })
	}
	p.add("reload systemd and start the services in order ("+strings.Join(Units, ", ")+")", func() error { return e.startAll(ctx) })
	p.add("check health and validate the installed configuration", func() error {
		if err := e.waitHealthy(ctx, 60*time.Second); err != nil {
			return err
		}
		return nil
	})
	p.add("check the firewall for conflicts with the VM network and record the result (read-only; no rule is changed)", func() error { return e.recordFirewall(ctx) })
	e.nightlyStep(ctx, p, o, w)
	if err := p.Run(w, o.Apply); err != nil {
		return err
	}
	if !o.Apply {
		return nil
	}
	rep := ValidateConfig(ctx, e, ValidateOptions{})
	rep.Text(w)
	_, _ = fmt.Fprintf(w, "\nNext: create the administrator (one time):\n  sudo -u svavyom-api %s/api bootstrap-admin --db %s/api/svavyom.db --username admin < PASSWORD_FILE\n"+
		"Import a base image (root): %s/api register-image --provision-config %s ...\n", LibexecDir, LibDir, LibexecDir, ConfigFile)
	if rep.Verdict == Fail {
		return errors.New("the installed configuration does not validate; see the findings above")
	}
	return nil
}

// nightlyStep adds the plan step of --enable-nightly-boot / --disable-nightly-boot (nothing when neither was given).
func (e *Env) nightlyStep(ctx context.Context, p *Plan, o InstallOptions, w io.Writer) {
	switch {
	case o.EnableNightlyBoot != "":
		p.add("enable the nightly real guest boot check at "+o.EnableNightlyBoot+" (a service account of the operator role, "+NightlyService+" and "+NightlyTimer+"; the API is restarted once if the account has to be created)", func() error {
			return e.EnableNightlyBoot(ctx, o.EnableNightlyBoot, w)
		})
	case o.DisableNightlyBoot:
		p.add("disable the nightly real guest boot check (remove "+NightlyTimer+" and "+NightlyService+"; the service account stays)", func() error { return e.DisableNightlyBoot(ctx) })
	}
}

// waitHealthy waits until every installed unit is active and the API answers, up to the deadline.
func (e *Env) waitHealthy(ctx context.Context, d time.Duration) error {
	end := e.Now().Add(d)
	var last Report
	for {
		last = Status(ctx, e, StatusOptions{})
		if last.Verdict == Pass {
			return nil
		}
		if last.Verdict == Fail || e.Now().After(end) {
			break
		}
		if err := e.Sleep(ctx, 2*time.Second); err != nil {
			return err
		}
	}
	var why []string
	for _, f := range last.Findings {
		if f.Required && f.Status != Pass {
			why = append(why, f.ID+" "+f.Code)
		}
	}
	sort.Strings(why)
	return fmt.Errorf("the services are not healthy: %s", strings.Join(why, ", "))
}

// selfSignedTLS creates cert.pem and key.pem for a Development Preview. An existing pair is never replaced.
func (e *Env) selfSignedTLS(host string) error {
	dir := e.P(ConfigDir + "/tls")
	certPath, keyPath := dir+"/cert.pem", dir+"/key.pem"
	if _, err := os.Lstat(keyPath); err == nil {
		return nil
	}
	_, apiG, err := e.Getpw("svavyom-api")
	if err != nil {
		return errors.New("the account svavyom-api does not exist")
	}
	if err := e.ensureDir(dir, 0o750, 0, apiG); err != nil {
		return err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	tpl := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: host, Organization: []string{"Svavyom Development Preview (self-signed)"}},
		NotBefore: e.Now().Add(-time.Hour), NotAfter: e.Now().AddDate(1, 0, 0), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames: []string{host, "localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")}}
	if ip := net.ParseIP(host); ip != nil {
		tpl.IPAddresses = append(tpl.IPAddresses, ip)
		tpl.DNSNames = []string{"localhost"}
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		return err
	}
	kb, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	if _, err := e.writeAtomic(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kb}), 0o640, 0, apiG); err != nil {
		return err
	}
	_, err = e.writeAtomic(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644, 0, apiG)
	return err
}

// createPool defines the libvirt pool from the artifact's template when it does not exist yet. It never touches an existing pool.
func (e *Env) createPool(ctx context.Context, o InstallOptions) error {
	if out, err := e.Run.Run(ctx, "virsh", "-c", "qemu:///system", "pool-info", "--", o.Pool); err == nil {
		_ = out
		return nil
	}
	tpl, err := readArtifact(o.Artifact, "packages/ubuntu/libvirt/pool-svavyom.xml")
	if err != nil {
		return err
	}
	xml := strings.ReplaceAll(string(tpl), "<name>svavyom</name>", "<name>"+o.Pool+"</name>")
	tmp := filepath.Join(os.TempDir(), fmt.Sprintf("svavyom-pool-%d.xml", e.Now().UnixNano()))
	if err := os.WriteFile(tmp, []byte(xml), 0o600); err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp) }()
	for _, args := range [][]string{{"pool-define", tmp}, {"pool-start", "--", o.Pool}, {"pool-autostart", "--", o.Pool}} {
		if out, err := e.Run.Run(ctx, "virsh", append([]string{"-c", "qemu:///system"}, args...)...); err != nil {
			return fmt.Errorf("virsh %s: %s", args[0], clean(out))
		}
	}
	return nil
}

// installAccounts installs the account and directory definitions from the artifact and applies them. Install and upgrade both run it: a release
// that adds a service (the off-host copy service) adds its directories here, and an upgrade must create them before the service starts.
func (e *Env) installAccounts(ctx context.Context, artifact string) error {
	for _, f := range [][2]string{{"packages/ubuntu/sysusers.d/svavyom.conf", SysusersFile}, {"packages/ubuntu/tmpfiles.d/svavyom.conf", TmpfilesFile}} {
		data, err := readArtifact(artifact, f[0])
		if err != nil {
			return err
		}
		if err := e.ensureDir(filepath.Dir(e.P(f[1])), 0o755, 0, 0); err != nil {
			return err
		}
		if _, err := e.writeAtomic(e.P(f[1]), data, 0o644, 0, 0); err != nil {
			return err
		}
	}
	if out, err := e.Run.Run(ctx, "systemd-sysusers", e.P(SysusersFile)); err != nil {
		return fmt.Errorf("systemd-sysusers: %s", clean(out))
	}
	if out, err := e.Run.Run(ctx, "systemd-tmpfiles", "--create", e.P(TmpfilesFile)); err != nil {
		return fmt.Errorf("systemd-tmpfiles: %s", clean(out))
	}
	return nil
}
