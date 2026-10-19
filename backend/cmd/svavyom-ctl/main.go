// Command svavyom-ctl is the administrator's tool for a Svavyom Development Preview installation: host preflight, configuration validation, service status,
// support bundle, install, upgrade, rollback and uninstall. It is not a service and links no libvirt. Every privileged subcommand prints its plan and changes
// nothing unless --apply is given.
//
//	svavyom-ctl version|preflight|validate-config|status|support-bundle|verify-artifact|install|upgrade|rollback|backups|uninstall ...
//
// Exit codes: 0 success / PASS, 10 FAIL, 11 NOT_READY, 1 an operation failed, 2 usage.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"example.invalid/dedicatedcloud/backend/internal/auth"
	"example.invalid/dedicatedcloud/backend/internal/ctl"
	"example.invalid/dedicatedcloud/backend/internal/metrics"
	"example.invalid/dedicatedcloud/backend/internal/operation"
)

// Version is set at build time (-ldflags "-X main.Version=...").
var Version = "0.0.0-dev"

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := run(ctx, ctl.NewEnv(), os.Args[1:], os.Stdout, os.Stderr)
	stop()
	os.Exit(code)
}

const usage = `usage: svavyom-ctl <command> [flags]
  version [--json]
  preflight        [--config FILE] [--min-free-gib N] [--json]        read-only host check: PASS / FAIL / NOT_READY
  validate-config  [--config FILE] [--deep] [--online] [--json]       read-only configuration check with typed findings
  status           [--url URL] [--json]                               service and API health
  support-bundle   --out DIR [--config FILE]                          scrubbed diagnostic archive (mode 0600)
  verify-artifact  DIR [--signatures DIR --public-key FILE] [--json]  check a release artifact against its manifest (and its signatures)
  install          --artifact DIR [--apply] [--allow-not-ready] [--tls-self-signed HOST] [--pool P] [--network N] [--backup-dir D]
                   [--create-pool] [--enable-mutation] [--enable-console] [--listen ADDR] [--min-free-gib N]
                   [--enable-nightly-boot HH:MM | --disable-nightly-boot]
  upgrade          --artifact DIR [--apply] [--allow-downgrade] [install flags]
  rollback         [--backup ID|latest] [--apply] [--restore-db]
  nightly-boot                                                        root: create, boot, check and delete a disposable VM through the API; record the result
  firewall-check   [--write] [--config FILE] [--json]                 read-only: does a firewall block the VM network? (--write records it for the console)
  bridge plan                                                         read-only: propose a host bridge (svbr0) for the uplink and show the exact change (root records the plan)
  bridge apply     --plan ID --confirm-bridge svbr0 [--countdown S]   root: apply the plan; the old configuration returns by itself unless "bridge confirm" follows
  bridge confirm | rollback [--confirm-bridge svbr0] | status | adopt --name BR --confirm-bridge BR
  backups                                                             list pre-upgrade backups
  db-backup        [--keep N]                                         consistent, verified copy of the API database (service keeps running)
  db-backups                                                          list the database copies and re-verify each
  db-restore       [ID|latest] [--apply]                              put a verified copy back (keeps the replaced database)
  uninstall        [--apply] [--purge --confirm-purge DELETE-SVAVYOM-DATA]
Privileged commands print their plan and change nothing without --apply.`

func run(ctx context.Context, e *ctl.Env, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		_, _ = fmt.Fprintln(stderr, usage)
		return 2
	}
	cmd, rest := args[0], args[1:]
	fl := flag.NewFlagSet(cmd, flag.ContinueOnError)
	fl.SetOutput(stderr)
	asJSON := fl.Bool("json", false, "machine-readable output")
	cfg := fl.String("config", "", "provisioning configuration (default: the installed one)")
	deep := fl.Bool("deep", false, "validate-config: re-hash every catalog image")
	online := fl.Bool("online", false, "validate-config: also ask libvirt and the agent")
	minFree := fl.Int("min-free-gib", 30, "preflight, install, upgrade: free space wanted on the state file system")
	url := fl.String("url", "", "status: health URL (default: derived from the installed API unit)")
	out := fl.String("out", "", "support-bundle: output directory")
	artifact := fl.String("artifact", "", "release artifact directory")
	apply := fl.Bool("apply", false, "perform the plan (default: print it only)")
	allowNR := fl.Bool("allow-not-ready", false, "install: continue when the preflight is NOT_READY (never when it FAILs)")
	tlsHost := fl.String("tls-self-signed", "", "install: create a Development Preview self-signed certificate for this host name if none exists")
	pool := fl.String("pool", "", "install: libvirt pool name (default svavyom)")
	network := fl.String("network", "", "install: libvirt network name (default default)")
	backupDir := fl.String("backup-dir", "", "install: local backup store directory")
	createPool := fl.Bool("create-pool", false, "install: define the libvirt pool if it does not exist")
	enMut := fl.Bool("enable-mutation", false, "install: enable the Development Preview VM create/lifecycle switch")
	enCon := fl.Bool("enable-console", false, "install: enable the Development Preview interactive console")
	listen := fl.String("listen", "", "install: API listen address (default 0.0.0.0:8443)")
	enNightly := fl.String("enable-nightly-boot", "", "install, upgrade: run the nightly real guest boot check every day at HH:MM (host time)")
	disNightly := fl.Bool("disable-nightly-boot", false, "install, upgrade: remove the nightly real guest boot check")
	downgrade := fl.Bool("allow-downgrade", false, "upgrade: allow an older artifact")
	backup := fl.String("backup", "", "rollback: backup id or latest")
	restoreDB := fl.Bool("restore-db", false, "rollback: also restore the pre-upgrade database copy")
	sigDir := fl.String("signatures", "", "verify-artifact: directory with the detached signatures and SIGNING-INFO.json")
	pubKey := fl.String("public-key", "", "verify-artifact: the trusted public key file, obtained out of band")
	write := fl.Bool("write", false, "firewall-check: record the result in "+ctl.FirewallStatusFile+" (root)")
	planID := fl.String("plan", "", "bridge apply: the plan id printed by `bridge plan`")
	typedBridge := fl.String("confirm-bridge", "", "bridge apply, rollback, adopt: the bridge name, typed as a confirmation")
	countdown := fl.Int("countdown", 0, "bridge apply: seconds to confirm before the old configuration returns (default 120)")
	auto := fl.Bool("auto", false, "bridge rollback: run by the timer; no confirmation, no error when there is nothing to undo")
	noApply := fl.Bool("no-apply", false, "bridge rollback: only regenerate the netplan output (boot-time recovery)")
	brName := fl.String("name", "", "bridge adopt: the existing bridge")
	keep := fl.Int("keep", 0, "db-backup: keep only this many of the newest copies (0 keeps all)")
	purge := fl.Bool("purge", false, "uninstall: also delete Svavyom's own data")
	confirm := fl.String("confirm-purge", "", "uninstall: the confirmation token")
	// Flags may follow a positional argument (verify-artifact DIR --json).
	var pos []string
	for len(rest) > 0 {
		if err := fl.Parse(rest); err != nil {
			return 2
		}
		if fl.NArg() == 0 {
			break
		}
		pos = append(pos, fl.Arg(0))
		rest = fl.Args()[1:]
	}
	report := func(r ctl.Report) int {
		if *asJSON {
			_, _ = stdout.Write(r.JSON())
		} else {
			r.Text(stdout)
		}
		return r.ExitCode()
	}
	fail := func(err error) int {
		_, _ = fmt.Fprintln(stderr, "ERROR", err)
		return 1
	}
	inst := ctl.InstallOptions{Artifact: *artifact, Apply: *apply, AllowNotReady: *allowNR, TLSSelfSigned: *tlsHost, Pool: *pool, Network: *network, BackupDir: *backupDir,
		CreatePool: *createPool, EnableMutation: *enMut, EnableConsole: *enCon, Listen: *listen, MinFreeGiB: *minFree, EnableNightlyBoot: *enNightly, DisableNightlyBoot: *disNightly}
	switch cmd {
	case "version":
		v := map[string]any{"product": "svavyom", "version": Version, "classification": "Development Preview / Pre-Alpha",
			"schema_versions": map[string]int{"operation": operation.SchemaVersion(), "auth": auth.SchemaVersion(), "usage": metrics.SchemaVersion()}}
		if *asJSON {
			b, _ := json.MarshalIndent(v, "", "  ")
			_, _ = fmt.Fprintln(stdout, string(b))
		} else {
			_, _ = fmt.Fprintf(stdout, "svavyom-ctl %s (Development Preview / Pre-Alpha)\n", Version)
		}
		return 0
	case "preflight":
		return report(ctl.Preflight(ctx, e, ctl.PreflightOptions{ConfigPath: *cfg, MinFreeGiB: *minFree}))
	case "validate-config":
		return report(ctl.ValidateConfig(ctx, e, ctl.ValidateOptions{ConfigPath: *cfg, Deep: *deep, Online: *online}))
	case "status":
		return report(ctl.Status(ctx, e, ctl.StatusOptions{URL: *url}))
	case "support-bundle":
		if *out == "" {
			_, _ = fmt.Fprintln(stderr, "usage: svavyom-ctl support-bundle --out DIR")
			return 2
		}
		path, man, err := ctl.SupportBundle(ctx, e, ctl.BundleOptions{OutDir: *out, ConfigPath: *cfg, Version: Version})
		if err != nil {
			return fail(err)
		}
		_, _ = fmt.Fprintf(stdout, "support bundle written: %s (%d files, %d redactions)\nIt excludes: %v\nInspect it before sending it anywhere.\n", path, len(man.Entries), man.Redactions, man.Excluded)
		return 0
	case "verify-artifact":
		dir := *artifact
		if len(pos) == 1 {
			dir = pos[0]
		}
		if dir == "" {
			_, _ = fmt.Fprintln(stderr, "usage: svavyom-ctl verify-artifact DIR")
			return 2
		}
		m, err := ctl.VerifyArtifact(dir)
		if err != nil {
			return fail(err)
		}
		if (*sigDir != "") != (*pubKey != "") {
			_, _ = fmt.Fprintln(stderr, "usage: --signatures and --public-key go together")
			return 2
		}
		sigNote := "unsigned (no --signatures given)"
		if *sigDir != "" {
			sr, serr := ctl.VerifySignatures(ctx, e, dir, ctl.SignatureOptions{Dir: *sigDir, PublicKey: *pubKey})
			if serr != nil {
				return fail(serr)
			}
			sigNote = fmt.Sprintf("signed with %s (%s), signature valid", sr.Method, sr.KeyDetail)
		}
		if *asJSON {
			b, _ := json.MarshalIndent(map[string]any{"version": m.Version, "classification": m.Classification, "files": len(m.Files), "schema_versions": m.SchemaVersions, "signature": sigNote}, "", "  ")
			_, _ = fmt.Fprintln(stdout, string(b))
		} else {
			_, _ = fmt.Fprintf(stdout, "OK artifact svavyom %s (%s): %d files, every digest matches, nothing unlisted; %s\n", m.Version, m.Classification, len(m.Files), sigNote)
		}
		return 0
	case "install", "upgrade":
		if *artifact == "" || len(pos) > 0 {
			_, _ = fmt.Fprintln(stderr, usage)
			return 2
		}
		var err error
		if cmd == "install" {
			err = ctl.Install(ctx, e, inst, stdout)
		} else {
			err = ctl.Upgrade(ctx, e, ctl.UpgradeOptions{InstallOptions: inst, AllowDowngrade: *downgrade}, stdout)
		}
		if err != nil {
			return fail(err)
		}
		return 0
	case "rollback":
		if err := ctl.Rollback(ctx, e, ctl.RollbackOptions{BackupID: *backup, Apply: *apply, RestoreDB: *restoreDB}, stdout); err != nil {
			return fail(err)
		}
		return 0
	case "nightly-boot":
		res, err := ctl.NightlyBoot(ctx, e, stdout, ctl.NightlyDeps{})
		if err != nil {
			return fail(err)
		}
		if res.Result == "fail" {
			return 1
		}
		return 0
	case "bridge":
		// Applying or undoing a bridge can drop the very session that started it; the command must finish regardless.
		signal.Ignore(syscall.SIGHUP)
		sub := ""
		if len(pos) > 0 {
			sub = pos[0]
		}
		var err error
		switch sub {
		case "plan":
			var p *ctl.BridgePlan
			if *asJSON {
				if p, err = e.BridgePlanFor(ctx); err == nil {
					b, _ := json.MarshalIndent(p, "", "  ")
					_, _ = fmt.Fprintln(stdout, string(b))
				}
			} else {
				_, err = e.BridgePlanAndRecord(ctx, stdout)
			}
		case "apply":
			err = e.BridgeApply(ctx, stdout, *planID, *typedBridge, *countdown)
		case "confirm":
			err = e.BridgeConfirm(ctx, stdout)
		case "rollback":
			err = e.BridgeRollback(ctx, stdout, *auto, *noApply, *typedBridge)
		case "recover":
			err = e.BridgeRecover(ctx, stdout)
		case "adopt":
			err = e.BridgeAdopt(ctx, stdout, *brName, *typedBridge)
		case "status":
			_, _ = fmt.Fprintln(stdout, e.BridgeStatusText())
		default:
			_, _ = fmt.Fprintln(stderr, "usage: svavyom-ctl bridge plan|apply|confirm|rollback|status|adopt")
			return 2
		}
		var ref *ctl.BridgeRefusal
		if errors.As(err, &ref) {
			_, _ = fmt.Fprintf(stderr, "REFUSED %s: %s\n", ref.Code, ref.Detail)
			return 11
		}
		if err != nil {
			return fail(err)
		}
		return 0
	case "firewall-check":
		res := ctl.FirewallCheck(ctx, e, e.NetworkOfConfig(*cfg))
		if *write {
			if e.Euid() != 0 {
				return fail(errors.New("--write needs root (run with sudo)"))
			}
			if err := e.WriteFirewallStatus(res); err != nil {
				return fail(err)
			}
		}
		if *asJSON {
			b, _ := json.MarshalIndent(res, "", "  ")
			_, _ = fmt.Fprintln(stdout, string(b))
		} else if len(res.Findings) == 0 {
			_, _ = fmt.Fprintln(stdout, "PASS firewall: no rule found that blocks the VM network (network "+res.Network+")")
		} else {
			for _, f := range res.Findings {
				_, _ = fmt.Fprintf(stdout, "NOT_READY %s: %s\n", f.Code, f.Remediation)
			}
		}
		return 0
	case "backups":
		l, err := e.ListBackups()
		if err != nil {
			return fail(errors.New("no upgrade backups"))
		}
		for _, b := range l {
			_, _ = fmt.Fprintf(stdout, "%s  %s -> %s  database copy: %v\n", b.ID, b.FromVersion, b.ToVersion, b.HasDB)
		}
		return 0
	case "db-backup":
		m, err := ctl.DBBackup(ctx, e, ctl.DBBackupOptions{Keep: *keep}, stdout)
		if err != nil {
			return fail(err)
		}
		_, _ = fmt.Fprintf(stdout, "OK %s\n", m.ID)
		return 0
	case "db-backups":
		l, err := e.ListDBBackups()
		if err != nil {
			return fail(errors.New("no database copies"))
		}
		for _, m := range l {
			state := "verified"
			if verr := e.VerifyDBBackup(ctx, m); verr != nil {
				state = "NOT VERIFIED: " + verr.Error()
			}
			_, _ = fmt.Fprintf(stdout, "%s  %s  %d bytes  %s\n", m.ID, m.CreatedAt, m.SizeBytes, state)
		}
		return 0
	case "db-restore":
		id := ""
		if len(pos) > 0 {
			id = pos[0]
		}
		if err := ctl.DBRestore(ctx, e, ctl.DBRestoreOptions{ID: id, Apply: *apply}, stdout); err != nil {
			return fail(err)
		}
		return 0
	case "uninstall":
		if err := ctl.Uninstall(ctx, e, ctl.UninstallOptions{Apply: *apply, Purge: *purge, ConfirmPurge: *confirm}, stdout); err != nil {
			return fail(err)
		}
		return 0
	}
	_, _ = fmt.Fprintln(stderr, usage)
	return 2
}
