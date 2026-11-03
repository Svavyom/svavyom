package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"example.invalid/dedicatedcloud/backend/internal/agent"
	"example.invalid/dedicatedcloud/backend/internal/alerts"
	"example.invalid/dedicatedcloud/backend/internal/api"
	"example.invalid/dedicatedcloud/backend/internal/auth"
	"example.invalid/dedicatedcloud/backend/internal/backupstore"
	"example.invalid/dedicatedcloud/backend/internal/bridgestatus"
	"example.invalid/dedicatedcloud/backend/internal/console"
	"example.invalid/dedicatedcloud/backend/internal/fwstatus"
	"example.invalid/dedicatedcloud/backend/internal/hostinfo"
	"example.invalid/dedicatedcloud/backend/internal/metrics"
	"example.invalid/dedicatedcloud/backend/internal/mutagent"
	"example.invalid/dedicatedcloud/backend/internal/nightly"
	"example.invalid/dedicatedcloud/backend/internal/offsite"
	"example.invalid/dedicatedcloud/backend/internal/operation"
	"example.invalid/dedicatedcloud/backend/internal/provision"
	"example.invalid/dedicatedcloud/backend/internal/schedule"
	"example.invalid/dedicatedcloud/backend/internal/sqlitedb"
)

// run executes a subcommand and returns the process exit code. It never prints a password, hash or token.
func run(ctx context.Context, args []string, stdin *os.File, stdout, stderr io.Writer) int {
	switch args[0] {
	case "serve":
		return serve(ctx, args[1:], stderr)
	case "bootstrap-admin":
		return adminCommand(ctx, args[1:], stdin, stdout, stderr, true)
	case "reset-admin-password":
		return adminCommand(ctx, args[1:], stdin, stdout, stderr, false)
	case "user-add", "user-list", "user-role", "user-disable", "user-enable", "user-passwd":
		return userCommand(ctx, args[0], args[1:], stdin, stdout, stderr)
	case "register-image":
		return registerImage(args[1:], stdout, stderr)
	case "image-state":
		return imageState(args[1:], stdout, stderr)
	case "image-verify":
		return imageVerify(args[1:], stdout, stderr)
	case "image-remove":
		return imageRemove(args[1:], stdout, stderr)
	}
	_, _ = fmt.Fprintln(stderr, "usage: api [serve|bootstrap-admin|reset-admin-password|user-add|user-list|user-role|user-disable|user-enable|user-passwd|register-image|image-state|image-verify|image-remove] ...")
	return 2
}

// readPassword reads one line from f. It refuses an interactive terminal (the password would echo, and the safe
// alternatives are a pipe or a 0600 file redirect) and never takes the password from arguments or the environment.
func readPassword(f *os.File) (string, error) {
	st, err := f.Stat()
	if err != nil {
		return "", err
	}
	if st.Mode()&os.ModeCharDevice != 0 {
		return "", errors.New("standard input is a terminal: pipe the password in, for example `api bootstrap-admin ... < password-file`")
	}
	line, err := bufio.NewReaderSize(io.LimitReader(f, 1024), 1024).ReadString('\n')
	if err != nil && !(errors.Is(err, io.EOF) && line != "") {
		return "", errors.New("no password on standard input")
	}
	return strings.TrimRight(line, "\r\n"), nil
}

func adminCommand(ctx context.Context, args []string, stdin *os.File, stdout, stderr io.Writer, bootstrap bool) int {
	fl := flag.NewFlagSet("admin", flag.ContinueOnError)
	fl.SetOutput(stderr)
	dbPath := fl.String("db", os.Getenv("SVAVYOM_DB"), "SQLite database file (or SVAVYOM_DB)")
	username := fl.String("username", "", "administrator username (bootstrap), or the user whose password is reset (default: the first administrator)")
	if err := fl.Parse(args); err != nil || fl.NArg() != 0 || *dbPath == "" || (bootstrap && *username == "") {
		_, _ = fmt.Fprintln(stderr, "usage: api bootstrap-admin --db FILE --username NAME < password-file")
		return 2
	}
	password, err := readPassword(stdin)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "ERROR", err)
		return 2
	}
	release, err := sqlitedb.LockProcess(*dbPath)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "ERROR the database is in use by a running server; stop it first")
		return 1
	}
	defer release()
	db, err := sqlitedb.Open(*dbPath)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "ERROR cannot open the database")
		return 1
	}
	defer func() { _ = db.Close() }()
	svc, err := auth.New(ctx, db, auth.Config{})
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "ERROR cannot initialise authentication")
		return 1
	}
	if bootstrap {
		err = svc.Bootstrap(ctx, *username, password)
	} else if *username != "" {
		err = svc.SetPassword(ctx, *username, password)
	} else {
		err = svc.ResetPassword(ctx, password)
	}
	switch {
	case err == nil:
		if bootstrap {
			_, _ = fmt.Fprintln(stdout, "administrator created")
		} else {
			_, _ = fmt.Fprintln(stdout, "password changed; all sessions revoked")
		}
		return 0
	case errors.Is(err, auth.ErrAlreadyBootstrapped):
		_, _ = fmt.Fprintln(stderr, "ERROR an administrator already exists; use reset-admin-password to change the password")
	case errors.Is(err, auth.ErrNotBootstrapped):
		_, _ = fmt.Fprintln(stderr, "ERROR no administrator exists; run bootstrap-admin first")
	case errors.Is(err, auth.ErrBadUsername):
		_, _ = fmt.Fprintln(stderr, "ERROR username must be 3-32 characters: lower-case letters, digits, '.', '_' or '-', starting with a letter")
	case errors.Is(err, auth.ErrPasswordPolicy):
		_, _ = fmt.Fprintf(stderr, "ERROR password must be %d-%d bytes of printable text and not a single repeated character\n", auth.MinPasswordBytes, auth.MaxPasswordBytes)
	default:
		_, _ = fmt.Fprintln(stderr, "ERROR the operation failed")
	}
	return 1
}

// userCommand manages users and their roles (DR-023 D1). It is run by the host administrator with the server stopped, like bootstrap-admin: the
// password is read from standard input only, a role change or a disable revokes that user's sessions, and the last enabled administrator is protected.
func userCommand(ctx context.Context, cmd string, args []string, stdin *os.File, stdout, stderr io.Writer) int {
	fl := flag.NewFlagSet(cmd, flag.ContinueOnError)
	fl.SetOutput(stderr)
	dbPath := fl.String("db", os.Getenv("SVAVYOM_DB"), "SQLite database file (or SVAVYOM_DB)")
	username := fl.String("username", "", "the user")
	role := fl.String("role", "", "admin, operator or viewer")
	if err := fl.Parse(args); err != nil || fl.NArg() != 0 || *dbPath == "" ||
		(cmd != "user-list" && *username == "") || ((cmd == "user-add" || cmd == "user-role") && *role == "") {
		_, _ = fmt.Fprintln(stderr, "usage: api user-add --db FILE --username NAME --role ROLE < password-file | user-list --db FILE | user-role|user-disable|user-enable --db FILE --username NAME [--role ROLE] | user-passwd --db FILE --username NAME < password-file")
		return 2
	}
	password := ""
	if cmd == "user-add" || cmd == "user-passwd" {
		pw, err := readPassword(stdin)
		if err != nil {
			_, _ = fmt.Fprintln(stderr, "ERROR", err)
			return 2
		}
		password = pw
	}
	release, err := sqlitedb.LockProcess(*dbPath)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "ERROR the database is in use by a running server; stop it first")
		return 1
	}
	defer release()
	db, err := sqlitedb.Open(*dbPath)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "ERROR cannot open the database")
		return 1
	}
	defer func() { _ = db.Close() }()
	svc, err := auth.New(ctx, db, auth.Config{})
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "ERROR cannot initialise authentication")
		return 1
	}
	switch cmd {
	case "user-add":
		var r auth.Role
		if r, err = auth.ParseRole(*role); err == nil {
			err = svc.AddUser(ctx, *username, password, r)
		}
	case "user-role":
		var r auth.Role
		if r, err = auth.ParseRole(*role); err == nil {
			err = svc.SetRole(ctx, *username, r)
		}
	case "user-disable":
		err = svc.SetDisabled(ctx, *username, true)
	case "user-enable":
		err = svc.SetDisabled(ctx, *username, false)
	case "user-passwd":
		err = svc.SetPassword(ctx, *username, password)
	case "user-list":
		var users []auth.User
		if users, err = svc.ListUsers(ctx); err == nil {
			for _, u := range users {
				state := "enabled"
				if u.Disabled {
					state = "disabled"
				}
				_, _ = fmt.Fprintf(stdout, "%-32s %-9s %s\n", u.Username, u.Role, state)
			}
		}
	}
	switch {
	case err == nil:
		if cmd != "user-list" {
			_, _ = fmt.Fprintln(stdout, "done; the user's sessions were revoked where that applies")
		}
		return 0
	case errors.Is(err, auth.ErrBadUsername):
		_, _ = fmt.Fprintln(stderr, "ERROR username must be 3-32 characters: lower-case letters, digits, '.', '_' or '-', starting with a letter")
	case errors.Is(err, auth.ErrPasswordPolicy):
		_, _ = fmt.Fprintf(stderr, "ERROR password must be %d-%d bytes of printable text and not a single repeated character\n", auth.MinPasswordBytes, auth.MaxPasswordBytes)
	case errors.Is(err, auth.ErrBadRole):
		_, _ = fmt.Fprintln(stderr, "ERROR role must be admin, operator or viewer")
	case errors.Is(err, auth.ErrNoSuchUser):
		_, _ = fmt.Fprintln(stderr, "ERROR no such user")
	case errors.Is(err, auth.ErrUserExists):
		_, _ = fmt.Fprintln(stderr, "ERROR that username is taken")
	case errors.Is(err, auth.ErrLastAdmin):
		_, _ = fmt.Fprintln(stderr, "ERROR this would leave no enabled administrator")
	default:
		_, _ = fmt.Fprintln(stderr, "ERROR the operation failed")
	}
	return 1
}

func isLoopback(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func serve(ctx context.Context, args []string, stderr io.Writer) int {
	fl := flag.NewFlagSet("serve", flag.ContinueOnError)
	fl.SetOutput(stderr)
	dbPath := fl.String("db", os.Getenv("SVAVYOM_DB"), "SQLite database file (or SVAVYOM_DB)")
	listen := fl.String("listen", listenAddr, "listen address")
	staticDir := fl.String("static-dir", "", "built frontend directory to serve at /")
	agentSocket := fl.String("agent-socket", "", "Unix socket of the read-only host agent (enables the VM inventory)")
	provCfg := fl.String("provision-config", "", "server-owned provisioning configuration (image catalog, network profile); enables the image list")
	mutSocket := fl.String("mutation-socket", "", "Unix socket of the mutation supervisor (needed with --experimental-mutation)")
	offsiteSocket := fl.String("offsite-socket", "", "Unix socket of the off-host backup service (optional with --experimental-mutation; without it no backup can be copied off the host)")
	devSingle := fl.Bool("insecure-dev-single-identity", false, "DEVELOPMENT/TEST ONLY: run mutation mode without the operator-owned trust-anchor separation (never in production)")
	experimental := fl.Bool("experimental-mutation", false, "Development Preview: allow VM create and start (default closed; unqualified on real hardware)")
	consoleSocket := fl.String("console-socket", "", "Unix socket of the console broker (enables serial boot output; needs --agent-socket)")
	firewallStatus := fl.String("firewall-status", "/var/lib/svavyom/firewall-status.json", "file written by `svavyom-ctl firewall-check --write` whose findings the host summary shows (missing or older than 7 days: none shown)")
	nightlyStatus := fl.String("nightly-status", nightly.StatusFile, "file written by `svavyom-ctl nightly-boot` whose last result the host summary shows (missing: none shown)")
	bridgeStatus := fl.String("bridge-status", bridgestatus.DefaultFile, "file written by `svavyom-ctl bridge` whose state the host summary shows (missing: no bridge work shown)")
	usageInterval := fl.Duration("usage-interval", metrics.DefaultInterval, "how often host and VM usage is sampled for the dashboard and VM pages (1s to 1h)")
	consoleOn := fl.Bool("experimental-console", false, "Development Preview: allow the interactive serial console (default closed; a full-power channel into the guest)")
	hostName := fl.String("host-name", "This host", "display name of this host")
	cert := fl.String("tls-cert", "", "TLS certificate file")
	key := fl.String("tls-key", "", "TLS key file")
	proxy := fl.Bool("behind-tls-proxy", false, "a TLS-terminating reverse proxy on this host sets X-Forwarded-Proto (loopback listener only)")
	if err := fl.Parse(args); err != nil || fl.NArg() != 0 || *dbPath == "" || (*cert == "") != (*key == "") {
		_, _ = fmt.Fprintln(stderr, "usage: api serve --db FILE [--listen ADDR] [--static-dir DIR] [--tls-cert F --tls-key F | --behind-tls-proxy (loopback only)]")
		return 2
	}
	tls := *cert != ""
	// Proxy trust boundary (CT-PRODUCT-DELIVERY-003): X-Forwarded-Proto is trusted only when the backend can be reached
	// by nothing but the proxy on the same host, i.e. a loopback listener. A non-loopback listener needs native TLS.
	if *proxy && (tls || !isLoopback(*listen)) {
		_, _ = fmt.Fprintln(stderr, "ERROR --behind-tls-proxy requires a loopback listener and no native TLS; a non-loopback listener requires --tls-cert/--tls-key")
		return 2
	}
	if !isLoopback(*listen) && !tls {
		_, _ = fmt.Fprintln(stderr, "ERROR refusing to listen on a non-loopback address without TLS: use --tls-cert/--tls-key")
		return 2
	}
	release, err := sqlitedb.LockProcess(*dbPath)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "ERROR the database is already in use by another process")
		return 1
	}
	defer release()
	db, err := sqlitedb.Open(*dbPath)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "ERROR cannot open the database")
		return 1
	}
	defer func() { _ = db.Close() }()
	svc, err := auth.New(ctx, db, auth.Config{})
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "ERROR cannot initialise authentication")
		return 1
	}
	if ok, err := svc.Configured(ctx); err != nil || !ok {
		_, _ = fmt.Fprintln(stderr, "NOTE no administrator exists yet: run `api bootstrap-admin` before signing in")
	}
	hosts, err := hostinfo.New(hostinfo.Config{Name: *hostName, AgentVersion: version})
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "ERROR invalid host configuration")
		return 2
	}
	deps := api.Deps{Auth: svc, Hosts: hosts, TrustForwardedProto: *proxy}
	// Alerts (DR-024 D2): the store and engine exist before the operation manager so an acknowledgement can run as an operation.
	astore, err := alerts.OpenSQLite(ctx, db)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "ERROR cannot initialise the alert store")
		return 1
	}
	alertEngine := &alerts.Engine{Store: astore}
	schedStore, err := schedule.OpenSQLite(ctx, db)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "ERROR cannot initialise the schedule store")
		return 1
	}
	sched := &schedule.Scheduler{Store: schedStore, Log: func(m string) { _, _ = fmt.Fprintln(stderr, m) }}
	var schedRunning bool
	var (
		alertSettings *provision.AlertSettings
		opStore       operation.Store
	)
	if *firewallStatus != "" {
		deps.Firewall = func() []api.FirewallFinding {
			r, ok := fwstatus.Read(os.ReadFile, *firewallStatus, time.Now(), 7*24*time.Hour)
			if !ok {
				return nil
			}
			out := make([]api.FirewallFinding, 0, len(r.Findings))
			for _, f := range r.Findings {
				out = append(out, api.FirewallFinding{Code: f.Code, Remediation: f.Remediation})
			}
			return out
		}
	}
	if *bridgeStatus != "" {
		deps.Bridge = func() *api.BridgeObserved {
			o, ok := bridgestatus.Read(os.ReadFile, *bridgeStatus, time.Now())
			if !ok {
				return nil
			}
			return &api.BridgeObserved{State: o.State, Bridge: o.Bridge, Interface: o.Interface, SecondsLeft: o.SecondsLeft}
		}
	}
	if *nightlyStatus != "" {
		deps.NightlyBoot = func() *api.NightlyResult {
			f, ok := nightly.Read(os.ReadFile, *nightlyStatus)
			if !ok {
				return nil
			}
			l := f.Last()
			if l == nil {
				return nil
			}
			return &api.NightlyResult{At: l.At, Result: l.Result, Seconds: l.Seconds}
		}
	}
	if *agentSocket != "" {
		// The API never touches libvirt: it only speaks the read-only agent protocol over a Unix socket.
		c, err := agent.NewClient(*agentSocket, 5*time.Second)
		if err != nil {
			_, _ = fmt.Fprintln(stderr, "ERROR invalid --agent-socket")
			return 2
		}
		deps.VMs = c
	}
	if *consoleOn && *consoleSocket == "" {
		_, _ = fmt.Fprintln(stderr, "ERROR --experimental-console needs --console-socket")
		return 2
	}
	if *consoleSocket != "" {
		if *agentSocket == "" {
			_, _ = fmt.Fprintln(stderr, "ERROR --console-socket needs --agent-socket (the console is offered only for VMs the agent reports)")
			return 2
		}
		cc, err := console.NewClient(*consoleSocket, 10*time.Second)
		if err != nil {
			_, _ = fmt.Fprintln(stderr, "ERROR invalid --console-socket")
			return 2
		}
		con := &api.Console{Enabled: *consoleOn, Broker: cc, Audit: func(a api.ConsoleAudit) {
			// One line per event: who, which VM, what happened. Never console content, a ticket or a cookie.
			_, _ = fmt.Fprintf(stderr, "audit console actor=%s vm=%s event=%s outcome=%s\n", a.Actor, a.VM, a.Event, a.Outcome)
		}}
		if *consoleOn {
			con.Tickets = console.NewTickets(0, nil)
			_, _ = fmt.Fprintln(stderr, "NOTE Development Preview: the interactive serial console is ENABLED (experimental; a full-power channel into the guest)")
		}
		deps.Console = con
	}
	var worker *operation.Worker
	if *provCfg != "" {
		pc, err := provision.LoadConfig(*provCfg)
		if err != nil {
			_, _ = fmt.Fprintln(stderr, "ERROR invalid --provision-config")
			return 2
		}
		catFn := func() (*provision.Catalog, error) { return provision.LoadCatalog(pc.CatalogDir) }
		if _, err := catFn(); errors.Is(err, provision.ErrCatalogSchema) {
			_, _ = fmt.Fprintln(stderr, "NOTE the image catalog uses an older format: re-import the images with `api register-image` (Development Preview catalogs are not migrated)")
		}
		alertSettings = pc.Alerts
		cr := &api.Creation{Catalog: catFn, Network: pc.Network, RequireKVM: pc.DomainType == "kvm"}
		if *experimental {
			if *agentSocket == "" || *mutSocket == "" {
				_, _ = fmt.Fprintln(stderr, "ERROR --experimental-mutation needs --agent-socket and --mutation-socket")
				return 2
			}
			pol, err := pc.TrustPolicy(*devSingle)
			if err != nil {
				_, _ = fmt.Fprintln(stderr, "ERROR refusing mutation mode:", err)
				return 2
			}
			if bad := pol.CheckDeployment(*provCfg, pc); len(bad) > 0 {
				_, _ = fmt.Fprintln(stderr, "ERROR refusing mutation mode: these trust anchors are not operator-owned and read-only for every Svavyom runtime identity:", strings.Join(bad, ", "))
				_, _ = fmt.Fprintln(stderr, "      The helper, provisioning configuration, catalog, image store and published images belong to root and must not be writable by the API, agent or mutation identities (docs/VM-CREATION.md).")
				return 2
			}
			if *devSingle {
				_, _ = fmt.Fprintln(stderr, "WARNING --insecure-dev-single-identity: trust-anchor separation is NOT enforced")
			}
			mc, err := mutagent.NewClient(*mutSocket, 0)
			if err != nil {
				_, _ = fmt.Fprintln(stderr, "ERROR invalid --mutation-socket")
				return 2
			}
			store, err := operation.OpenSQLite(ctx, db)
			if err != nil {
				_, _ = fmt.Fprintln(stderr, "ERROR cannot initialise the operation store")
				return 1
			}
			opStore = store
			capacity := func() (int, int) {
				cctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				if i, err := hosts.Host(cctx); err == nil {
					return i.CPUCount, int(i.MemoryMiB)
				}
				return 0, 0
			}
			var offsitePrune func(context.Context, string, string) error
			mh := &mutagent.Host{Reader: deps.VMs, Mut: mc, HostPrefixes: func(context.Context) ([]string, error) {
				p, err := hostPrefixes()
				if err != nil {
					return nil, err
				}
				return prefixStrings(p), nil
			}}
			if *offsiteSocket != "" && len(pc.BackupTargets) > 0 {
				oc, oerr := offsite.NewClient(*offsiteSocket)
				if oerr != nil {
					_, _ = fmt.Fprintln(stderr, "ERROR invalid --offsite-socket")
					return 2
				}
				mh.Offsite = oc
				offsitePrune = oc.Prune
				cr.Targets = func(c context.Context) ([]api.TargetInfo, error) {
					ts, err := oc.Targets(c)
					out := make([]api.TargetInfo, 0, len(ts))
					for _, t := range ts {
						out = append(out, api.TargetInfo{ID: t.ID, Kind: t.Kind, State: t.State})
					}
					return out, err
				}
				cr.Copies = oc.Copies
			}
			mgr := operation.NewManager(store, mh, api.Authorizer(), newLogAudit(stderr),
				operation.Config{PrepareCreate: api.NewCreatePreparer(catFn, pc.Network, capacity), PrepareParams: api.NewParamsPreparer(catFn), Local: localOps{engine: alertEngine, sched: sched}})
			// A backup or restore may run for the supervisor's longest deadline; the worker waits a little longer than that.
			worker = operation.NewWorker(mgr, operation.WorkerConfig{OpTimeout: mutagent.MaxDeadline + 30*time.Second})
			cr.Enabled, cr.Ops, cr.Notify = true, mgr, worker.Notify
			sched.Ops, sched.Notify, schedRunning = mgr, worker.Notify, true
			cr.HostPrefixes = hostPrefixes
			// The read-only helper requests of the host summary and the storage views (preflight, pool facts, backup listing) take turns, so a page
			// that needs three of them can never crowd out the operation executors at the supervisor's concurrency limit.
			readGate := make(chan struct{}, 1)
			gated := func(c context.Context) (release func(), err error) {
				select {
				case readGate <- struct{}{}:
					return func() { <-readGate }, nil
				case <-c.Done():
					return nil, c.Err()
				}
			}
			cr.Preflight = func(c context.Context) (provision.Readiness, error) {
				rel, err := gated(c)
				if err != nil {
					return provision.Readiness{}, err
				}
				defer rel()
				return mc.Preflight(c)
			}
			cr.ListBackups = func(c context.Context) ([]api.BackupInfo, error) {
				rel, gerr := gated(c)
				if gerr != nil {
					return nil, gerr
				}
				defer rel()
				l, err := mc.ListBackups(c)
				out := make([]api.BackupInfo, 0, len(l))
				for _, x := range l {
					out = append(out, api.BackupInfo{ID: x.ID, VM: x.VM, CreatedAt: x.CreatedAt, SizeBytes: x.SizeBytes, DiskGiB: x.DiskGiB, ImageID: x.ImageID, Valid: x.Valid})
				}
				return out, err
			}
			cr.Stats = func(c context.Context) (api.StorageStats, error) {
				rel, gerr := gated(c)
				if gerr != nil {
					return api.StorageStats{}, gerr
				}
				defer rel()
				st, err := mc.Stats(c)
				return api.StorageStats{PoolCapacity: st.PoolCapacity, PoolAvailable: st.PoolAvailable, PoolAllocation: st.PoolAllocation,
					BackupsKnown: st.BackupsKnown, BackupBytes: st.BackupBytes, BackupFree: st.BackupFree, BackupTotal: st.BackupTotal, Snapshots: st.Snapshots}, err
			}
			// The scheduler decides from absence, so it gets the complete listing and an explicit error when the store holds more than that (retention then acts on nothing).
			listAllBackups := func(c context.Context) ([]api.BackupInfo, error) {
				rel, gerr := gated(c)
				if gerr != nil {
					return nil, gerr
				}
				defer rel()
				l, truncated, err := mc.ListBackupsComplete(c)
				if err != nil {
					return nil, err
				}
				if truncated {
					return nil, schedule.ErrIncomplete
				}
				out := make([]api.BackupInfo, 0, len(l))
				for _, x := range l {
					out = append(out, api.BackupInfo{ID: x.ID, VM: x.VM, CreatedAt: x.CreatedAt, SizeBytes: x.SizeBytes, DiskGiB: x.DiskGiB, ImageID: x.ImageID, Valid: x.Valid})
				}
				return out, nil
			}
			sched.World = scheduleWorld{vms: deps.VMs, backups: listAllBackups, copies: cr.Copies, prune: offsitePrune}
			if pc.Schedule != nil {
				sched.Disabled = pc.Schedule.Disabled
			}
			_, _ = fmt.Fprintln(stderr, "NOTE Development Preview: VM create and start are ENABLED (experimental, not qualified on real hardware)")
		}
		deps.Creation = cr
	}
	uctx, ucancel := context.WithCancel(ctx)
	defer ucancel()
	// Usage sampling (DR-022): host figures from /proc, VM CPU from the read-only agent, kept in the API's own database for 24 hours.
	if *usageInterval < time.Second || *usageInterval > time.Hour {
		_, _ = fmt.Fprintln(stderr, "ERROR --usage-interval must be between 1s and 1h")
		return 2
	}
	if ustore, err := metrics.OpenSQLite(ctx, db); err != nil {
		_, _ = fmt.Fprintln(stderr, "ERROR cannot initialise the usage store")
		return 1
	} else {
		sampler := &metrics.Sampler{Store: ustore, HostSrc: metrics.ProcReader{}, Interval: *usageInterval}
		if deps.VMs != nil {
			sampler.VMSrc = deps.VMs
		}
		deps.Usage = sampler
		go sampler.Run(uctx)
	}
	if schedRunning {
		deps.Schedules = schedStore
		go sched.Run(uctx)
	}
	startAlerts(uctx, stderr, &deps, alertEngine, astore, alertSettings, opStore, hosts, schedStore)
	var h http.Handler = api.NewHandlerWith(deps)
	if *staticDir != "" {
		abs, err := filepath.Abs(*staticDir)
		if err != nil {
			return 2
		}
		if st, err := os.Stat(filepath.Join(abs, "index.html")); err != nil || st.IsDir() {
			_, _ = fmt.Fprintln(stderr, "ERROR --static-dir has no index.html")
			return 2
		}
		h = withStatic(h, abs)
	}
	srv := &http.Server{Addr: *listen, Handler: h, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second,
		WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 << 10}
	workerDone := make(chan struct{})
	wctx, wcancel := context.WithCancel(ctx)
	defer wcancel()
	if worker != nil {
		go func() { _ = worker.Run(wctx); close(workerDone) }() // reconciles first, then advances queued operations
	} else {
		close(workerDone)
	}
	errc := make(chan error, 1)
	go func() {
		if tls {
			errc <- srv.ListenAndServeTLS(*cert, *key)
		} else {
			errc <- srv.ListenAndServe()
		}
	}()
	_, _ = fmt.Fprintf(stderr, "serving on %s (tls=%v)\n", *listen, tls)
	select {
	case <-ctx.Done():
		sctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = srv.Shutdown(sctx)
		wcancel()
		<-workerDone // in-flight host attempts finish (bounded) so no outcome is abandoned
		return 0
	case err := <-errc:
		if !errors.Is(err, http.ErrServerClosed) {
			_, _ = fmt.Fprintln(stderr, "ERROR server stopped")
			return 1
		}
		return 0
	}
}

func serveIndex(files http.Handler, w http.ResponseWriter, r *http.Request) {
	r2 := r.Clone(r.Context())
	r2.URL.Path = "/"
	files.ServeHTTP(w, r2)
}

// withStatic routes /api/ and /healthz to the API and serves the built frontend for everything else, with the
// single-page-app fallback to index.html for unknown GET paths. Static responses carry restrictive headers.
func withStatic(api http.Handler, dir string) http.Handler {
	root := http.Dir(dir)
	files := http.FileServer(root)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" || strings.HasPrefix(r.URL.Path, "/api/") || strings.HasPrefix(r.URL.Path, "/console/v1/") {
			api.ServeHTTP(w, r)
			return
		}
		hd := w.Header()
		hd.Set("Content-Security-Policy", "default-src 'self'; style-src 'self'; img-src 'self' data:; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")
		hd.Set("X-Content-Type-Options", "nosniff")
		hd.Set("X-Frame-Options", "DENY")
		hd.Set("Referrer-Policy", "no-referrer")
		hd.Set("Cache-Control", "no-cache")
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			http.Error(w, "", http.StatusMethodNotAllowed)
			return
		}
		// http.Dir resolves the request path inside dir only (it cleans the path and refuses to leave the root).
		f, err := root.Open(path.Clean("/" + r.URL.Path))
		if err != nil {
			serveIndex(files, w, r)
			return
		}
		st, err := f.Stat()
		_ = f.Close()
		if err != nil || st.IsDir() {
			serveIndex(files, w, r)
			return
		}
		files.ServeHTTP(w, r)
	})
}

// registerImage is the explicit, host-side workflow that IMPORTS an image into the Svavyom-managed immutable image store. The
// source is read once (no symlink, regular file, valid qcow2 without a backing file or encryption), copied, fsynced, made
// read-only and published under its SHA-256; the catalog never refers to the source again. Run it as root or as the mutation
// service identity. Without --cloud-init the image is only "registered" and cannot be chosen for a VM. A browser can never reach this.
func registerImage(args []string, stdout, stderr io.Writer) int {
	fl := flag.NewFlagSet("register-image", flag.ContinueOnError)
	fl.SetOutput(stderr)
	dir := fl.String("catalog-dir", "", "image catalog directory (absolute); only with --insecure-dev-single-identity")
	pcfg := fl.String("provision-config", "", "provisioning configuration (supplies the catalog directory and the trust declaration)")
	insecure := fl.Bool("insecure-dev-single-identity", false, "DEVELOPMENT/TEST ONLY: skip the root/runtime-identity trust model")
	id := fl.String("id", "", "stable image id")
	name := fl.String("display-name", "", "display name")
	dist := fl.String("distribution", "", "distribution")
	ver := fl.String("version", "", "release / version")
	source := fl.String("source", "", "absolute path of the qcow2 file to import")
	user := fl.String("login-user", "", "the image's default cloud user")
	minDisk := fl.Int("min-disk-gib", 0, "smallest root disk the image supports")
	ci := fl.Bool("cloud-init", false, "assert that the image reads a NoCloud seed and has --login-user as its default account (marks it verified)")
	media := fl.String("media", "disk", "disk (a bootable qcow2 cloud image) or iso (installation media: verified by SHA-256, no cloud-init, no login user)")
	if err := fl.Parse(args); err != nil || fl.NArg() != 0 || *id == "" || *source == "" || (*media != "disk" && *media != "iso") {
		_, _ = fmt.Fprintln(stderr, "usage: api register-image --provision-config FILE (or --insecure-dev-single-identity --catalog-dir DIR) --id ID --display-name N --distribution D --version V --source /abs/path --min-disk-gib N [--media disk --login-user U [--cloud-init]] | [--media iso]")
		return 2
	}
	pol, cdir, err := adminPolicy(*pcfg, *dir, *insecure)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "ERROR", err)
		return 2
	}
	im, err := provision.Register(pol, cdir, provision.RegisterRequest{ID: *id, DisplayName: *name, Distribution: *dist, Version: *ver, Source: *source, LoginUser: *user, MinDiskGiB: *minDisk, CloudInit: *ci, Media: *media})
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "ERROR", err)
		return 1
	}
	_, _ = fmt.Fprintf(stdout, "registered %s (sha256 %s, %d bytes, state=%s)\n", im.ID, im.SHA256, im.SizeBytes, im.State)
	return 0
}

// imageState changes an image's qualification state. "qualified" needs a reference to the real-host qualification record and
// must never be set from simulation; nothing here deletes an image.
func imageState(args []string, stdout, stderr io.Writer) int {
	fl := flag.NewFlagSet("image-state", flag.ContinueOnError)
	fl.SetOutput(stderr)
	dir := fl.String("catalog-dir", "", "image catalog directory (absolute); only with --insecure-dev-single-identity")
	pcfg := fl.String("provision-config", "", "provisioning configuration (supplies the catalog directory and the trust declaration)")
	insecure := fl.Bool("insecure-dev-single-identity", false, "DEVELOPMENT/TEST ONLY: skip the root/runtime-identity trust model")
	id := fl.String("id", "", "image id")
	state := fl.String("state", "", "registered | verified | qualified | disabled")
	evidence := fl.String("evidence", "", "qualification record reference (required for qualified)")
	if err := fl.Parse(args); err != nil || fl.NArg() != 0 || *id == "" || *state == "" || (*state == provision.StateQualified) == (*evidence == "") {
		_, _ = fmt.Fprintln(stderr, "usage: api image-state --provision-config FILE (or --insecure-dev-single-identity --catalog-dir DIR) --id ID --state registered|verified|qualified|disabled [--evidence REF (qualified only)]")
		return 2
	}
	pol, cdir, err := adminPolicy(*pcfg, *dir, *insecure)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "ERROR", err)
		return 2
	}
	im, err := provision.SetState(pol, cdir, *id, *state, *evidence)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "ERROR", err)
		return 1
	}
	_, _ = fmt.Fprintf(stdout, "image %s is now %s\n", im.ID, im.State)
	return 0
}

// imageVerify re-checks one catalog image against its recorded size and SHA-256 and the trust rules for the store (the same check the mutation
// helper makes before an image becomes a backing file). It changes nothing.
func imageVerify(args []string, stdout, stderr io.Writer) int {
	fl := flag.NewFlagSet("image-verify", flag.ContinueOnError)
	fl.SetOutput(stderr)
	dir := fl.String("catalog-dir", "", "image catalog directory (absolute); only with --insecure-dev-single-identity")
	pcfg := fl.String("provision-config", "", "provisioning configuration (supplies the catalog directory and the trust declaration)")
	insecure := fl.Bool("insecure-dev-single-identity", false, "DEVELOPMENT/TEST ONLY: skip the root/runtime-identity trust model")
	id := fl.String("id", "", "image id")
	if err := fl.Parse(args); err != nil || fl.NArg() != 0 || *id == "" {
		_, _ = fmt.Fprintln(stderr, "usage: api image-verify --provision-config FILE (or --insecure-dev-single-identity --catalog-dir DIR) --id ID")
		return 2
	}
	pol, cdir, err := adminPolicy(*pcfg, *dir, *insecure)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "ERROR", err)
		return 2
	}
	cat, err := provision.LoadTrustedCatalog(pol, cdir)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "ERROR", err)
		return 1
	}
	im, ok := cat.Get(*id)
	if !ok {
		_, _ = fmt.Fprintln(stderr, "ERROR", provision.ErrImageNotFound)
		return 1
	}
	if _, err := cat.Verify(im); err != nil {
		_, _ = fmt.Fprintln(stderr, "ERROR", err)
		return 1
	}
	_, _ = fmt.Fprintf(stdout, "image %s verified (sha256 %s, %d bytes, state=%s)\n", im.ID, im.SHA256, im.SizeBytes, im.State)
	return 0
}

// imageRemove retires a DISABLED image that nothing references: no root overlay in the pool directory has it as its backing file and no backup in the
// backup store was made from it. Any doubt (a symlink in the pool directory, an unreadable backup) refuses. Host administrator only.
func imageRemove(args []string, stdout, stderr io.Writer) int {
	fl := flag.NewFlagSet("image-remove", flag.ContinueOnError)
	fl.SetOutput(stderr)
	dir := fl.String("catalog-dir", "", "image catalog directory (absolute); only with --insecure-dev-single-identity")
	pcfg := fl.String("provision-config", "", "provisioning configuration (supplies the catalog directory and the trust declaration)")
	insecure := fl.Bool("insecure-dev-single-identity", false, "DEVELOPMENT/TEST ONLY: skip the root/runtime-identity trust model")
	id := fl.String("id", "", "image id (must be disabled)")
	poolDir := fl.String("pool-dir", "", "the storage pool's target directory (absolute), scanned for overlays that use the image")
	backupDir := fl.String("backup-dir", "", "the backup store directory (absolute); defaults to the provisioning configuration's backup_dir")
	if err := fl.Parse(args); err != nil || fl.NArg() != 0 || *id == "" || *poolDir == "" {
		_, _ = fmt.Fprintln(stderr, "usage: api image-remove --provision-config FILE (or --insecure-dev-single-identity --catalog-dir DIR) --id ID --pool-dir DIR [--backup-dir DIR]")
		return 2
	}
	pol, cdir, err := adminPolicy(*pcfg, *dir, *insecure)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "ERROR", err)
		return 2
	}
	bdir := *backupDir
	if bdir == "" && *pcfg != "" {
		if pc, err := provision.LoadConfig(*pcfg); err == nil {
			bdir = pc.BackupDir
		}
	}
	var bk *backupstore.Store
	if bdir != "" {
		if bk, err = backupstore.Open(bdir); err != nil {
			_, _ = fmt.Fprintln(stderr, "ERROR the backup store cannot be read, so the image cannot be shown to be unused")
			return 1
		}
	}
	im, err := provision.RemoveImage(pol, cdir, *id, func(c *provision.Catalog, im provision.Image) ([]string, error) {
		return provision.ImageReferences(c, im, *poolDir, bk)
	}, time.Now)
	switch {
	case errors.Is(err, provision.ErrImageInUse):
		_, _ = fmt.Fprintln(stderr, "ERROR the image is still used by a VM disk or a backup; nothing was removed")
		return 1
	case err != nil:
		_, _ = fmt.Fprintln(stderr, "ERROR", err)
		return 1
	}
	_, _ = fmt.Fprintf(stdout, "image %s removed (sha256 %s); recorded in %s\n", im.ID, im.SHA256, provision.RemovalLog)
	return 0
}

// adminPolicy resolves the trust policy and catalog directory of an image-administration command. Production: the
// provisioning configuration supplies both. The explicit development flag is the only way to name a bare catalog directory.
func adminPolicy(cfgPath, dir string, insecure bool) (provision.Policy, string, error) {
	if insecure {
		if dir == "" || cfgPath != "" {
			return provision.Policy{}, "", errors.New("--insecure-dev-single-identity needs --catalog-dir and no --provision-config")
		}
		return provision.DevPolicy(), dir, nil
	}
	if cfgPath == "" || dir != "" {
		return provision.Policy{}, "", errors.New("--provision-config is required (and --catalog-dir is not accepted outside the development mode)")
	}
	pc, err := provision.LoadConfig(cfgPath)
	if err != nil {
		return provision.Policy{}, "", err
	}
	pol, err := pc.TrustPolicy(false)
	if err != nil {
		return provision.Policy{}, "", err
	}
	if bad := pol.CheckDeployment(cfgPath, pc); len(bad) > 0 {
		return provision.Policy{}, "", fmt.Errorf("the deployment is not operator-owned and read-only for the runtime identities: %s", strings.Join(bad, ", "))
	}
	return pol, pc.CatalogDir, nil
}
