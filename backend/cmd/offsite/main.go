// Command offsite is the off-host backup service (M2-E01-S01, DR-023 D4). `serve` answers the API on a Unix socket and copies verified backups to the
// targets declared in the provisioning configuration; `targets` prints the declared targets and whether each is usable; `import` is the operator's way
// back: it fetches a named backup from a target into the local backup store. It refuses to run as root and never listens on TCP.
//
//	offsite serve   --config FILE --socket PATH --allow-uid UID [--allow-uid UID ...] [--state-dir DIR]
//	offsite targets --config FILE [--state-dir DIR]
//	offsite import  --config FILE --target ID --backup bk-... [--state-dir DIR]
//
// `import` writes the local backup store, which belongs to the mutation identity: run it as that identity, for example
// `sudo -u svavyom-mut /usr/libexec/svavyom/offsite import ...`.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strconv"
	"syscall"

	"example.invalid/dedicatedcloud/backend/internal/backupstore"
	"example.invalid/dedicatedcloud/backend/internal/offsite"
	"example.invalid/dedicatedcloud/backend/internal/provision"
)

type uidList []uint32

func (u *uidList) String() string { return fmt.Sprint(*u) }
func (u *uidList) Set(v string) error {
	n, err := strconv.ParseUint(v, 10, 32)
	if err != nil {
		return err
	}
	*u = append(*u, uint32(n))
	return nil
}

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

const usage = "usage: offsite serve|targets|import --config FILE ... (see the package comment)"

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		_, _ = fmt.Fprintln(stderr, usage)
		return 2
	}
	if os.Geteuid() == 0 {
		_, _ = fmt.Fprintln(stderr, "ERROR refusing to run as root: use the mutation service identity (the backup store belongs to it)")
		return 2
	}
	fl := flag.NewFlagSet(args[0], flag.ContinueOnError)
	fl.SetOutput(stderr)
	cfgPath := fl.String("config", "", "provisioning configuration (absolute path)")
	socket := fl.String("socket", "", "serve: Unix socket path (absolute)")
	stateDir := fl.String("state-dir", "/var/lib/svavyom/offsite", "directory owned by this identity for the record of copies")
	target := fl.String("target", "", "import: target id")
	backup := fl.String("backup", "", "import: backup id")
	var uids uidList
	fl.Var(&uids, "allow-uid", "serve: uid allowed to connect (repeatable; required)")
	if err := fl.Parse(args[1:]); err != nil || fl.NArg() != 0 || *cfgPath == "" {
		_, _ = fmt.Fprintln(stderr, usage)
		return 2
	}
	pc, err := provision.LoadConfig(*cfgPath)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "ERROR invalid --config")
		return 2
	}
	if pc.BackupDir == "" {
		_, _ = fmt.Fprintln(stderr, "ERROR no local backup store is configured (backup_dir)")
		return 2
	}
	store, err := backupstore.Open(pc.BackupDir)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "ERROR the local backup store is not usable by this identity")
		return 1
	}
	if err := os.MkdirAll(*stateDir, 0o700); err != nil { // #nosec G703 -- the operator-set state directory of this service, created owner-only
		_, _ = fmt.Fprintln(stderr, "ERROR the state directory cannot be created")
		return 1
	}
	ex := &offsite.Exporter{Store: store, Targets: pc.BackupTargets, StateDir: *stateDir}
	switch args[0] {
	case "targets":
		for _, t := range ex.States() {
			_, _ = fmt.Fprintf(stdout, "%s  %s  %s\n", t.ID, t.Kind, t.State)
		}
		return 0
	case "import":
		if !backupstore.ValidID(*backup) || !provision.ValidTargetID(*target) {
			_, _ = fmt.Fprintln(stderr, usage)
			return 2
		}
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		if err := ex.Import(ctx, *backup, *target); err != nil {
			_, _ = fmt.Fprintln(stderr, "ERROR import failed:", offsite.CategoryOf(err))
			return 1
		}
		_, _ = fmt.Fprintf(stdout, "imported %s from %s; it is verified and now listed with the local backups\n", *backup, *target)
		return 0
	case "serve":
		if *socket == "" || len(uids) == 0 {
			_, _ = fmt.Fprintln(stderr, usage)
			return 2
		}
		srv, err := offsite.Listen(offsite.ServerConfig{Socket: *socket, AllowUIDs: uids, Exporter: ex})
		if err != nil {
			_, _ = fmt.Fprintln(stderr, "ERROR cannot start:", err)
			return 1
		}
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		go func() { <-ctx.Done(); srv.Close() }()
		_, _ = fmt.Fprintln(stderr, "offsite: serving on", *socket, "with", len(pc.BackupTargets), "declared target(s)")
		if err := srv.Serve(); err != nil {
			_, _ = fmt.Fprintln(stderr, "ERROR serve stopped")
			return 1
		}
		return 0
	}
	_, _ = fmt.Fprintln(stderr, usage)
	return 2
}
