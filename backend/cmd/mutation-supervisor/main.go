// Command mutation-supervisor is the MUTATING host-agent service (VM creation slice): it listens on its own Unix socket and runs
// every request in a short-lived helper process under a hard deadline (see package mutagent). It never links libvirt, never
// listens on TCP and refuses to run as root.
//
//	mutation-supervisor --socket PATH --allow-uid UID [--allow-uid UID ...] --helper ABS_PATH --helper-config ABS_PATH [--deadline 2m] [--insecure-dev-single-identity]
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"example.invalid/dedicatedcloud/backend/internal/mutagent"
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

func main() { os.Exit(run(os.Args[1:])) }

func run(args []string) int {
	fl := flag.NewFlagSet("mutation-supervisor", flag.ContinueOnError)
	socket := fl.String("socket", "", "Unix socket path (absolute)")
	helper := fl.String("helper", "", "absolute path of the helper executable")
	helperCfg := fl.String("helper-config", "", "absolute path of the provisioning configuration passed to the helper")
	deadline := fl.Duration("deadline", mutagent.DefaultDeadline, "hard deadline of one helper run")
	insecure := fl.Bool("insecure-dev-single-identity", false, "DEVELOPMENT/TEST ONLY: accept trust anchors owned by this identity (never in production)")
	var uids uidList
	fl.Var(&uids, "allow-uid", "uid allowed to connect (repeatable; required)")
	if err := fl.Parse(args); err != nil || fl.NArg() != 0 || *socket == "" || *helper == "" || *helperCfg == "" || len(uids) == 0 || !filepath.IsAbs(*helperCfg) {
		fmt.Fprintln(os.Stderr, "usage: mutation-supervisor --socket PATH --allow-uid UID --helper ABS_PATH --helper-config ABS_PATH [--deadline 2m]")
		return 2
	}
	if os.Geteuid() == 0 {
		fmt.Fprintln(os.Stderr, "ERROR refusing to run as root: use a dedicated service identity with libvirt access")
		return 2
	}
	pc, err := provision.LoadConfig(*helperCfg)
	if err != nil {
		fmt.Fprintln(os.Stderr, "ERROR invalid --helper-config")
		return 2
	}
	pol, err := pc.TrustPolicy(*insecure)
	if err != nil {
		fmt.Fprintln(os.Stderr, "ERROR", err)
		return 2
	}
	helperArgs := []string{"--config", *helperCfg}
	if *insecure {
		fmt.Fprintln(os.Stderr, "WARNING --insecure-dev-single-identity: trust-anchor separation is NOT enforced")
		helperArgs = append(helperArgs, "--insecure-dev-single-identity")
	}
	sup, err := mutagent.Listen(mutagent.SupervisorConfig{Socket: *socket, AllowUIDs: uids, HelperPath: *helper,
		HelperArgs: helperArgs, TrustedFiles: []string{*helperCfg}, Trust: pol,
		Deployment: func() []string { return pol.CheckDeployment(*helperCfg, pc) },
		Env:        []string{"LANG=C", "PATH=/usr/bin:/bin"}, Deadline: *deadline})
	if err != nil {
		fmt.Fprintln(os.Stderr, "ERROR cannot start:", err)
		return 1
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() { <-ctx.Done(); sup.Close() }()
	fmt.Fprintln(os.Stderr, "mutation-supervisor: serving on", *socket, "(deadline", deadline.Round(time.Second), ")")
	if err := sup.Serve(); err != nil {
		fmt.Fprintln(os.Stderr, "ERROR serve stopped")
		return 1
	}
	return 0
}
