//go:build libvirt

// Command agent is the local host agent (ADR-011): it owns libvirt access and serves the typed, READ-ONLY protocol of
// package agent on a Unix socket. This slice supports `list` and `lookup` only; there is no mutating operation.
//
//	agent --socket PATH --allow-uid UID [--allow-uid UID ...] [--libvirt-uri qemu:///system]
//
// It refuses to run as root (libvirt group membership is enough for a read-only connection) and never listens on TCP.
// Built with -tags libvirt (cgo, libvirt-dev).
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"syscall"

	"example.invalid/dedicatedcloud/backend/internal/agent"
	"example.invalid/dedicatedcloud/backend/internal/hypervisor/libvirtro"
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
	fl := flag.NewFlagSet("agent", flag.ContinueOnError)
	socket := fl.String("socket", "", "Unix socket path (absolute)")
	uri := fl.String("libvirt-uri", libvirtro.SystemURI, "libvirt URI (qemu:///system, or test:///default for tests)")
	var uids uidList
	fl.Var(&uids, "allow-uid", "uid allowed to connect (repeatable; required)")
	if err := fl.Parse(args); err != nil || fl.NArg() != 0 || *socket == "" || len(uids) == 0 {
		fmt.Fprintln(os.Stderr, "usage: agent --socket PATH --allow-uid UID [--allow-uid UID ...] [--libvirt-uri URI]")
		return 2
	}
	if os.Geteuid() == 0 {
		fmt.Fprintln(os.Stderr, "ERROR refusing to run as root: a read-only libvirt connection needs no privilege beyond libvirt group membership")
		return 2
	}
	reader, err := libvirtro.Open(*uri)
	if err != nil {
		fmt.Fprintln(os.Stderr, "ERROR cannot open libvirt read-only")
		return 1
	}
	defer reader.Close()
	srv, err := agent.Listen(*socket, reader, uids)
	if err != nil {
		fmt.Fprintln(os.Stderr, "ERROR cannot listen:", err)
		return 1
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() { <-ctx.Done(); srv.Close() }()
	fmt.Fprintln(os.Stderr, "agent: read-only, serving on", *socket)
	if err := srv.Serve(); err != nil {
		fmt.Fprintln(os.Stderr, "ERROR serve stopped")
		return 1
	}
	return 0
}
