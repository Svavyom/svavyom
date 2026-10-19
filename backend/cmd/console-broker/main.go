//go:build libvirt

// Command console-broker is the SERIAL CONSOLE broker (M1-D): a separate, non-root service with its own identity, its own Unix
// socket and a closed protocol (package console). It follows the serial console of every running Svavyom-managed VM so boot output
// is captured from (nearly) the start, answers "snapshot VM x" and serves one interactive attachment per VM. The browser never reaches
// it and it never sees a cookie or a ticket: the API authenticates the administrator and redeems the ticket, then asks the broker for
// that one VM over a socket only the API's identity may open.
//
//	console-broker --socket PATH --allow-uid UID [--allow-uid UID ...] [--libvirt-uri qemu:///system]
//
// It links libvirt but uses it for exactly three things (list running managed VMs, read one VM's facts, open its serial console),
// refuses to run as root and never listens on TCP.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"syscall"

	"example.invalid/dedicatedcloud/backend/internal/console"
	"example.invalid/dedicatedcloud/backend/internal/console/libvirtcon"
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
	fl := flag.NewFlagSet("console-broker", flag.ContinueOnError)
	socket := fl.String("socket", "", "Unix socket path (absolute)")
	uri := fl.String("libvirt-uri", libvirtcon.SystemURI, "libvirt URI (qemu:///system)")
	var uids uidList
	fl.Var(&uids, "allow-uid", "uid allowed to connect (repeatable; required)")
	if err := fl.Parse(args); err != nil || fl.NArg() != 0 || *socket == "" || len(uids) == 0 {
		fmt.Fprintln(os.Stderr, "usage: console-broker --socket PATH --allow-uid UID [--libvirt-uri qemu:///system]")
		return 2
	}
	if os.Geteuid() == 0 {
		fmt.Fprintln(os.Stderr, "ERROR refusing to run as root: use a dedicated service identity with libvirt access")
		return 2
	}
	src, err := libvirtcon.Open(*uri)
	if err != nil {
		fmt.Fprintln(os.Stderr, "ERROR cannot reach libvirt")
		return 1
	}
	defer src.Close()
	b, err := console.NewBroker(console.BrokerConfig{Socket: *socket, AllowUIDs: uids, Source: src})
	if err != nil {
		fmt.Fprintln(os.Stderr, "ERROR cannot start:", err)
		return 1
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() { <-ctx.Done(); b.Close() }()
	fmt.Fprintln(os.Stderr, "console-broker: serving on", *socket)
	if err := b.Serve(); err != nil {
		fmt.Fprintln(os.Stderr, "ERROR serve stopped")
		return 1
	}
	return 0
}
