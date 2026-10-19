// Command console-broker-sim is a TEST-ONLY console broker for the browser tests: the real broker (package console) over a
// SIMULATED hypervisor. It watches the same file-backed simulated host the test-only mutation helper writes (package simhost), so a VM
// the browser creates and starts gets a scripted boot log and a toy login prompt. It refuses to start unless SVAVYOM_FIXTURE_CONSOLE=1,
// is never installed by any package, and is not evidence about libvirt, QEMU or any guest.
//
//	SVAVYOM_FIXTURE_CONSOLE=1 console-broker-sim --socket PATH --allow-uid UID --sim-dir DIR
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"example.invalid/dedicatedcloud/backend/internal/console"
	"example.invalid/dedicatedcloud/backend/internal/console/consolesim"
	"example.invalid/dedicatedcloud/backend/internal/hypervisor"
	"example.invalid/dedicatedcloud/backend/internal/simhost"
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
	if os.Getenv("SVAVYOM_FIXTURE_CONSOLE") != "1" {
		fmt.Fprintln(os.Stderr, "console-broker-sim is a test fixture: set SVAVYOM_FIXTURE_CONSOLE=1")
		return 2
	}
	fl := flag.NewFlagSet("console-broker-sim", flag.ContinueOnError)
	socket := fl.String("socket", "", "Unix socket path (absolute)")
	simDir := fl.String("sim-dir", "", "state directory of the simulated host")
	var uids uidList
	fl.Var(&uids, "allow-uid", "uid allowed to connect (repeatable; required)")
	if err := fl.Parse(args); err != nil || *socket == "" || *simDir == "" || len(uids) == 0 {
		fmt.Fprintln(os.Stderr, "usage: console-broker-sim --socket PATH --allow-uid UID --sim-dir DIR")
		return 2
	}
	host, err := simhost.New(*simDir)
	if err != nil {
		return 2
	}
	src := consolesim.New()
	reader := simhost.Reader{H: host}
	sync := func() {
		doms, err := reader.List(context.Background())
		if err != nil {
			return
		}
		seen := map[string]bool{}
		for _, d := range doms {
			seen[d.Name] = true
			src.Set(d.Name, consolesim.VM{Managed: d.Managed, Configured: true, Running: d.State == hypervisor.StateRunning, Graphics: d.Graphics,
				Boot: []string{"[    0.000000] Linux version 6.8.0 (simulated)", "[    1.204511] cloud-init[512]: simulated guest booted", "Ubuntu 24.04 LTS " + d.Name + " ttyS0", ""}})
		}
	}
	b, err := console.NewBroker(console.BrokerConfig{Socket: *socket, AllowUIDs: uids, Source: src, ScanEvery: 100 * time.Millisecond})
	if err != nil {
		fmt.Fprintln(os.Stderr, "ERROR cannot start:", err)
		return 1
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		t := time.NewTicker(100 * time.Millisecond)
		defer t.Stop()
		for {
			sync()
			select {
			case <-ctx.Done():
				b.Close()
				return
			case <-t.C:
			}
		}
	}()
	if err := b.Serve(); err != nil {
		return 1
	}
	return 0
}
