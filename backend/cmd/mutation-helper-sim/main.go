// Command mutation-helper-sim is a TEST-ONLY helper that executes the mutation protocol against the file-backed simulated host
// (package simhost) instead of libvirt, with injectable faults. It refuses to run unless SVAVYOM_SIM_HOST=1, is never installed
// by any package, and is not evidence about libvirt or KVM.
//
// Fault injection: if <state_dir>/sim-fault.json exists as {"kill_after":"STEP"} or {"hang_after":"STEP"} the helper consumes the
// file and, after STEP completes ("begin", "image-verified", "preflight", "root-volume", "seed-volume", "domain-defined",
// "started"), kills itself (SIGKILL) or hangs until the supervisor's deadline kills it.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"example.invalid/dedicatedcloud/backend/internal/mutagent"
	"example.invalid/dedicatedcloud/backend/internal/provision"
	"example.invalid/dedicatedcloud/backend/internal/simhost"
)

type fault struct {
	KillAfter string `json:"kill_after"`
	HangAfter string `json:"hang_after"`
}

func main() {
	if os.Getenv("SVAVYOM_SIM_HOST") != "1" {
		fmt.Fprintln(os.Stderr, "ERROR test-only simulation: set SVAVYOM_SIM_HOST=1")
		os.Exit(2)
	}
	cfgPath := flag.String("config", "", "provisioning configuration")
	insecure := flag.Bool("insecure-dev-single-identity", false, "DEVELOPMENT/TEST ONLY: accept trust anchors owned by the current identity")
	flag.Parse()
	cfg, err := provision.LoadConfig(*cfgPath)
	if err != nil {
		os.Exit(2)
	}
	pol, err := cfg.TrustPolicy(*insecure)
	if err != nil {
		os.Exit(2)
	}
	host, err := simhost.New(filepath.Join(cfg.StateDir, "sim"))
	if err != nil {
		os.Exit(2)
	}
	hook := func(step string) {
		p := filepath.Join(cfg.StateDir, "sim-fault.json")
		b, err := os.ReadFile(p) // #nosec G304 -- fixed name in the server-owned state directory
		if err != nil {
			return
		}
		var f fault
		if json.Unmarshal(b, &f) != nil {
			return
		}
		if f.KillAfter == step {
			_ = os.Remove(p)
			_ = syscall.Kill(os.Getpid(), syscall.SIGKILL)
			select {}
		}
		if f.HangAfter == step {
			_ = os.Remove(p)
			time.Sleep(time.Hour)
		}
	}
	os.Exit(mutagent.RunHelper(context.Background(), os.Stdin, os.Stdout, host, cfg, pol, hook))
}
