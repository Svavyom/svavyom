// Command agent-fixture is a TEST-ONLY stand-in for the host agent: it speaks the same read-only protocol on a Unix socket
// but answers from a JSON state file that tests rewrite (empty, populated, "down"). It exists so browser tests can drive
// inventory states deterministically without libvirt. It refuses to start unless SVAVYOM_FIXTURE_AGENT=1, is never
// installed by any package, and is not evidence about libvirt or KVM.
//
//	SVAVYOM_FIXTURE_AGENT=1 agent-fixture --socket PATH --state FILE
//	SVAVYOM_FIXTURE_AGENT=1 agent-fixture --socket PATH --sim-dir DIR
//
// With --sim-dir the answers come from the file-backed simulated host (package simhost) that the test-only mutation helper
// writes, so the browser sees what a create/start really changed (simulation only; not libvirt).
//
// State file: {"mode":"up"|"down","domains":[{"name":"vm-1","power":"running"}]}
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"example.invalid/dedicatedcloud/backend/internal/agent"
	"example.invalid/dedicatedcloud/backend/internal/hypervisor"
	"example.invalid/dedicatedcloud/backend/internal/simhost"
)

type state struct {
	Mode    string         `json:"mode"`
	Domains []agent.Domain `json:"domains"`
}

type fileReader struct{ path string }

func (f fileReader) load() (state, error) {
	b, err := os.ReadFile(f.path)
	if err != nil {
		return state{}, hypervisor.NewError(hypervisor.Unavailable, "fixture", "", "no state")
	}
	var s state
	if err := json.Unmarshal(b, &s); err != nil || s.Mode == "down" {
		return state{}, hypervisor.NewError(hypervisor.Unavailable, "fixture", "", "down")
	}
	return s, nil
}

func (f fileReader) List(context.Context) ([]hypervisor.Domain, error) {
	s, err := f.load()
	if err != nil {
		return nil, err
	}
	out := make([]hypervisor.Domain, 0, len(s.Domains))
	for _, d := range s.Domains {
		out = append(out, hypervisor.Domain{Name: d.Name, State: hypervisor.State(d.Power)})
	}
	return out, nil
}

func (f fileReader) Lookup(ctx context.Context, name string) (hypervisor.Domain, error) {
	list, err := f.List(ctx)
	if err != nil {
		return hypervisor.Domain{}, err
	}
	for _, d := range list {
		if d.Name == name {
			return d, nil
		}
	}
	return hypervisor.Domain{}, hypervisor.NewError(hypervisor.NotFound, "fixture", name, "no such domain")
}

func main() {
	if os.Getenv("SVAVYOM_FIXTURE_AGENT") != "1" {
		fmt.Fprintln(os.Stderr, "ERROR test-only fixture: set SVAVYOM_FIXTURE_AGENT=1")
		os.Exit(2)
	}
	socket := flag.String("socket", "", "Unix socket path")
	stateFile := flag.String("state", "", "state file")
	simDir := flag.String("sim-dir", "", "simulated host directory (instead of --state)")
	flag.Parse()
	if *socket == "" || (*stateFile == "") == (*simDir == "") {
		os.Exit(2)
	}
	var rd hypervisor.Reader = fileReader{*stateFile}
	if *simDir != "" {
		h, err := simhost.New(*simDir)
		if err != nil {
			fmt.Fprintln(os.Stderr, "ERROR", err)
			os.Exit(1)
		}
		rd = simhost.Reader{H: h}
	}
	srv, err := agent.Listen(*socket, rd, []uint32{uint32(os.Getuid())}) // #nosec G115
	if err != nil {
		fmt.Fprintln(os.Stderr, "ERROR", err)
		os.Exit(1)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() { <-ctx.Done(); srv.Close() }()
	_ = srv.Serve()
}
