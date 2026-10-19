//go:build libvirt

// Command mutation-helper is the short-lived, libvirt-linked helper the mutation supervisor starts for ONE request. It reads the
// request from standard input, performs it with the libvirt storage/network/domain APIs, writes one reply to standard output and
// exits. Configuration (--config) is the server-owned provisioning file; nothing in a request chooses a path or an executable.
// It is the only binary besides the read-only agent that links libvirt, and the only one that links it read-write.
package main

import (
	"context"
	"flag"
	"os"

	"example.invalid/dedicatedcloud/backend/internal/hypervisor/libvirtmut"
	"example.invalid/dedicatedcloud/backend/internal/mutagent"
	"example.invalid/dedicatedcloud/backend/internal/provision"
)

func main() {
	cfgPath := flag.String("config", "", "provisioning configuration")
	insecure := flag.Bool("insecure-dev-single-identity", false, "DEVELOPMENT/TEST ONLY: accept trust anchors owned by the current identity")
	flag.Parse()
	if os.Geteuid() == 0 {
		os.Exit(2) // never as root
	}
	cfg, err := provision.LoadConfig(*cfgPath)
	if err != nil {
		os.Exit(2)
	}
	pol, err := cfg.TrustPolicy(*insecure)
	if err != nil {
		os.Exit(2)
	}
	ops, err := libvirtmut.Open(cfg.LibvirtURI)
	if err != nil {
		os.Exit(2)
	}
	defer ops.Close()
	os.Exit(mutagent.RunHelper(context.Background(), os.Stdin, os.Stdout, ops, cfg, pol, faultHook()))
}
