//go:build libvirt && faultinject

package main

import (
	"os"
	"syscall"

	"example.invalid/dedicatedcloud/backend/internal/provision"
)

// faultHook (test builds only, -tags faultinject) kills the helper right after the named step completes, so crash-safety can be
// tested against the real libvirt calls. The step comes from the environment variable SVAVYOM_FAULT_KILL_AFTER.
func faultHook() provision.Hook {
	step := os.Getenv("SVAVYOM_FAULT_KILL_AFTER")
	if step == "" {
		return nil
	}
	return func(s string) {
		if s == step {
			_ = syscall.Kill(os.Getpid(), syscall.SIGKILL)
			select {}
		}
	}
}
