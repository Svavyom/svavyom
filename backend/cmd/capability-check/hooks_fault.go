//go:build capability_fault

package main

// Test-only build (-tags capability_fault) for AC03 fault injection through the
// built CLI. CAPABILITY_FAULT is a comma-separated list of:
//   slow:<probe-id>     the probe sleeps past its deadline
//   vanish:<path>       the path behaves as removed between lstat and read
// The release binary is built without this file.

import (
	"os"
	"strings"
	"time"

	"example.invalid/dedicatedcloud/backend/internal/capability"
)

func faults() (slow, vanish map[string]bool) {
	slow, vanish = map[string]bool{}, map[string]bool{}
	for _, f := range strings.Split(os.Getenv("CAPABILITY_FAULT"), ",") {
		kind, arg, ok := strings.Cut(f, ":")
		if !ok {
			continue
		}
		switch kind {
		case "slow":
			slow[arg] = true
		case "vanish":
			vanish[arg] = true
		}
	}
	return slow, vanish
}

type vanishFS struct {
	capability.FS
	vanish map[string]bool
}

func (v vanishFS) ReadRegular(name string, limit int64) ([]byte, error) {
	if v.vanish[name] {
		return nil, capability.ErrVanished // existed at lstat, gone at read
	}
	return v.FS.ReadRegular(name, limit)
}

func wrapFS(f capability.FS) capability.FS {
	_, vanish := faults()
	return vanishFS{f, vanish}
}

func options() capability.Options {
	slow, _ := faults()
	return capability.Options{Hook: func(id string) {
		if slow[id] {
			time.Sleep(time.Minute)
		}
	}}
}
