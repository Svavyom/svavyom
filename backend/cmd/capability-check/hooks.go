//go:build !capability_fault

package main

import "example.invalid/dedicatedcloud/backend/internal/capability"

// Release build: no fault hooks of any kind (erratum r2a, note 10).
func wrapFS(f capability.FS) capability.FS { return f }

func options() capability.Options { return capability.Options{} }
