//go:build libvirt && !faultinject

package main

import "example.invalid/dedicatedcloud/backend/internal/provision"

// faultHook is nil in production builds: there is no fault-injection code path in the shipped helper.
func faultHook() provision.Hook { return nil }
