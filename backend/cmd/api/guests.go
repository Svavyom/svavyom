package main

import (
	"os"
	"path/filepath"

	"example.invalid/dedicatedcloud/backend/internal/api"
	"example.invalid/dedicatedcloud/backend/internal/guestshutdown"
)

// guestFindings reports a host whose guests would not be shut down cleanly (DR-042 D6). The API only reads two small files under etc: whether
// libvirt-guests is enabled (a link in a target's wants directory) and its defaults file. It changes nothing and runs nothing.
func guestFindings(etc string) func() []api.FirewallFinding {
	return func() []api.FirewallFinding {
		enabled := false
		if m, _ := filepath.Glob(filepath.Join(etc, "systemd", "system", "*.wants", "libvirt-guests.service")); len(m) > 0 {
			enabled = true
		}
		mode := "shutdown"
		if b, err := os.ReadFile(filepath.Join(etc, "default", "libvirt-guests")); err == nil { // #nosec G304 -- a fixed path under /etc
			mode = guestshutdown.OnShutdown(string(b))
		}
		if code := guestshutdown.Judge(enabled, mode); code != "" {
			return []api.FirewallFinding{{Code: code, Remediation: guestshutdown.Remediation}}
		}
		return nil
	}
}
