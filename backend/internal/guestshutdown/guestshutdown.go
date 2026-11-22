// Package guestshutdown judges whether the host would stop its guests cleanly when it shuts down (DR-042 D6). Svavyom does not change libvirt-guests: it reads
// whether the service is enabled and what /etc/default/libvirt-guests says, and reports when guests would be killed with the host.
package guestshutdown

import "strings"

// Finding codes (they join the host report's capability findings and the svavyom-ctl status report).
const (
	CodeOff  = "LIBVIRT_GUESTS_OFF"
	CodeMode = "LIBVIRT_GUESTS_MODE"
)

// Remediation is the one text for both findings: short enough for the host report.
const Remediation = "Enable libvirt-guests (systemctl enable libvirt-guests) and set ON_SHUTDOWN=shutdown in /etc/default/libvirt-guests, so running VMs are shut down cleanly when the host stops."

// OnShutdown returns the ON_SHUTDOWN value of a libvirt-guests defaults file; "shutdown" (the packaged default on Ubuntu) when it is not set.
func OnShutdown(file string) string {
	mode := "shutdown"
	for _, line := range strings.Split(file, "\n") {
		if v, ok := strings.CutPrefix(strings.TrimSpace(line), "ON_SHUTDOWN="); ok {
			mode = strings.Trim(strings.TrimSpace(v), "\"'")
		}
	}
	return mode
}

// Judge returns "" when guests would be stopped cleanly (service enabled, mode shutdown or suspend), otherwise the finding code.
func Judge(enabled bool, mode string) string {
	switch {
	case !enabled:
		return CodeOff
	case mode != "shutdown" && mode != "suspend":
		return CodeMode
	}
	return ""
}
