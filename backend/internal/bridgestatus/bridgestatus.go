// Package bridgestatus is the contract between svavyom-ctl (which plans and applies a host bridge as root and writes a status file) and the API (which
// only reads it, DR-024 D5). It is deliberately tiny so the API binary links nothing of the operator tool.
package bridgestatus

import (
	"encoding/json"
	"regexp"
	"time"
)

// DefaultFile is where svavyom-ctl writes the status and the API reads it.
const DefaultFile = "/var/lib/svavyom/bridge-status.json"

// States of the host bridge, closed.
const (
	StatePlanned             = "planned"
	StatePendingConfirmation = "pending_confirmation"
	StateActive              = "active"
)

// File is the content of the status file (written by svavyom-ctl, root-owned, world-readable). No status file means no bridge work is in progress.
type File struct {
	State       string `json:"state"`
	Bridge      string `json:"bridge"`
	Interface   string `json:"interface"`
	Deadline    string `json:"deadline,omitempty"` // RFC 3339; only while pending_confirmation
	GeneratedAt string `json:"generated_at"`
}

// Observed is what the API shows in Host.observed.bridge.
type Observed struct {
	State       string
	Bridge      string
	Interface   string
	SecondsLeft *int // only while pending_confirmation; never negative
}

var nameRE = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9_.:-]{0,14}$`)

// NameOK reports whether s is acceptable as a device name (Linux limits it to 15 characters).
func NameOK(s string) bool { return nameRE.MatchString(s) }

// Read decodes the status file; ok is false when it is missing, unreadable, malformed or outside the closed vocabulary.
func Read(read func(string) ([]byte, error), path string, now time.Time) (Observed, bool) {
	b, err := read(path)
	if err != nil || len(b) > 8<<10 {
		return Observed{}, false
	}
	var f File
	if json.Unmarshal(b, &f) != nil {
		return Observed{}, false
	}
	switch f.State {
	case StatePlanned, StatePendingConfirmation, StateActive:
	default:
		return Observed{}, false
	}
	if !NameOK(f.Bridge) || !NameOK(f.Interface) {
		return Observed{}, false
	}
	out := Observed{State: f.State, Bridge: f.Bridge, Interface: f.Interface}
	if f.State == StatePendingConfirmation {
		d, err := time.Parse(time.RFC3339, f.Deadline)
		if err != nil {
			return Observed{}, false
		}
		left := int(d.Sub(now).Seconds())
		if left < 0 {
			left = 0
		}
		if left > 3600 {
			return Observed{}, false
		}
		out.SecondsLeft = &left
	}
	return out, true
}
