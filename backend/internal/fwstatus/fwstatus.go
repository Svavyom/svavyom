// Package fwstatus is the contract between svavyom-ctl (which inspects the firewall as root and writes a status file) and the API (which only reads it).
// It is deliberately tiny so the API binary links nothing of the operator tool.
package fwstatus

import (
	"encoding/json"
	"time"
)

// Finding is one recorded conflict: a closed code and remediation text (at most 200 characters, the browser contract's bound).
type Finding struct {
	Code        string `json:"code"`
	Remediation string `json:"remediation"`
}

// Result is the content of the status file.
type Result struct {
	GeneratedAt string    `json:"generated_at"`
	Network     string    `json:"network"`
	Findings    []Finding `json:"findings"`
}

// Read decodes a status file's bytes; ok is false when they are unreadable, malformed, older than maxAge, or carry more findings than a host may show.
func Read(read func(string) ([]byte, error), path string, now time.Time, maxAge time.Duration) (Result, bool) {
	b, err := read(path)
	if err != nil || len(b) > 64<<10 {
		return Result{}, false
	}
	var r Result
	if json.Unmarshal(b, &r) != nil {
		return Result{}, false
	}
	t, err := time.Parse(time.RFC3339, r.GeneratedAt)
	if err != nil || now.Sub(t) > maxAge || len(r.Findings) > 8 {
		return Result{}, false
	}
	for _, f := range r.Findings {
		if len(f.Code) > 40 || len(f.Remediation) > 200 {
			return Result{}, false
		}
	}
	return r, true
}
