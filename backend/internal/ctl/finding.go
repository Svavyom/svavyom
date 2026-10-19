package ctl

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
)

// Status of one finding. A report is FAIL if any required finding FAILs, NOT_READY if none fails but a required one is not ready (usually something to
// install or start) or cannot be verified, and PASS otherwise. INFO never changes the verdict.
const (
	Pass     = "PASS"
	Fail     = "FAIL"
	NotReady = "NOT_READY"
	Info     = "INFO"
)

// Finding is one typed, actionable result. Code is a closed identifier (documented in docs/OPERATIONS.md); Detail is short, printable and never contains
// a secret; Remediation says what the administrator does, and never suggests weakening a security control.
type Finding struct {
	ID          string `json:"id"`
	Status      string `json:"status"`
	Required    bool   `json:"required"`
	Code        string `json:"code,omitempty"`
	Detail      string `json:"detail,omitempty"`
	Remediation string `json:"remediation,omitempty"`
}

// Report is a list of findings and the verdict derived from them.
type Report struct {
	Kind     string    `json:"kind"`
	Verdict  string    `json:"verdict"`
	Findings []Finding `json:"findings"`
}

// Verdict derives the overall verdict.
func Verdict(fs []Finding) string {
	v := Pass
	for _, f := range fs {
		if !f.Required {
			continue
		}
		switch f.Status {
		case Fail:
			return Fail
		case NotReady:
			v = NotReady
		}
	}
	return v
}

// NewReport builds a report and its verdict.
func NewReport(kind string, fs []Finding) Report {
	sort.SliceStable(fs, func(i, j int) bool { return false })
	return Report{Kind: kind, Verdict: Verdict(fs), Findings: fs}
}

// ExitCode maps a verdict to the process exit status: 0 PASS, 10 FAIL, 11 NOT_READY.
func (r Report) ExitCode() int {
	switch r.Verdict {
	case Pass:
		return 0
	case Fail:
		return 10
	default:
		return 11
	}
}

// Text renders the report for a terminal.
func (r Report) Text(w io.Writer) {
	_, _ = fmt.Fprintf(w, "svavyom-ctl %s\n", r.Kind)
	for _, f := range r.Findings {
		req := " "
		if !f.Required {
			req = "-"
		}
		line := fmt.Sprintf("  %-9s%s %-26s", f.Status, req, f.ID)
		if f.Code != "" {
			line += " " + f.Code
		}
		if f.Detail != "" {
			line += ": " + f.Detail
		}
		_, _ = fmt.Fprintln(w, strings.TrimRight(line, " "))
		if f.Remediation != "" && (f.Status == Fail || f.Status == NotReady) {
			_, _ = fmt.Fprintf(w, "            -> %s\n", f.Remediation)
		}
	}
	_, _ = fmt.Fprintf(w, "RESULT: %s\n", r.Verdict)
}

// JSON renders the report as indented JSON.
func (r Report) JSON() []byte {
	b, _ := json.MarshalIndent(r, "", "  ")
	return append(b, '\n')
}

// clean keeps printable ASCII only and caps the length: a detail may come from a file or a command and must not smuggle control characters.
func clean(s string) string {
	var b strings.Builder
	for _, r := range s {
		if b.Len() >= 160 {
			break
		}
		if r >= 0x20 && r < 0x7f {
			b.WriteRune(r)
		} else {
			b.WriteByte('?')
		}
	}
	return b.String()
}
