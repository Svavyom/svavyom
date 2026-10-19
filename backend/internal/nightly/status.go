// Package nightly is the nightly real guest boot of DR-024 D4: once a night a disposable VM is created from a qualified image, started, waited for until
// it has an address and answers on the SSH port with an SSH banner, then stopped and deleted, and the host is checked to be clean. The run goes through the
// API like any person's request, with a service account of the operator role; it keeps a history of 30 nights in a status file that the API only reads.
// It proves that this host can still boot a real guest. It does not prove anything about what runs inside one beyond an SSH banner.
package nightly

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"
)

// StatusFile is where the history is kept (root writes it, the API reads it).
const StatusFile = "/var/lib/svavyom/nightly-boot.json"

// Outcomes and reasons. A reason is a closed code, never host text.
const (
	Pass    = "pass"
	Fail    = "fail"
	Skipped = "skipped"

	ReasonNone     = ""
	ReasonNotReady = "creation_not_ready"
	ReasonSpace    = "low_space"
	ReasonMemory   = "low_memory"
	ReasonBusy     = "operations_running"
	ReasonNoImage  = "no_qualified_image"
	ReasonAPI      = "api_unreachable"
	ReasonCreate   = "create_failed"
	ReasonStart    = "start_failed"
	ReasonAddress  = "no_address"
	ReasonBanner   = "no_ssh_banner"
	ReasonStop     = "stop_failed"
	ReasonDelete   = "delete_failed"
	ReasonLeftover = "leftover_not_cleaned"
	ReasonNotClean = "host_not_clean"
	MaxHistory     = 30
	maxStatusBytes = 32 << 10
)

// Result is one night.
type Result struct {
	At      time.Time `json:"at"`
	Result  string    `json:"result"`
	Seconds int       `json:"seconds"`
	Reason  string    `json:"reason"`
}

// File is the content of the status file: the newest night last.
type File struct {
	V    int      `json:"v"`
	Runs []Result `json:"runs"`
}

// Add appends a night and keeps the newest MaxHistory.
func (f *File) Add(r Result) {
	f.V = 1
	f.Runs = append(f.Runs, r)
	if len(f.Runs) > MaxHistory {
		f.Runs = f.Runs[len(f.Runs)-MaxHistory:]
	}
}

// Last returns the newest night, or nil.
func (f File) Last() *Result {
	if len(f.Runs) == 0 {
		return nil
	}
	r := f.Runs[len(f.Runs)-1]
	return &r
}

func valid(r Result) bool {
	switch r.Result {
	case Pass, Fail, Skipped:
	default:
		return false
	}
	return r.Seconds >= 0 && r.Seconds <= 86400 && len(r.Reason) <= 40 && !r.At.IsZero()
}

// Parse decodes the status file strictly: anything malformed or out of range reads as "no history", so the API never shows a figure it cannot vouch for.
func Parse(b []byte) (File, bool) {
	if len(b) > maxStatusBytes {
		return File{}, false
	}
	var f File
	if json.Unmarshal(b, &f) != nil || f.V != 1 || len(f.Runs) > MaxHistory {
		return File{}, false
	}
	for _, r := range f.Runs {
		if !valid(r) {
			return File{}, false
		}
	}
	return f, true
}

// Read loads the history through read; a missing or damaged file is an empty history and ok false.
func Read(read func(string) ([]byte, error), path string) (File, bool) {
	b, err := read(path)
	if err != nil {
		return File{}, false
	}
	return Parse(b)
}

// Write stores the history atomically (a temporary file in the same directory, then rename), world-readable and root-owned like the other status files.
func Write(path string, f File) error {
	b, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	if len(b) > maxStatusBytes {
		return errors.New("nightly: status too large")
	}
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".nightly-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer func() { _ = os.Remove(name) }()
	if _, err := tmp.Write(append(b, '\n')); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o644); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}
