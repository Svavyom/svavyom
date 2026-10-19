// Package offsite is the off-host backup service (M2-E01-S01, DR-023 D4). The mutation unit has no network by design, so copying a backup to
// another host runs here instead, in a service of its own: it reads the local backup store, writes only to the targets the operator declared in the
// provisioning configuration (a trust anchor), and answers a closed one-request protocol on a Unix socket whose peer must be the API identity.
// It never takes a path, a host name or a command from a request: a request names a backup id and a target id, nothing else.
package offsite

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"regexp"

	"example.invalid/dedicatedcloud/backend/internal/backupstore"
	"example.invalid/dedicatedcloud/backend/internal/provision"
)

// Version is the protocol version.
const Version = 1

// Operations.
const (
	OpTargets = "targets" // the declared targets and whether each is ready
	OpExport  = "export"  // copy backup Backup to target Target and verify it there
	OpCopies  = "copies"  // which targets hold a verified copy of which backup
	OpPrune   = "prune"   // remove the copy this service exported of backup Backup from target Target (retention of scheduled backups)
)

// Request is the only message a client may send.
type Request struct {
	V      int    `json:"v"`
	Op     string `json:"op"`
	Backup string `json:"backup,omitempty"`
	Target string `json:"target,omitempty"`
}

// Valid reports whether the request is well formed for its operation.
func (q Request) Valid() bool {
	if q.V != Version {
		return false
	}
	switch q.Op {
	case OpTargets, OpCopies:
		return q.Backup == "" && q.Target == ""
	case OpExport, OpPrune:
		return backupstore.ValidID(q.Backup) && provision.ValidTargetID(q.Target)
	}
	return false
}

// TargetState is what the API may know about a target: its id, its kind and whether it can be used now. Never a host, a path or a key.
type TargetState struct {
	ID    string `json:"id"`
	Kind  string `json:"kind"`
	State string `json:"state"` // ready | unavailable
}

// Copy lists the targets that hold a verified copy of a backup.
type Copy struct {
	Backup  string   `json:"backup"`
	Targets []string `json:"targets"`
}

// Reply is the only message the service sends.
type Reply struct {
	V        int           `json:"v"`
	OK       bool          `json:"ok"`
	Category string        `json:"category,omitempty"` // validation | not_found | conflict | unavailable | timeout | host_error
	Targets  []TargetState `json:"targets,omitempty"`
	Copies   []Copy        `json:"copies,omitempty"`
}

// Limits.
const (
	maxFrame   = 64 << 10
	maxCopies  = 4096
	categoryRE = `^(validation|not_found|conflict|unavailable|timeout|host_error)$`
)

var categoryOK = regexp.MustCompile(categoryRE)

var errFrame = errors.New("offsite: bad frame")

// writeFrame writes one length-prefixed JSON message.
func writeFrame(w io.Writer, v any) error {
	b, err := json.Marshal(v)
	if err != nil || len(b) > maxFrame {
		return errFrame
	}
	var h [4]byte
	binary.BigEndian.PutUint32(h[:], uint32(len(b))) // #nosec G115 -- bounded above
	_, err = w.Write(append(h[:], b...))
	return err
}

// readFrame reads one frame, strictly (unknown fields refused, nothing may follow the object).
func readFrame(r io.Reader, dst any) error {
	var h [4]byte
	if _, err := io.ReadFull(r, h[:]); err != nil {
		return err
	}
	n := binary.BigEndian.Uint32(h[:])
	if n == 0 || n > maxFrame {
		return errFrame
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(r, body); err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return errFrame
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return errFrame
	}
	return nil
}

func (r *Reply) marshal() ([]byte, error) { return json.Marshal(r) }
