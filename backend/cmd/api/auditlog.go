package main

import (
	"fmt"
	"io"
	"strings"
	"sync"

	"example.invalid/dedicatedcloud/backend/internal/operation"
)

// logAudit writes one journal line per operation audit event so an operator can follow an operation by its id. The durable audit record is the
// database row committed with the state change; this line is a convenience copy. It carries identifiers and categories only (the event type already
// excludes secrets, host messages and paths), and every field is reduced to a safe token so a crafted actor or id cannot forge a second log line.
type logAudit struct {
	mu sync.Mutex
	w  io.Writer
}

func newLogAudit(w io.Writer) *logAudit { return &logAudit{w: w} }

func (l *logAudit) Emit(ev operation.AuditEvent) {
	l.mu.Lock()
	defer l.mu.Unlock()
	_, _ = fmt.Fprintf(l.w, "audit op=%s project=%s actor=%s event=%s outcome=%s category=%s\n",
		token(ev.OperationID), token(ev.ProjectID), token(ev.Actor), token(ev.Event), token(ev.Outcome), token(ev.ErrorCategory))
}

func token(s string) string {
	if s == "" {
		return "-"
	}
	if len(s) > 80 {
		s = s[:80]
	}
	return strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '.', r == '-', r == '_', r == ':', r == '@':
			return r
		}
		return '_'
	}, s)
}
