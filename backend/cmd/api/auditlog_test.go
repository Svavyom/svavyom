package main

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"example.invalid/dedicatedcloud/backend/internal/operation"
)

func TestAuditLineIsOneSafeLine(t *testing.T) {
	var b bytes.Buffer
	newLogAudit(&b).Emit(operation.AuditEvent{At: time.Now(), OperationID: "op-1", ProjectID: "default", Actor: "evil\nactor=root password=hunter2", Event: "operation.submit", Outcome: "accepted"})
	line := b.String()
	if strings.Count(line, "\n") != 1 || !strings.HasPrefix(line, "audit op=op-1 project=default actor=evil_actor_root_password_hunter2 ") || !strings.Contains(line, "category=-") {
		t.Fatalf("%q", line)
	}
}
