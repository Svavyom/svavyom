package main

import (
	"context"
	"testing"
	"time"

	"example.invalid/dedicatedcloud/backend/internal/operation"
)

func put(t *testing.T, s *operation.MemStore, id string, typ operation.Type, vm string, at time.Time, st operation.Status) {
	t.Helper()
	_, _, err := s.Insert(operation.Operation{ID: id, ProjectID: "default", ResourceKind: operation.KindVM, ResourceID: vm, Type: typ, Status: st, IdempotencyKey: id, RequestedBy: "x", Generation: 1, CreatedAt: at, UpdatedAt: at})
	if err != nil {
		t.Fatal(err)
	}
}

// A VM that was created or started a minute ago and then stops by itself is exactly what vm_stopped_unexpectedly is for; only an operation that asks
// for the VM to be off may explain it (found on the real host: a create in the last ten minutes had hidden the alert).
func TestOnlyOperationsThatAskForAStopExplainAStoppedVM(t *testing.T) {
	now := time.Date(2026, 10, 15, 14, 0, 0, 0, time.UTC)
	s := operation.NewMemStore()
	put(t, s, "op-create", operation.Create, "fresh", now.Add(-2*time.Minute), operation.Succeeded)
	put(t, s, "op-start", operation.Start, "fresh", now.Add(-time.Minute), operation.Succeeded)
	put(t, s, "op-stop", operation.Stop, "asked", now.Add(-time.Minute), operation.Succeeded)
	put(t, s, "op-old", operation.ForceOff, "old", now.Add(-30*time.Minute), operation.Succeeded)
	put(t, s, "op-open", operation.Reboot, "waiting", now.Add(-time.Hour), operation.Running)
	in := alertSources{Ops: s, MaxAttempts: 3, Now: func() time.Time { return now }}.gather(context.Background())
	for vm, want := range map[string]bool{"fresh": false, "asked": true, "old": false, "waiting": true} {
		if in.StoppedByOperation[vm] != want {
			t.Errorf("%s: explained=%v, want %v", vm, in.StoppedByOperation[vm], want)
		}
	}
	if !in.ExhaustedKnown {
		t.Error("the operation store was read")
	}
}

func TestExhaustedOperationsAreThoseOutOfAttempts(t *testing.T) {
	now := time.Now().UTC()
	s := operation.NewMemStore()
	_, _, _ = s.Insert(operation.Operation{ID: "op-a", ProjectID: "default", ResourceKind: operation.KindVM, ResourceID: "stuck", Type: operation.Stop, Status: operation.RetryableFailure, Attempts: 3, IdempotencyKey: "a", RequestedBy: "x", Generation: 1, CreatedAt: now, UpdatedAt: now})
	_, _, _ = s.Insert(operation.Operation{ID: "op-b", ProjectID: "default", ResourceKind: operation.KindVM, ResourceID: "trying", Type: operation.Stop, Status: operation.RetryableFailure, Attempts: 1, IdempotencyKey: "b", RequestedBy: "x", Generation: 1, CreatedAt: now, UpdatedAt: now})
	in := alertSources{Ops: s, MaxAttempts: 3}.gather(context.Background())
	if len(in.ExhaustedOps) != 1 || in.ExhaustedOps[0].ID != "stuck" {
		t.Fatalf("%+v", in.ExhaustedOps)
	}
}
