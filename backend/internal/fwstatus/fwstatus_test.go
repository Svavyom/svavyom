package fwstatus

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func TestReadRefusesWhatItShouldNotShow(t *testing.T) {
	now := time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)
	file := func(s string) func(string) ([]byte, error) {
		return func(string) ([]byte, error) { return []byte(s), nil }
	}
	good := `{"generated_at":"2026-10-15T11:00:00Z","network":"default","findings":[{"code":"FW_FORWARD_DROP","remediation":"x"}]}`
	if r, ok := Read(file(good), "p", now, 24*time.Hour); !ok || len(r.Findings) != 1 {
		t.Fatal("a fresh well-formed file is shown")
	}
	for name, body := range map[string]string{
		"old":           `{"generated_at":"2026-10-01T11:00:00Z","findings":[]}`,
		"not json":      `nope`,
		"bad time":      `{"generated_at":"yesterday","findings":[]}`,
		"long text":     `{"generated_at":"2026-10-15T11:00:00Z","findings":[{"code":"X","remediation":"` + strings.Repeat("a", 201) + `"}]}`,
		"too many":      `{"generated_at":"2026-10-15T11:00:00Z","findings":[{},{},{},{},{},{},{},{},{}]}`,
		"oversize file": strings.Repeat(" ", 70<<10),
	} {
		if _, ok := Read(file(body), "p", now, 24*time.Hour); ok {
			t.Errorf("%s must not be shown", name)
		}
	}
	if _, ok := Read(func(string) ([]byte, error) { return nil, errors.New("x") }, "p", now, time.Hour); ok {
		t.Error("unreadable")
	}
}
