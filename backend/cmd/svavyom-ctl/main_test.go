package main

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"example.invalid/dedicatedcloud/backend/internal/ctl"
)

type noRun struct{}

func (noRun) Run(context.Context, string, ...string) (string, error) {
	return "", errors.New("not available")
}

func cli(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	e := ctl.NewEnv()
	e.Root = t.TempDir()
	e.Run = noRun{}
	var out, errb bytes.Buffer
	code := run(context.Background(), e, args, &out, &errb)
	return code, out.String(), errb.String()
}

func TestExitCodes(t *testing.T) {
	for _, c := range []struct {
		name string
		args []string
		want int
	}{
		{"no command", nil, 2},
		{"unknown command", []string{"frobnicate"}, 2},
		{"bad flag", []string{"status", "--nope"}, 2},
		{"version", []string{"version"}, 0},
		{"support bundle needs --out", []string{"support-bundle"}, 2},
		{"verify-artifact needs a directory", []string{"verify-artifact"}, 2},
		{"verify-artifact of nothing fails", []string{"verify-artifact", "/nonexistent-artifact"}, 1},
		{"install needs an artifact", []string{"install"}, 2},
		{"upgrade needs an artifact", []string{"upgrade", "--apply"}, 2},
		{"backups with none", []string{"backups"}, 1},
		{"rollback with no backup", []string{"rollback"}, 1},
		{"a dry-run uninstall changes nothing and succeeds", []string{"uninstall"}, 0},
		{"an uninstall purge without the token is refused", []string{"uninstall", "--apply", "--purge"}, 1},
		{"status of an empty host is NOT_READY", []string{"status"}, 11},
	} {
		code, _, errs := cli(t, c.args...)
		if code != c.want {
			t.Errorf("%s: exit %d, want %d (%s)", c.name, code, c.want, errs)
		}
	}
}

func TestPreflightOnABareHostIsNeverPass(t *testing.T) {
	code, out, _ := cli(t, "preflight")
	if code != 10 && code != 11 {
		t.Fatalf("exit %d\n%s", code, out)
	}
	code, out, _ = cli(t, "preflight", "--json")
	if (code != 10 && code != 11) || !strings.HasPrefix(strings.TrimSpace(out), "{") {
		t.Fatalf("exit %d\n%s", code, out)
	}
}

func TestVersionJSONNamesTheClassificationAndSchemas(t *testing.T) {
	_, out, _ := cli(t, "version", "--json")
	for _, want := range []string{`"classification": "Development Preview / Pre-Alpha"`, `"operation"`, `"auth"`, `"product": "svavyom"`} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %s in\n%s", want, out)
		}
	}
}

func TestFlagsMayFollowThePositionalArgument(t *testing.T) {
	code, out, _ := cli(t, "verify-artifact", "/nonexistent", "--json")
	if code != 1 || out != "" {
		t.Fatalf("%d %q", code, out)
	}
}
