package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var fixtures = filepath.Join("..", "..", "..", "tests", "fixtures", "distribution")

func cli(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var out, errb bytes.Buffer
	rc := run(args, &out, &errb)
	return rc, out.String(), errb.String()
}

func TestExitCodes(t *testing.T) {
	matrix := filepath.Join(fixtures, "support-matrix.json")
	for name, want := range map[string]int{"debian-13": 0, "ubuntu-22.04": 10, "docker-container": 11, "osrelease-nul": 11} {
		rc, out, _ := cli(t, "--root", filepath.Join(fixtures, "roots", name), "--matrix", matrix)
		if rc != want || !strings.Contains(out, `"qualification": "none"`) {
			t.Errorf("%s: rc %d, want %d", name, rc, want)
		}
	}
}

func TestUsageAndContractErrorsExit2(t *testing.T) {
	dir := t.TempDir()
	bad := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(bad, []byte(`{"schema": 2}`), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link.json")
	if err := os.Symlink(filepath.Join("..", filepath.Base(fixtures), "support-matrix.json"), link); err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(fixtures, "roots", "debian-13")
	for _, args := range [][]string{{}, {"--root", root}, {"--matrix", bad}, {"--root", root, "--matrix", bad},
		{"--root", root, "--matrix", link}, {"--root", filepath.Join(dir, "absent"), "--matrix", filepath.Join(fixtures, "support-matrix.json")},
		{"--root", root, "--matrix", filepath.Join(fixtures, "support-matrix.json"), "extra"}} {
		if rc, _, _ := cli(t, args...); rc != 2 {
			t.Errorf("%v: rc %d, want 2", args, rc)
		}
	}
}

func TestOutNeverOverwrites(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "report.json")
	args := []string{"--root", filepath.Join(fixtures, "roots", "debian-13"), "--matrix", filepath.Join(fixtures, "support-matrix.json"), "--out", out}
	if rc, stdout, _ := cli(t, args...); rc != 0 || stdout != "" {
		t.Fatalf("first write: rc %d", rc)
	}
	first, _ := os.ReadFile(out)
	if err := os.WriteFile(out, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if rc, _, _ := cli(t, args...); rc != 2 {
		t.Fatalf("existing --out accepted: rc %d", rc)
	}
	if got, _ := os.ReadFile(out); string(got) != "keep" || len(first) == 0 {
		t.Fatal("existing file was overwritten")
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(filepath.Join(dir, "target"), link); err != nil {
		t.Fatal(err)
	}
	args[len(args)-1] = link
	if rc, _, _ := cli(t, args...); rc != 2 {
		t.Fatal("--out followed a symlink")
	}
	if _, err := os.Stat(filepath.Join(dir, "target")); err == nil {
		t.Fatal("symlink target was created")
	}
}
