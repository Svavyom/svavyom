package main

import (
	"net"
	"path/filepath"
	"testing"
)

func TestServiceProbeSaysOkUnreachableAndNotEnabled(t *testing.T) {
	dir := t.TempDir()
	live := filepath.Join(dir, "live.sock")
	l, err := net.Listen("unix", live)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	got := serviceProbe(map[string]string{"agent": live, "mutation": filepath.Join(dir, "gone.sock"), "console": "", "offsite": ""})()
	want := map[string]string{"agent": "ok", "mutation": "unreachable", "console": "not_enabled", "offsite": "not_enabled"}
	if len(got) != len(want) {
		t.Fatalf("got %v", got)
	}
	for _, s := range got {
		if want[s.ID] != s.State {
			t.Errorf("%s: got %s, want %s", s.ID, s.State, want[s.ID])
		}
	}
}

func TestServiceProbeKeepsItsAnswerBrieflyInsteadOfDialingEveryTime(t *testing.T) {
	dir := t.TempDir()
	live := filepath.Join(dir, "live.sock")
	l, err := net.Listen("unix", live)
	if err != nil {
		t.Fatal(err)
	}
	probe := serviceProbe(map[string]string{"agent": live})
	if probe()[0].State != "ok" {
		t.Fatal("first probe should find the socket")
	}
	l.Close()
	if probe()[0].State != "ok" {
		t.Fatal("the second probe within the interval should reuse the first answer")
	}
}
