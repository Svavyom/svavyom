package guestshutdown

import "testing"

func TestOnShutdownReadsTheLastSettingAndDefaultsToShutdown(t *testing.T) {
	for in, want := range map[string]string{
		"":                             "shutdown",
		"# ON_SHUTDOWN=ignore\n":       "shutdown",
		"ON_SHUTDOWN=ignore\n":         "ignore",
		"ON_SHUTDOWN=\"suspend\"\n":    "suspend",
		"  ON_SHUTDOWN='shutdown'  \n": "shutdown",
		"ON_SHUTDOWN=ignore\nON_SHUTDOWN=shutdown\n": "shutdown",
	} {
		if got := OnShutdown(in); got != want {
			t.Errorf("%q: %q, want %q", in, got, want)
		}
	}
}

func TestJudgeNamesTheProblem(t *testing.T) {
	for _, c := range []struct {
		enabled bool
		mode    string
		want    string
	}{{false, "shutdown", CodeOff}, {true, "ignore", CodeMode}, {true, "shutdown", ""}, {true, "suspend", ""}, {false, "ignore", CodeOff}} {
		if got := Judge(c.enabled, c.mode); got != c.want {
			t.Errorf("%+v: %q", c, got)
		}
	}
}
