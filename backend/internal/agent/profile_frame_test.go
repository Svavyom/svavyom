package agent

import "testing"

// DR-032: the Windows profile in an inventory frame.
func TestProfileInAFrame(t *testing.T) {
	base := Domain{Name: "web-1", Managed: true, Media: "iso"}
	ok := map[string]Domain{"none": base, "windows": func() Domain { d := base; d.Profile = "windows"; return d }()}
	for name, d := range ok {
		if !validProfile(d) {
			t.Errorf("%s refused", name)
		}
	}
	bad := map[string]Domain{
		"linux is never written":       func() Domain { d := base; d.Profile = "linux"; return d }(),
		"an unknown profile":           func() Domain { d := base; d.Profile = "mac"; return d }(),
		"on a domain that is not ours": {Name: "web-1", Media: "iso", Profile: "windows"},
		"on a VM from a cloud image":   {Name: "web-1", Managed: true, Profile: "windows"},
	}
	for name, d := range bad {
		if validProfile(d) {
			t.Errorf("%s accepted", name)
		}
	}
}
