package agent

import (
	"strings"
	"testing"
)

// DR-031: the list of attached installation media in an inventory frame.
func TestMediaListInAFrame(t *testing.T) {
	a, b, c := strings.Repeat("a", 64), strings.Repeat("b", 64), strings.Repeat("c", 64)
	ok := map[string]Domain{
		"none":                  {Managed: true},
		"one":                   {Managed: true, ISOSHA256: a, ISOSHA256s: []string{a}},
		"two, first is single":  {Managed: true, ISOSHA256: a, ISOSHA256s: []string{a, b}},
		"two, second is single": {Managed: true, ISOSHA256: b, ISOSHA256s: []string{a, b}},
		"an old frame":          {Managed: true, ISOSHA256: a},
	}
	for name, d := range ok {
		if !validMediaList(d) {
			t.Errorf("%s refused", name)
		}
	}
	bad := map[string]Domain{
		"three":               {Managed: true, ISOSHA256: a, ISOSHA256s: []string{a, b, c}},
		"duplicates":          {Managed: true, ISOSHA256: a, ISOSHA256s: []string{a, a}},
		"not a digest":        {Managed: true, ISOSHA256: a, ISOSHA256s: []string{a, "zz"}},
		"single not in list":  {Managed: true, ISOSHA256: c, ISOSHA256s: []string{a, b}},
		"list without single": {Managed: true, ISOSHA256s: []string{a}},
		"not a Svavyom VM":    {ISOSHA256: a, ISOSHA256s: []string{a}},
	}
	for name, d := range bad {
		if validMediaList(d) {
			t.Errorf("%s accepted", name)
		}
	}
}
