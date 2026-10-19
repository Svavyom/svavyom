package main

import (
	"strings"
	"testing"
)

const routes = `Iface	Destination	Gateway 	Flags	RefCnt	Use	Metric	Mask		MTU	Window	IRTT
eno1	00000000	0136669E	0003	0	0	0	00000000	0	0	0
eno1	0036669E	00000000	0001	0	0	0	00FFFFFF	0	0	0
virbr0	007AA8C0	00000000	0001	0	0	0	00FFFFFF	0	0	0
docker0	000011AC	00000000	0001	0	0	0	0000FFFF	0	0	0
`

func TestParseProcRoutesReadsTheKernelTable(t *testing.T) {
	got, err := parseProcRoutes(strings.NewReader(routes))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"158.102.54.0/24", "192.168.122.0/24", "172.17.0.0/16"}
	if len(got) != len(want) {
		t.Fatalf("%v", got)
	}
	for i, w := range want {
		if got[i].String() != w {
			t.Errorf("%d: %s != %s", i, got[i], w)
		}
	}
}

func TestParseProcRoutesFailsClosedOnAnythingOdd(t *testing.T) {
	for name, in := range map[string]string{
		"empty": "", "wrong header": "x\ty\n", "short line": "Iface\tDestination\neno1\t1\n",
		"not hex":    "Iface\tDestination\nGateway\tFlags\tRefCnt\tUse\tMetric\tMask\nx\tzz\t0\t0\t0\t0\t0\t00FFFFFF\n",
		"holey mask": "Iface\n" + "eno1\t0036669E\t0\t0\t0\t0\t0\t00FF00FF\n",
	} {
		if _, err := parseProcRoutes(strings.NewReader(in)); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}

func TestPrefixStringsAreCanonicalUniqueAndBounded(t *testing.T) {
	got, _ := parseProcRoutes(strings.NewReader(routes))
	s := prefixStrings(append(got, got...))
	if len(s) != 3 {
		t.Fatalf("%v", s)
	}
}
