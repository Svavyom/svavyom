package nightly

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type fakeAPI struct {
	host     HostState
	images   []Image
	vms      map[string]*VM
	active   int
	calls    []string
	failOn   map[string]bool // "create", "start", "stop", "force_off", "delete"
	apiDown  bool
	noAddr   bool
	stopSlow bool // graceful stop does not complete
	ops      map[string]string
	n        int
}

func newFake() *fakeAPI {
	two := func(n int) *int { return &n }
	return &fakeAPI{host: HostState{CreationReady: true, PoolFreeGiB: two(200), MemoryFreeMiB: two(8000), VCPUOptions: []int{1, 2}, MemoryOptions: []int{512, 1024}, DiskOptions: []int{10, 20}},
		images: []Image{{ID: "debian-13", Qualified: false, MinDisk: 3}, {ID: "ubuntu-24.04", Qualified: true, MinDisk: 10}}, vms: map[string]*VM{}, failOn: map[string]bool{}, ops: map[string]string{}}
}

func (f *fakeAPI) Host(context.Context) (HostState, error) {
	if f.apiDown {
		return HostState{}, errors.New("down")
	}
	return f.host, nil
}
func (f *fakeAPI) Images(context.Context) ([]Image, error) { return f.images, nil }
func (f *fakeAPI) VMs(context.Context) ([]VM, error) {
	if f.apiDown {
		return nil, errors.New("down")
	}
	var out []VM
	for _, v := range f.vms {
		out = append(out, *v)
	}
	return out, nil
}
func (f *fakeAPI) ActiveOperations(context.Context) (int, error) { return f.active, nil }
func (f *fakeAPI) Submit(_ context.Context, typ, name string, c *CreateRequest) (string, error) {
	f.calls = append(f.calls, typ+" "+name)
	f.n++
	id := fmt.Sprintf("op-%d", f.n)
	if f.failOn[typ] {
		f.ops[id] = "failed"
		return id, nil
	}
	f.ops[id] = "succeeded"
	switch typ {
	case "create":
		f.vms[name] = &VM{Name: name, Managed: true, Power: "stopped"}
	case "start":
		f.vms[name].Power = "running"
		if !f.noAddr {
			f.vms[name].IP = "192.168.122.50"
		}
	case "stop":
		if f.stopSlow {
			f.ops[id] = "failed"
		} else {
			f.vms[name].Power, f.vms[name].IP = "stopped", ""
		}
	case "force_off":
		f.vms[name].Power, f.vms[name].IP = "stopped", ""
	case "delete":
		delete(f.vms, name)
	}
	return id, nil
}
func (f *fakeAPI) Wait(_ context.Context, id string, _ time.Duration) (string, error) {
	return f.ops[id], nil
}

type fakeProber struct {
	banner string
	err    error
	calls  int
}

func (p *fakeProber) SSHBanner(context.Context, string) (string, error) {
	p.calls++
	return p.banner, p.err
}

type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }
func (c *clock) sleep(_ context.Context, d time.Duration) error {
	c.t = c.t.Add(d)
	return nil
}

func runner(f *fakeAPI, p *fakeProber) (*Runner, *clock) {
	c := &clock{t: time.Date(2026, 10, 16, 2, 0, 0, 0, time.UTC)}
	return &Runner{API: f, Prober: p, Now: c.now, Sleep: c.sleep, Suffix: "ab12", Timing: Timings{Create: time.Minute, Start: time.Minute, Stop: time.Minute, Delete: time.Minute, Address: time.Minute, Banner: time.Minute, Poll: 5 * time.Second}}, c
}

func TestAPassingNightCreatesBootsChecksAndLeavesNothing(t *testing.T) {
	f, p := newFake(), &fakeProber{banner: "SSH-2.0-OpenSSH_9.6"}
	r, _ := runner(f, p)
	res := r.Run(context.Background())
	if res.Result != Pass || res.Reason != "" {
		t.Fatalf("%+v", res)
	}
	if got := strings.Join(f.calls, ","); got != "create svnb-ab12,start svnb-ab12,stop svnb-ab12,delete svnb-ab12" {
		t.Fatalf("%s", got)
	}
	if len(f.vms) != 0 {
		t.Fatalf("host must be clean: %v", f.vms)
	}
}

func TestTheDisposableVMUsesTheQualifiedImageAndTheSmallestSizes(t *testing.T) {
	f, p := newFake(), &fakeProber{banner: "SSH-2.0-x"}
	var got *CreateRequest
	r, _ := runner(f, p)
	r.API = &spy{fakeAPI: f, onCreate: func(c *CreateRequest) { got = c }}
	if res := r.Run(context.Background()); res.Result != Pass {
		t.Fatalf("%+v", res)
	}
	if got == nil || got.ImageID != "ubuntu-24.04" || got.DiskGiB != 10 || got.MemoryMiB != 512 || got.VCPUs != 1 || !strings.HasPrefix(got.SSHPublicKey, "ssh-ed25519 ") || strings.Contains(got.SSHPublicKey, "PRIVATE") {
		t.Fatalf("%+v", got)
	}
}

type spy struct {
	*fakeAPI
	onCreate func(*CreateRequest)
}

func (s *spy) Submit(ctx context.Context, typ, name string, c *CreateRequest) (string, error) {
	if c != nil {
		s.onCreate(c)
	}
	return s.fakeAPI.Submit(ctx, typ, name, c)
}

func TestSkipsAreHonestAndTouchNothing(t *testing.T) {
	cases := map[string]struct {
		mut    func(*fakeAPI)
		reason string
	}{
		"not ready":  {func(f *fakeAPI) { f.host.CreationReady = false }, ReasonNotReady},
		"busy":       {func(f *fakeAPI) { f.active = 1 }, ReasonBusy},
		"no image":   {func(f *fakeAPI) { f.images = []Image{{ID: "x", Qualified: false}} }, ReasonNoImage},
		"low space":  {func(f *fakeAPI) { n := 12; f.host.PoolFreeGiB = &n }, ReasonSpace},
		"low memory": {func(f *fakeAPI) { n := 1200; f.host.MemoryFreeMiB = &n }, ReasonMemory},
	}
	for name, c := range cases {
		f, p := newFake(), &fakeProber{banner: "SSH-2.0-x"}
		c.mut(f)
		r, _ := runner(f, p)
		res := r.Run(context.Background())
		if res.Result != Skipped || res.Reason != c.reason || len(f.calls) != 0 {
			t.Errorf("%s: %+v calls %v", name, res, f.calls)
		}
	}
}

func TestUnknownMemoryDoesNotBlockTheNight(t *testing.T) {
	f, p := newFake(), &fakeProber{banner: "SSH-2.0-x"}
	f.host.MemoryFreeMiB = nil
	r, _ := runner(f, p)
	if res := r.Run(context.Background()); res.Result != Pass {
		t.Fatalf("%+v", res)
	}
}

func TestAGuestWithoutAnAddressOrBannerFailsAndIsStillRemoved(t *testing.T) {
	f, p := newFake(), &fakeProber{err: errors.New("refused")}
	f.noAddr = true
	r, _ := runner(f, p)
	res := r.Run(context.Background())
	if res.Result != Fail || res.Reason != ReasonAddress || len(f.vms) != 0 {
		t.Fatalf("%+v left %v", res, f.vms)
	}
	f2, p2 := newFake(), &fakeProber{err: errors.New("refused")}
	r2, _ := runner(f2, p2)
	res = r2.Run(context.Background())
	if res.Result != Fail || res.Reason != ReasonBanner || len(f2.vms) != 0 || p2.calls < 2 {
		t.Fatalf("%+v left %v probes %d", res, f2.vms, p2.calls)
	}
	f3, p3 := newFake(), &fakeProber{banner: "HTTP/1.1 400 Bad Request"}
	r3, _ := runner(f3, p3)
	if res := r3.Run(context.Background()); res.Result != Fail || res.Reason != ReasonBanner {
		t.Fatalf("a non-SSH answer is not a banner: %+v", res)
	}
}

func TestAFailedCreateOrStartFailsWithTheirReasons(t *testing.T) {
	for typ, reason := range map[string]string{"create": ReasonCreate, "start": ReasonStart} {
		f, p := newFake(), &fakeProber{banner: "SSH-2.0-x"}
		f.failOn[typ] = true
		r, _ := runner(f, p)
		res := r.Run(context.Background())
		if res.Result != Fail || res.Reason != reason || len(f.vms) != 0 {
			t.Errorf("%s: %+v left %v", typ, res, f.vms)
		}
	}
}

func TestAGuestThatWillNotStopGracefullyIsForcedOffBecauseItIsTheChecksOwn(t *testing.T) {
	f, p := newFake(), &fakeProber{banner: "SSH-2.0-x"}
	f.stopSlow = true
	r, _ := runner(f, p)
	res := r.Run(context.Background())
	if res.Result != Pass || len(f.vms) != 0 || !strings.Contains(strings.Join(f.calls, ","), "force_off svnb-ab12") {
		t.Fatalf("%+v calls %v", res, f.calls)
	}
}

func TestAFailedDeleteFailsTheNight(t *testing.T) {
	f, p := newFake(), &fakeProber{banner: "SSH-2.0-x"}
	f.failOn["delete"] = true
	r, _ := runner(f, p)
	res := r.Run(context.Background())
	if res.Result != Fail || res.Reason != ReasonDelete {
		t.Fatalf("%+v", res)
	}
}

func TestLeftoversAreCleanedByPrefixAndOwnershipOnly(t *testing.T) {
	f, p := newFake(), &fakeProber{banner: "SSH-2.0-x"}
	f.vms["svnb-dead"] = &VM{Name: "svnb-dead", Managed: true, Power: "running", IP: "10.0.0.9"}
	f.vms["svnb-foreign"] = &VM{Name: "svnb-foreign", Managed: false, Power: "running"}
	f.vms["web-1"] = &VM{Name: "web-1", Managed: true, Power: "running"}
	r, _ := runner(f, p)
	res := r.Run(context.Background())
	if res.Result != Pass {
		t.Fatalf("%+v", res)
	}
	if _, ok := f.vms["svnb-dead"]; ok {
		t.Fatal("the leftover must be removed")
	}
	for _, n := range []string{"svnb-foreign", "web-1"} {
		if v, ok := f.vms[n]; !ok || v.Power != "running" {
			t.Fatalf("%s must not be touched: %+v", n, v)
		}
	}
	for _, c := range f.calls {
		if strings.Contains(c, "web-1") || strings.Contains(c, "svnb-foreign") {
			t.Fatalf("touched %q", c)
		}
	}
}

func TestAnUnreachableAPIIsAFailureWithItsReason(t *testing.T) {
	f, p := newFake(), &fakeProber{}
	f.apiDown = true
	r, _ := runner(f, p)
	if res := r.Run(context.Background()); res.Result != Fail || res.Reason != ReasonAPI {
		t.Fatalf("%+v", res)
	}
}

func TestResultsRecordTheTimeAndDuration(t *testing.T) {
	f, p := newFake(), &fakeProber{banner: "SSH-2.0-x"}
	f.noAddr = true
	r, c := runner(f, p)
	start := c.t
	res := r.Run(context.Background())
	if !res.At.Equal(start) || res.Seconds < 60 || res.Seconds > 400 {
		t.Fatalf("%+v", res)
	}
}

// ---- the status file ------------------------------------------------------------------------------------------------------

func TestHistoryKeepsThirtyNightsNewestLast(t *testing.T) {
	var f File
	for i := 0; i < 45; i++ {
		f.Add(Result{At: time.Date(2026, 9, 1+i%28, 2, 0, 0, 0, time.UTC).Add(time.Duration(i) * time.Hour), Result: Pass, Seconds: i})
	}
	if len(f.Runs) != MaxHistory || f.Runs[0].Seconds != 15 || f.Last().Seconds != 44 {
		t.Fatalf("%d runs, first %d last %d", len(f.Runs), f.Runs[0].Seconds, f.Last().Seconds)
	}
}

func TestStatusFileRoundTripAndStrictness(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "nightly-boot.json")
	var f File
	f.Add(Result{At: time.Date(2026, 10, 16, 2, 0, 0, 0, time.UTC), Result: Fail, Seconds: 300, Reason: ReasonBanner})
	if err := Write(p, f); err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(p); fi.Mode().Perm() != 0o644 {
		t.Fatalf("mode %v", fi.Mode())
	}
	got, ok := Read(os.ReadFile, p)
	if !ok || got.Last().Result != Fail || got.Last().Reason != ReasonBanner || got.Last().Seconds != 300 {
		t.Fatalf("%+v %v", got, ok)
	}
	for name, body := range map[string]string{
		"not json": "{", "wrong version": `{"v":2,"runs":[]}`, "bad result": `{"v":1,"runs":[{"at":"2026-10-16T02:00:00Z","result":"great","seconds":1,"reason":""}]}`,
		"negative seconds": `{"v":1,"runs":[{"at":"2026-10-16T02:00:00Z","result":"pass","seconds":-1,"reason":""}]}`, "no time": `{"v":1,"runs":[{"result":"pass","seconds":1,"reason":""}]}`,
		"huge": strings.Repeat(" ", 40<<10),
	} {
		if _, ok := Parse([]byte(body)); ok {
			t.Errorf("%s accepted", name)
		}
	}
	if _, ok := Read(os.ReadFile, filepath.Join(dir, "missing")); ok {
		t.Error("a missing file has no history")
	}
}
