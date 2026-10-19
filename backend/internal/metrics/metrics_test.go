package metrics

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"example.invalid/dedicatedcloud/backend/internal/hypervisor"
	"example.invalid/dedicatedcloud/backend/internal/sqlitedb"
)

type fakeHost struct {
	busy, total uint64
	mem         int64
	cpuErr      error
}

func (f *fakeHost) CPU() (uint64, uint64, error)  { return f.busy, f.total, f.cpuErr }
func (f *fakeHost) MemoryUsedMiB() (int64, error) { return f.mem, nil }

type fakeVMs struct{ doms []hypervisor.Domain }

func (f *fakeVMs) List(context.Context) ([]hypervisor.Domain, error) { return f.doms, nil }

type clock struct{ t time.Time }

func (c *clock) now() time.Time      { return c.t }
func (c *clock) add(d time.Duration) { c.t = c.t.Add(d) }

func openStore(t *testing.T) *SQLiteStore {
	t.Helper()
	db, err := sqlitedb.Open(filepath.Join(t.TempDir(), "u.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	s, err := OpenSQLite(context.Background(), db)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func newSampler(st Store, h *fakeHost, v *fakeVMs, c *clock) *Sampler {
	return &Sampler{Store: st, HostSrc: h, VMSrc: v, Interval: 30 * time.Second, Now: c.now}
}

func TestProcReaderReadsStatAndMeminfo(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "proc"), 0o755); err != nil {
		t.Fatal(err)
	}
	// user nice system idle iowait irq softirq steal: busy = total - idle - iowait
	write := func(name, body string) {
		if err := os.WriteFile(filepath.Join(root, "proc", name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("stat", "cpu  100 10 90 700 100 0 0 0 0 0\ncpu0 1 1 1 1 1 0 0 0 0 0\n")
	write("meminfo", "MemTotal:       16384000 kB\nMemFree:         1000 kB\nMemAvailable:    8192000 kB\n")
	p := ProcReader{Root: root}
	busy, total, err := p.CPU()
	if err != nil || busy != 200 || total != 1000 {
		t.Fatalf("cpu = %d/%d, %v", busy, total, err)
	}
	mem, err := p.MemoryUsedMiB()
	if err != nil || mem != 8000 {
		t.Fatalf("mem = %d, %v", mem, err)
	}
	write("stat", "garbage\n")
	if _, _, err := p.CPU(); err == nil {
		t.Fatal("garbage stat must be an error")
	}
	write("meminfo", "MemTotal: 10 kB\nMemAvailable: 20 kB\n")
	if _, err := p.MemoryUsedMiB(); err == nil {
		t.Fatal("available above total must be an error")
	}
}

func TestSamplerNeedsTwoReadingsThenReportsPercentages(t *testing.T) {
	c := &clock{t: time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)}
	h := &fakeHost{busy: 0, total: 1000, mem: 2048}
	v := &fakeVMs{doms: []hypervisor.Domain{{Name: "web-1", State: hypervisor.StateRunning, VCPUs: 2, CPUTimeNs: 1e9}, {Name: "off-1", State: hypervisor.StateShutoff}}}
	s := newSampler(openStore(t), h, v, c)
	ctx := context.Background()
	s.Tick(ctx)
	if u := s.Host(ctx); u.Available || len(u.History) != 0 {
		t.Fatalf("one reading cannot give a percentage: %+v", u)
	}
	c.add(30 * time.Second)
	h.busy, h.total, h.mem = 250, 1000+1000, 3072 // 250 busy of 1000 more ticks: 25%
	v.doms[0].CPUTimeNs += 30e9                   // 30 CPU-seconds in 30 s on 2 vCPUs: 50%
	s.Tick(ctx)
	hu := s.Host(ctx)
	if !hu.Available || *hu.CPUPercent != 25 || *hu.MemUsedMiB != 3072 || len(hu.History) != 1 || hu.IntervalSeconds != 30 {
		t.Fatalf("host usage = %+v", hu)
	}
	vu := s.VMs(ctx)
	if got := vu["web-1"]; !got.Available || *got.CPUPercent != 50 || len(got.History) != 1 {
		t.Fatalf("vm usage = %+v", got)
	}
	if _, ok := vu["off-1"]; ok {
		t.Fatal("a stopped VM has no usage")
	}
}

func TestSamplerNeverInventsAValue(t *testing.T) {
	c := &clock{t: time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)}
	h := &fakeHost{busy: 10, total: 100, mem: 1}
	v := &fakeVMs{doms: []hypervisor.Domain{{Name: "a", State: hypervisor.StateRunning, VCPUs: 1, CPUTimeNs: 5e9}}}
	s := newSampler(openStore(t), h, v, c)
	ctx := context.Background()
	s.Tick(ctx)
	// the counter goes backwards (guest restarted): no sample, no negative or huge percentage
	c.add(30 * time.Second)
	h.busy, h.total = 20, 200
	v.doms[0].CPUTimeNs = 1e9
	s.Tick(ctx)
	if got := s.VMs(ctx); len(got) != 0 {
		t.Fatalf("a restarted counter must leave a gap: %+v", got)
	}
	// more CPU than the VM could have: clamped to 100
	c.add(30 * time.Second)
	v.doms[0].CPUTimeNs += 300e9
	h.busy, h.total = 30, 300
	s.Tick(ctx)
	if p := *s.VMs(ctx)["a"].CPUPercent; p != 100 {
		t.Fatalf("percent = %d, want clamped to 100", p)
	}
	// a failing CPU read leaves a gap in the host history
	c.add(30 * time.Second)
	before := len(s.Host(ctx).History)
	h.cpuErr = errors.New("boom")
	s.Tick(ctx)
	if got := len(s.Host(ctx).History); got != before {
		t.Fatalf("history %d -> %d", before, got)
	}
}

func TestHistorySurvivesARestartAndIsPrunedAfterRetention(t *testing.T) {
	c := &clock{t: time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)}
	st := openStore(t)
	h := &fakeHost{busy: 0, total: 100, mem: 5}
	s := &Sampler{Store: st, HostSrc: h, Interval: 30 * time.Second, Now: c.now}
	ctx := context.Background()
	s.Tick(ctx)
	for i := 1; i <= 3; i++ {
		c.add(30 * time.Second)
		h.busy, h.total = uint64(i)*10, 100+uint64(i)*100
		s.Tick(ctx)
	}
	// a new process over the same database sees the history at once
	s2 := &Sampler{Store: st, HostSrc: &fakeHost{}, Interval: 30 * time.Second, Now: c.now}
	if got := len(s2.Host(ctx).History); got != 3 {
		t.Fatalf("history after restart = %d, want 3", got)
	}
	// 25 hours later the old rows are gone from the database
	c.add(25 * time.Hour)
	h.busy, h.total = 100, 5000
	s.Tick(ctx)
	rows, err := st.Since(ctx, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rows {
		if c.now().Sub(r.At) > Retention {
			t.Fatalf("a row older than the retention survived: %+v", r)
		}
	}
	// and only the last hour is reported, oldest first, bounded
	if got := s.Host(ctx).History; len(got) > MaxPoints {
		t.Fatalf("history is not bounded: %d", len(got))
	}
}

type brokenStore struct{}

func (brokenStore) Append(context.Context, []Row) error { return errors.New("disk full") }
func (brokenStore) Since(context.Context, time.Time) ([]Row, error) {
	return nil, errors.New("disk full")
}
func (brokenStore) Prune(context.Context, time.Time) error { return nil }

func TestADatabaseFailureFallsBackToMemoryAndIsReported(t *testing.T) {
	c := &clock{t: time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)}
	h := &fakeHost{busy: 0, total: 100, mem: 7}
	s := &Sampler{Store: brokenStore{}, HostSrc: h, Interval: 30 * time.Second, Now: c.now}
	ctx := context.Background()
	s.Tick(ctx)
	c.add(30 * time.Second)
	h.busy, h.total = 50, 200
	s.Tick(ctx)
	if !s.Degraded() {
		t.Fatal("a failed write must be reported")
	}
	if u := s.Host(ctx); !u.Available || *u.CPUPercent != 50 || len(u.History) != 1 {
		t.Fatalf("the figures must still show from memory: %+v", u)
	}
}

func TestANilSamplerReportsNothing(t *testing.T) {
	var s *Sampler
	if u := s.Host(context.Background()); u.Available || u.History == nil {
		t.Fatalf("%+v", u)
	}
	if len(s.VMs(context.Background())) != 0 {
		t.Fatal("no VM usage without a sampler")
	}
}

func TestSchemaIsOneMigration(t *testing.T) {
	if SchemaVersion() != 2 {
		t.Fatalf("schema version %d: new steps must be appended and pinned here", SchemaVersion())
	}
}

func TestProcReaderIOCountsPhysicalDisksAndInterfacesOnce(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "proc", "net"), 0o755); err != nil {
		t.Fatal(err)
	}
	write := func(name, body string) {
		if err := os.WriteFile(filepath.Join(root, "proc", name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// sda counts (100 + 300 sectors); its partition, loop and device-mapper devices must not be counted again.
	write("diskstats", "   8       0 sda 10 0 100 5 20 0 300 7 0 0 0\n   8       1 sda1 10 0 100 5 20 0 300 7 0 0 0\n   7       0 loop0 1 0 999 0 1 0 999 0 0 0 0\n 253       0 dm-0 1 0 999 0 1 0 999 0 0 0 0\n 259       0 nvme0n1 1 0 10 0 1 0 20 0 0 0 0\n")
	write("net/dev", "Inter-|   Receive |  Transmit\n face |bytes packets errs drop fifo frame compressed multicast|bytes packets errs drop fifo colls carrier compressed\n"+
		"    lo: 5000 1 0 0 0 0 0 0 5000 1 0 0 0 0 0 0\n  eth0: 1000 1 0 0 0 0 0 0 2000 1 0 0 0 0 0 0\nvirbr0: 9999 1 0 0 0 0 0 0 9999 1 0 0 0 0 0 0\n vnet3: 7777 1 0 0 0 0 0 0 7777 1 0 0 0 0 0 0\n")
	disk, net, err := ProcReader{Root: root}.IO()
	if err != nil || disk != (100+300+10+20)*512 || net != 3000 {
		t.Fatalf("disk %d net %d: %v", disk, net, err)
	}
	write("net/dev", "eth0: x\n")
	if _, _, err := (ProcReader{Root: root}).IO(); err != nil {
		t.Fatalf("a short interface line is skipped, not an error: %v", err)
	}
	write("diskstats", "8 0 sda 1 0 xx 0 1 0 1 0\n")
	if _, _, err := (ProcReader{Root: root}).IO(); err == nil {
		t.Fatal("unparsable counters must be an error")
	}
}

func TestRatesAreComputedFromTwoReadingsAndNeverInvented(t *testing.T) {
	if got := rate(1024*1024, 11*1024*1024, 10*time.Second); got != 1024 {
		t.Fatalf("10 MiB in 10 s is 1024 KiB/s, got %d", got)
	}
	for name, got := range map[string]int64{"no previous": rate(0, 5000, time.Second), "counter reset": rate(9000, 100, time.Second), "no time": rate(1, 2, 0)} {
		if got != 0 {
			t.Errorf("%s: %d", name, got)
		}
	}
	if kibPerSec(1<<60, time.Second) != 0 || kibPerSec(2048, 2*time.Second) != 1 {
		t.Fatal("kibPerSec")
	}
}

type ioHost struct {
	fakeHost
	disk, net uint64
}

func (f *ioHost) IO() (uint64, uint64, error) { return f.disk, f.net, nil }

func TestSamplerCarriesDiskNetworkAndVMMemory(t *testing.T) {
	c := &clock{t: time.Date(2026, 10, 14, 9, 0, 0, 0, time.UTC)}
	h := &ioHost{fakeHost: fakeHost{busy: 0, total: 100, mem: 1000}}
	vms := &fakeVMs{doms: []hypervisor.Domain{{Name: "web-1", State: hypervisor.StateRunning, VCPUs: 2, CPUTimeNs: 1, MemUsedMiB: 300, DiskIOBytes: 1 << 20, NetIOBytes: 1 << 20}}}
	st := openStore(t)
	s := &Sampler{Store: st, HostSrc: h, VMSrc: vms, Interval: 30 * time.Second, Now: c.now}
	s.Tick(context.Background())
	c.add(30 * time.Second)
	h.busy, h.total, h.disk, h.net = 50, 200, 30*1024*1024, 60*1024*1024
	vms.doms[0].CPUTimeNs = 30e9
	vms.doms[0].DiskIOBytes, vms.doms[0].NetIOBytes = (1<<20)+30*1024*1024, (1<<20)+3*1024*1024
	s.Tick(context.Background())
	hu := s.Host(context.Background())
	if !hu.Available || hu.DiskKiBs == nil || hu.NetKiBs == nil {
		t.Fatalf("%+v", hu)
	}
	// The host's own I/O counters are first read on the second tick, so its first rate is 0 (never invented); a VM has its first reading on tick one.
	vu := s.VMs(context.Background())["web-1"]
	if !vu.Available || *vu.MemUsedMiB != 300 || *vu.DiskKiBs != 1024 || *vu.NetKiBs != 102 {
		t.Fatalf("%+v disk=%d net=%d", vu, *vu.DiskKiBs, *vu.NetKiBs)
	}
	if len(vu.History) != 1 || vu.History[0].DiskKiBs != 1024 {
		t.Fatalf("%+v", vu.History)
	}
}
