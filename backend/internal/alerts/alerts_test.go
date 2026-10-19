package alerts

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"example.invalid/dedicatedcloud/backend/internal/hypervisor"
	"example.invalid/dedicatedcloud/backend/internal/sqlitedb"
)

func newEngine(t *testing.T) (*Engine, *SQLiteStore, *time.Time) {
	t.Helper()
	db, err := sqlitedb.Open(filepath.Join(t.TempDir(), "a.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	s, err := OpenSQLite(context.Background(), db)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)
	var n int
	e := &Engine{Store: s, Now: func() time.Time { return now }, NewID: func() (string, error) { n++; return fmt.Sprintf("al-%016x", n), nil }}
	return e, s, &now
}

func ip(n int) *int { return &n }

func pool(free int) Obs {
	return freeSpace(PoolFreeLow, "Host", "h1", ip(free), Thresholds{}.WithDefaults())
}

func TestRaiseDedupAndEscalate(t *testing.T) {
	e, s, now := newEngine(t)
	ctx := context.Background()
	ch, err := e.Apply(ctx, []Obs{pool(18)}, []string{PoolFreeLow})
	if err != nil || len(ch) != 1 || ch[0].Event != "opened" || ch[0].Alert.Severity != Warning {
		t.Fatalf("first: %+v %v", ch, err)
	}
	*now = now.Add(30 * time.Second)
	if ch, _ = e.Apply(ctx, []Obs{pool(17)}, []string{PoolFreeLow}); len(ch) != 0 {
		t.Fatalf("the same condition must not be announced again: %+v", ch)
	}
	a, _, _ := s.ByKey(ctx, "pool_free_low|Host|h1")
	if a.Value == nil || *a.Value != 17 || a.State != StateOpen {
		t.Fatalf("figure should follow the condition: %+v", a)
	}
	if err := e.Acknowledge(ctx, a.ID); err != nil {
		t.Fatal(err)
	}
	if ch, _ = e.Apply(ctx, []Obs{pool(16)}, []string{PoolFreeLow}); len(ch) != 0 {
		t.Fatalf("an acknowledged alert stays acknowledged while the condition continues: %+v", ch)
	}
	if a, _, _ = s.ByKey(ctx, "pool_free_low|Host|h1"); a.State != StateAcknowledged {
		t.Fatalf("state %s", a.State)
	}
	ch, _ = e.Apply(ctx, []Obs{pool(8)}, []string{PoolFreeLow})
	if len(ch) != 1 || ch[0].Event != "escalated" || ch[0].Alert.State != StateOpen || ch[0].Alert.Severity != Critical {
		t.Fatalf("worse than acknowledged must re-open: %+v", ch)
	}
	if n := len(mustOpen(t, s)); n != 1 {
		t.Fatalf("one condition, one alert: %d", n)
	}
}

func mustOpen(t *testing.T, s Store) []Alert {
	t.Helper()
	o, err := s.Open(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return o
}

func TestHysteresisResolveAndReopen(t *testing.T) {
	e, s, now := newEngine(t)
	ctx := context.Background()
	cov := []string{PoolFreeLow}
	e.Apply(ctx, []Obs{pool(15)}, cov)
	// 22 percent free is above the 20 percent threshold but inside the margin: nothing changes.
	for i := 0; i < 3; i++ {
		*now = now.Add(time.Minute)
		if ch, _ := e.Apply(ctx, []Obs{pool(22)}, cov); len(ch) != 0 {
			t.Fatalf("dead zone must not resolve: %+v", ch)
		}
	}
	// Clear once: still open (needs two in a row).
	*now = now.Add(time.Minute)
	if ch, _ := e.Apply(ctx, []Obs{pool(40)}, cov); len(ch) != 0 {
		t.Fatalf("one clear evaluation must not resolve: %+v", ch)
	}
	// A dead-zone reading interrupts the run.
	e.Apply(ctx, []Obs{pool(22)}, cov)
	if ch, _ := e.Apply(ctx, []Obs{pool(40)}, cov); len(ch) != 0 {
		t.Fatalf("interrupted run must not resolve: %+v", ch)
	}
	*now = now.Add(time.Minute)
	ch, _ := e.Apply(ctx, []Obs{pool(40)}, cov)
	if len(ch) != 1 || ch[0].Event != "resolved" || ch[0].Alert.State != StateResolved {
		t.Fatalf("two clear evaluations resolve: %+v", ch)
	}
	id := ch[0].Alert.ID
	*now = now.Add(time.Hour)
	ch, _ = e.Apply(ctx, []Obs{pool(5)}, cov)
	if len(ch) != 1 || ch[0].Event != "reopened" || ch[0].Alert.ID != id || !ch[0].Alert.CreatedAt.Equal(*now) {
		t.Fatalf("a returning condition re-opens the same alert as a new episode: %+v", ch)
	}
	if a, _, _ := s.ByID(ctx, id); a.State != StateOpen || a.Severity != Critical {
		t.Fatalf("%+v", a)
	}
}

func TestUnknownDataNeverResolvesAndGoneSubjectsDo(t *testing.T) {
	e, s, _ := newEngine(t)
	ctx := context.Background()
	e.Apply(ctx, []Obs{{Type: VMCrashed, Kind: "VM", ResourceID: "web", Severity: Critical, Active: true}}, []string{VMCrashed})
	// Inventory unreadable: the rule is not covered and nothing is observed.
	for i := 0; i < 5; i++ {
		if ch, _ := e.Apply(ctx, nil, nil); len(ch) != 0 {
			t.Fatalf("unknown data changed an alert: %+v", ch)
		}
	}
	if len(mustOpen(t, s)) != 1 {
		t.Fatal("alert must remain")
	}
	// The VM is gone from a complete inventory: it clears (after two evaluations).
	e.Apply(ctx, nil, []string{VMCrashed})
	ch, _ := e.Apply(ctx, nil, []string{VMCrashed})
	if len(ch) != 1 || ch[0].Event != "resolved" {
		t.Fatalf("%+v", ch)
	}
}

func TestAcknowledgeErrors(t *testing.T) {
	e, _, _ := newEngine(t)
	ctx := context.Background()
	for id, want := range map[string]hypervisor.Category{"bad": hypervisor.Validation, "al-00000000000000ff": hypervisor.NotFound} {
		if got := hypervisor.CategoryOf(e.Acknowledge(ctx, id)); got != want {
			t.Errorf("%s: %s", id, got)
		}
	}
	e.Apply(ctx, []Obs{pool(5)}, []string{PoolFreeLow})
	a, _, _ := e.Store.ByKey(ctx, "pool_free_low|Host|h1")
	if err := e.Acknowledge(ctx, a.ID); err != nil {
		t.Fatal(err)
	}
	if err := e.Acknowledge(ctx, a.ID); err != nil {
		t.Fatalf("acknowledging twice is idempotent: %v", err)
	}
	e.Apply(ctx, []Obs{pool(50)}, []string{PoolFreeLow})
	e.Apply(ctx, []Obs{pool(50)}, []string{PoolFreeLow})
	if got := hypervisor.CategoryOf(e.Acknowledge(ctx, a.ID)); got != hypervisor.Conflict {
		t.Fatalf("resolved: %s", got)
	}
}

func TestListPaging(t *testing.T) {
	e, s, now := newEngine(t)
	ctx := context.Background()
	for i := 0; i < 5; i++ {
		*now = now.Add(time.Second)
		e.Apply(ctx, []Obs{{Type: VMCrashed, Kind: "VM", ResourceID: fmt.Sprintf("vm%d", i), Severity: Critical, Active: true}}, nil)
	}
	var got []string
	after := ""
	for {
		page, more, err := s.List(ctx, StateOpen, 2, after)
		if err != nil {
			t.Fatal(err)
		}
		for _, a := range page {
			got = append(got, a.ResourceID)
		}
		if !more {
			break
		}
		after = page[len(page)-1].ID
	}
	if fmt.Sprint(got) != "[vm4 vm3 vm2 vm1 vm0]" {
		t.Fatalf("newest first, no gaps: %v", got)
	}
	if page, _, _ := s.List(ctx, StateResolved, 10, ""); len(page) != 0 {
		t.Fatal("state filter")
	}
}

func TestEvaluateRules(t *testing.T) {
	ev := &Evaluator{}
	p := func(n int) *int { return &n }
	obs, cov := ev.Evaluate(Inputs{PoolFreePercent: p(9), BackupStoreFreePercent: p(30), HostMemoryUsedPercent: p(98), HostID: "h1"})
	find := func(typ string) Obs {
		for _, o := range obs {
			if o.Type == typ {
				return o
			}
		}
		t.Fatalf("no %s in %+v", typ, obs)
		return Obs{}
	}
	if o := find(PoolFreeLow); !o.Active || o.Severity != Critical || *o.Value != 9 {
		t.Errorf("%+v", o)
	}
	if o := find(BackupStoreFreeLow); o.Active || !o.Clear {
		t.Errorf("%+v", o)
	}
	if o := find(HostMemoryHigh); !o.Active || o.Severity != Critical {
		t.Errorf("%+v", o)
	}
	for _, c := range cov {
		if c == VMCrashed || c == RetriesExhausted || c == ScheduledBackup {
			t.Errorf("rule %s covered without its inputs", c)
		}
	}
	// Unreadable inputs raise nothing and cover nothing.
	obs, cov = ev.Evaluate(Inputs{})
	for _, o := range obs {
		if o.Active {
			t.Errorf("active without data: %+v", o)
		}
	}
	for _, c := range cov {
		if c != NightlyBootFailed {
			t.Errorf("covered without data: %s", c)
		}
	}
}

func TestVMRules(t *testing.T) {
	ev := &Evaluator{}
	vms := func(state string) Inputs {
		return Inputs{VMsKnown: true, VMs: []VMState{{Name: "web", Managed: true, State: state}, {Name: "foreign", Managed: false, State: "crashed"}}, HostID: "h1"}
	}
	active := func(obs []Obs, typ string) bool {
		for _, o := range obs {
			if o.Type == typ && o.Active {
				return true
			}
			if o.ResourceID == "foreign" {
				t.Fatal("a VM Svavyom does not manage is not judged")
			}
		}
		return false
	}
	obs, _ := ev.Evaluate(vms("shutoff"))
	if active(obs, VMStoppedUnasked) {
		t.Fatal("never seen running: nothing to say (restart of the API, or a VM that was always stopped)")
	}
	ev.Evaluate(vms("running"))
	in := vms("shutoff")
	in.StoppedByOperation = map[string]bool{"web": true}
	if obs, _ = ev.Evaluate(in); active(obs, VMStoppedUnasked) {
		t.Fatal("a stop somebody asked for is not an alert")
	}
	ev.Evaluate(vms("running"))
	if obs, _ = ev.Evaluate(vms("shutoff")); !active(obs, VMStoppedUnasked) {
		t.Fatal("running to shut off with no operation is an alert")
	}
	if obs, _ = ev.Evaluate(vms("crashed")); !active(obs, VMCrashed) {
		t.Fatal("crashed")
	}
}

func TestValidateWebhook(t *testing.T) {
	good := []struct {
		u        string
		internal bool
	}{
		{"https://hooks.example.com/a", false},
		{"https://hooks.example.com:8443/a?x=1", false},
		{"https://93.184.216.34/a", false},
		{"https://[2606:2800:220:1:248:1893:25c8:1946]/a", false},
		{"http://127.0.0.1:9000/a", true},
		{"https://10.1.2.3/a", true},
	}
	for _, c := range good {
		if err := ValidateWebhook(c.u, c.internal); err != nil {
			t.Errorf("%s: %v", c.u, err)
		}
	}
	bad := []struct {
		u        string
		internal bool
	}{
		{"", false}, {"http://hooks.example.com/a", false}, {"ftp://x/a", true}, {"https:///a", false}, {"https://user:pw@hooks.example.com/a", false},
		{"https://127.0.0.1/a", false}, {"https://localhost/a", false}, {"https://a.localhost/a", false}, {"https://[::1]/a", false},
		{"https://10.0.0.1/a", false}, {"https://192.168.1.1/a", false}, {"https://172.16.0.1/a", false}, {"https://169.254.169.254/a", false},
		{"https://100.64.0.1/a", false}, {"https://0.0.0.0/a", false}, {"https://[fe80::1]/a", false}, {"https://[fd00::1]/a", false},
		{"https://[::ffff:127.0.0.1]/a", false}, {"https://224.0.0.1/a", false}, {"https://hooks.example.com:0/a", false},
		{"https://hooks.example.com:70000/a", false}, {"https://hooks.example.com/a#frag", false}, {"https://hooks.example.com/a b", false},
		{"https://host.internal/a", false}, {"mailto:x@y", true},
	}
	for _, c := range bad {
		if err := ValidateWebhook(c.u, c.internal); err == nil {
			t.Errorf("accepted %q (internal %v)", c.u, c.internal)
		}
	}
	long := "https://example.com/" + string(make([]byte, 600))
	if ValidateWebhook(long, true) == nil {
		t.Error("overlong url accepted")
	}
}

func sampleChange() Change {
	return Change{Event: "opened", Alert: Alert{ID: "al-0000000000000001", Type: PoolFreeLow, Kind: "Host", ResourceID: "h1", Severity: Warning, State: StateOpen,
		Value: ip(18), UpdatedAt: time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)}}
}

func TestNotifierDelivers(t *testing.T) {
	var got atomic.Value
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var p Payload
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&p); err != nil || r.Method != http.MethodPost || r.Header.Get("Content-Type") != "application/json" {
			w.WriteHeader(400)
			return
		}
		got.Store(p)
	}))
	defer srv.Close()
	n, err := NewNotifier(Webhook{URL: srv.URL, Internal: true})
	if err != nil {
		t.Fatal(err)
	}
	n.deliver(context.Background(), sampleChange())
	p, _ := got.Load().(Payload)
	if p.V != 1 || p.Rule != PoolFreeLow || p.Severity != Warning || p.AlertID != "al-0000000000000001" || p.Value == nil || *p.Value != 18 || n.Sent != 1 {
		t.Fatalf("%+v sent %d", p, n.Sent)
	}
	b, _ := json.Marshal(p)
	if len(b) > maxBodyBytes {
		t.Fatal("body too large")
	}
}

func TestNotifierRetriesThenBreaker(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); w.WriteHeader(500) }))
	defer srv.Close()
	n, _ := NewNotifier(Webhook{URL: srv.URL, Internal: true})
	n.Sleep = func(time.Duration) {}
	clock := time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)
	n.Now = func() time.Time { return clock }
	for i := 0; i < breakerFails; i++ {
		n.deliver(context.Background(), sampleChange())
	}
	if int(calls.Load()) != breakerFails*maxAttempts {
		t.Fatalf("each change gets %d attempts: %d calls", maxAttempts, calls.Load())
	}
	before := calls.Load()
	n.deliver(context.Background(), sampleChange())
	if calls.Load() != before || n.Dropped != 1 {
		t.Fatal("an open breaker must not send")
	}
	clock = clock.Add(breakerOpenFor + time.Second)
	n.deliver(context.Background(), sampleChange())
	if calls.Load() == before {
		t.Fatal("the breaker must close again after its pause")
	}
}

func TestNotifierRefusesRedirectAndHang(t *testing.T) {
	var hits atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1) }))
	defer target.Close()
	redir := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, target.URL, http.StatusFound) }))
	defer redir.Close()
	n, _ := NewNotifier(Webhook{URL: redir.URL, Internal: true})
	n.Sleep = func(time.Duration) {}
	n.deliver(context.Background(), sampleChange())
	if hits.Load() != 0 || n.Sent != 0 {
		t.Fatalf("a redirect must not be followed: hits %d sent %d", hits.Load(), n.Sent)
	}
	release := make(chan struct{})
	hang := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-release }))
	defer hang.Close()
	defer close(release)
	m, _ := NewNotifier(Webhook{URL: hang.URL, Internal: true})
	m.Client.Timeout = 200 * time.Millisecond
	m.Sleep = func(time.Duration) {}
	start := time.Now()
	m.deliver(context.Background(), sampleChange())
	if time.Since(start) > 5*time.Second || m.Sent != 0 {
		t.Fatalf("a hanging endpoint must time out: %v", time.Since(start))
	}
}

func TestPublicOnlyClientRefusesLoopback(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1) }))
	defer srv.Close()
	// The URL itself is rejected for a non-internal webhook...
	if _, err := NewNotifier(Webhook{URL: srv.URL}); err == nil {
		t.Fatal("loopback http url accepted without internal")
	}
	// ...and even a validated https host name cannot reach a loopback address: the dial is checked after resolution.
	n := &Notifier{Hook: Webhook{URL: "https://localhost.example.invalid/"}, Client: confinedClient(false), q: make(chan Change, 1)}
	c := confinedClient(false)
	req, _ := http.NewRequest(http.MethodPost, srv.URL, nil) // plain http to 127.0.0.1: the dial control must refuse before connecting
	if _, err := c.Do(req); err == nil || hits.Load() != 0 {
		t.Fatalf("connect to a loopback address must be refused (hits %d)", hits.Load())
	}
	_ = n
}

func TestOversizeBodyAndQueueBound(t *testing.T) {
	n, _ := NewNotifier(Webhook{URL: "https://hooks.example.com/a"})
	for i := 0; i < queueLen+10; i++ {
		n.Notify([]Change{sampleChange()})
	}
	if n.Dropped != 10 {
		t.Fatalf("a full queue drops: %d", n.Dropped)
	}
}
