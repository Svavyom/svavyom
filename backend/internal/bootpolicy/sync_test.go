package bootpolicy

import (
	"context"
	"errors"
	"sort"
	"sync"
	"testing"
	"time"
)

type fakeHost struct {
	mu    sync.Mutex
	flags map[string]bool
	calls []string
	fail  map[string]bool
	doms  []Domain
	err   error
}

func (f *fakeHost) Domains(context.Context) ([]Domain, error) { return f.doms, f.err }
func (f *fakeHost) SetAutostart(_ context.Context, n string, on bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fail[n] {
		return errors.New("libvirt said no")
	}
	f.flags[n] = on
	f.calls = append(f.calls, n)
	return nil
}

func newSyncer(t *testing.T, doms ...Domain) (*Syncer, *fakeHost) {
	t.Helper()
	h := &fakeHost{flags: map[string]bool{}, fail: map[string]bool{}, doms: doms}
	return NewSyncer(open(t), h, h, nil), h
}

func TestTheFlagFollowsTheBoxAndTheIntentForEveryManagedVM(t *testing.T) {
	s, h := newSyncer(t, Domain{"a", true, true}, Domain{"b", true, false}, Domain{"c", true, true})
	ctx := context.Background()
	// VMs that existed before the feature get a row: the box ticked, the intent as observed now
	if err := s.Once(ctx); err != nil {
		t.Fatal(err)
	}
	if !h.flags["a"] || h.flags["b"] || !h.flags["c"] {
		t.Fatalf("running VMs start at boot, the stopped one does not: %v", h.flags)
	}
	// the owner unticks c, and stops a through the console
	_ = s.SetStartOnBoot(ctx, "c", false, "olly")
	_ = s.PowerIntent(ctx, "a", false, "olly")
	_ = s.PowerIntent(ctx, "b", true, "olly")
	if err := s.Once(ctx); err != nil {
		t.Fatal(err)
	}
	if h.flags["a"] || !h.flags["b"] || h.flags["c"] {
		t.Fatalf("flags: %v", h.flags)
	}
}

func TestAnUnmanagedDomainIsNeverGivenARowOrAFlag(t *testing.T) {
	s, h := newSyncer(t, Domain{"theirs", false, true}, Domain{"mine", true, true})
	if err := s.Once(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, ok := h.flags["theirs"]; ok {
		t.Fatal("a domain Svavyom does not manage was touched")
	}
	if _, ok, _ := s.Store.Get(context.Background(), "theirs"); ok {
		t.Fatal("a row for a domain Svavyom does not manage")
	}
}

func TestFlagsAreSetOnlyWhenTheyChangeAndAgainOnTheFullPass(t *testing.T) {
	s, h := newSyncer(t, Domain{"a", true, true})
	s.FullEvery = 3
	ctx := context.Background()
	for i := 0; i < 2; i++ {
		_ = s.Once(ctx)
	}
	if len(h.calls) != 1 {
		t.Fatalf("an unchanged flag is not set again: %v", h.calls)
	}
	_ = s.Once(ctx) // the third pass sets everything again, so a flag changed by hand is repaired
	if len(h.calls) != 2 {
		t.Fatalf("the full pass: %v", h.calls)
	}
}

func TestAFailureIsReportedAndTheRestOfThePassStillRuns(t *testing.T) {
	s, h := newSyncer(t, Domain{"a", true, true}, Domain{"b", true, true})
	h.fail["a"] = true
	if err := s.Once(context.Background()); err == nil {
		t.Fatal("the failure must be reported")
	}
	if !h.flags["b"] {
		t.Fatal("one VM's failure stopped the others")
	}
	h.fail["a"] = false
	if err := s.Once(context.Background()); err != nil || !h.flags["a"] {
		t.Fatalf("the next pass repairs it: %v %v", err, h.flags)
	}
}

func TestARowIsForgottenOnlyAfterTheDomainIsMissingTwoPassesInARow(t *testing.T) {
	s, h := newSyncer(t, Domain{"a", true, true})
	ctx := context.Background()
	_ = s.Once(ctx)
	h.doms = nil
	_ = s.Once(ctx)
	if _, ok, _ := s.Store.Get(ctx, "a"); !ok {
		t.Fatal("one empty listing must not erase the owner's choices")
	}
	h.doms = []Domain{{"a", true, true}}
	_ = s.Once(ctx)
	h.doms = nil
	_ = s.Once(ctx)
	_ = s.Once(ctx)
	if _, ok, _ := s.Store.Get(ctx, "a"); ok {
		t.Fatal("the row of a domain that is gone stays forever")
	}
	h.err = errors.New("agent down")
	if err := s.Once(ctx); err == nil {
		t.Fatal("an unreadable listing is an error, never a reason to delete")
	}
}

func TestRunDoesAPassAtStartAndWhenKickedAndStopsWithItsContext(t *testing.T) {
	s, h := newSyncer(t, Domain{"a", true, true})
	s.Every = time.Hour
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { s.Run(ctx); close(done) }()
	wait := func(want int) {
		t.Helper()
		for i := 0; i < 200; i++ {
			h.mu.Lock()
			n := len(h.calls)
			h.mu.Unlock()
			if n >= want {
				return
			}
			time.Sleep(20 * time.Millisecond)
		}
		t.Fatalf("no pass: %d calls", len(h.calls))
	}
	wait(1)
	_ = s.PowerIntent(ctx, "a", false, "x")
	wait(2)
	cancel()
	<-done
	var names []string
	for n := range h.flags {
		names = append(names, n)
	}
	sort.Strings(names)
	if len(names) != 1 || h.flags["a"] {
		t.Fatalf("%v", h.flags)
	}
}
