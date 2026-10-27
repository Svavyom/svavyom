package consolesim

import (
	"context"
	"errors"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
)

// The broker scans the source on a timer while a test turns the "hypervisor unreachable" switch on and off. SetFail takes the lock the readers take;
// assigning Fail directly does not, and the race detector (make go-test runs it with -race) reports that as a data race. This test is the deterministic
// form of the race that failed CI on 2026-10-25 (TestSnapshotStatesAreTyped): many readers, one toggler, no sleeps.
func TestFailCanBeToggledWhileTheSourceIsRead(t *testing.T) {
	s := New()
	s.Set("web-1", VM{Managed: true, Configured: true, Running: true})
	boom := errors.New("unreachable")
	ctx := context.Background()

	// The readers and the toggler must overlap, or there is nothing for the race detector to see: the toggler keeps going until the readers have done a
	// minimum amount of work, and the readers start before it does.
	stop := make(chan struct{})
	var reads atomic.Int64
	var started, readers sync.WaitGroup
	for i := 0; i < 4; i++ {
		started.Add(1)
		readers.Add(1)
		go func() {
			defer readers.Done()
			started.Done()
			for {
				select {
				case <-stop:
					return
				default:
					_, _ = s.Running(ctx)
					_, _ = s.Check(ctx, "web-1")
					reads.Add(1)
					runtime.Gosched()
				}
			}
		}()
	}
	started.Wait()
	for toggles := 0; toggles < 2000 || reads.Load() < 2000; toggles++ {
		s.SetFail(boom)
		s.SetFail(nil)
		runtime.Gosched()
	}
	close(stop)
	readers.Wait()

	if _, err := s.Running(ctx); err != nil {
		t.Fatalf("cleared: %v", err)
	}
	s.SetFail(boom)
	if _, err := s.Running(ctx); !errors.Is(err, boom) {
		t.Fatalf("set: %v", err)
	}
	if _, err := s.Check(ctx, "web-1"); !errors.Is(err, boom) {
		t.Fatalf("set (Check): %v", err)
	}
}
