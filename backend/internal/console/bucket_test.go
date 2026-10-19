package console

import (
	"testing"
	"time"
)

// A viewer's input towards the VM is rationed: a burst beyond the per-second allowance waits instead of reaching the VM at once.
func TestTheInputBucketRationsABurst(t *testing.T) {
	k := newBucket(4096)
	stop := make(chan struct{})
	start := time.Now()
	k.wait(4096, stop) // the first second's allowance is available at once
	if time.Since(start) > 200*time.Millisecond {
		t.Fatalf("the allowance should be there: %v", time.Since(start))
	}
	start = time.Now()
	k.wait(2048, stop) // a half second's worth more must wait about half a second
	if d := time.Since(start); d < 300*time.Millisecond || d > 2*time.Second {
		t.Fatalf("waited %v", d)
	}
	close(stop)
	start = time.Now()
	k.wait(1<<20, stop) // a stopped broker does not hold the viewer's goroutine
	if time.Since(start) > time.Second {
		t.Fatal("stop must release the wait")
	}
}
