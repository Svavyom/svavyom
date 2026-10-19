package operation

import (
	"context"
	"sync"
	"time"
)

// WorkerConfig tunes a Worker. Zero values select the defaults; out-of-range values are clamped, never rejected,
// so a bad setting cannot disable the safety bounds.
type WorkerConfig struct {
	// Concurrency is the fixed number of executor goroutines (default 2, max 16). It is the hard bound on
	// simultaneous host commands; no goroutine is created per operation.
	Concurrency int
	// Poll is the longest idle wait between scans (default 1s, min 10ms). Notify wakes the worker sooner.
	Poll time.Duration
	// BackoffBase and BackoffMax bound the wait before a retryable_failure is attempted again: base*2^(attempts-1),
	// capped (defaults 1s and 1m).
	BackoffBase time.Duration
	BackoffMax  time.Duration
	// OpTimeout bounds one host attempt (default 2m). Shutdown waits for in-flight attempts up to this bound.
	OpTimeout time.Duration
	// RecoverRetry is the wait between failed startup reconciliations (default 1s).
	RecoverRetry time.Duration
	// ObserveEvery is the interval of the observation-only look at creates that exhausted their attempts while their
	// earlier outcome is unknown (default BackoffMax, minimum 10ms). The first look after a start is immediate.
	ObserveEvery time.Duration
}

func (c *WorkerConfig) clamp() {
	if c.Concurrency <= 0 {
		c.Concurrency = 2
	}
	if c.Concurrency > 16 {
		c.Concurrency = 16
	}
	if c.Poll < 10*time.Millisecond {
		c.Poll = time.Second
	}
	if c.BackoffBase <= 0 {
		c.BackoffBase = time.Second
	}
	if c.BackoffMax < c.BackoffBase {
		c.BackoffMax = max(time.Minute, c.BackoffBase)
	}
	if c.OpTimeout <= 0 {
		c.OpTimeout = 2 * time.Minute
	}
	if c.RecoverRetry <= 0 {
		c.RecoverRetry = time.Second
	}
	if c.ObserveEvery < 10*time.Millisecond {
		c.ObserveEvery = c.BackoffMax
	}
}

// Worker advances queued operations of one Manager on a single node. It is not a distributed queue: exactly one
// worker process may run against a database (the caller holds sqlitedb.LockProcess), and that is what makes it safe
// for the worker to reconcile only once, at startup. Within the process, duplicate execution is prevented twice:
// an operation is never handed to two executors, and Manager.Run claims it with a compare-and-swap on generation.
type Worker struct {
	m      *Manager
	cfg    WorkerConfig
	wake   chan struct{}
	mu     sync.Mutex
	active map[string]bool // operation ids handed to an executor and not yet finished
	// nextObs schedules the observation-only looks (in memory: a restart looks again at once); obsOnly marks a job as one.
	nextObs map[string]time.Time
	obsOnly map[string]bool
}

// NewWorker builds a worker for m.
func NewWorker(m *Manager, cfg WorkerConfig) *Worker {
	cfg.clamp()
	return &Worker{m: m, cfg: cfg, wake: make(chan struct{}, 1), active: map[string]bool{}, nextObs: map[string]time.Time{}, obsOnly: map[string]bool{}}
}

// Notify asks the worker to scan now (for example after Submit). It never blocks and coalesces.
func (w *Worker) Notify() {
	select {
	case w.wake <- struct{}{}:
	default:
	}
}

// Backoff is the wait before attempt number attempts+1.
func (w *Worker) Backoff(attempts int) time.Duration {
	d := w.cfg.BackoffBase
	for i := 1; i < attempts && d < w.cfg.BackoffMax; i++ {
		d *= 2
	}
	return min(d, w.cfg.BackoffMax)
}

// Run reconciles the persisted operations, then executes work until ctx is cancelled. On cancellation it stops
// taking new work and returns after in-flight attempts finish (each bounded by OpTimeout); an attempt interrupted
// by process death instead is resolved by the next start's reconciliation. It returns ctx.Err() on shutdown.
func (w *Worker) Run(ctx context.Context) error {
	if err := w.recover(ctx); err != nil {
		return err
	}
	jobs := make(chan string)
	var wg sync.WaitGroup
	for i := 0; i < w.cfg.Concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for id := range jobs {
				w.execute(ctx, id)
			}
		}()
	}
	defer func() { close(jobs); wg.Wait() }()

	timer := time.NewTimer(0)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
		case <-w.wake:
		}
		next := w.dispatch(ctx, jobs)
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
		timer.Reset(next)
	}
}

// recover runs the startup reconciliation until it succeeds: an operation whose host outcome is unknown must be
// observed before anything else runs.
func (w *Worker) recover(ctx context.Context) error {
	for {
		if _, err := w.m.Reconcile(ctx); err == nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(w.cfg.RecoverRetry):
		}
	}
}

// dispatch hands every currently runnable operation to an idle executor and returns how long to wait before the
// next scan. Operations on one resource run strictly in submission order, one at a time: only the oldest open
// operation of a resource is eligible, so a start can never overtake the create before it, and a running,
// backing-off or retry-exhausted operation holds back its successors.
func (w *Worker) dispatch(ctx context.Context, jobs chan<- string) time.Duration {
	next := w.cfg.Poll
	ops, err := w.m.store.NonTerminal()
	if err != nil {
		return w.cfg.Poll
	}
	now := w.m.cfg.Clock()
	seen := map[[3]string]bool{}
	for _, op := range ops {
		key := [3]string{op.ProjectID, op.ResourceKind, op.ResourceID}
		if seen[key] {
			continue
		}
		seen[key] = true
		switch op.Status {
		case Pending:
		case Running:
			// Not active in this process, so its attempt returned with an unknown outcome (timeout) or its
			// observation failed: observe again. Safe because startup reconciliation already resolved crashes
			// and this process is the only one executing.
			w.mu.Lock()
			held := w.active[op.ID]
			w.mu.Unlock()
			if held {
				continue
			}
		case RetryableFailure:
			if op.Attempts >= w.m.cfg.MaxAttempts {
				// Exhausted: no further host mutation, ever. A create with an unknown earlier outcome is still looked at
				// (observation only, bounded interval) so a late success is found; anything else stays for an operator.
				if op.Type != Create || !op.UnknownOutcome {
					continue
				}
				w.mu.Lock()
				due, scheduled := w.nextObs[op.ID]
				w.mu.Unlock()
				if scheduled && due.After(now) {
					next = min(next, due.Sub(now))
					continue
				}
				w.mu.Lock()
				w.obsOnly[op.ID] = true
				w.mu.Unlock()
			} else if due := op.UpdatedAt.Add(w.Backoff(op.Attempts)); due.After(now) {
				next = min(next, due.Sub(now))
				continue
			}
		default:
			continue
		}
		w.mu.Lock()
		busy := w.active[op.ID]
		if !busy {
			w.active[op.ID] = true
		}
		w.mu.Unlock()
		if busy {
			continue
		}
		select {
		case jobs <- op.ID:
		case <-ctx.Done():
			w.release(op.ID)
			return w.cfg.Poll
		default: // every executor is busy: try again at the next scan
			w.release(op.ID)
			next = min(next, 10*time.Millisecond)
		}
	}
	return max(next, time.Millisecond)
}

func (w *Worker) release(id string) {
	w.mu.Lock()
	delete(w.active, id)
	w.mu.Unlock()
}

// execute runs one attempt. The attempt is detached from shutdown cancellation on purpose: abandoning a host
// command halfway leaves an unknown outcome, so it is allowed to finish (bounded by OpTimeout) instead.
func (w *Worker) execute(ctx context.Context, id string) {
	defer w.release(id)
	runCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), w.cfg.OpTimeout)
	defer cancel()
	w.mu.Lock()
	observeOnly := w.obsOnly[id]
	delete(w.obsOnly, id)
	w.mu.Unlock()
	if observeOnly { // TD-D: look, never send, never count an attempt
		_, _ = w.m.ObserveUncertain(runCtx, id)
		w.mu.Lock()
		w.nextObs[id] = w.m.cfg.Clock().Add(w.cfg.ObserveEvery)
		w.mu.Unlock()
		w.Notify()
		return
	}
	op, ok, err := w.m.store.Get(id)
	if err != nil || !ok {
		return
	}
	if op.Status == Running {
		_, _ = w.m.ReconcileOne(runCtx, id) // observe, never re-send
	} else {
		// Typed errors are already persisted in the operation record (and audited) or are lost-CAS conflicts;
		// the next scan re-evaluates from the store, never from this return value.
		_, _ = w.m.Run(runCtx, id)
		if got, ok, err := w.m.store.Get(id); err == nil && ok && got.Status == Running {
			_, _ = w.m.ReconcileOne(runCtx, id) // timeout: the host outcome is unknown until observed
		}
	}
	w.Notify() // a finished operation may unblock its successor
}
