package bootpolicy

import (
	"context"
	"errors"
	"sync"
	"time"
)

// Domain is what the syncer needs to know about a libvirt domain.
type Domain struct {
	Name    string
	Managed bool
	Running bool
}

// Source lists the domains of the host.
type Source interface {
	Domains(ctx context.Context) ([]Domain, error)
}

// Flagger sets the libvirt autostart flag of a managed domain.
type Flagger interface {
	SetAutostart(ctx context.Context, name string, on bool) error
}

// Syncer keeps libvirt's autostart flag of every managed VM equal to what the store says it should be (DR-042), and gives every managed VM a row. It is
// the only thing that touches the flag: an operation records the owner's intent in the store and wakes the syncer, so the flag cannot drift (a failed
// attempt, a restart, a flag changed by hand, a VM that existed before this feature). It also implements operation.Boot.
type Syncer struct {
	Store *Store
	Src   Source
	Host  Flagger
	Log   func(string)
	// Every is the pause between passes (default 5 minutes); a pass also runs when an operation wakes the syncer. FullEvery is how many passes go by before
	// every flag is set again even though it is believed right (default 12).
	Every     time.Duration
	FullEvery int

	kick    chan struct{}
	mu      sync.Mutex
	applied map[string]bool
	absent  map[string]int
	passes  int
}

// NewSyncer returns a syncer over the store.
func NewSyncer(store *Store, src Source, host Flagger, log func(string)) *Syncer {
	return &Syncer{Store: store, Src: src, Host: host, Log: log, kick: make(chan struct{}, 1), applied: map[string]bool{}, absent: map[string]int{}}
}

func (s *Syncer) logf(m string) {
	if s.Log != nil {
		s.Log(m)
	}
}

// Kick asks for a pass soon (it never blocks).
func (s *Syncer) Kick() {
	select {
	case s.kick <- struct{}{}:
	default:
	}
}

// Once runs one pass and returns the first error it met (the rest of the pass still ran).
func (s *Syncer) Once(ctx context.Context) error {
	doms, err := s.Src.Domains(ctx)
	if err != nil {
		return err
	}
	managed := map[string]Domain{}
	for _, d := range doms {
		if d.Managed {
			managed[d.Name] = d
		}
	}
	rows, err := s.Store.All(ctx)
	if err != nil {
		return err
	}
	var first error
	note := func(e error) {
		if e != nil && first == nil {
			first = e
		}
	}
	s.mu.Lock()
	s.passes++
	if s.FullEvery <= 0 {
		s.FullEvery = 12
	}
	if s.passes%s.FullEvery == 0 {
		s.applied = map[string]bool{}
	}
	s.mu.Unlock()
	// a managed VM without a row (it existed before this feature, or was made outside the console) gets one: the box ticked, the intent as it is now
	for name, d := range managed {
		if _, ok := rows[name]; !ok {
			intent := Stopped
			if d.Running {
				intent = Running
			}
			p, err := s.Store.Ensure(ctx, name, true, intent, "system")
			note(err)
			if err == nil {
				rows[name] = p
			}
		}
	}
	for name, p := range rows {
		if _, ok := managed[name]; !ok {
			// the domain is gone (or not seen): forget the row only after two passes in a row, so one failed listing cannot erase the owner's choices
			s.mu.Lock()
			s.absent[name]++
			n := s.absent[name]
			s.mu.Unlock()
			if n >= 2 {
				note(s.Store.Delete(ctx, name))
				s.mu.Lock()
				delete(s.absent, name)
				delete(s.applied, name)
				s.mu.Unlock()
			}
			continue
		}
		s.mu.Lock()
		delete(s.absent, name)
		have, known := s.applied[name]
		s.mu.Unlock()
		want := p.Autostart()
		if known && have == want {
			continue
		}
		if err := s.Host.SetAutostart(ctx, name, want); err != nil {
			note(err)
			s.logf("WARN boot policy: the autostart flag of " + name + " could not be set")
			continue
		}
		s.mu.Lock()
		s.applied[name] = want
		s.mu.Unlock()
	}
	return first
}

// Run syncs once at start and then every Every, and whenever it is kicked, until ctx ends.
func (s *Syncer) Run(ctx context.Context) {
	every := s.Every
	if every <= 0 {
		every = 5 * time.Minute
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		if err := s.Once(ctx); err != nil && !errors.Is(err, context.Canceled) {
			s.logf("WARN boot policy: a pass did not finish")
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		case <-s.kick:
			select { // let a burst of operations (a schedule window) settle into one pass
			case <-time.After(500 * time.Millisecond):
			case <-ctx.Done():
				return
			}
		}
	}
}

// VMCreated, VMDeleted, PowerIntent and SetStartOnBoot implement operation.Boot: each records the owner's intent and wakes the syncer.
func (s *Syncer) VMCreated(ctx context.Context, name string, startOnBoot bool, actor string) error {
	_, err := s.Store.Ensure(ctx, name, startOnBoot, Stopped, actor)
	s.Kick()
	return err
}

func (s *Syncer) VMDeleted(ctx context.Context, name string) error {
	err := s.Store.Delete(ctx, name)
	s.mu.Lock()
	delete(s.applied, name)
	delete(s.absent, name)
	s.mu.Unlock()
	return err
}

func (s *Syncer) PowerIntent(ctx context.Context, name string, running bool, actor string) error {
	intent := Stopped
	if running {
		intent = Running
	}
	_, err := s.Store.SetIntent(ctx, name, intent, actor)
	s.Kick()
	return err
}

func (s *Syncer) SetStartOnBoot(ctx context.Context, name string, on bool, actor string) error {
	_, err := s.Store.SetStartOnBoot(ctx, name, on, actor)
	s.Kick()
	return err
}
