package operation

import "sync"

// ErrStale is returned by Store.Update when the stored generation is not the one the caller read.
var ErrStale = fail("conflict")

// Store persists operations. The operation manager is its only writer (ADR-003); implementations must make
// Insert and Update atomic. Update is a compare-and-swap on Generation.
type Store interface {
	// Insert stores op unless an operation with the same (project, idempotency key) exists; it returns the
	// stored operation and whether op was created.
	Insert(op Operation) (Operation, bool, error)
	Get(id string) (Operation, bool, error)
	// Update replaces the operation if the stored generation equals op.Generation, and stores it with the
	// generation incremented.
	Update(op Operation) (Operation, error)
	// NonTerminal lists operations whose status is not terminal, oldest first.
	NonTerminal() ([]Operation, error)
}

// Lister is an optional Store capability: the most recent operations first, for the browser's activity list. `after` is the id of the last
// operation of the previous page ("" for the first page); an unknown id yields an empty page. More reports whether older operations remain.
type Lister interface {
	Recent(limit int, after string) (page []Operation, more bool, err error)
}

// AuditedStore is a Store that commits an audit event in the same transaction as the state change it describes.
// The Manager uses it when the store offers it, so a destructive transition and its audit record cannot diverge.
type AuditedStore interface {
	Store
	InsertAudited(op Operation, ev AuditEvent) (Operation, bool, error)
	UpdateAudited(op Operation, ev AuditEvent) (Operation, error)
}

// MemStore is an in-memory Store for tests and development. It is not durable: restart tests re-create the
// Manager over the same MemStore. SQLiteStore (sqlite.go) implements the same interface durably.
type MemStore struct {
	mu    sync.Mutex
	ops   map[string]Operation
	keys  map[[2]string]string
	order []string
}

// NewMemStore returns an empty store.
func NewMemStore() *MemStore {
	return &MemStore{ops: map[string]Operation{}, keys: map[[2]string]string{}}
}

// Insert implements Store.
func (s *MemStore) Insert(op Operation) (Operation, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := [2]string{op.ProjectID, op.IdempotencyKey}
	if id, ok := s.keys[k]; ok {
		return s.ops[id], false, nil
	}
	s.ops[op.ID] = op
	s.keys[k] = op.ID
	s.order = append(s.order, op.ID)
	return op, true, nil
}

// Get implements Store.
func (s *MemStore) Get(id string) (Operation, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	op, ok := s.ops[id]
	return op, ok, nil
}

// Update implements Store.
func (s *MemStore) Update(op Operation) (Operation, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cur, ok := s.ops[op.ID]
	if !ok || cur.Generation != op.Generation || cur.Status.Terminal() {
		return Operation{}, ErrStale // a terminal record never changes (parity with SQLiteStore)
	}
	op.Generation++
	s.ops[op.ID] = op
	return op, nil
}

// NonTerminal implements Store.
func (s *MemStore) NonTerminal() ([]Operation, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []Operation
	for _, id := range s.order {
		if op := s.ops[id]; !op.Status.Terminal() {
			out = append(out, op)
		}
	}
	return out, nil
}

// Recent implements Lister: newest first by insertion order.
func (s *MemStore) Recent(limit int, after string) ([]Operation, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	end := len(s.order)
	if after != "" {
		end = -1
		for i, id := range s.order {
			if id == after {
				end = i
			}
		}
		if end < 0 {
			return nil, false, nil
		}
	}
	var out []Operation
	for i := end - 1; i >= 0; i-- {
		if len(out) == limit {
			return out, true, nil
		}
		out = append(out, s.ops[s.order[i]])
	}
	return out, false, nil
}
