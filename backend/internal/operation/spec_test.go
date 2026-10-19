package operation

import (
	"context"
	"testing"

	"example.invalid/dedicatedcloud/backend/internal/hypervisor"
	"example.invalid/dedicatedcloud/backend/internal/hypervisor/fake"
	"example.invalid/dedicatedcloud/backend/internal/sqlitedb"
)

// Create reconciliation compares the host with the persisted definition (CT-PRODUCT-DELIVERY-003 s5).

func crashedCreate(t *testing.T, s Store, hv *fake.Hypervisor) (*Manager, Operation) {
	t.Helper()
	m := NewManager(s, hv, owners{"p1": "alice"}, nil, Config{})
	op := mustSubmit(t, m, req(Create, "vm-a", "k1"))
	op.Status, op.Attempts = Running, 1 // the attempt was recorded, then the process died
	if _, err := s.Update(op); err != nil {
		t.Fatal(err)
	}
	return m, op
}

func TestReconcileCreate_SameNameDifferentSpecIsAConflictNotSuccess(t *testing.T) {
	stores(t, func(t *testing.T, s Store) {
		for name, seeded := range map[string]hypervisor.DomainSpec{
			"vcpus":  {Name: "vm-a", VCPUs: 2, MemoryMiB: 512},
			"memory": {Name: "vm-a", VCPUs: 1, MemoryMiB: 2048},
		} {
			t.Run(name, func(t *testing.T) {
				hv := fake.New()
				hv.Seed(seeded, hypervisor.StateShutoff)
				m := NewManager(s, hv, owners{"p1": "alice"}, nil, Config{})
				op := mustSubmit(t, m, Request{ProjectID: "p1", Type: Create, Kind: KindVM, ResourceID: "vm-a", IdempotencyKey: "key-" + name})
				op.Status, op.Attempts = Running, 1
				if _, err := s.Update(op); err != nil {
					t.Fatal(err)
				}
				res, err := m.Reconcile(context.Background())
				if err != nil || len(res) != 1 || res[0].Status != Failed || res[0].ErrorCategory != CatConflict {
					t.Fatalf("%+v %v", res, err)
				}
				if len(hv.Calls()) != 0 {
					t.Fatalf("reconcile touched the host: %v", hv.Calls())
				}
			})
		}
	})
}

// Strong identity: a domain with the right name, size and even UUID is still not this operation's VM unless the persisted
// fingerprint matches too (the UUID alone, or the size alone, is never ownership).
func TestReconcileCreate_UUIDOrFingerprintMismatchIsAConflict(t *testing.T) {
	for name, alter := range map[string]func(*hypervisor.DomainSpec){
		"fingerprint": func(d *hypervisor.DomainSpec) { d.Fingerprint = "00" + d.Fingerprint[2:] },
		"uuid":        func(d *hypervisor.DomainSpec) { d.UUID = "00000000-0000-4000-8000-000000000000" },
	} {
		t.Run(name, func(t *testing.T) {
			stores(t, func(t *testing.T, s Store) {
				hv := fake.New()
				m, op := crashedCreate(t, s, hv)
				id := identityOf(op)
				alter(&id)
				hv.Seed(id, hypervisor.StateShutoff)
				res, err := m.Reconcile(context.Background())
				if err != nil || len(res) != 1 || res[0].Status != Failed || res[0].ErrorCategory != CatConflict {
					t.Fatalf("%+v %v", res, err)
				}
			})
		})
	}
}

func TestReconcileCreate_MatchingSpecSucceedsAndUnknownSpecFailsClosed(t *testing.T) {
	stores(t, func(t *testing.T, s Store) {
		hv := fake.New()
		m, op := crashedCreate(t, s, hv)
		hv.Seed(identityOf(op), hypervisor.StateShutoff) // the crashed attempt did create it
		if res, err := m.Reconcile(context.Background()); err != nil || len(res) != 1 || res[0].Status != Succeeded {
			t.Fatalf("matching: %+v %v", res, err)
		}
	})
	stores(t, func(t *testing.T, s Store) {
		// A host that cannot report the definition (0, 0) must never be read as a match.
		m := NewManager(s, zeroSpecHost{fake.New()}, owners{"p1": "alice"}, nil, Config{})
		op := mustSubmit(t, m, req(Create, "vm-a", "k1"))
		op.Status, op.Attempts = Running, 1
		_, _ = s.Update(op)
		res, err := m.Reconcile(context.Background())
		if err != nil || len(res) != 1 || res[0].Status != Failed || res[0].ErrorCategory != CatHostError {
			t.Fatalf("unknown: %+v %v", res, err)
		}
	})
}

// zeroSpecHost reports every domain as present with an unknown definition.
type zeroSpecHost struct{ *fake.Hypervisor }

func (z zeroSpecHost) Lookup(_ context.Context, name string) (hypervisor.Domain, error) {
	return hypervisor.Domain{Name: name, State: hypervisor.StateShutoff}, nil
}

func TestCreateUsesPersistedSpecAfterConfigChange(t *testing.T) {
	stores(t, func(t *testing.T, s Store) {
		hv := fake.New()
		old := NewManager(s, hv, owners{"p1": "alice"}, nil, Config{VCPUs: 2, MemoryMiB: 1024})
		op := mustSubmit(t, old, req(Create, "vm-a", "k1"))
		if op.Spec.VCPUs != 2 || op.Spec.MemoryMiB != 1024 || op.Spec.UUID == "" || op.Spec.Fingerprint != ComputeFingerprint("vm-a", op.Spec) {
			t.Fatalf("spec %+v", op.Spec)
		}
		restarted := NewManager(s, hv, owners{"p1": "alice"}, nil, Config{VCPUs: 8, MemoryMiB: 4096})
		mustRun(t, restarted, op.ID, Succeeded)
		if d, _ := hv.Lookup(context.Background(), "vm-a"); d.VCPUs != 2 || d.MemoryMiB != 1024 {
			t.Fatalf("defined with %d/%d, persisted spec was 2/1024", d.VCPUs, d.MemoryMiB)
		}
	})
}

func TestRequestedSpecIsValidatedAndIdempotencyAware(t *testing.T) {
	stores(t, func(t *testing.T, s Store) {
		m := NewManager(s, fake.New(), owners{"p1": "alice"}, nil, Config{})
		for name, r := range map[string]Request{
			"too many vcpus": {Spec: CreateSpec{VCPUs: 65, MemoryMiB: 512}},
			"too little mem": {Spec: CreateSpec{VCPUs: 1, MemoryMiB: 8}},
			"zero vcpus":     {Spec: CreateSpec{VCPUs: 0, MemoryMiB: 512}},
		} {
			r.ProjectID, r.Type, r.Kind, r.ResourceID, r.IdempotencyKey = "p1", Create, KindVM, "vm-a", "kv-"+name[:4]
			if _, err := m.Submit(alice, r); CategoryOf(err) != CatValidation {
				t.Errorf("%s: %v", name, err)
			}
		}
		if _, err := m.Submit(alice, Request{ProjectID: "p1", Type: Start, Kind: KindVM, ResourceID: "vm-a", IdempotencyKey: "ks", Spec: CreateSpec{VCPUs: 1, MemoryMiB: 512}}); CategoryOf(err) != CatValidation {
			t.Errorf("spec on start: %v", err)
		}
		first, err := m.Submit(alice, Request{ProjectID: "p1", Type: Create, Kind: KindVM, ResourceID: "vm-b", IdempotencyKey: "kk", Spec: CreateSpec{VCPUs: 4, MemoryMiB: 2048}})
		if err != nil || first.Spec.VCPUs != 4 || first.Spec.MemoryMiB != 2048 {
			t.Fatalf("%+v %v", first, err)
		}
		if _, err := m.Submit(alice, Request{ProjectID: "p1", Type: Create, Kind: KindVM, ResourceID: "vm-b", IdempotencyKey: "kk", Spec: CreateSpec{VCPUs: 2, MemoryMiB: 2048}}); CategoryOf(err) != CatConflict {
			t.Errorf("same key, other spec: %v", err)
		}
		if again, err := m.Submit(alice, Request{ProjectID: "p1", Type: Create, Kind: KindVM, ResourceID: "vm-b", IdempotencyKey: "kk"}); err != nil || again.ID != first.ID {
			t.Errorf("replay without a spec: %+v %v", again, err)
		}
	})
}

func TestSQLite_MigrationAddsSpecAndLegacyCreatesFailClosed(t *testing.T) {
	path := t.TempDir() + "/ops.db"
	db, err := sqlitedb.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := sqlitedb.Migrate(context.Background(), db, "operation", schema[:1]); err != nil { // the schema as first released
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO operations (id, project_id, resource_kind, resource_id, type, status, idempotency_key, requested_by,
		generation, attempts, error_category, created_at, updated_at) VALUES ('op-old','p1','VM','vm-a','create','pending','k','alice',1,0,'',1,1)`); err != nil {
		t.Fatal(err)
	}
	st, err := OpenSQLite(context.Background(), db) // applies step 2
	if err != nil {
		t.Fatal(err)
	}
	hv := fake.New()
	m := NewManager(st, hv, owners{"p1": "alice"}, nil, Config{VCPUs: 4, MemoryMiB: 4096})
	got := mustRun(t, m, "op-old", Failed)
	if got.ErrorCategory != CatValidation || len(hv.Snapshot()) != 0 {
		t.Fatalf("a create without a persisted definition must not be executed with process defaults: %+v %v", got, hv.Snapshot())
	}
}

func TestSQLite_SpecIsImmutableAndBounded(t *testing.T) {
	s, db, _ := sqliteStore(t)
	op := newOp(1, "k")
	op.Spec = CreateSpec{VCPUs: 2, MemoryMiB: 1024, UUID: "11111111-2222-4333-8444-555555555555", Fingerprint: "ab", ImageID: "debian-13", ImageSHA256: "cd",
		DiskGiB: 20, SSHPublicKey: "ssh-ed25519 AAAA", SSHFingerprint: "SHA256:x", Network: "svavyom-nat"}
	if got, _, err := s.Insert(op); err != nil || got.Spec != op.Spec {
		t.Fatalf("%+v %v", got, err)
	}
	if read, _, _ := s.Get(op.ID); read.Spec != op.Spec {
		t.Fatalf("round trip %+v", read.Spec)
	}
	for _, stmt := range []string{`UPDATE operations SET vcpus = 8`, `UPDATE operations SET memory_mib = 2048`,
		`UPDATE operations SET vcpus = 65`, `UPDATE operations SET memory_mib = 10`} {
		if _, err := db.Exec(stmt); err == nil {
			t.Errorf("%s succeeded", stmt)
		}
	}
}

// The create identity: server generated, persisted, immutable, and what separates our VM from a foreign one of the same size.
func TestCreateIdentityIsServerGeneratedAndPersisted(t *testing.T) {
	stores(t, func(t *testing.T, s Store) {
		m := NewManager(s, fake.New(), owners{"p1": "alice"}, nil, Config{})
		a := mustSubmit(t, m, req(Create, "vm-a", "k1"))
		b := mustSubmit(t, m, req(Create, "vm-b", "k2"))
		if a.Spec.UUID == "" || a.Spec.UUID == b.Spec.UUID || len(a.Spec.UUID) != 36 || a.Spec.UUID[14] != '4' {
			t.Fatalf("uuids %q %q", a.Spec.UUID, b.Spec.UUID)
		}
		if a.Spec.Fingerprint != ComputeFingerprint("vm-a", a.Spec) || a.Spec.Fingerprint == b.Spec.Fingerprint {
			t.Fatalf("fingerprint %q", a.Spec.Fingerprint)
		}
		// Identical inputs, different operation: different identity, so one VM can never satisfy the other's create.
		c := mustSubmit(t, m, req(Create, "vm-a", "k3"))
		if c.Spec.UUID == a.Spec.UUID || c.Spec.Fingerprint == a.Spec.Fingerprint {
			t.Fatal("two creates share an identity")
		}
		if _, err := m.Submit(alice, Request{ProjectID: "p1", Type: Create, Kind: KindVM, ResourceID: "vm-z", IdempotencyKey: "kz",
			Spec: CreateSpec{VCPUs: 1, MemoryMiB: 512, UUID: "11111111-2222-4333-8444-555555555555"}}); CategoryOf(err) != CatValidation {
			t.Fatalf("a caller supplied identity must be refused: %v", err)
		}
		again, err := m.Submit(alice, req(Create, "vm-a", "k1")) // replay keeps the original identity
		if err != nil || again.Spec != a.Spec {
			t.Fatalf("%+v %v", again, err)
		}
	})
}

func TestPrepareCreateHookFailureStoresNothingAndEnrichmentIsPersisted(t *testing.T) {
	stores(t, func(t *testing.T, s Store) {
		calls := 0
		m := NewManager(s, fake.New(), owners{"p1": "alice"}, nil, Config{PrepareCreate: func(name string, sp *CreateSpec) error {
			calls++
			if sp.ImageID == "bad" {
				return fail(CatValidation)
			}
			sp.ImageSHA256, sp.SSHPublicKey, sp.SSHFingerprint, sp.Network = "feed", "ssh-ed25519 AAAA", "SHA256:abc", "svavyom-nat"
			return nil
		}})
		r := Request{ProjectID: "p1", Type: Create, Kind: KindVM, ResourceID: "vm-a", IdempotencyKey: "k1", Spec: CreateSpec{VCPUs: 2, MemoryMiB: 1024, ImageID: "bad", DiskGiB: 20}}
		if _, err := m.Submit(alice, r); CategoryOf(err) != CatValidation {
			t.Fatal(err)
		}
		if ops, _ := s.NonTerminal(); len(ops) != 0 {
			t.Fatal("a rejected create was stored")
		}
		r.Spec.ImageID = "debian-13"
		op, err := m.Submit(alice, r)
		if err != nil || op.Spec.ImageSHA256 != "feed" || op.Spec.Network != "svavyom-nat" || op.Spec.SSHFingerprint != "SHA256:abc" {
			t.Fatalf("%+v %v", op.Spec, err)
		}
		r2 := r
		r2.Spec.DiskGiB = 40 // same key, different immutable input
		if _, err := m.Submit(alice, r2); CategoryOf(err) != CatConflict {
			t.Fatalf("replay with another spec: %v", err)
		}
		if got, _, _ := s.Get(op.ID); got.Spec != op.Spec {
			t.Fatalf("persisted spec differs: %+v vs %+v", got.Spec, op.Spec)
		}
		_ = calls
	})
}
