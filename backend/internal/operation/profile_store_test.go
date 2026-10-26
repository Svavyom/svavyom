package operation

import (
	"context"
	"testing"

	"example.invalid/dedicatedcloud/backend/internal/sqlitedb"
)

// DR-032: the create spec is stored in explicit columns, so the guest profile needs its own; losing it would turn a Windows VM into a Linux one after a
// restart or a crash recovery.
func TestSQLite_ProfileRoundTripsSurvivesARestartAndIsImmutable(t *testing.T) {
	s, db, path := sqliteStore(t)
	spec := CreateSpec{VCPUs: 2, MemoryMiB: 1024, UUID: "11111111-2222-4333-8444-555555555555", Fingerprint: "ab", ImageID: "win-iso", ImageSHA256: "cd", DiskGiB: 20,
		Network: "svavyom-nat", Profile: "windows"}
	win := newOp(1, "k-win")
	win.Spec = spec
	lin := newOp(2, "k-lin")
	lin.Spec = spec
	lin.Spec.Profile = ""
	for _, op := range []Operation{win, lin} {
		if got, _, err := s.Insert(op); err != nil || got.Spec != op.Spec {
			t.Fatalf("%+v %v", got.Spec, err)
		}
	}
	check := func(st *SQLiteStore, when string) {
		t.Helper()
		if r, _, err := st.Get(win.ID); err != nil || r.Spec.Profile != "windows" || r.Spec != win.Spec {
			t.Fatalf("%s: the Windows profile was lost: %+v %v", when, r.Spec, err)
		}
		if r, _, err := st.Get(lin.ID); err != nil || r.Spec.Profile != "" {
			t.Fatalf("%s: %+v %v", when, r.Spec, err)
		}
	}
	check(s, "after insert")

	// a restart: the same file, a new connection and store
	_ = db.Close()
	db2, err := sqlitedb.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db2.Close() })
	s2, err := OpenSQLite(context.Background(), db2)
	if err != nil {
		t.Fatal(err)
	}
	check(s2, "after a restart")

	// immutable, and only the two valid values
	for _, stmt := range []string{`UPDATE operations SET spec_profile = '' WHERE spec_profile = 'windows'`, `UPDATE operations SET spec_profile = 'windows' WHERE spec_profile = ''`,
		`UPDATE operations SET spec_profile = 'mac'`} {
		if _, err := db2.Exec(stmt); err == nil {
			t.Errorf("%s succeeded", stmt)
		}
	}
	bad := newOp(3, "k-bad")
	bad.Spec = spec
	bad.Spec.Profile = "mac"
	if _, _, err := s2.Insert(bad); err == nil {
		t.Error("a profile outside the two valid ones was stored")
	}
	check(s2, "after the refusals")
}
