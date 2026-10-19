package offsite

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"example.invalid/dedicatedcloud/backend/internal/backupstore"
)

func TestRequestGrammar(t *testing.T) {
	good := []Request{{V: 1, Op: OpTargets}, {V: 1, Op: OpCopies}, {V: 1, Op: OpExport, Backup: bk1, Target: "nas"}, {V: 1, Op: OpPrune, Backup: bk1, Target: "nas"}}
	bad := []Request{{V: 2, Op: OpTargets}, {V: 1, Op: "delete"}, {V: 1, Op: OpTargets, Target: "nas"}, {V: 1, Op: OpExport, Backup: "bk-1", Target: "nas"},
		{V: 1, Op: OpExport, Backup: bk1, Target: "../x"}, {V: 1, Op: OpExport, Backup: bk1}, {V: 1, Op: OpCopies, Backup: bk1}, {V: 1, Op: OpPrune, Backup: bk1}, {V: 1, Op: OpPrune, Target: "nas"}}
	for _, q := range good {
		if !q.Valid() {
			t.Errorf("%+v", q)
		}
	}
	for _, q := range bad {
		if q.Valid() {
			t.Errorf("%+v must be refused", q)
		}
	}
}

func TestServerAnswersOnlyTheAPIIdentityAndExportsThroughTheSocket(t *testing.T) {
	tg := pathTarget(t)
	e, s := exporter(t, tg)
	writeBackup(t, s, bk1, "bytes")
	sock := filepath.Join(t.TempDir(), "o.sock")
	srv, err := Listen(ServerConfig{Socket: sock, AllowUIDs: []uint32{uint32(os.Getuid())}, Exporter: e, Deadline: 10 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Serve() }()
	t.Cleanup(srv.Close)
	c, _ := NewClient(sock)
	ctx := context.Background()
	ts, err := c.Targets(ctx)
	if err != nil || len(ts) != 1 || ts[0].State != "ready" {
		t.Fatalf("%+v %v", ts, err)
	}
	if err := c.Export(ctx, bk1, "usb"); err != nil {
		t.Fatal(err)
	}
	if m, err := c.Copies(ctx); err != nil || len(m[bk1]) != 1 {
		t.Fatalf("%v %v", m, err)
	}
	if err := c.Export(ctx, bk1, "nope"); CategoryOf(err) != "not_found" {
		t.Fatalf("%v", err)
	}
	// an identity that is not allowed gets nothing
	srv2, err := Listen(ServerConfig{Socket: filepath.Join(t.TempDir(), "p.sock"), AllowUIDs: []uint32{uint32(os.Getuid()) + 1}, Exporter: e})
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv2.Serve() }()
	t.Cleanup(srv2.Close)
	c2, _ := NewClient(srv2.ln.Addr().String())
	if _, err := c2.Targets(ctx); err == nil {
		t.Fatal("a stranger must be refused")
	}
	// garbage on the wire is answered with a validation category, not a crash
	conn, _ := net.Dial("unix", sock)
	_, _ = conn.Write([]byte{0, 0, 0, 5, 'n', 'o', 'p', 'e', '!'})
	var r Reply
	if err := readFrame(conn, &r); err != nil || r.Category != "validation" {
		t.Fatalf("%v %+v", err, r)
	}
	_ = conn.Close()
	_ = backupstore.ValidID
}

func TestClientRefusesRelativeSocketPaths(t *testing.T) {
	if _, err := NewClient("run/x.sock"); err == nil {
		t.Fatal("relative")
	}
}
