package offsite

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"example.invalid/dedicatedcloud/backend/internal/backupstore"
	"example.invalid/dedicatedcloud/backend/internal/provision"
)

const bk1 = "bk-0123456789abcdef"

func newStore(t *testing.T) *backupstore.Store {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "backups")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	real, _ := filepath.EvalSymlinks(dir)
	s, err := backupstore.Open(real)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func writeBackup(t *testing.T, s *backupstore.Store, id, body string) {
	t.Helper()
	w, err := s.Begin(id, int64(len(body)))
	if err != nil {
		t.Fatal(err)
	}
	_, _ = w.Write([]byte(body))
	_, err = w.Commit(backupstore.Manifest{CreatedAt: "2026-10-14T10:00:00Z", Tool: "test", VM: backupstore.VM{Name: "web-1", UUID: "9a9a9a9a-2222-4333-8444-5555555555ab",
		Fingerprint: strings.Repeat("ab", 32), ImageID: "ubuntu-24.04", ImageSHA256: strings.Repeat("cd", 32), LoginUser: "ubuntu", VCPUs: 1, MemoryMiB: 1024, DiskGiB: 10, Network: "default"},
		Root: backupstore.Root{VirtualSizeBytes: 10 << 30}})
	if err != nil {
		t.Fatal(err)
	}
}

func exporter(t *testing.T, targets ...provision.BackupTarget) (*Exporter, *backupstore.Store) {
	t.Helper()
	s := newStore(t)
	state := filepath.Join(t.TempDir(), "state")
	if err := os.Mkdir(state, 0o700); err != nil {
		t.Fatal(err)
	}
	return &Exporter{Store: s, Targets: targets, StateDir: state}, s
}

func pathTarget(t *testing.T) provision.BackupTarget {
	t.Helper()
	d := filepath.Join(t.TempDir(), "mnt")
	if err := os.Mkdir(d, 0o700); err != nil {
		t.Fatal(err)
	}
	return provision.BackupTarget{ID: "usb", Kind: "path", Dir: d}
}

func TestExportToAPathTargetIsVerifiedRecordedAndRepeatable(t *testing.T) {
	tg := pathTarget(t)
	e, s := exporter(t, tg)
	writeBackup(t, s, bk1, "root-overlay-bytes")
	if err := e.Export(context.Background(), bk1, "usb"); err != nil {
		t.Fatal(err)
	}
	for _, n := range backupstore.Files {
		if _, err := os.Stat(filepath.Join(tg.Dir, bk1, n)); err != nil {
			t.Fatalf("the copy lacks %s: %v", n, err)
		}
	}
	if left, _ := filepath.Glob(filepath.Join(tg.Dir, ".partial-*")); len(left) != 0 {
		t.Fatalf("no partial directory may remain: %v", left)
	}
	cp, err := e.Copies()
	if err != nil || len(cp) != 1 || cp[0].Backup != bk1 || strings.Join(cp[0].Targets, ",") != "usb" {
		t.Fatalf("%+v %v", cp, err)
	}
	// again: a verified copy in place is success and changes nothing
	if err := e.Export(context.Background(), bk1, "usb"); err != nil {
		t.Fatal(err)
	}
	// the copy is a complete, verifiable backup: it can be imported into a fresh store
	e2, s2 := exporter(t, tg)
	if err := e2.Import(context.Background(), bk1, "usb"); err != nil {
		t.Fatal(err)
	}
	if b, err := s2.Verify(bk1); err != nil || b.Manifest.BackupID != bk1 {
		t.Fatalf("%v", err)
	}
}

func TestExportRefusesWhatItMustNot(t *testing.T) {
	tg := pathTarget(t)
	e, s := exporter(t, tg)
	writeBackup(t, s, bk1, "bytes")
	ctx := context.Background()
	if CategoryOf(e.Export(ctx, bk1, "nope")) != "not_found" {
		t.Error("an undeclared target")
	}
	if CategoryOf(e.Export(ctx, "bk-ffffffffffffffff", "usb")) != "not_found" {
		t.Error("a missing backup")
	}
	if CategoryOf(e.Export(ctx, "../etc", "usb")) != "validation" {
		t.Error("a malformed id")
	}
	// a damaged local backup is never exported
	root := filepath.Join(s.Dir(), bk1, backupstore.RootFile)
	b, _ := os.ReadFile(root)
	b[0] ^= 0xff
	_ = os.WriteFile(root, b, 0o600)
	if CategoryOf(e.Export(ctx, bk1, "usb")) != "conflict" {
		t.Error("a damaged backup")
	}
	if _, err := os.Stat(filepath.Join(tg.Dir, bk1)); err == nil {
		t.Error("nothing may have been written")
	}
	// somebody else's data under the same name is left alone
	e3, s3 := exporter(t, tg)
	writeBackup(t, s3, bk1, "bytes")
	if err := os.Mkdir(filepath.Join(tg.Dir, bk1), 0o700); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(filepath.Join(tg.Dir, bk1, backupstore.RootFile), []byte("someone else's"), 0o600)
	if CategoryOf(e3.Export(ctx, bk1, "usb")) != "conflict" {
		t.Error("a different object under the name")
	}
	if got, _ := os.ReadFile(filepath.Join(tg.Dir, bk1, backupstore.RootFile)); string(got) != "someone else's" {
		t.Error("it was overwritten or removed")
	}
	// an unavailable target
	gone := provision.BackupTarget{ID: "gone", Kind: "path", Dir: filepath.Join(t.TempDir(), "missing")}
	e4, s4 := exporter(t, gone)
	writeBackup(t, s4, bk1, "bytes")
	if CategoryOf(e4.Export(ctx, bk1, "gone")) != "unavailable" {
		t.Error("a missing directory")
	}
	if st := e4.States(); len(st) != 1 || st[0].State != "unavailable" {
		t.Errorf("%+v", st)
	}
}

func TestImportNeverReplacesAndNeverKeepsAnImperfectCopy(t *testing.T) {
	tg := pathTarget(t)
	e, s := exporter(t, tg)
	writeBackup(t, s, bk1, "bytes")
	if err := e.Export(context.Background(), bk1, "usb"); err != nil {
		t.Fatal(err)
	}
	if CategoryOf(e.Import(context.Background(), bk1, "usb")) != "conflict" {
		t.Error("the backup is already here")
	}
	// damage the remote root copy: the import is refused and leaves nothing
	r := filepath.Join(tg.Dir, bk1, backupstore.RootFile)
	b, _ := os.ReadFile(r)
	b[0] ^= 0xff
	_ = os.WriteFile(r, b, 0o600)
	e2, s2 := exporter(t, tg)
	if err := e2.Import(context.Background(), bk1, "usb"); CategoryOf(err) != "host_error" {
		t.Fatalf("%v", err)
	}
	if l, _ := s2.List(); len(l) != 0 {
		t.Fatalf("a damaged copy must not be listed: %+v", l)
	}
	ents, _ := os.ReadDir(s2.Dir())
	if len(ents) != 0 {
		t.Fatalf("nothing may remain, not even a partial directory: %v", ents)
	}
}

func TestStatesNeverRevealAHostPathOrKey(t *testing.T) {
	e, _ := exporter(t, provision.BackupTarget{ID: "nas", Kind: "ssh", Host: "nas.example", User: "svavyom", Dir: "/backups", KeyFile: "/etc/svavyom/offsite_key", HostKey: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPlaceholderPlaceholderPlaceholder"})
	st := e.States()
	if len(st) != 1 || st[0].ID != "nas" || st[0].Kind != "ssh" || st[0].State != "unavailable" {
		t.Fatalf("a key file that cannot be read makes the target unavailable: %+v", st)
	}
	b, _ := (&Reply{V: Version, OK: true, Targets: st}).marshal()
	for _, bad := range []string{"nas.example", "/backups", "offsite_key", "AAAAC3"} {
		if strings.Contains(string(b), bad) {
			t.Errorf("the reply must not carry %q: %s", bad, b)
		}
	}
}

// fakeSSH stands in for the ssh client: it records its arguments and runs the remote command on this machine, which is what a server would do.
func fakeSSH(t *testing.T) (script, log string) {
	t.Helper()
	dir := t.TempDir()
	log = filepath.Join(dir, "args.log")
	script = filepath.Join(dir, "ssh")
	body := "#!/bin/sh\nprintf '%s\\n' \"$*\" >> " + log + "\nfor last; do :; done\nexec sh -c \"$last\"\n"
	if err := os.WriteFile(script, []byte(body), 0o700); err != nil {
		t.Fatal(err)
	}
	return script, log
}

func sshTarget(t *testing.T) provision.BackupTarget {
	t.Helper()
	key := filepath.Join(t.TempDir(), "id")
	_ = os.WriteFile(key, []byte("key"), 0o600)
	return provision.BackupTarget{ID: "nas", Kind: "ssh", Host: "nas.example", Port: 2222, User: "svavyom", Dir: filepath.Join(t.TempDir(), "remote"), KeyFile: key,
		HostKey: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPlaceholderPlaceholderPlaceholder"}
}

func TestExportOverSSHUsesAPinnedHostKeyAndFixedCommands(t *testing.T) {
	tg := sshTarget(t)
	e, s := exporter(t, tg)
	script, log := fakeSSH(t)
	e.SSH = script
	writeBackup(t, s, bk1, "root-overlay-bytes")
	if err := e.Export(context.Background(), bk1, "nas"); err != nil {
		t.Fatal(err)
	}
	for _, n := range backupstore.Files {
		if _, err := os.Stat(filepath.Join(tg.Dir, bk1, n)); err != nil {
			t.Fatalf("the remote copy lacks %s: %v", n, err)
		}
	}
	args, _ := os.ReadFile(log)
	for _, want := range []string{"-F /dev/null", "-p 2222", "BatchMode=yes", "StrictHostKeyChecking=yes", "GlobalKnownHostsFile=/dev/null", "IdentitiesOnly=yes", "ClearAllForwardings=yes", "svavyom@nas.example"} {
		if !strings.Contains(string(args), want) {
			t.Errorf("the ssh command line lacks %q:\n%s", want, args)
		}
	}
	kh, err := os.ReadFile(filepath.Join(e.StateDir, "known_hosts-nas"))
	if err != nil || !strings.HasPrefix(string(kh), "[nas.example]:2222 ssh-ed25519 ") {
		t.Fatalf("the pinned host key goes into a generated known_hosts: %q %v", kh, err)
	}
	// again: found, compared by SHA-256 at the target, success
	if err := e.Export(context.Background(), bk1, "nas"); err != nil {
		t.Fatal(err)
	}
	// and back
	e2, s2 := exporter(t, tg)
	e2.SSH = script
	if err := e2.Import(context.Background(), bk1, "nas"); err != nil {
		t.Fatal(err)
	}
	if _, err := s2.Verify(bk1); err != nil {
		t.Fatal(err)
	}
}

func TestExportOverSSHReportsAnUnreachableServerAndTimesOut(t *testing.T) {
	tg := sshTarget(t)
	e, s := exporter(t, tg)
	writeBackup(t, s, bk1, "bytes")
	fail := filepath.Join(t.TempDir(), "ssh")
	_ = os.WriteFile(fail, []byte("#!/bin/sh\nexit 255\n"), 0o700)
	e.SSH = fail
	if CategoryOf(e.Export(context.Background(), bk1, "nas")) != "unavailable" {
		t.Error("an unreachable server")
	}
	slow := filepath.Join(t.TempDir(), "ssh")
	_ = os.WriteFile(slow, []byte("#!/bin/sh\nsleep 5\n"), 0o700)
	e.SSH, e.Timeout = slow, 200*time.Millisecond
	if got := CategoryOf(e.Export(context.Background(), bk1, "nas")); got != "timeout" {
		t.Errorf("a stalled copy: %q", got)
	}
}

func TestTheRecordSurvivesARestartAndForgetsUndeclaredTargets(t *testing.T) {
	tg := pathTarget(t)
	e, s := exporter(t, tg)
	writeBackup(t, s, bk1, "bytes")
	if err := e.Export(context.Background(), bk1, "usb"); err != nil {
		t.Fatal(err)
	}
	again := &Exporter{Store: s, Targets: e.Targets, StateDir: e.StateDir}
	if cp, _ := again.Copies(); len(cp) != 1 {
		t.Fatalf("%+v", cp)
	}
	none := &Exporter{Store: s, StateDir: e.StateDir}
	if cp, _ := none.Copies(); len(cp) != 0 {
		t.Fatalf("a target that is no longer declared holds no counted copy: %+v", cp)
	}
}

func TestPruneRemovesOnlyWhatThisServiceExportedAndNothingElse(t *testing.T) {
	tg := pathTarget(t)
	e, s := exporter(t, tg)
	writeBackup(t, s, bk1, "root-overlay-bytes")
	ctx := context.Background()
	// A copy nobody here exported is never touched, even under a backup name.
	foreign := filepath.Join(tg.Dir, bk1)
	if err := os.Mkdir(foreign, 0o700); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(filepath.Join(foreign, "mine.txt"), []byte("keep"), 0o600)
	if err := e.Prune(ctx, bk1, "usb"); err != nil {
		t.Fatalf("not recorded: nothing of ours, success: %v", err)
	}
	if _, err := os.Stat(filepath.Join(foreign, "mine.txt")); err != nil {
		t.Fatal("a foreign directory must be left alone")
	}
	_ = os.RemoveAll(foreign)
	if err := e.Export(ctx, bk1, "usb"); err != nil {
		t.Fatal(err)
	}
	if err := e.Prune(ctx, bk1, "usb"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Join(tg.Dir, bk1)); !os.IsNotExist(err) {
		t.Fatalf("the copy should be gone: %v", err)
	}
	cp, _ := e.Copies()
	if len(cp) != 0 {
		t.Fatalf("the record must forget it: %+v", cp)
	}
	if err := e.Prune(ctx, bk1, "usb"); err != nil {
		t.Fatalf("pruning twice is success: %v", err)
	}
	if _, err := s.Verify(bk1); err != nil {
		t.Fatal("the local backup is not touched by pruning the copy")
	}
}

func TestPruneRefusesLinksStrangersAndBadNames(t *testing.T) {
	tg := pathTarget(t)
	e, s := exporter(t, tg)
	writeBackup(t, s, bk1, "root-overlay-bytes")
	ctx := context.Background()
	if err := e.Export(ctx, bk1, "usb"); err != nil {
		t.Fatal(err)
	}
	// Someone put extra data into the copy's directory: files go, the directory and the stranger's file stay.
	final := filepath.Join(tg.Dir, bk1)
	_ = os.WriteFile(filepath.Join(final, "notes.txt"), []byte("not ours"), 0o600)
	if got := CategoryOf(e.Prune(ctx, bk1, "usb")); got != "conflict" {
		t.Fatalf("a directory holding something else: %q", got)
	}
	if _, err := os.Stat(filepath.Join(final, "notes.txt")); err != nil {
		t.Fatal("the stranger's file must stay")
	}
	_ = os.Remove(filepath.Join(final, "notes.txt"))
	// A link where the copy should be is never followed.
	outside := t.TempDir()
	_ = os.WriteFile(filepath.Join(outside, "precious"), []byte("x"), 0o600)
	_ = os.RemoveAll(final)
	if err := os.Symlink(outside, final); err != nil {
		t.Fatal(err)
	}
	if got := CategoryOf(e.Prune(ctx, bk1, "usb")); got != "conflict" {
		t.Fatalf("a link: %q", got)
	}
	if _, err := os.Stat(filepath.Join(outside, "precious")); err != nil {
		t.Fatal("nothing behind a link may be removed")
	}
	for _, c := range []struct{ id, target, want string }{{"../x", "usb", "validation"}, {bk1, "nope", "not_found"}, {"bk-1", "usb", "validation"}} {
		if got := CategoryOf(e.Prune(ctx, c.id, c.target)); got != c.want {
			t.Errorf("%+v: %q", c, got)
		}
	}
}

func TestPruneOverSSHUsesFixedCommands(t *testing.T) {
	tg := sshTarget(t)
	e, s := exporter(t, tg)
	script, log := fakeSSH(t)
	e.SSH = script
	writeBackup(t, s, bk1, "root-overlay-bytes")
	ctx := context.Background()
	if err := e.Export(ctx, bk1, "nas"); err != nil {
		t.Fatal(err)
	}
	if err := e.Prune(ctx, bk1, "nas"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Join(tg.Dir, bk1)); !os.IsNotExist(err) {
		t.Fatalf("remote copy should be gone: %v", err)
	}
	args, _ := os.ReadFile(log)
	if !strings.Contains(string(args), "rmdir -- '"+tg.Dir+"/"+bk1+"'") {
		t.Fatalf("expected the fixed removal command:\n%s", args)
	}
	if err := e.Prune(ctx, bk1, "nas"); err != nil {
		t.Fatalf("twice: %v", err)
	}
}
