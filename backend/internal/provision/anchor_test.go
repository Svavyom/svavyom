package provision

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func anchorFixture(t *testing.T) (string, AnchorWant) {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, "img.qcow2")
	body := []byte("base image body")
	if err := os.WriteFile(p, body, 0o444); err != nil { // #nosec G306 -- test fixture
		t.Fatal(err)
	}
	a, err := TakeAnchor(p)
	if err != nil {
		t.Fatal(err)
	}
	return p, AnchorWant{Path: p, UID: myUID, GID: myGID, SHA256: a.SHA256, Size: int64(len(body))}
}

func TestAnchorRecordsOwnerGroupModeSizeDigestPathAndType(t *testing.T) {
	p, want := anchorFixture(t)
	a, err := CheckAnchor(want, nil)
	if err != nil {
		t.Fatal(err)
	}
	if a.Path != p || a.UID != myUID || a.GID != myGID || a.Owner == "" || a.Group == "" || a.Mode != "-r--r--r--" || a.Size != 15 || len(a.SHA256) != 64 || !a.Regular || a.Symlink {
		t.Fatalf("%+v", a)
	}
	if !strings.Contains(a.String(), "sha256="+a.SHA256) {
		t.Fatal(a.String())
	}
	if again, err := CheckAnchor(want, &a); err != nil || len(again.Diff(a)) != 0 {
		t.Fatalf("an unchanged image must compare equal: %v", err)
	}
}

func TestAnyMutationOfTheBaseImageIsDetected(t *testing.T) {
	cases := map[string]func(t *testing.T, p string){
		"mode made writable":   func(t *testing.T, p string) { must(t, os.Chmod(p, 0o644)) },
		"mode made executable": func(t *testing.T, p string) { must(t, os.Chmod(p, 0o555)) },
		"setuid added":         func(t *testing.T, p string) { must(t, os.Chmod(p, os.ModeSetuid|0o444)) },
		"content rewritten": func(t *testing.T, p string) {
			must(t, os.Chmod(p, 0o644))
			must(t, os.WriteFile(p, []byte("base image bodY"), 0o444)) // same size, different digest
		},
		"content appended": func(t *testing.T, p string) {
			must(t, os.Chmod(p, 0o644))
			f, err := os.OpenFile(p, os.O_APPEND|os.O_WRONLY, 0)
			must(t, err)
			_, err = f.WriteString("x")
			must(t, err)
			must(t, f.Close())
			must(t, os.Chmod(p, 0o444))
		},
		"replaced by a symlink": func(t *testing.T, p string) {
			other := p + ".other"
			must(t, os.Rename(p, other))
			must(t, os.Symlink(other, p))
		},
		"replaced by a directory": func(t *testing.T, p string) {
			must(t, os.Remove(p))
			must(t, os.Mkdir(p, 0o755))
		},
		"removed": func(t *testing.T, p string) { must(t, os.Remove(p)) },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			p, want := anchorFixture(t)
			base, err := CheckAnchor(want, nil)
			if err != nil {
				t.Fatal(err)
			}
			mutate(t, p)
			if _, err := CheckAnchor(want, &base); err == nil {
				t.Fatal("mutation not detected")
			}
		})
	}
}

func TestAnchorIsJudgedAgainstTheTrustModelEvenWithoutABaseline(t *testing.T) {
	p, want := anchorFixture(t)
	wrongDigest, wrongSize, wrongPath, wrongOwner, wrongGroup := want, want, want, want, want
	wrongDigest.SHA256 = strings.Repeat("0", 64)
	wrongSize.Size++
	wrongPath.Path = p + ".other"
	wrongOwner.UID++
	wrongGroup.GID++
	for name, w := range map[string]AnchorWant{"digest": wrongDigest, "size": wrongSize, "path": wrongPath, "owner": wrongOwner, "group": wrongGroup} {
		if _, err := CheckAnchor(w, nil); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	for name, mode := range map[string]os.FileMode{"writable": 0o644, "group-writable": 0o464, "executable": 0o555, "owner-only": 0o400} {
		must(t, os.Chmod(p, mode))
		if _, err := CheckAnchor(want, nil); err == nil {
			t.Errorf("mode %s accepted: a published base image is exactly 0444", name)
		}
	}
}

func TestAnchorOwnershipChangeIsDetectedFieldByField(t *testing.T) {
	p, want := anchorFixture(t)
	base, _ := CheckAnchor(want, nil)
	// chown to another user needs root; the comparison itself is exercised on the record, which is what the harness stores.
	other := base
	other.UID, other.Owner = base.UID+1, "libvirt-qemu"
	other.GID, other.Group = base.GID+1, "kvm"
	diff := other.Diff(base)
	for _, f := range []string{"owner-uid", "owner-name", "group-gid", "group-name"} {
		found := false
		for _, d := range diff {
			found = found || d == f
		}
		if !found {
			t.Errorf("%s not reported in %v", f, diff)
		}
	}
	if v := other.Violations(want); len(v) != 2 || v[0] != "owner-uid" || v[1] != "group-gid" {
		t.Errorf("violations %v", v)
	}
	// libvirt-qemu:kvm 0444 is exactly the observed defect; it must never satisfy the root:root requirement.
	root := AnchorWant{Path: p, UID: 0, GID: 0, SHA256: want.SHA256, Size: want.Size}
	if myUID != 0 {
		if v := base.Violations(root); len(v) == 0 {
			t.Error("a non-root-owned image satisfied the root:root requirement")
		}
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
