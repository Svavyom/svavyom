package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestGuestFindingsReadTheEnableLinkAndTheDefaultsFile(t *testing.T) {
	etc := t.TempDir()
	f := guestFindings(etc)
	if got := f(); len(got) != 1 || got[0].Code != "LIBVIRT_GUESTS_OFF" || len(got[0].Remediation) > 200 {
		t.Fatalf("not enabled: %+v", got)
	}
	wants := filepath.Join(etc, "systemd", "system", "multi-user.target.wants")
	os.MkdirAll(wants, 0o755)
	os.Symlink("/lib/systemd/system/libvirt-guests.service", filepath.Join(wants, "libvirt-guests.service"))
	if got := f(); len(got) != 0 {
		t.Fatalf("enabled with the packaged default is fine: %+v", got)
	}
	os.MkdirAll(filepath.Join(etc, "default"), 0o755)
	os.WriteFile(filepath.Join(etc, "default", "libvirt-guests"), []byte("ON_SHUTDOWN=ignore\n"), 0o644)
	if got := f(); len(got) != 1 || got[0].Code != "LIBVIRT_GUESTS_MODE" {
		t.Fatalf("a mode that does not stop guests: %+v", got)
	}
}
