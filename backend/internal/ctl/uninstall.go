package ctl

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// PurgeToken must be typed exactly to authorise the destructive purge.
const PurgeToken = "DELETE-SVAVYOM-DATA" // #nosec G101 -- a typed confirmation phrase, not a credential

// UninstallOptions are the inputs of uninstall.
type UninstallOptions struct {
	Apply bool
	// Purge also removes the API database, the mutation state, the upgrade backups and the configuration (including the TLS files) and the service accounts. It
	// needs ConfirmPurge == PurgeToken. It never touches libvirt: VMs, networks, pools, the image store, VM disks and the backup store stay where they are.
	Purge        bool
	ConfirmPurge string
}

// Uninstall stops and removes what Svavyom installed (binaries, units and drop-ins, web assets, account and directory definitions) and keeps everything the
// administrator may still need: the database, the configuration, the image store and catalog, the pool (VM disks) and the backup store, the libvirt networks,
// pools and VMs, and the service accounts. A purge is a separate, explicitly confirmed mode that removes only Svavyom's own data.
func Uninstall(ctx context.Context, e *Env, o UninstallOptions, w io.Writer) error {
	if o.Purge && o.ConfirmPurge != PurgeToken {
		return fmt.Errorf("--purge deletes the database, the configuration and the service accounts. To confirm, pass --confirm-purge %s", PurgeToken)
	}
	if o.ConfirmPurge != "" && !o.Purge {
		return errors.New("--confirm-purge only goes with --purge")
	}
	if o.Apply && e.Euid() != 0 {
		return errors.New("--apply needs root (run with sudo)")
	}
	p := &Plan{}
	p.add("stop and disable the services ("+strings.Join(reverse(Units), ", ")+")", func() error {
		for _, u := range reverse(Units) {
			if _, err := os.Lstat(e.P(UnitDir + "/" + u)); err != nil {
				continue
			}
			_, _ = e.Run.Run(ctx, "systemctl", "disable", "--now", "--", u)
		}
		return nil
	})
	p.add("remove the binaries ("+strings.Join(Binaries, ", ")+") and VERSION from "+LibexecDir+", and the web assets from "+ShareDir, func() error {
		for _, b := range Binaries {
			if err := removeIfExists(e.P(LibexecDir + "/" + b)); err != nil {
				return err
			}
		}
		if err := removeIfExists(e.P(VersionFile)); err != nil {
			return err
		}
		_ = os.Remove(e.P(LibexecDir)) // only if now empty
		if err := os.RemoveAll(e.P(ShareDir + "/web")); err != nil {
			return err
		}
		_ = os.Remove(e.P(ShareDir))
		return nil
	})
	p.add("remove Svavyom's unit files and drop-ins from "+UnitDir+", and the account and directory definitions", func() error {
		for _, u := range Units {
			if err := removeIfExists(e.P(UnitDir + "/" + u)); err != nil {
				return err
			}
			if err := os.RemoveAll(e.P(UnitDir + "/" + strings.TrimSuffix(u, ".service") + ".service.d")); err != nil {
				return err
			}
		}
		if err := removeIfExists(e.P(SysusersFile)); err != nil {
			return err
		}
		if err := removeIfExists(e.P(TmpfilesFile)); err != nil {
			return err
		}
		if err := e.DisableNightlyBoot(ctx); err != nil {
			return err
		}
		_, _ = e.Run.Run(ctx, "systemctl", "daemon-reload")
		return nil
	})
	if o.Purge {
		p.add("PURGE: remove the API database and its directory, the mutation state, the upgrade backups and the configuration with the TLS files", func() error {
			for _, d := range []string{LibDir + "/api", LibDir + "/state", BackupRoot, ConfigDir, LibDir + "/nightly-boot.json", LibDir + "/nightly-boot.lock"} {
				if err := os.RemoveAll(e.P(d)); err != nil {
					return err
				}
			}
			return nil
		})
		p.add("PURGE: remove the service accounts svavyom-api, svavyom-ro, svavyom-mut and svavyom-con", func() error {
			for _, u := range []string{"svavyom-api", "svavyom-ro", "svavyom-mut", "svavyom-con"} {
				if _, _, err := e.Getpw(u); err == nil {
					if out, err := e.Run.Run(ctx, "userdel", u); err != nil {
						return fmt.Errorf("userdel %s: %s", u, clean(out))
					}
				}
			}
			return nil
		})
	}
	if err := p.Run(w, o.Apply); err != nil {
		return err
	}
	kept := []string{LibDir + "/images (the catalog and the image store)", LibDir + "/pool (VM disks)", "the libvirt networks, pools and VMs", "the backup store, if one was configured"}
	if !o.Purge {
		kept = append(kept, LibDir+"/api (the database)", ConfigDir+" (configuration and TLS files)", "the service accounts")
	}
	_, _ = fmt.Fprintln(w, "KEPT (Svavyom never deletes these):")
	for _, k := range kept {
		_, _ = fmt.Fprintln(w, "  - "+k)
	}
	if !o.Apply {
		return nil
	}
	if out, err := e.Run.Run(ctx, "virsh", "-r", "-c", "qemu:///system", "list", "--all", "--name"); err == nil {
		names := strings.Fields(out)
		if len(names) > 0 {
			_, _ = fmt.Fprintf(w, "VMs still defined in libvirt (not touched): %s\n", strings.Join(names, ", "))
		}
	}
	return nil
}

func removeIfExists(path string) error {
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

var _ = filepath.Join
