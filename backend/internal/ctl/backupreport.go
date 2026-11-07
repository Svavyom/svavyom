package ctl

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"example.invalid/dedicatedcloud/backend/internal/backupstore"
	"example.invalid/dedicatedcloud/backend/internal/provision"
	"example.invalid/dedicatedcloud/backend/internal/sqlitedb"
)

// BackupReport is what `svavyom-ctl backup-report` prints (M0-E01-S08, finding F-01). Before preview.14 the scheduler's retention could not see more than the newest
// 100 backups: backups beyond that were never pruned and the scheduler forgot them while they stayed on disk. This read-only report shows, per VM, what is on disk next
// to what the scheduler keeps, so an operator can see what the bug left behind and delete it. It never deletes or changes anything.
type BackupReport struct {
	BackupDir string           `json:"backup_dir"`
	VMs       []BackupVMReport `json:"vms"`
	// RecordsWithoutBackup lists scheduler records whose backup is no longer in the store (harmless; the scheduler drops them at its next window).
	RecordsWithoutBackup []string `json:"records_without_backup"`
	TotalBackups         int      `json:"total_backups"`
	TotalBytes           int64    `json:"total_bytes"`
}

// BackupVMReport is one VM's backups.
type BackupVMReport struct {
	VM        string `json:"vm"`
	Scheduled bool   `json:"scheduled"`
	KeepLocal int    `json:"keep_local"` // the schedule's limit; 0 when the VM has no schedule
	Backups   int    `json:"backups"`
	Bytes     int64  `json:"bytes"`
	Oldest    string `json:"oldest,omitempty"`
	Newest    string `json:"newest,omitempty"`
	// Tracked backups are those the scheduler made and still knows: its retention keeps the newest KeepLocal of them. Untracked backups are on disk but not in the
	// scheduler's records: a backup you made by hand, or one the retention bug made it forget. Retention never prunes an untracked backup.
	Tracked      int      `json:"tracked"`
	Untracked    int      `json:"untracked"`
	Excess       int      `json:"excess"` // Backups minus KeepLocal, only for a scheduled VM and only when positive
	UntrackedIDs []string `json:"untracked_ids,omitempty"`
}

type backupFound struct {
	id, vm, at string
	size       int64
}

var storeBackupIDRE = regexp.MustCompile(`^bk-[0-9a-f]{16}$`)

// readBackupListing lists the backup directories of dir by their manifests. It reads as whoever runs it (root: the store is owned by the mutation identity, so the
// store's own Open, which insists on its owner, is not used) and trusts nothing it reads: an entry that is not a well-formed backup directory is skipped.
func readBackupListing(dir string) ([]backupFound, error) {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("the backup directory cannot be read: %w", err)
	}
	var out []backupFound
	for _, e := range ents {
		if !e.IsDir() || !storeBackupIDRE.MatchString(e.Name()) {
			continue
		}
		raw, err := readRegular(filepath.Join(dir, e.Name(), backupstore.ManifestFile), 64<<10)
		if err != nil {
			continue
		}
		var m backupstore.Manifest
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.DisallowUnknownFields()
		if dec.Decode(&m) != nil || m.BackupID != e.Name() || m.Validate() != nil {
			continue
		}
		out = append(out, backupFound{id: m.BackupID, vm: m.VM.Name, at: m.CreatedAt, size: m.Root.Size})
	}
	return out, nil
}

type scheduleKnown struct {
	keep    map[string]int    // vm -> keep_local
	tracked map[string]string // backup id -> vm
}

// openForReport opens the API database for reading without leaving anything behind. A WAL-mode database read by a process that is not the service creates its -wal and
// -shm files when nobody else has it open, and a root-owned -shm in the service's private directory would stop the service from starting. So: when the service has the
// database open (its -wal and -shm exist) the normal read-only open is safe; when nothing has it open the file is opened immutable (no locks, no new files).
func openForReport(path string) (*sql.DB, error) {
	_, werr := os.Stat(path + "-wal")
	_, serr := os.Stat(path + "-shm")
	if werr == nil && serr == nil {
		return sqlitedb.OpenReadOnly(path)
	}
	fi, err := os.Stat(path)
	if err != nil || !fi.Mode().IsRegular() {
		return nil, errors.New("no database")
	}
	q := url.Values{}
	q.Set("mode", "ro")
	q.Set("immutable", "1")
	db, err := sql.Open("sqlite", "file:"+(&url.URL{Path: path}).EscapedPath()+"?"+q.Encode())
	if err != nil {
		return nil, err
	}
	if err := db.PingContext(context.Background()); err != nil {
		_ = db.Close()
		return nil, err
	}
	return db, nil
}

func readSchedules(path string) (scheduleKnown, error) {
	k := scheduleKnown{keep: map[string]int{}, tracked: map[string]string{}}
	db, err := openForReport(path)
	if err != nil {
		return k, nil // no database (or none readable): there are no schedules to compare with
	}
	defer func() { _ = db.Close() }()
	rows, err := db.Query(`SELECT vm, keep_local FROM schedules`)
	if err == nil {
		for rows.Next() {
			var vm string
			var keep int
			if rows.Scan(&vm, &keep) == nil {
				k.keep[vm] = keep
			}
		}
		_ = rows.Close()
	}
	rows, err = db.Query(`SELECT backup_id, vm FROM schedule_backups`)
	if err == nil {
		for rows.Next() {
			var id, vm string
			if rows.Scan(&id, &vm) == nil {
				k.tracked[id] = vm
			}
		}
		_ = rows.Close()
	}
	return k, nil
}

// BuildBackupReport compares the backups on disk with the scheduler's records.
func BuildBackupReport(found []backupFound, k scheduleKnown, dir string) BackupReport {
	rep := BackupReport{BackupDir: dir, RecordsWithoutBackup: []string{}}
	byVM := map[string]*BackupVMReport{}
	onDisk := map[string]bool{}
	sort.Slice(found, func(i, j int) bool {
		return found[i].at < found[j].at || (found[i].at == found[j].at && found[i].id < found[j].id)
	})
	for _, b := range found {
		onDisk[b.id] = true
		v := byVM[b.vm]
		if v == nil {
			keep, sched := k.keep[b.vm]
			v = &BackupVMReport{VM: b.vm, Scheduled: sched, KeepLocal: keep}
			byVM[b.vm] = v
		}
		v.Backups++
		v.Bytes += b.size
		if v.Oldest == "" {
			v.Oldest = b.at
		}
		v.Newest = b.at
		if k.tracked[b.id] == b.vm {
			v.Tracked++
		} else {
			v.Untracked++
			v.UntrackedIDs = append(v.UntrackedIDs, b.id)
		}
		rep.TotalBackups++
		rep.TotalBytes += b.size
	}
	for id := range k.tracked {
		if !onDisk[id] {
			rep.RecordsWithoutBackup = append(rep.RecordsWithoutBackup, id)
		}
	}
	sort.Strings(rep.RecordsWithoutBackup)
	for _, v := range byVM {
		if v.Scheduled && v.Backups > v.KeepLocal {
			v.Excess = v.Backups - v.KeepLocal
		}
		rep.VMs = append(rep.VMs, *v)
	}
	sort.Slice(rep.VMs, func(i, j int) bool { return rep.VMs[i].VM < rep.VMs[j].VM })
	return rep
}

// BackupReportRun reads the configuration, the backup directory and the scheduler's records and prints the report. asJSON prints it as JSON. It is read-only.
func BackupReportRun(ctx context.Context, e *Env, cfgPath string, asJSON bool, w io.Writer) error {
	if cfgPath == "" {
		cfgPath = e.P(ConfigFile)
	}
	cfg, err := provision.LoadConfig(cfgPath)
	if err != nil {
		return errors.New("the provisioning configuration cannot be read or is invalid")
	}
	if cfg.BackupDir == "" {
		return errors.New("no local backup store is configured (backup_dir is empty)")
	}
	dir := e.P(cfg.BackupDir)
	found, err := readBackupListing(dir)
	if err != nil {
		if e.Euid() != 0 {
			return errors.New("the backup directory belongs to the mutation service: run this as root (sudo)")
		}
		return err
	}
	k, _ := readSchedules(e.dbPath())
	rep := BuildBackupReport(found, k, cfg.BackupDir)
	if asJSON {
		b, _ := json.MarshalIndent(rep, "", "  ")
		_, _ = fmt.Fprintln(w, string(b))
		return nil
	}
	_, _ = fmt.Fprintf(w, "Backups in %s: %d, %s in total. This report only reads; it deletes nothing.\n", rep.BackupDir, rep.TotalBackups, humanBytes(rep.TotalBytes))
	if rep.TotalBackups == 0 {
		return nil
	}
	_, _ = fmt.Fprintf(w, "%-22s %-10s %8s %10s %8s %10s %7s\n", "VM", "scheduled", "backups", "size", "tracked", "untracked", "excess")
	any := false
	for _, v := range rep.VMs {
		sched := "no"
		if v.Scheduled {
			sched = fmt.Sprintf("keep %d", v.KeepLocal)
		}
		_, _ = fmt.Fprintf(w, "%-22s %-10s %8d %10s %8d %10d %7d\n", v.VM, sched, v.Backups, humanBytes(v.Bytes), v.Tracked, v.Untracked, v.Excess)
		if v.Excess > 0 || (v.Scheduled && v.Untracked > 0) {
			any = true
		}
	}
	if any {
		_, _ = fmt.Fprintln(w, "\nWhat the columns mean:\n  tracked    backups the scheduler made and still knows; its retention keeps the newest 'keep' of them\n  untracked  on disk but not in the scheduler's records: made by hand, or forgotten because of the retention bug fixed in 0.1.0-preview.14 (it never pruned them)\n  excess     backups beyond the schedule's limit")
		for _, v := range rep.VMs {
			if v.Scheduled && v.Untracked > 0 {
				_, _ = fmt.Fprintf(w, "\n%s: untracked backups (oldest first), delete the ones you do not want from the console (Backups) or with a delete operation:\n  %s\n", v.VM, strings.Join(v.UntrackedIDs, " "))
			}
		}
	} else {
		_, _ = fmt.Fprintln(w, "\nNothing is beyond a schedule's limit and no scheduled VM has a backup the scheduler has lost track of.")
	}
	if len(rep.RecordsWithoutBackup) > 0 {
		_, _ = fmt.Fprintf(w, "\n%d scheduler record(s) name a backup that is no longer in the store (harmless; the scheduler drops them at its next window).\n", len(rep.RecordsWithoutBackup))
	}
	return nil
}

func humanBytes(n int64) string {
	const k = 1024
	switch {
	case n >= k*k*k:
		return fmt.Sprintf("%.1f GiB", float64(n)/(k*k*k))
	case n >= k*k:
		return fmt.Sprintf("%.1f MiB", float64(n)/(k*k))
	case n >= k:
		return fmt.Sprintf("%.1f KiB", float64(n)/k)
	}
	return fmt.Sprintf("%d B", n)
}
