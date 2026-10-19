// Package metrics samples host and VM usage (DR-022): a reading every interval, kept for 24 hours in the API's own SQLite database so the
// history survives a restart, and read back as the last hour. It observes only; it never changes the host and adds no privilege: the host figures
// come from /proc and a VM's CPU time comes from the read-only inventory agent. A missed cycle is a gap, never an invented value.
package metrics

import (
	"context"
	"database/sql"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"example.invalid/dedicatedcloud/backend/internal/hypervisor"
	"example.invalid/dedicatedcloud/backend/internal/sqlitedb"
)

const (
	// DefaultInterval is the sampling period; Retention how long rows are kept; Window the span the API reports; MaxPoints its bound.
	DefaultInterval = 30 * time.Second
	Retention       = 24 * time.Hour
	Window          = time.Hour
	MaxPoints       = 240
	hostSubject     = "host"
)

// Row is one stored sample. Subject is "host" or "vm:<name>". DiskKiBs and NetKiBs are rates (DR-023 D5); a figure the source could not give is 0.
type Row struct {
	Subject    string
	At         time.Time
	CPUPercent int
	MemUsedMiB int64
	DiskKiBs   int64
	NetKiBs    int64
}

// Store persists samples.
type Store interface {
	Append(ctx context.Context, rows []Row) error
	Since(ctx context.Context, since time.Time) ([]Row, error)
	Prune(ctx context.Context, before time.Time) error
}

var schema = []string{`CREATE TABLE usage_samples (
	subject      TEXT    NOT NULL,
	at           INTEGER NOT NULL,
	cpu_percent  INTEGER NOT NULL CHECK (cpu_percent BETWEEN 0 AND 100),
	mem_used_mib INTEGER NOT NULL DEFAULT 0 CHECK (mem_used_mib >= 0),
	PRIMARY KEY (subject, at)
) WITHOUT ROWID;
CREATE INDEX usage_samples_at ON usage_samples (at);`,
	// Step 2 (DR-023 D5): disk and network rates.
	`ALTER TABLE usage_samples ADD COLUMN disk_kib_s INTEGER NOT NULL DEFAULT 0 CHECK (disk_kib_s >= 0);
ALTER TABLE usage_samples ADD COLUMN net_kib_s INTEGER NOT NULL DEFAULT 0 CHECK (net_kib_s >= 0);`}

// SchemaVersion is the schema version this build migrates the usage tables to.
func SchemaVersion() int { return len(schema) }

// SQLiteStore is the durable Store.
type SQLiteStore struct{ db *sql.DB }

// OpenSQLite migrates the schema in db and returns a store over it. The caller owns db.
func OpenSQLite(ctx context.Context, db *sql.DB) (*SQLiteStore, error) {
	if err := sqlitedb.Migrate(ctx, db, "usage", schema); err != nil {
		return nil, fmt.Errorf("metrics: migrate: %w", err)
	}
	return &SQLiteStore{db: db}, nil
}

// Append implements Store. A repeated (subject, time) keeps the first row.
func (s *SQLiteStore) Append(ctx context.Context, rows []Row) error {
	if len(rows) == 0 {
		return nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	for _, r := range rows {
		if _, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO usage_samples (subject, at, cpu_percent, mem_used_mib, disk_kib_s, net_kib_s) VALUES (?, ?, ?, ?, ?, ?)`,
			r.Subject, r.At.Unix(), r.CPUPercent, r.MemUsedMiB, r.DiskKiBs, r.NetKiBs); err != nil {
			_ = tx.Rollback()
			return err
		}
	}
	return tx.Commit()
}

// Since implements Store: rows at or after since, oldest first.
func (s *SQLiteStore) Since(ctx context.Context, since time.Time) ([]Row, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT subject, at, cpu_percent, mem_used_mib, disk_kib_s, net_kib_s FROM usage_samples WHERE at >= ? ORDER BY at, subject`, since.Unix())
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []Row
	for rows.Next() {
		var r Row
		var at int64
		if err := rows.Scan(&r.Subject, &at, &r.CPUPercent, &r.MemUsedMiB, &r.DiskKiBs, &r.NetKiBs); err != nil {
			return nil, err
		}
		r.At = time.Unix(at, 0).UTC()
		out = append(out, r)
	}
	return out, rows.Err()
}

// Prune implements Store: delete rows older than before.
func (s *SQLiteStore) Prune(ctx context.Context, before time.Time) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM usage_samples WHERE at < ?`, before.Unix())
	return err
}

// HostReader reads the host's cumulative CPU counters and memory use.
type HostReader interface {
	CPU() (busy, total uint64, err error)
	MemoryUsedMiB() (int64, error)
}

// ProcReader reads /proc/stat and /proc/meminfo under Root (empty means "/"); Root exists so tests can use a fixture tree.
type ProcReader struct{ Root string }

func (p ProcReader) read(name string) (string, error) {
	f, err := os.Open(filepath.Join(p.Root, "/proc", name)) // #nosec G304 -- Root is empty in production and name is one of three constants
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	b, err := io.ReadAll(io.LimitReader(f, 64<<10))
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// CPU implements HostReader from the aggregate "cpu" line: busy = total - idle - iowait.
func (p ProcReader) CPU() (uint64, uint64, error) {
	txt, err := p.read("stat")
	if err != nil {
		return 0, 0, err
	}
	line, _, _ := strings.Cut(txt, "\n")
	f := strings.Fields(line)
	if len(f) < 5 || f[0] != "cpu" {
		return 0, 0, fmt.Errorf("metrics: unreadable stat")
	}
	var total, idle uint64
	for i, v := range f[1:] {
		n, err := strconv.ParseUint(v, 10, 64)
		if err != nil {
			return 0, 0, fmt.Errorf("metrics: unreadable stat")
		}
		if i < 8 { // user nice system idle iowait irq softirq steal; guest time is already in user
			total += n
		}
		if i == 3 || i == 4 {
			idle += n
		}
	}
	return total - idle, total, nil
}

// MemoryUsedMiB implements HostReader: MemTotal minus MemAvailable.
func (p ProcReader) MemoryUsedMiB() (int64, error) {
	txt, err := p.read("meminfo")
	if err != nil {
		return 0, err
	}
	var total, avail int64 = -1, -1
	for _, line := range strings.Split(txt, "\n") {
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		n, _ := strconv.ParseInt(strings.Fields(v + " x")[0], 10, 64)
		switch k {
		case "MemTotal":
			total = n
		case "MemAvailable":
			avail = n
		}
	}
	if total < 0 || avail < 0 || avail > total {
		return 0, fmt.Errorf("metrics: unreadable meminfo")
	}
	return (total - avail) / 1024, nil
}

// IOReader is the optional second interface of a HostReader: cumulative bytes through the physical disks and network interfaces.
type IOReader interface {
	IO() (diskBytes, netBytes uint64, err error)
}

var (
	diskRE = regexp.MustCompile(`^(sd[a-z]+|vd[a-z]+|xvd[a-z]+|nvme[0-9]+n[0-9]+|mmcblk[0-9]+)$`)
	skipIf = regexp.MustCompile(`^(lo|vnet.*|virbr.*|veth.*|docker.*|br-.*|tun.*|tap.*)$`)
)

// IO implements IOReader: sectors (512 bytes) read plus written of whole physical disks from /proc/diskstats (partitions, loop and device-mapper
// devices are not counted twice), and bytes received plus transmitted of the host's real interfaces from /proc/net/dev (loopback, bridges and
// the VMs' own tap devices are left out so traffic is not counted twice).
func (p ProcReader) IO() (uint64, uint64, error) {
	ds, err := p.read("diskstats")
	if err != nil {
		return 0, 0, err
	}
	var disk, net uint64
	for _, line := range strings.Split(ds, "\n") {
		f := strings.Fields(line)
		if len(f) < 10 || !diskRE.MatchString(f[2]) {
			continue
		}
		r, e1 := strconv.ParseUint(f[5], 10, 64)
		w, e2 := strconv.ParseUint(f[9], 10, 64)
		if e1 != nil || e2 != nil {
			return 0, 0, fmt.Errorf("metrics: unreadable diskstats")
		}
		disk += (r + w) * 512
	}
	nd, err := p.read("net/dev")
	if err != nil {
		return 0, 0, err
	}
	for _, line := range strings.Split(nd, "\n") {
		name, rest, ok := strings.Cut(line, ":")
		name = strings.TrimSpace(name)
		if !ok || skipIf.MatchString(name) {
			continue
		}
		f := strings.Fields(rest)
		if len(f) < 9 {
			continue
		}
		rx, e1 := strconv.ParseUint(f[0], 10, 64)
		tx, e2 := strconv.ParseUint(f[8], 10, 64)
		if e1 != nil || e2 != nil {
			return 0, 0, fmt.Errorf("metrics: unreadable net/dev")
		}
		net += rx + tx
	}
	return disk, net, nil
}

// Lister is the read-only view of the VMs (the agent client).
type Lister interface {
	List(ctx context.Context) ([]hypervisor.Domain, error)
}

// kibPerSec is a byte difference over wall time in KiB per second, bounded so it cannot overflow.
func kibPerSec(bytes uint64, wall time.Duration) int64 {
	if wall <= 0 || bytes > 1<<50 {
		return 0
	}
	return int64(bytes) * int64(time.Second) / int64(wall) / 1024 // #nosec G115 -- bounded above
}

type vmSnap struct {
	at        time.Time
	cpu       int64
	disk, net int64
}

// rate turns two cumulative byte counters into KiB per second; a counter that went backwards (a restart) or a missing reading is 0.
func rate(prev, cur int64, wall time.Duration) int64 {
	if prev <= 0 || cur < prev || wall <= 0 {
		return 0
	}
	return (cur - prev) * int64(time.Second) / int64(wall) / 1024
}

// Sampler takes a sample every Interval and answers the API's usage reads.
type Sampler struct {
	Store     Store
	HostSrc   HostReader
	VMSrc     Lister
	Interval  time.Duration
	Retention time.Duration
	Now       func() time.Time

	mu        sync.Mutex
	prevBusy  uint64
	prevTotal uint64
	havePrev  bool
	prevVM    map[string]vmSnap
	prevIO    struct {
		at        time.Time
		disk, net uint64
		have      bool
	}
	ring    map[string][]Row // the last Window of every subject, kept in memory so a failing database never blanks the view
	lastErr bool
	taken   bool
}

func (s *Sampler) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s *Sampler) interval() time.Duration {
	if s.Interval > 0 {
		return s.Interval
	}
	return DefaultInterval
}

// Run samples until ctx ends: once at once, then every interval.
func (s *Sampler) Run(ctx context.Context) {
	s.Tick(ctx)
	t := time.NewTicker(s.interval())
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.Tick(ctx)
		}
	}
}

// Tick takes one sample cycle. Failures leave a gap and never stop the sampler.
func (s *Sampler) Tick(ctx context.Context) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now().UTC().Truncate(time.Second)
	var rows []Row
	if s.HostSrc != nil {
		busy, total, cerr := s.HostSrc.CPU()
		mem, merr := s.HostSrc.MemoryUsedMiB()
		if cerr == nil {
			if s.havePrev && total > s.prevTotal && merr == nil {
				pct := min((busy-s.prevBusy)*100/(total-s.prevTotal), 100)
				row := Row{Subject: hostSubject, At: now, CPUPercent: int(pct), MemUsedMiB: mem} // #nosec G115 -- bounded to 100 above
				if io, ok := s.HostSrc.(IOReader); ok {
					if d, n, err := io.IO(); err == nil {
						if s.prevIO.have && d >= s.prevIO.disk && n >= s.prevIO.net && now.After(s.prevIO.at) {
							wall := now.Sub(s.prevIO.at)
							row.DiskKiBs, row.NetKiBs = kibPerSec(d-s.prevIO.disk, wall), kibPerSec(n-s.prevIO.net, wall)
						}
						s.prevIO.at, s.prevIO.disk, s.prevIO.net, s.prevIO.have = now, d, n, true
					}
				}
				rows = append(rows, row)
			}
			s.prevBusy, s.prevTotal, s.havePrev = busy, total, true
		}
	}
	if s.VMSrc != nil {
		lctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		doms, err := s.VMSrc.List(lctx)
		cancel()
		if err == nil {
			seen := map[string]bool{}
			next := map[string]vmSnap{}
			for _, d := range doms {
				seen[d.Name] = true
				if d.State != hypervisor.StateRunning || d.CPUTimeNs <= 0 {
					continue
				}
				next[d.Name] = vmSnap{at: now, cpu: d.CPUTimeNs, disk: d.DiskIOBytes, net: d.NetIOBytes}
				prev, ok := s.prevVM[d.Name]
				wall := now.Sub(prev.at)
				if !ok || wall <= 0 || d.CPUTimeNs < prev.cpu || d.VCPUs < 1 {
					continue
				}
				pct := int((d.CPUTimeNs - prev.cpu) * 100 / (wall.Nanoseconds() * int64(d.VCPUs)))
				rows = append(rows, Row{Subject: "vm:" + d.Name, At: now, CPUPercent: clamp(pct), MemUsedMiB: d.MemUsedMiB,
					DiskKiBs: rate(prev.disk, d.DiskIOBytes, wall), NetKiBs: rate(prev.net, d.NetIOBytes, wall)})
			}
			s.prevVM = next
			for subj := range s.ring { // a VM that no longer exists has no history to show
				if strings.HasPrefix(subj, "vm:") && !seen[strings.TrimPrefix(subj, "vm:")] {
					delete(s.ring, subj)
				}
			}
		}
	}
	s.taken = true
	if s.ring == nil {
		s.ring = map[string][]Row{}
	}
	for _, r := range rows {
		h := append(s.ring[r.Subject], r)
		if len(h) > MaxPoints {
			h = h[len(h)-MaxPoints:]
		}
		s.ring[r.Subject] = h
	}
	if s.Store != nil {
		sctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		err := s.Store.Append(sctx, rows)
		if err == nil {
			ret := s.Retention
			if ret <= 0 {
				ret = Retention
			}
			err = s.Store.Prune(sctx, now.Add(-ret))
		}
		s.lastErr = err != nil
	}
}

func clamp(n int) int {
	if n < 0 {
		return 0
	}
	if n > 100 {
		return 100
	}
	return n
}

// HostUsage and VMUsage are what the API reports. Available is false until a sample exists.
type HostPoint struct {
	At         time.Time
	CPUPercent int
	MemUsedMiB int64
	DiskKiBs   int64
	NetKiBs    int64
}

type HostUsage struct {
	Available       bool
	IntervalSeconds int
	CPUPercent      *int
	MemUsedMiB      *int64
	DiskKiBs        *int64
	NetKiBs         *int64
	History         []HostPoint
}

type VMPoint struct {
	At         time.Time
	CPUPercent int
	MemUsedMiB int64
	DiskKiBs   int64
	NetKiBs    int64
}

type VMUsage struct {
	Available  bool
	CPUPercent *int
	MemUsedMiB *int64
	DiskKiBs   *int64
	NetKiBs    *int64
	History    []VMPoint
}

// load returns the rows of the last Window for every subject: from the database, or from memory when the database cannot be read.
func (s *Sampler) load(ctx context.Context) map[string][]Row {
	since := s.now().Add(-Window)
	out := map[string][]Row{}
	if s.Store != nil {
		if rows, err := s.Store.Since(ctx, since); err == nil {
			for _, r := range rows {
				out[r.Subject] = append(out[r.Subject], r)
			}
			return trim(out)
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, v := range s.ring {
		for _, r := range v {
			if !r.At.Before(since) {
				out[k] = append(out[k], r)
			}
		}
	}
	return trim(out)
}

func trim(m map[string][]Row) map[string][]Row {
	for k, v := range m {
		if len(v) > MaxPoints {
			m[k] = v[len(v)-MaxPoints:]
		}
	}
	return m
}

// Host returns the host's usage. With no sample yet it reports unavailable and an empty history.
func (s *Sampler) Host(ctx context.Context) HostUsage {
	if s == nil {
		return HostUsage{History: []HostPoint{}}
	}
	u := HostUsage{IntervalSeconds: int(s.interval() / time.Second), History: []HostPoint{}}
	rows := s.load(ctx)[hostSubject]
	for _, r := range rows {
		u.History = append(u.History, HostPoint{At: r.At, CPUPercent: r.CPUPercent, MemUsedMiB: r.MemUsedMiB, DiskKiBs: r.DiskKiBs, NetKiBs: r.NetKiBs})
	}
	if n := len(rows); n > 0 && s.now().Sub(rows[n-1].At) <= 4*s.interval() {
		last := rows[n-1]
		c, m, d, nt := last.CPUPercent, last.MemUsedMiB, last.DiskKiBs, last.NetKiBs
		u.Available, u.CPUPercent, u.MemUsedMiB, u.DiskKiBs, u.NetKiBs = true, &c, &m, &d, &nt
	}
	return u
}

// VMs returns the usage of every VM that has samples, by name; a VM absent from the map has none.
func (s *Sampler) VMs(ctx context.Context) map[string]VMUsage {
	out := map[string]VMUsage{}
	if s == nil {
		return out
	}
	for subj, rows := range s.load(ctx) {
		name, ok := strings.CutPrefix(subj, "vm:")
		if !ok {
			continue
		}
		u := VMUsage{History: []VMPoint{}}
		for _, r := range rows {
			u.History = append(u.History, VMPoint{At: r.At, CPUPercent: r.CPUPercent, MemUsedMiB: r.MemUsedMiB, DiskKiBs: r.DiskKiBs, NetKiBs: r.NetKiBs})
		}
		if n := len(rows); n > 0 && s.now().Sub(rows[n-1].At) <= 4*s.interval() {
			last := rows[n-1]
			c, m, d, nt := last.CPUPercent, last.MemUsedMiB, last.DiskKiBs, last.NetKiBs
			u.Available, u.CPUPercent, u.MemUsedMiB, u.DiskKiBs, u.NetKiBs = true, &c, &m, &d, &nt
		}
		out[name] = u
	}
	return out
}

// Degraded reports that the last write to the database failed (the figures still come from memory).
func (s *Sampler) Degraded() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lastErr
}
