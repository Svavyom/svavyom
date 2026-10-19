package sqlitedb

import (
	"errors"
	"fmt"
	"os"
	"syscall"
)

// ErrLocked means another live process already runs the control plane against this database.
var ErrLocked = errors.New("sqlitedb: database is in use by another process")

// LockProcess takes an exclusive, non-blocking advisory lock on dbPath+".lock" for the life of the process (or until
// release). The kernel drops it when the holder dies, including by SIGKILL, so a crashed process never leaves a stale
// lock behind. The operation worker is single-node by design: it reconciles unknown outcomes only at start-up, which
// is correct only while no second executor can be running.
func LockProcess(dbPath string) (release func(), err error) {
	f, err := os.OpenFile(dbPath+".lock", os.O_CREATE|os.O_RDWR, 0o600) // #nosec G304 -- operator-configured path
	if err != nil {
		return nil, fmt.Errorf("sqlitedb: lock: %w", err)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil { // #nosec G115 -- fd fits int
		_ = f.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, ErrLocked
		}
		return nil, fmt.Errorf("sqlitedb: lock: %w", err)
	}
	return func() { _ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN); _ = f.Close() }, nil // #nosec G115
}
