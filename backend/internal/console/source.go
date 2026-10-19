package console

import (
	"context"
	"io"
)

// Info is what the broker needs to know about one VM's console.
type Info struct {
	Managed    bool // carries Svavyom's ownership marker
	Configured bool // has a serial console device
	Running    bool
	Graphics   bool // has the VNC console device (DR-026 D1)
}

// Source is the broker's only view of the hypervisor. The libvirt implementation (package libvirtcon, build tag libvirt) can do
// exactly these three things; a test source can fake them. Errors are *hypervisor.Error-like: a "not found" error is reported with
// the NotFound method returning true.
type Source interface {
	// Running lists the names of the Svavyom-managed VMs that are running and have a serial console.
	Running(ctx context.Context) ([]string, error)
	// Check reports the facts about one VM. ErrNotFound (or an error whose IsNotFound is true) when it does not exist.
	Check(ctx context.Context, vm string) (Info, error)
	// Open attaches to the serial console of a running, managed VM. Reading returns console output; writing sends keystrokes;
	// closing detaches. The stream ends (io.EOF or an error) when the VM stops.
	Open(ctx context.Context, vm string) (io.ReadWriteCloser, error)
	// OpenGraphics connects to the VNC server of a running, managed VM that has the console device. The stream carries the RFB protocol; closing it
	// detaches. There is no TCP port or file: the connection exists only inside the hypervisor and this process.
	OpenGraphics(ctx context.Context, vm string) (io.ReadWriteCloser, error)
}

// NotFound is implemented by errors that mean "no such VM".
type NotFound interface{ IsNotFound() bool }

// IsNotFound reports whether err (or what it wraps) says the VM does not exist.
func IsNotFound(err error) bool {
	for err != nil {
		if nf, ok := err.(NotFound); ok && nf.IsNotFound() {
			return true
		}
		u, ok := err.(interface{ Unwrap() error })
		if !ok {
			return false
		}
		err = u.Unwrap()
	}
	return false
}
