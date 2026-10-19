package nightly

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// NamePrefix marks the disposable VMs of this check. Cleanup of a leftover VM requires this prefix AND Svavyom ownership.
const NamePrefix = "svnb-"

// Floors below which the night is skipped rather than risk a busy host.
const (
	MinSpareDiskGiB  = 5
	MinFreeMemoryMiB = 1024
)

// Image is a catalog image as the check needs it.
type Image struct {
	ID        string
	Qualified bool
	MinDisk   int
}

// HostState is the host facts the guard reads.
type HostState struct {
	CreationReady bool
	PoolFreeGiB   *int
	MemoryFreeMiB *int // nil when no usage has been sampled
	VCPUOptions   []int
	MemoryOptions []int
	DiskOptions   []int
}

// VM is a virtual machine as the check needs it.
type VM struct {
	Name    string
	Managed bool
	Power   string // running | stopped | other
	IP      string
}

// CreateRequest is the small, fixed definition of the disposable VM.
type CreateRequest struct {
	VCPUs, MemoryMiB, DiskGiB int
	ImageID, SSHPublicKey     string
}

// API is the control plane as the check uses it: every call is an ordinary request of a signed-in operator.
type API interface {
	Host(ctx context.Context) (HostState, error)
	Images(ctx context.Context) ([]Image, error)
	VMs(ctx context.Context) ([]VM, error)
	ActiveOperations(ctx context.Context) (int, error)
	// Submit asks for an operation and returns its id; create is set only for type "create".
	Submit(ctx context.Context, typ, name string, create *CreateRequest) (string, error)
	// Wait follows an operation to a final status: succeeded, failed or cancelled; an error when it is still open at the deadline.
	Wait(ctx context.Context, id string, timeout time.Duration) (string, error)
}

// Prober checks that something answers on the SSH port with a banner.
type Prober interface {
	SSHBanner(ctx context.Context, ip string) (string, error)
}

// Timings of a night; tests shorten them.
type Timings struct {
	Create, Start, Stop, Delete time.Duration
	Address, Banner             time.Duration
	Poll                        time.Duration
}

// DefaultTimings are generous: a real guest on a loaded host takes minutes.
var DefaultTimings = Timings{Create: 5 * time.Minute, Start: 2 * time.Minute, Stop: 3 * time.Minute, Delete: 3 * time.Minute, Address: 4 * time.Minute, Banner: 4 * time.Minute, Poll: 5 * time.Second}

// Runner performs one night.
type Runner struct {
	API    API
	Prober Prober
	Now    func() time.Time
	Sleep  func(context.Context, time.Duration) error
	Timing Timings
	// Suffix names the VM; tests fix it. Empty draws random bytes.
	Suffix string
	// Log gets one short line per step (never a key, a password or host text).
	Log func(string)
}

func (r *Runner) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

func (r *Runner) logf(s string) {
	if r.Log != nil {
		r.Log(s)
	}
}

func (r *Runner) sleep(ctx context.Context, d time.Duration) error {
	if r.Sleep != nil {
		return r.Sleep(ctx, d)
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(d):
		return nil
	}
}

func (r *Runner) poll() time.Duration {
	if r.Timing.Poll > 0 {
		return r.Timing.Poll
	}
	return DefaultTimings.Poll
}

func pick(have []int, want int) (int, bool) {
	for _, v := range have {
		if v == want {
			return v, true
		}
	}
	return 0, false
}

func smallest(have []int, atLeast int) (int, bool) {
	best, ok := 0, false
	for _, v := range have {
		if v >= atLeast && (!ok || v < best) {
			best, ok = v, true
		}
	}
	return best, ok
}

// ephemeralKey makes a throw-away public key for the guest. The private half is dropped at once: the check never logs in, it only reads the banner.
func ephemeralKey() (string, error) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", err
	}
	k, err := ssh.NewPublicKey(pub)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(k))), nil
}

// Run performs one night and returns its result. It never returns an error: every way a night can go wrong is a result with a closed reason.
func (r *Runner) Run(ctx context.Context) Result {
	start := r.now()
	done := func(res, reason string) Result {
		return Result{At: start.UTC().Truncate(time.Second), Result: res, Seconds: int(r.now().Sub(start) / time.Second), Reason: reason}
	}
	t := r.Timing
	if t == (Timings{}) {
		t = DefaultTimings
	}
	r.Timing = t

	hs, err := r.API.Host(ctx)
	if err != nil {
		return done(Fail, ReasonAPI)
	}
	// Leftovers of an earlier night are removed first, by name prefix and ownership only, so a crash never leaves a VM behind for good.
	vms, err := r.API.VMs(ctx)
	if err != nil {
		return done(Fail, ReasonAPI)
	}
	for _, v := range vms {
		if strings.HasPrefix(v.Name, NamePrefix) && v.Managed {
			r.logf("removing a leftover VM of an earlier night")
			if !r.remove(ctx, v.Name) {
				return done(Fail, ReasonLeftover)
			}
		}
	}
	if !hs.CreationReady {
		return done(Skipped, ReasonNotReady)
	}
	if n, err := r.API.ActiveOperations(ctx); err != nil {
		return done(Fail, ReasonAPI)
	} else if n > 0 {
		return done(Skipped, ReasonBusy)
	}
	images, err := r.API.Images(ctx)
	if err != nil {
		return done(Fail, ReasonAPI)
	}
	var img *Image
	for i := range images {
		if images[i].Qualified {
			img = &images[i]
			break
		}
	}
	if img == nil {
		return done(Skipped, ReasonNoImage)
	}
	disk, ok := smallest(hs.DiskOptions, max(img.MinDisk, 1))
	if _, vok := pick(hs.VCPUOptions, 1); !ok || !vok || len(hs.MemoryOptions) == 0 {
		return done(Skipped, ReasonNotReady)
	}
	mem := hs.MemoryOptions[0]
	for _, m := range hs.MemoryOptions {
		if m < mem {
			mem = m
		}
	}
	if hs.PoolFreeGiB != nil && *hs.PoolFreeGiB < disk+MinSpareDiskGiB {
		return done(Skipped, ReasonSpace)
	}
	if hs.MemoryFreeMiB != nil && *hs.MemoryFreeMiB < mem+MinFreeMemoryMiB {
		return done(Skipped, ReasonMemory)
	}
	key, err := ephemeralKey()
	if err != nil {
		return done(Fail, ReasonCreate)
	}
	name := NamePrefix + r.start8()
	r.logf("creating the disposable VM")
	if !r.step(ctx, "create", name, &CreateRequest{VCPUs: 1, MemoryMiB: mem, DiskGiB: disk, ImageID: img.ID, SSHPublicKey: key}, t.Create) {
		r.remove(ctx, name)
		return done(Fail, ReasonCreate)
	}
	reason := r.exercise(ctx, name)
	// The VM is always taken away again, whatever happened above.
	if !r.remove(ctx, name) {
		if reason == ReasonNone {
			reason = ReasonDelete
		}
		return done(Fail, reason)
	}
	if left, err := r.API.VMs(ctx); err != nil {
		if reason == ReasonNone {
			reason = ReasonAPI
		}
	} else {
		for _, v := range left {
			if v.Name == name && reason == ReasonNone {
				reason = ReasonNotClean
			}
		}
	}
	if reason != ReasonNone {
		return done(Fail, reason)
	}
	return done(Pass, ReasonNone)
}

func (r *Runner) start8() string {
	if r.Suffix != "" {
		return r.Suffix
	}
	var b [4]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// step submits one operation and waits for it to succeed.
func (r *Runner) step(ctx context.Context, typ, name string, c *CreateRequest, timeout time.Duration) bool {
	id, err := r.API.Submit(ctx, typ, name, c)
	if err != nil {
		return false
	}
	st, err := r.API.Wait(ctx, id, timeout)
	return err == nil && st == "succeeded"
}

// exercise starts the VM and waits for an address and a banner; it returns a reason ("" when all went well).
func (r *Runner) exercise(ctx context.Context, name string) string {
	t := r.Timing
	r.logf("starting it")
	if !r.step(ctx, "start", name, nil, t.Start) {
		return ReasonStart
	}
	ip := ""
	deadline := r.now().Add(t.Address)
	for ip == "" {
		vms, err := r.API.VMs(ctx)
		if err == nil {
			for _, v := range vms {
				if v.Name == name && v.Power == "running" && v.IP != "" {
					ip = v.IP
				}
			}
		}
		if ip != "" {
			break
		}
		if r.now().After(deadline) || ctx.Err() != nil {
			return ReasonAddress
		}
		if r.sleep(ctx, r.poll()) != nil {
			return ReasonAddress
		}
	}
	r.logf("it has an address; looking for an SSH banner")
	deadline = r.now().Add(t.Banner)
	for {
		b, err := r.Prober.SSHBanner(ctx, ip)
		if err == nil && strings.HasPrefix(b, "SSH-") {
			return ReasonNone
		}
		if r.now().After(deadline) || ctx.Err() != nil {
			return ReasonBanner
		}
		if r.sleep(ctx, r.poll()) != nil {
			return ReasonBanner
		}
	}
}

// remove stops the VM (gracefully first, and by force only because this VM is the check's own disposable one) and deletes it. It reports whether the VM is gone.
func (r *Runner) remove(ctx context.Context, name string) bool {
	t := r.Timing
	if t == (Timings{}) {
		t = DefaultTimings
	}
	state := func() (VM, bool, error) {
		vms, err := r.API.VMs(ctx)
		if err != nil {
			return VM{}, false, err
		}
		for _, v := range vms {
			if v.Name == name {
				return v, true, nil
			}
		}
		return VM{}, false, nil
	}
	v, found, err := state()
	if err != nil {
		return false
	}
	if !found {
		return true
	}
	if !v.Managed || !strings.HasPrefix(v.Name, NamePrefix) {
		return false // never touch what is not ours
	}
	if v.Power != "stopped" {
		if !r.step(ctx, "stop", name, nil, t.Stop) {
			if !r.step(ctx, "force_off", name, nil, t.Stop) {
				return false
			}
		}
	}
	if !r.step(ctx, "delete", name, nil, t.Delete) {
		return false
	}
	_, still, err := state()
	return err == nil && !still
}

// ErrNoCredential is returned when the service account's credential cannot be read.
var ErrNoCredential = errors.New("nightly: no credential")
