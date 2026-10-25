//go:build libvirt

// Package libvirtmut implements provision.HostOps on libvirt's storage-pool, network and domain APIs (libvirt.org/go/libvirt):
// no virsh, no qemu-img, no shell. It is linked ONLY into the short-lived mutation helper (cmd/mutation-helper), never into the
// API, the supervisor or the read-only inventory agent. It accepts the system hypervisor and, for tests, the in-process test
// driver, and nothing else. Every XML document it sends is generated from validated values and XML-escaped.
package libvirtmut

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	libvirt "libvirt.org/go/libvirt"

	"example.invalid/dedicatedcloud/backend/internal/hypervisor"
	"example.invalid/dedicatedcloud/backend/internal/provision"
)

// URIs accepted by Open.
const (
	SystemURI = "qemu:///system"
	TestURI   = "test:///default"
)

// Ops is the libvirt-backed provision.HostOps.
type Ops struct {
	conn *libvirt.Connect
	// eventsErr is non-nil when libvirt's default event loop could not be started; only RebootDomain needs it.
	eventsErr error
	// SkipUploadUnsupported lets tests run against the libvirt test driver, which does not implement volume upload
	// (virStorageVolUpload). It is never set by the production helper; it is a simulation gap, stated in the tests.
	SkipUploadUnsupported bool
	// Diag, when set, receives the RAW libvirt error text of a failed define or start. Only the qualification harness sets it: the
	// production helper returns the closed error categories and never forwards libvirt's text, which can contain host paths.
	Diag func(op, detail string)

	// Lstat and Canonical inspect a volume's resolved path (default os.Lstat and filepath.EvalSymlinks). Tests inject them; the
	// production helper leaves them nil and runs on the host that owns the pool.
	Lstat     func(string) (os.FileInfo, error)
	Canonical func(string) (string, error)
}

var _ provision.HostOps = (*Ops)(nil)

var (
	eventsOnce sync.Once
	eventsErr  error
)

// startEvents starts libvirt's default event loop (once per process, before the first connection) so lifecycle events can be received.
func startEvents() {
	if eventsErr = libvirt.EventRegisterDefaultImpl(); eventsErr != nil {
		return
	}
	go func() {
		for {
			if libvirt.EventRunDefaultImpl() != nil {
				time.Sleep(time.Second)
			}
		}
	}()
}

// Open connects read-write to the configured hypervisor. The URI must be one of the two allowed values.
func Open(uri string) (*Ops, error) {
	if uri != SystemURI && uri != TestURI {
		return nil, hypervisor.NewError(hypervisor.Prohibited, "open", "", "uri not allowed")
	}
	eventsOnce.Do(startEvents)
	c, err := libvirt.NewConnect(uri)
	if err != nil {
		return nil, mapErr("open", err)
	}
	return &Ops{conn: c, eventsErr: eventsErr}, nil
}

// Close releases the connection.
func (o *Ops) Close() {
	if o.conn != nil {
		_, _ = o.conn.Close()
	}
}

func mapErr(op string, err error) error {
	var lerr libvirt.Error
	if !errors.As(err, &lerr) {
		return hypervisor.NewError(hypervisor.HostError, op, "", "unexpected error")
	}
	switch lerr.Code {
	case libvirt.ERR_NO_DOMAIN, libvirt.ERR_NO_STORAGE_VOL, libvirt.ERR_NO_STORAGE_POOL, libvirt.ERR_NO_NETWORK:
		return hypervisor.NewError(hypervisor.NotFound, op, "", "not found")
	case libvirt.ERR_DOM_EXIST, libvirt.ERR_STORAGE_VOL_EXIST, libvirt.ERR_OPERATION_INVALID:
		return hypervisor.NewError(hypervisor.Conflict, op, "", "conflict")
	case libvirt.ERR_OPERATION_TIMEOUT:
		return hypervisor.NewError(hypervisor.Timeout, op, "", "libvirt timeout")
	case libvirt.ERR_NO_CONNECT, libvirt.ERR_SYSTEM_ERROR, libvirt.ERR_RPC, libvirt.ERR_INTERNAL_ERROR, libvirt.ERR_AUTH_FAILED, libvirt.ERR_OPERATION_DENIED:
		return hypervisor.NewError(hypervisor.Unavailable, op, "", "libvirt unavailable")
	case libvirt.ERR_XML_ERROR, libvirt.ERR_INVALID_ARG:
		return hypervisor.NewError(hypervisor.Validation, op, "", "rejected")
	default:
		return hypervisor.NewError(hypervisor.HostError, op, "", "libvirt error")
	}
}

func (o *Ops) diag(op string, err error) {
	if o.Diag != nil {
		o.Diag(op, err.Error())
	}
}

func ctxErr(ctx context.Context, op string) error {
	if ctx.Err() != nil {
		return hypervisor.NewError(hypervisor.Timeout, op, "", "cancelled")
	}
	return nil
}

// NetworkActive implements provision.HostOps.
func (o *Ops) NetworkActive(ctx context.Context, name string) (bool, error) {
	if err := ctxErr(ctx, "network"); err != nil {
		return false, err
	}
	n, err := o.conn.LookupNetworkByName(name)
	if err != nil {
		if e := mapErr("network", err); hypervisor.CategoryOf(e) == hypervisor.NotFound {
			return false, nil
		} else {
			return false, e
		}
	}
	defer func() { _ = n.Free() }()
	a, err := n.IsActive()
	if err != nil {
		return false, mapErr("network", err)
	}
	return a, nil
}

func (o *Ops) pool(name string) (*libvirt.StoragePool, error) {
	p, err := o.conn.LookupStoragePoolByName(name)
	if err != nil {
		return nil, mapErr("pool", err)
	}
	return p, nil
}

// PoolActive implements provision.HostOps.
func (o *Ops) PoolActive(ctx context.Context, name string) (bool, error) {
	if err := ctxErr(ctx, "pool"); err != nil {
		return false, err
	}
	p, err := o.pool(name)
	if err != nil {
		if hypervisor.CategoryOf(err) == hypervisor.NotFound {
			return false, nil
		}
		return false, err
	}
	defer func() { _ = p.Free() }()
	a, err := p.IsActive()
	if err != nil {
		return false, mapErr("pool", err)
	}
	return a, nil
}

// LookupDomain implements provision.HostOps.
func (o *Ops) LookupDomain(ctx context.Context, name string) (provision.DomainInfo, error) {
	if err := ctxErr(ctx, "lookup"); err != nil {
		return provision.DomainInfo{}, err
	}
	d, err := o.conn.LookupDomainByName(name)
	if err != nil {
		return provision.DomainInfo{}, mapErr("lookup", err)
	}
	defer func() { _ = d.Free() }()
	x, err := d.GetXMLDesc(0)
	if err != nil {
		return provision.DomainInfo{}, mapErr("lookup", err)
	}
	pd, perr := provision.ParseDomain(x)
	if perr != nil {
		return provision.DomainInfo{}, hypervisor.NewError(hypervisor.HostError, "lookup", "", "unreadable definition")
	}
	active, err := d.IsActive()
	if err != nil {
		return provision.DomainInfo{}, mapErr("lookup", err)
	}
	return provision.DomainInfo{Name: pd.Name, Data: pd.Data, Media: pd.Media, ISO: pd.ISO, ISOs: pd.ISOs, Graphics: pd.Graphics, Rescue: pd.Rescue, UUID: pd.UUID, Fingerprint: pd.Fingerprint, Managed: pd.Managed, Running: active, Root: pd.Root, Seed: pd.Seed, XML: x, VCPUs: pd.VCPUs, MemoryMiB: pd.MemoryMiB, ImageID: pd.ImageID}, nil
}

type volumeDoc struct {
	Type   string `xml:"type,attr"`
	Name   string `xml:"name"`
	Key    string `xml:"key"`
	Target struct {
		Path   string `xml:"path"`
		Format struct {
			Type string `xml:"type,attr"`
		} `xml:"format"`
	} `xml:"target"`
	Capacity struct {
		Unit  string `xml:"unit,attr"`
		Value int64  `xml:",chardata"`
	} `xml:"capacity"`
	Allocation struct {
		Unit  string `xml:"unit,attr"`
		Value int64  `xml:",chardata"`
	} `xml:"allocation"`
	Backing struct {
		Path string `xml:"path"`
	} `xml:"backingStore"`
}

// LookupVolume implements provision.HostOps.
func (o *Ops) LookupVolume(ctx context.Context, pool, name string) (provision.VolumeInfo, error) {
	if err := ctxErr(ctx, "lookup-volume"); err != nil {
		return provision.VolumeInfo{}, err
	}
	p, err := o.pool(pool)
	if err != nil {
		return provision.VolumeInfo{}, err
	}
	defer func() { _ = p.Free() }()
	v, err := p.LookupStorageVolByName(name)
	if err != nil {
		return provision.VolumeInfo{}, mapErr("lookup-volume", err)
	}
	defer func() { _ = v.Free() }()
	x, err := v.GetXMLDesc(0)
	if err != nil {
		return provision.VolumeInfo{}, mapErr("lookup-volume", err)
	}
	var d volumeDoc
	if xml.Unmarshal([]byte(x), &d) != nil || (d.Capacity.Unit != "" && d.Capacity.Unit != "bytes") {
		return provision.VolumeInfo{}, hypervisor.NewError(hypervisor.HostError, "lookup-volume", "", "unreadable volume")
	}
	info := provision.VolumeInfo{CapacityBytes: d.Capacity.Value, BackingPath: d.Backing.Path}
	if d.Allocation.Unit == "" || d.Allocation.Unit == "bytes" {
		info.AllocationBytes = d.Allocation.Value
	}
	o.placement(p, v, d, name, &info)
	return info, nil
}

type poolDoc struct {
	Type   string `xml:"type,attr"`
	Target struct {
		Path string `xml:"path"`
	} `xml:"target"`
}

// placement fills the filesystem facts of a file-backed volume (CT-PRODUCT-DELIVERY-009). It only ever REPORTS: any inconsistency
// (libvirt's own answers disagree, the volume is not a plain file volume of a file-backed pool, the path cannot be inspected) leaves
// the info without a trustworthy placement, and provision.ResolveRootSource refuses it. The path comes from libvirt, never from the
// caller, and is inspected without following a symlink.
func (o *Ops) placement(p *libvirt.StoragePool, v *libvirt.StorageVol, d volumeDoc, name string, info *provision.VolumeInfo) {
	path, err := v.GetPath()
	if err != nil || d.Name != name || d.Target.Path != path || (d.Key != "" && d.Key != path) || (d.Type != "" && d.Type != "file") {
		return
	}
	px, err := p.GetXMLDesc(0)
	var pd poolDoc
	if err != nil || xml.Unmarshal([]byte(px), &pd) != nil || (pd.Type != "dir" && pd.Type != "fs") {
		return
	}
	info.Name, info.Path, info.PoolPath = d.Name, path, pd.Target.Path
	lstat, canon := o.Lstat, o.Canonical
	if lstat == nil {
		lstat = os.Lstat
	}
	if canon == nil {
		canon = filepath.EvalSymlinks
	}
	fi, err := lstat(path)
	if err != nil {
		return // not inspectable here (for example the pool directory is not visible to this process): FSChecked stays false
	}
	real, err := canon(path)
	info.FSChecked = true
	info.Regular = fi.Mode().IsRegular()
	info.Symlink = fi.Mode()&os.ModeSymlink != 0
	info.Canonical = err == nil && real == path
}

func esc(s string) string {
	var b bytes.Buffer
	_ = xml.EscapeText(&b, []byte(s))
	return b.String()
}

// CreateRootVolume implements provision.HostOps: a qcow2 volume backed by the verified catalog image.
func (o *Ops) CreateRootVolume(ctx context.Context, pool, name string, capacity int64, backing string) error {
	if err := ctxErr(ctx, "create-volume"); err != nil {
		return err
	}
	p, err := o.pool(pool)
	if err != nil {
		return err
	}
	defer func() { _ = p.Free() }()
	x := fmt.Sprintf("<volume type='file'><name>%s</name><capacity unit='bytes'>%d</capacity><target><format type='qcow2'/></target>"+
		"<backingStore><path>%s</path><format type='qcow2'/></backingStore></volume>", esc(name), capacity, esc(backing))
	if backing == "" { // a blank disk for a VM installed from media (DR-023 D3)
		x = fmt.Sprintf("<volume type='file'><name>%s</name><capacity unit='bytes'>%d</capacity><target><format type='qcow2'/></target></volume>", esc(name), capacity)
	}
	v, err := p.StorageVolCreateXML(x, 0)
	if err != nil {
		return mapErr("create-volume", err)
	}
	_ = v.Free()
	return nil
}

// CreateDataVolume implements provision.HostOps: an empty qcow2 volume (DR-023 D2).
func (o *Ops) CreateDataVolume(ctx context.Context, pool, name string, capacity int64) error {
	if err := ctxErr(ctx, "create-volume"); err != nil {
		return err
	}
	if _, ok := provision.ParseDataVolumeName(name); !ok || capacity < 1 {
		return hypervisor.NewError(hypervisor.Validation, "create-volume", "", "name")
	}
	p, err := o.pool(pool)
	if err != nil {
		return err
	}
	defer func() { _ = p.Free() }()
	x := fmt.Sprintf("<volume type='file'><name>%s</name><capacity unit='bytes'>%d</capacity><target><format type='qcow2'/></target></volume>", esc(name), capacity)
	v, err := p.StorageVolCreateXML(x, 0)
	if err != nil {
		return mapErr("create-volume", err)
	}
	_ = v.Free()
	return nil
}

// AttachDataDisk implements provision.HostOps: the device is rendered from validated values and added to the persistent definition only.
func (o *Ops) AttachDataDisk(ctx context.Context, domain, volume, path, dev string) error {
	if err := ctxErr(ctx, "attach"); err != nil {
		return err
	}
	x, err := provision.DataDiskXML(volume, provision.VolumeSource{Name: provision.DataVolumeName(volume), Path: path, PoolPath: filepath.Dir(path)}, dev)
	if err != nil {
		return hypervisor.NewError(hypervisor.Validation, "attach", "", "device")
	}
	d, err := o.domain("attach", domain)
	if err != nil {
		return err
	}
	defer func() { _ = d.Free() }()
	if err := d.AttachDeviceFlags(x, libvirt.DOMAIN_DEVICE_MODIFY_CONFIG); err != nil {
		o.diag("attach", err)
		return mapErr("attach", err)
	}
	return nil
}

// DetachDataDisk implements provision.HostOps: the device to remove is rebuilt from the definition's own entry for the volume.
func (o *Ops) DetachDataDisk(ctx context.Context, domain, volume string) error {
	if err := ctxErr(ctx, "detach"); err != nil {
		return err
	}
	d, err := o.domain("detach", domain)
	if err != nil {
		return err
	}
	defer func() { _ = d.Free() }()
	cur, err := d.GetXMLDesc(libvirt.DOMAIN_XML_INACTIVE)
	if err != nil {
		return mapErr("detach", err)
	}
	pd, perr := provision.ParseDomain(cur)
	path, ok := provision.DataDiskPath(cur, volume)
	if perr != nil || !ok {
		return nil // not carried: nothing to detach
	}
	dev := ""
	for _, dd := range pd.Data {
		if dd.Volume == volume {
			dev = dd.Dev
		}
	}
	x, err := provision.DataDiskXML(volume, provision.VolumeSource{Name: provision.DataVolumeName(volume), Path: path, PoolPath: filepath.Dir(path)}, dev)
	if err != nil {
		return hypervisor.NewError(hypervisor.Validation, "detach", "", "device")
	}
	if err := d.DetachDeviceFlags(x, libvirt.DOMAIN_DEVICE_MODIFY_CONFIG); err != nil {
		o.diag("detach", err)
		return mapErr("detach", err)
	}
	return nil
}

// CreateSeedVolume implements provision.HostOps.
func (o *Ops) CreateSeedVolume(ctx context.Context, pool, name string, capacity int64) error {
	if err := ctxErr(ctx, "create-volume"); err != nil {
		return err
	}
	p, err := o.pool(pool)
	if err != nil {
		return err
	}
	defer func() { _ = p.Free() }()
	x := fmt.Sprintf("<volume><name>%s</name><capacity unit='bytes'>%d</capacity><target><format type='raw'/></target></volume>", esc(name), capacity)
	v, err := p.StorageVolCreateXML(x, 0)
	if err != nil {
		return mapErr("create-volume", err)
	}
	_ = v.Free()
	return nil
}

// UploadSeed implements provision.HostOps through libvirt's volume upload stream.
func (o *Ops) UploadSeed(ctx context.Context, pool, name string, iso []byte) error {
	if err := ctxErr(ctx, "upload"); err != nil {
		return err
	}
	p, err := o.pool(pool)
	if err != nil {
		return err
	}
	defer func() { _ = p.Free() }()
	v, err := p.LookupStorageVolByName(name)
	if err != nil {
		return mapErr("upload", err)
	}
	defer func() { _ = v.Free() }()
	st, err := o.conn.NewStream(0)
	if err != nil {
		return mapErr("upload", err)
	}
	if err := v.Upload(st, 0, uint64(len(iso)), 0); err != nil {
		_ = st.Free()
		var lerr libvirt.Error
		if o.SkipUploadUnsupported && errors.As(err, &lerr) && lerr.Code == libvirt.ERR_NO_SUPPORT {
			return nil
		}
		return mapErr("upload", err)
	}
	r := bytes.NewReader(iso)
	buf := make([]byte, 64<<10)
	for {
		n, rerr := r.Read(buf)
		if n > 0 {
			if _, err := st.Send(buf[:n]); err != nil {
				_ = st.Abort()
				_ = st.Free()
				return mapErr("upload", err)
			}
		}
		if errors.Is(rerr, io.EOF) {
			break
		}
	}
	if err := st.Finish(); err != nil {
		_ = st.Free()
		return mapErr("upload", err)
	}
	_ = st.Free()
	return nil
}

// DefineDomain implements provision.HostOps (persistent definition, not started).
func (o *Ops) DefineDomain(ctx context.Context, x string) error {
	if err := ctxErr(ctx, "define"); err != nil {
		return err
	}
	d, err := o.conn.DomainDefineXML(x)
	if err != nil {
		o.diag("define", err)
		return mapErr("define", err)
	}
	_ = d.Free()
	return nil
}

// StartDomain implements provision.HostOps.
func (o *Ops) StartDomain(ctx context.Context, name string) error {
	if err := ctxErr(ctx, "start"); err != nil {
		return err
	}
	d, err := o.conn.LookupDomainByName(name)
	if err != nil {
		return mapErr("start", err)
	}
	defer func() { _ = d.Free() }()
	if err := d.Create(); err != nil {
		o.diag("start", err)
		return mapErr("start", err)
	}
	return nil
}

func (o *Ops) domain(op, name string) (*libvirt.Domain, error) {
	d, err := o.conn.LookupDomainByName(name)
	if err != nil {
		return nil, mapErr(op, err)
	}
	return d, nil
}

// ShutdownDomain implements provision.HostOps: a guest-cooperative power-off request (ACPI), never a forced one.
func (o *Ops) ShutdownDomain(ctx context.Context, name string) error {
	if err := ctxErr(ctx, "shutdown"); err != nil {
		return err
	}
	d, err := o.domain("shutdown", name)
	if err != nil {
		return err
	}
	defer func() { _ = d.Free() }()
	err = d.ShutdownFlags(libvirt.DOMAIN_SHUTDOWN_ACPI_POWER_BTN)
	var lerr libvirt.Error
	if errors.As(err, &lerr) && (lerr.Code == libvirt.ERR_INVALID_ARG || lerr.Code == libvirt.ERR_NO_SUPPORT) {
		err = d.Shutdown() // a driver without the ACPI flag (the test driver): the hypervisor's default graceful shutdown
	}
	if err != nil {
		o.diag("shutdown", err)
		return mapErr("shutdown", err)
	}
	return nil
}

// RebootDomain implements provision.HostOps: a guest reboot request (ACPI), confirmed by libvirt's reboot lifecycle event. There is no
// destroy-and-start fallback. The event is the only honest observation: an ACPI reboot resets the machine inside the same QEMU
// process, so the domain id and the process do not change.
func (o *Ops) RebootDomain(ctx context.Context, name string, wait time.Duration) error {
	if err := ctxErr(ctx, "reboot"); err != nil {
		return err
	}
	if o.eventsErr != nil {
		return hypervisor.NewError(hypervisor.Unavailable, "reboot", "", "libvirt event loop unavailable") // nothing was sent
	}
	d, err := o.domain("reboot", name)
	if err != nil {
		return err
	}
	defer func() { _ = d.Free() }()
	seen := make(chan struct{}, 1)
	id, err := o.conn.DomainEventRebootRegister(d, func(*libvirt.Connect, *libvirt.Domain) {
		select {
		case seen <- struct{}{}:
		default:
		}
	})
	if err != nil {
		return hypervisor.NewError(hypervisor.Unavailable, "reboot", "", "cannot watch for the reboot") // nothing was sent
	}
	defer func() { _ = o.conn.DomainEventDeregister(id) }()
	if err := d.Reboot(libvirt.DOMAIN_REBOOT_ACPI_POWER_BTN); err != nil {
		o.diag("reboot", err)
		return mapErr("reboot", err)
	}
	t := time.NewTimer(wait)
	defer t.Stop()
	select {
	case <-seen:
		return nil
	case <-t.C:
	case <-ctx.Done():
	}
	return hypervisor.NewError(hypervisor.Timeout, "reboot", "", "the guest reset was not observed")
}

// DestroyDomain implements provision.HostOps: immediate power-off of the running domain (no storage is touched).
func (o *Ops) DestroyDomain(ctx context.Context, name string) error {
	if err := ctxErr(ctx, "destroy"); err != nil {
		return err
	}
	d, err := o.domain("destroy", name)
	if err != nil {
		return err
	}
	defer func() { _ = d.Free() }()
	if err := d.DestroyFlags(libvirt.DOMAIN_DESTROY_DEFAULT); err != nil {
		o.diag("destroy", err)
		return mapErr("destroy", err)
	}
	return nil
}

// UndefineDomain implements provision.HostOps. Only the persistent definition goes; no storage flag is passed.
func (o *Ops) UndefineDomain(ctx context.Context, name string) error {
	if err := ctxErr(ctx, "undefine"); err != nil {
		return err
	}
	d, err := o.domain("undefine", name)
	if err != nil {
		return err
	}
	defer func() { _ = d.Free() }()
	if err := d.UndefineFlags(0); err != nil {
		o.diag("undefine", err)
		return mapErr("undefine", err)
	}
	return nil
}

// DeleteVolume implements provision.HostOps.
func (o *Ops) DeleteVolume(ctx context.Context, pool, name string) error {
	if err := ctxErr(ctx, "delete-volume"); err != nil {
		return err
	}
	p, err := o.pool(pool)
	if err != nil {
		return err
	}
	defer func() { _ = p.Free() }()
	v, err := p.LookupStorageVolByName(name)
	if err != nil {
		return mapErr("delete-volume", err)
	}
	defer func() { _ = v.Free() }()
	if err := v.Delete(libvirt.STORAGE_VOL_DELETE_NORMAL); err != nil {
		o.diag("delete-volume", err)
		return mapErr("delete-volume", err)
	}
	return nil
}

// PoolStats implements provision.HostOps. The pool is refreshed first so the numbers are the host's current ones.
func (o *Ops) PoolStats(ctx context.Context, pool string) (provision.PoolStats, error) {
	if err := ctxErr(ctx, "pool-stats"); err != nil {
		return provision.PoolStats{}, err
	}
	p, err := o.pool(pool)
	if err != nil {
		return provision.PoolStats{}, err
	}
	defer func() { _ = p.Free() }()
	_ = p.Refresh(0) // best effort: a stale answer is still an answer
	info, err := p.GetInfo()
	if err != nil {
		return provision.PoolStats{}, mapErr("pool-stats", err)
	}
	ps := provision.PoolStats{CapacityBytes: int64(info.Capacity), AvailableBytes: int64(info.Available), AllocationBytes: int64(info.Allocation)} // #nosec G115 -- libvirt byte counts of a real pool
	if x, err := p.GetXMLDesc(0); err == nil {
		var d struct {
			Type string `xml:"type,attr"`
		}
		if xml.Unmarshal([]byte(x), &d) == nil {
			ps.Type = d.Type
		}
	}
	return ps, nil
}

// ListVolumes implements provision.HostOps.
func (o *Ops) ListVolumes(ctx context.Context, pool string) ([]string, error) {
	if err := ctxErr(ctx, "list-volumes"); err != nil {
		return nil, err
	}
	p, err := o.pool(pool)
	if err != nil {
		return nil, err
	}
	defer func() { _ = p.Free() }()
	names, err := p.ListStorageVolumes()
	if err != nil {
		return nil, mapErr("list-volumes", err)
	}
	return names, nil
}

// ResizeVolume implements provision.HostOps. Flags are 0: libvirt refuses to shrink and treats the value as the new absolute size.
func (o *Ops) ResizeVolume(ctx context.Context, pool, name string, capacity int64) error {
	if err := ctxErr(ctx, "resize"); err != nil {
		return err
	}
	if capacity <= 0 {
		return hypervisor.NewError(hypervisor.Validation, "resize", "", "size")
	}
	p, err := o.pool(pool)
	if err != nil {
		return err
	}
	defer func() { _ = p.Free() }()
	v, err := p.LookupStorageVolByName(name)
	if err != nil {
		return mapErr("resize", err)
	}
	defer func() { _ = v.Free() }()
	if err := v.Resize(uint64(capacity), 0); err != nil { // #nosec G115 -- positive, checked above
		o.diag("resize", err)
		return mapErr("resize", err)
	}
	return nil
}

type snapshotDoc struct {
	Name         string `xml:"name"`
	Description  string `xml:"description"`
	CreationTime int64  `xml:"creationTime"`
}

// ListSnapshots implements provision.HostOps.
func (o *Ops) ListSnapshots(ctx context.Context, domain string) ([]provision.SnapshotInfo, error) {
	if err := ctxErr(ctx, "snapshots"); err != nil {
		return nil, err
	}
	d, err := o.domain("snapshots", domain)
	if err != nil {
		return nil, err
	}
	defer func() { _ = d.Free() }()
	snaps, err := d.ListAllSnapshots(0)
	if err != nil {
		return nil, mapErr("snapshots", err)
	}
	var out []provision.SnapshotInfo
	for i := range snaps {
		x, xerr := snaps[i].GetXMLDesc(0)
		_ = snaps[i].Free()
		if xerr != nil {
			return nil, mapErr("snapshots", xerr)
		}
		var sd snapshotDoc
		if xml.Unmarshal([]byte(x), &sd) != nil || sd.Name == "" {
			return nil, hypervisor.NewError(hypervisor.HostError, "snapshots", "", "unreadable snapshot")
		}
		out = append(out, provision.SnapshotInfo{Name: sd.Name, Description: sd.Description, Created: sd.CreationTime})
	}
	return out, nil
}

// CreateSnapshot implements provision.HostOps: an internal snapshot of the stopped domain's disks (libvirt's default for an inactive domain).
func (o *Ops) CreateSnapshot(ctx context.Context, domain, name, description string) error {
	if err := ctxErr(ctx, "snapshot"); err != nil {
		return err
	}
	d, err := o.domain("snapshot", domain)
	if err != nil {
		return err
	}
	defer func() { _ = d.Free() }()
	x := fmt.Sprintf("<domainsnapshot><name>%s</name><description>%s</description></domainsnapshot>", esc(name), esc(description))
	s, err := d.CreateSnapshotXML(x, 0)
	if err != nil {
		o.diag("snapshot", err)
		return mapErr("snapshot", err)
	}
	_ = s.Free()
	return nil
}

func (o *Ops) snapshot(op, domain, name string) (*libvirt.DomainSnapshot, *libvirt.Domain, error) {
	d, err := o.domain(op, domain)
	if err != nil {
		return nil, nil, err
	}
	s, err := d.SnapshotLookupByName(name, 0)
	if err != nil {
		_ = d.Free()
		return nil, nil, mapErr(op, err)
	}
	return s, d, nil
}

// RevertSnapshot implements provision.HostOps.
func (o *Ops) RevertSnapshot(ctx context.Context, domain, name string) error {
	if err := ctxErr(ctx, "revert"); err != nil {
		return err
	}
	s, d, err := o.snapshot("revert", domain, name)
	if err != nil {
		return err
	}
	defer func() { _ = s.Free(); _ = d.Free() }()
	if err := s.RevertToSnapshot(0); err != nil {
		o.diag("revert", err)
		return mapErr("revert", err)
	}
	return nil
}

// DeleteSnapshot implements provision.HostOps.
func (o *Ops) DeleteSnapshot(ctx context.Context, domain, name string) error {
	if err := ctxErr(ctx, "delete-snapshot"); err != nil {
		return err
	}
	s, d, err := o.snapshot("delete-snapshot", domain, name)
	if err != nil {
		return err
	}
	defer func() { _ = s.Free(); _ = d.Free() }()
	if err := s.Delete(0); err != nil {
		o.diag("delete-snapshot", err)
		return mapErr("delete-snapshot", err)
	}
	return nil
}

// DownloadVolume implements provision.HostOps through libvirt's volume download stream.
func (o *Ops) DownloadVolume(ctx context.Context, pool, name string, w io.Writer) (int64, error) {
	if err := ctxErr(ctx, "download"); err != nil {
		return 0, err
	}
	p, err := o.pool(pool)
	if err != nil {
		return 0, err
	}
	defer func() { _ = p.Free() }()
	v, err := p.LookupStorageVolByName(name)
	if err != nil {
		return 0, mapErr("download", err)
	}
	defer func() { _ = v.Free() }()
	st, err := o.conn.NewStream(0)
	if err != nil {
		return 0, mapErr("download", err)
	}
	if err := v.Download(st, 0, 0, 0); err != nil {
		_ = st.Free()
		o.diag("download", err)
		return 0, mapErr("download", err)
	}
	var total int64
	buf := make([]byte, 256<<10)
	for {
		if ctx.Err() != nil {
			_ = st.Abort()
			_ = st.Free()
			return total, hypervisor.NewError(hypervisor.Timeout, "download", "", "cancelled")
		}
		n, rerr := st.Recv(buf)
		if errors.Is(rerr, io.EOF) && n == 0 {
			break // this binding reports the end of the stream as io.EOF; Finish below still confirms a clean end
		}
		if rerr != nil {
			_ = st.Abort()
			_ = st.Free()
			o.diag("download", rerr)
			return total, mapErr("download", rerr)
		}
		if n == 0 {
			break
		}
		if _, werr := w.Write(buf[:n]); werr != nil {
			_ = st.Abort()
			_ = st.Free()
			return total, hypervisor.NewError(hypervisor.HostError, "download", "", "write")
		}
		total += int64(n)
	}
	if err := st.Finish(); err != nil {
		_ = st.Free()
		return total, mapErr("download", err)
	}
	_ = st.Free()
	return total, nil
}

// UploadVolume implements provision.HostOps through libvirt's volume upload stream.
func (o *Ops) UploadVolume(ctx context.Context, pool, name string, r io.Reader, size int64) error {
	if err := ctxErr(ctx, "upload"); err != nil {
		return err
	}
	if size <= 0 {
		return hypervisor.NewError(hypervisor.Validation, "upload", "", "size")
	}
	p, err := o.pool(pool)
	if err != nil {
		return err
	}
	defer func() { _ = p.Free() }()
	v, err := p.LookupStorageVolByName(name)
	if err != nil {
		return mapErr("upload", err)
	}
	defer func() { _ = v.Free() }()
	st, err := o.conn.NewStream(0)
	if err != nil {
		return mapErr("upload", err)
	}
	if err := v.Upload(st, 0, uint64(size), 0); err != nil { // #nosec G115 -- positive, checked above
		_ = st.Free()
		var lerr libvirt.Error
		if o.SkipUploadUnsupported && errors.As(err, &lerr) && lerr.Code == libvirt.ERR_NO_SUPPORT {
			return nil
		}
		return mapErr("upload", err)
	}
	buf := make([]byte, 256<<10)
	var sent int64
	for sent < size {
		if ctx.Err() != nil {
			_ = st.Abort()
			_ = st.Free()
			return hypervisor.NewError(hypervisor.Timeout, "upload", "", "cancelled")
		}
		n, rerr := r.Read(buf[:min(int64(len(buf)), size-sent)])
		if n > 0 {
			off := 0
			for off < n {
				m, serr := st.Send(buf[off:n])
				if serr != nil {
					_ = st.Abort()
					_ = st.Free()
					return mapErr("upload", serr)
				}
				off += m
			}
			sent += int64(n)
		}
		if rerr != nil {
			if errors.Is(rerr, io.EOF) && sent == size {
				break
			}
			_ = st.Abort()
			_ = st.Free()
			return hypervisor.NewError(hypervisor.HostError, "upload", "", "read")
		}
	}
	if err := st.Finish(); err != nil {
		_ = st.Free()
		return mapErr("upload", err)
	}
	_ = st.Free()
	return nil
}
