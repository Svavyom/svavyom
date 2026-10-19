package simhost

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"strings"
	"time"

	"example.invalid/dedicatedcloud/backend/internal/hypervisor"
	"example.invalid/dedicatedcloud/backend/internal/provision"
)

// Overlay builds the bytes of a minimal but REAL qcow2 version-3 overlay header (magic, version, backing-file name, cluster bits, virtual size,
// no encryption, no snapshots) followed by a payload derived from tag, so the production header parser accepts it. The simulation uses it as
// the content of a root volume.
func Overlay(backing string, virtual int64, tag string) []byte {
	h := make([]byte, 112)
	copy(h, []byte{'Q', 'F', 'I', 0xfb})
	binary.BigEndian.PutUint32(h[4:], 3)
	binary.BigEndian.PutUint64(h[8:], 112)                   // backing_file_offset
	binary.BigEndian.PutUint32(h[16:], uint32(len(backing))) // #nosec G115 -- a short path
	binary.BigEndian.PutUint32(h[20:], 16)                   // cluster_bits
	binary.BigEndian.PutUint64(h[24:], uint64(virtual))      // #nosec G115 -- positive
	return append(append(h, []byte(backing)...), []byte("\nPAYLOAD:"+tag)...)
}

// setVirtual rewrites the virtual size inside an Overlay header.
func setVirtual(data []byte, virtual int64) {
	if len(data) >= 32 {
		binary.BigEndian.PutUint64(data[24:], uint64(virtual)) // #nosec G115 -- positive
	}
}

// parseOverlayHeader returns (virtual size, backing path) of an Overlay or a real qcow2 header.
func parseOverlayHeader(data []byte) (int64, string, bool) {
	o, err := provision.ParseOverlay(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return 0, "", false
	}
	return int64(o.VirtualSize), o.BackingPath, true // #nosec G115 -- bounded by ParseOverlay
}

// SetPayload replaces the payload of a root volume (guest data written after the overlay was made), keeping its header.
func (h *Host) SetPayload(pool, name, payload string) error {
	return h.update(func(st *State) error {
		k := pool + "/" + name
		v, ok := st.Volumes[k]
		if !ok || len(v.Data) < 112 {
			return nf("payload")
		}
		i := bytes.Index(v.Data, []byte("\nPAYLOAD:"))
		if i < 0 {
			return nf("payload")
		}
		v.Data = append(append([]byte(nil), v.Data[:i]...), []byte("\nPAYLOAD:"+payload)...)
		st.Volumes[k] = v
		return nil
	})
}

// Payload returns the payload of a root volume ("" when it has none).
func (h *Host) Payload(pool, name string) string {
	v, ok := h.Load().Volumes[pool+"/"+name]
	if !ok {
		return ""
	}
	i := bytes.Index(v.Data, []byte("\nPAYLOAD:"))
	if i < 0 {
		return ""
	}
	return string(v.Data[i+len("\nPAYLOAD:"):])
}

// PoolStats implements provision.HostOps.
func (h *Host) PoolStats(_ context.Context, pool string) (provision.PoolStats, error) {
	st := h.Load()
	capacity := st.PoolCapacity
	if capacity == 0 {
		capacity = 1 << 40
	}
	var used int64
	for k, v := range st.Volumes {
		if strings.HasPrefix(k, pool+"/") {
			used += int64(len(v.Data)) + int64(v.SeedLen)
		}
	}
	avail := capacity - used
	if st.PoolAvailable != 0 {
		avail = st.PoolAvailable
	}
	return provision.PoolStats{CapacityBytes: capacity, AvailableBytes: avail, AllocationBytes: used, Type: "dir"}, nil
}

// ListVolumes implements provision.HostOps.
func (h *Host) ListVolumes(_ context.Context, pool string) ([]string, error) {
	var out []string
	for k := range h.Load().Volumes {
		if n, ok := strings.CutPrefix(k, pool+"/"); ok {
			out = append(out, n)
		}
	}
	return out, nil
}

// ResizeVolume implements provision.HostOps: grow only, like libvirt without the shrink flag.
func (h *Host) ResizeVolume(_ context.Context, pool, name string, capacity int64) error {
	return h.update(func(st *State) error {
		k := pool + "/" + name
		v, ok := st.Volumes[k]
		if !ok {
			return nf("resize")
		}
		if capacity < v.Capacity {
			return hypervisor.NewError(hypervisor.Conflict, "resize", "", "shrink")
		}
		v.Capacity = capacity
		setVirtual(v.Data, capacity)
		st.Volumes[k] = v
		return nil
	})
}

// ListSnapshots implements provision.HostOps.
func (h *Host) ListSnapshots(_ context.Context, domain string) ([]provision.SnapshotInfo, error) {
	st := h.Load()
	if _, ok := st.Domains[domain]; !ok {
		return nil, nf("snapshots")
	}
	var out []provision.SnapshotInfo
	for _, s := range st.Snapshots[domain] {
		out = append(out, provision.SnapshotInfo{Name: s.Name, Description: s.Description, Created: s.Created})
	}
	return out, nil
}

// rootKey finds the root volume key of a domain in the simulation.
func rootKey(st *State, d Domain) (string, bool) {
	for k := range st.Volumes {
		if strings.HasSuffix(k, "/"+d.Root) {
			return k, true
		}
	}
	return "", false
}

// CreateSnapshot implements provision.HostOps: refuses a running domain and a duplicate name, like libvirt.
func (h *Host) CreateSnapshot(_ context.Context, domain, name, description string) error {
	return h.update(func(st *State) error {
		d, ok := st.Domains[domain]
		if !ok {
			return nf("snapshot")
		}
		if d.Running {
			return hypervisor.NewError(hypervisor.Conflict, "snapshot", "", "running")
		}
		for _, s := range st.Snapshots[domain] {
			if s.Name == name {
				return hypervisor.NewError(hypervisor.Conflict, "snapshot", "", "exists")
			}
		}
		k, ok := rootKey(st, d)
		if !ok {
			return nf("snapshot")
		}
		v := st.Volumes[k]
		st.Snapshots[domain] = append(st.Snapshots[domain], Snapshot{Name: name, Description: description, Created: time.Now().Unix(), Volume: k,
			Data: append([]byte(nil), v.Data...), Capacity: v.Capacity})
		return nil
	})
}

// RevertSnapshot implements provision.HostOps: the root volume returns to the snapshot's content and size.
func (h *Host) RevertSnapshot(_ context.Context, domain, name string) error {
	return h.update(func(st *State) error {
		d, ok := st.Domains[domain]
		if !ok {
			return nf("revert")
		}
		if d.Running {
			return hypervisor.NewError(hypervisor.Conflict, "revert", "", "running")
		}
		for _, s := range st.Snapshots[domain] {
			if s.Name == name {
				v := st.Volumes[s.Volume]
				v.Data, v.Capacity = append([]byte(nil), s.Data...), s.Capacity
				st.Volumes[s.Volume] = v
				return nil
			}
		}
		return nf("revert")
	})
}

// DeleteSnapshot implements provision.HostOps.
func (h *Host) DeleteSnapshot(_ context.Context, domain, name string) error {
	return h.update(func(st *State) error {
		if _, ok := st.Domains[domain]; !ok {
			return nf("delete-snapshot")
		}
		list := st.Snapshots[domain]
		for i, s := range list {
			if s.Name == name {
				st.Snapshots[domain] = append(append([]Snapshot(nil), list[:i]...), list[i+1:]...)
				return nil
			}
		}
		return nf("delete-snapshot")
	})
}

// DownloadVolume implements provision.HostOps.
func (h *Host) DownloadVolume(_ context.Context, pool, name string, w io.Writer) (int64, error) {
	v, ok := h.Load().Volumes[pool+"/"+name]
	if !ok {
		return 0, nf("download")
	}
	n, err := w.Write(v.Data)
	return int64(n), err
}

// UploadVolume implements provision.HostOps: the volume takes the uploaded bytes; its virtual size and backing path follow the qcow2 header,
// as libvirt reports them after an upload.
func (h *Host) UploadVolume(_ context.Context, pool, name string, r io.Reader, size int64) error {
	data, err := io.ReadAll(io.LimitReader(r, size+1))
	if err != nil || int64(len(data)) != size {
		return hypervisor.NewError(hypervisor.HostError, "upload", "", "size")
	}
	return h.update(func(st *State) error {
		k := pool + "/" + name
		v, ok := st.Volumes[k]
		if !ok {
			return nf("upload")
		}
		v.Data = data
		if virt, backing, ok := parseOverlayHeader(data); ok {
			v.Capacity, v.Backing = virt, backing
		}
		st.Volumes[k] = v
		return nil
	})
}
