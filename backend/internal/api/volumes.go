package api

import (
	"context"
	"net/http"
	"sort"
	"strings"
	"time"

	"example.invalid/dedicatedcloud/backend/internal/auth"
	"example.invalid/dedicatedcloud/backend/internal/hypervisor"
	"example.invalid/dedicatedcloud/backend/internal/operation"
)

// Volumes (M1-E02-S06, DR-023 D2): a VM's own root disk (read only, named "<vm>-root") and the standalone data volumes Svavyom created (named by their own
// name). Data volumes can be created, attached to and detached from a Stopped VM, and deleted, all as operations of kind Volume.

// volumeType is the subset of lifecycleType that acts on a data volume (kind Volume).
func volumeType(t operation.Type) bool {
	switch t {
	case operation.VolumeCreate, operation.VolumeAttach, operation.VolumeDetach, operation.VolumeDelete:
		return true
	}
	return false
}

// dataVolumes reads the standalone data volumes through the read-only agent. known is false when the reader cannot say.
func (h *Handler) dataVolumes(ctx context.Context) (vols []hypervisor.DataVolume, known bool, err error) {
	if h.deps.VMs == nil {
		return nil, false, nil
	}
	dr, ok := h.deps.VMs.(hypervisor.DataVolumeReader)
	if !ok {
		return nil, false, nil
	}
	v, err := dr.DataVolumes(ctx)
	return v, err == nil, err
}

func (h *Handler) volumeActionsOn() bool { return h.deps.Creation != nil && h.deps.Creation.Enabled }

// toDataVolume renders a standalone data volume. holder is the VM that carries it ("" when none).
func (h *Handler) toDataVolume(v hypervisor.DataVolume, holder *hypervisor.Domain, role auth.Role) volumeJSON {
	out := volumeJSON{ID: v.Name, ProjectID: defaultProject, Generation: 1, Name: v.Name, Allowed: []string{},
		Desired: volumeDesired{SizeGiB: int((v.CapacityBytes + (1 << 30) - 1) >> 30)}, Observed: volumeState{State: "available"}}
	if out.Desired.SizeGiB < 1 {
		out.Desired.SizeGiB = 1
	}
	var actions []string
	if holder != nil {
		name := holder.Name
		out.Desired.AttachedTo, out.Observed.State = &name, "attached"
		if holder.State == hypervisor.StateShutoff {
			actions = []string{"detach"}
		}
	} else {
		actions = []string{"attach", "delete"}
	}
	if h.volumeActionsOn() {
		out.Allowed = restrict(role, "Volume", actions)
	}
	return out
}

// holders maps each data volume name to the VM carrying it.
func holders(doms []hypervisor.Domain) map[string]*hypervisor.Domain {
	m := map[string]*hypervisor.Domain{}
	for i := range doms {
		for _, n := range doms[i].DataVolumes {
			m[n] = &doms[i]
		}
	}
	return m
}

func (h *Handler) listVolumes(w http.ResponseWriter, r *http.Request) {
	if !h.requireStorageSession(w, r) {
		return
	}
	for k, v := range r.URL.Query() {
		if len(v) != 1 || (k != "limit" && k != "cursor") || (k == "limit" && !limitRE.MatchString(v[0])) || k == "cursor" {
			h.reject(w, categoryValidation) // one page: no cursor can be valid
			return
		}
	}
	list, err := h.deps.VMs.List(r.Context())
	if err != nil {
		h.vmError(w, err)
		return
	}
	role := h.roleOf(r)
	items := []volumeJSON{}
	for _, d := range list {
		if v, ok := toVolume(d); ok {
			items = append(items, v)
		}
	}
	vols, _, derr := h.dataVolumes(r.Context())
	if derr != nil {
		h.vmError(w, derr)
		return
	}
	held := holders(list)
	sort.Slice(vols, func(i, j int) bool { return vols[i].Name < vols[j].Name })
	for _, v := range vols {
		if len(items) >= 200 {
			break // the contract's page bound; a host with more has its list cut here
		}
		items = append(items, h.toDataVolume(v, held[v.Name], role))
	}
	allowed := []string{}
	if h.volumeActionsOn() {
		allowed = restrict(role, "Volume", []string{"create"})
	}
	writeJSON(w, http.StatusOK, struct {
		Items   []volumeJSON `json:"items"`
		Allowed []string     `json:"allowed_actions"`
		Next    *string      `json:"next_cursor"`
	}{Items: items, Allowed: allowed})
}

func (h *Handler) readVolume(w http.ResponseWriter, r *http.Request) {
	if !h.requireStorageSession(w, r) {
		return
	}
	if len(r.URL.Query()) != 0 {
		h.reject(w, categoryValidation)
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/api/v1/volumes/")
	if !vmIDRE.MatchString(id) {
		h.reject(w, categoryNotFound)
		return
	}
	if vm, isRoot := strings.CutSuffix(id, "-root"); isRoot {
		if vm == "" {
			h.reject(w, categoryNotFound)
			return
		}
		d, err := h.deps.VMs.Lookup(r.Context(), vm)
		if err != nil {
			h.vmError(w, err)
			return
		}
		v, ok := toVolume(d)
		if !ok {
			h.reject(w, categoryNotFound)
			return
		}
		writeJSON(w, http.StatusOK, v)
		return
	}
	vols, _, derr := h.dataVolumes(r.Context())
	if derr != nil {
		h.vmError(w, derr)
		return
	}
	for _, v := range vols {
		if v.Name != id {
			continue
		}
		list, err := h.deps.VMs.List(r.Context())
		if err != nil {
			h.vmError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, h.toDataVolume(v, holders(list)[id], h.roleOf(r)))
		return
	}
	h.reject(w, categoryNotFound)
}

// volumePrechecks are the early, friendly answers for a volume operation; the mutation helper re-proves ownership and state before it acts.
func (h *Handler) volumePrechecks(w http.ResponseWriter, r *http.Request, req operation.Request) bool {
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	vols, known, err := h.dataVolumes(ctx)
	if err != nil || !known {
		h.reject(w, categoryUnavailable)
		return false
	}
	doms, err := h.deps.VMs.List(ctx)
	if err != nil {
		h.reject(w, categoryUnavailable)
		return false
	}
	exists := false
	for _, v := range vols {
		exists = exists || v.Name == req.ResourceID
	}
	holder := holders(doms)[req.ResourceID]
	switch req.Type {
	case operation.VolumeCreate:
		if exists {
			h.reject(w, categoryConflict)
			return false
		}
		if h.poolShort(ctx) {
			h.reject(w, categoryConflict)
			return false
		}
		return true
	case operation.VolumeAttach:
		switch {
		case !exists:
			h.reject(w, categoryNotFound)
			return false
		case holder != nil:
			h.reject(w, categoryConflict)
			return false
		}
		var vm *hypervisor.Domain
		for i := range doms {
			if doms[i].Name == req.Params.VMID {
				vm = &doms[i]
			}
		}
		switch {
		case vm == nil:
			h.reject(w, categoryNotFound)
			return false
		case !vm.Managed:
			h.reject(w, categoryProhibited)
			return false
		case vm.State != hypervisor.StateShutoff || len(vm.DataVolumes) >= 8:
			h.reject(w, categoryConflict)
			return false
		}
	case operation.VolumeDetach:
		switch {
		case !exists:
			h.reject(w, categoryNotFound)
			return false
		case holder == nil || holder.State != hypervisor.StateShutoff:
			h.reject(w, categoryConflict)
			return false
		}
	case operation.VolumeDelete:
		switch {
		case !exists:
			h.reject(w, categoryNotFound)
			return false
		case holder != nil:
			h.reject(w, categoryConflict)
			return false
		}
	}
	return true
}

// poolShort reports whether the pool is known to have less than the reserve a new volume needs (an empty qcow2 is thin; the host keeps a reserve).
func (h *Handler) poolShort(ctx context.Context) bool {
	cr := h.deps.Creation
	if cr == nil || cr.Stats == nil {
		return false
	}
	st, err := cr.Stats(ctx)
	return err == nil && st.PoolAvailable > 0 && st.PoolAvailable < 256<<20
}
