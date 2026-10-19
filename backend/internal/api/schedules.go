package api

import (
	"context"
	"net/http"
	"time"

	"example.invalid/dedicatedcloud/backend/internal/hypervisor"
	"example.invalid/dedicatedcloud/backend/internal/operation"
)

// schedulePrechecks gives early answers for schedule_set and schedule_clear before anything is stored. The scheduler checks the same again when it
// runs, so these are not the safety net.
func (h *Handler) schedulePrechecks(w http.ResponseWriter, r *http.Request, req operation.Request) bool {
	if h.deps.Schedules == nil {
		h.reject(w, categoryProhibited) // no scheduler on this installation
		return false
	}
	if req.Type == operation.ScheduleClear {
		return true // clearing what is not there, or what belongs to a VM that is gone, is harmless
	}
	if h.deps.VMs == nil {
		h.reject(w, categoryUnavailable)
		return false
	}
	d, err := h.deps.VMs.Lookup(r.Context(), req.ResourceID)
	switch hypervisor.CategoryOf(err) {
	case "":
	case hypervisor.NotFound:
		h.reject(w, categoryNotFound)
		return false
	default:
		h.reject(w, categoryUnavailable)
		return false
	}
	if !d.Managed {
		h.reject(w, categoryProhibited) // not created by Svavyom: not ours to stop and back up
		return false
	}
	if t := req.Params.TargetID; t != "" {
		if !h.targetDeclared(r.Context(), t) {
			h.reject(w, categoryValidation) // only a target the operator declared
			return false
		}
	}
	return true
}

// targetDeclared reports whether the operator declared the off-host target.
func (h *Handler) targetDeclared(ctx context.Context, id string) bool {
	cr := h.deps.Creation
	if cr == nil || cr.Targets == nil {
		return false
	}
	cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	ts, err := cr.Targets(cctx)
	if err != nil && len(ts) == 0 {
		return false
	}
	for _, t := range ts {
		if t.ID == id {
			return true
		}
	}
	return false
}
