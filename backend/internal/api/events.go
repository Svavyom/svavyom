package api

import (
	"context"
	"encoding/base64"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"example.invalid/dedicatedcloud/backend/internal/alerts"
	"example.invalid/dedicatedcloud/backend/internal/auth"
	"example.invalid/dedicatedcloud/backend/internal/operation"
)

// AlertSource is the alert store as the API sees it (read only; the alert engine is the only writer, and an acknowledgement is an operation).
type AlertSource interface {
	List(ctx context.Context, state string, limit int, after string) ([]alerts.Alert, bool, error)
	ByID(ctx context.Context, id string) (alerts.Alert, bool, error)
	Open(ctx context.Context) ([]alerts.Alert, error)
}

// AlertsView is what the API needs of the alert subsystem. A nil Source reports no alerts.
type AlertsView struct {
	Source AlertSource
	// Webhook reports whether the operator configured a webhook (the address itself is never exposed).
	Webhook bool
}

// eventJSON is the Event schema (an alert).
type eventJSON struct {
	ID           string   `json:"id"`
	ProjectID    string   `json:"project_id"`
	Type         string   `json:"type"`
	ResourceKind string   `json:"resource_kind"`
	ResourceID   string   `json:"resource_id"`
	Severity     string   `json:"severity"`
	State        string   `json:"state"`
	Value        *int     `json:"value"`
	CreatedAt    string   `json:"created_at"`
	UpdatedAt    string   `json:"updated_at"`
	Allowed      []string `json:"allowed_actions"`
}

type hostAlertsJSON struct {
	Open    int    `json:"open"`
	Webhook string `json:"webhook"`
}

func toEventJSON(a alerts.Alert, role auth.Role, actionsOn bool) eventJSON {
	allowed := []string{}
	if actionsOn && a.State == alerts.StateOpen && role.AtLeast(auth.RoleOperator) {
		allowed = append(allowed, "acknowledge")
	}
	return eventJSON{ID: a.ID, ProjectID: defaultProject, Type: a.Type, ResourceKind: a.Kind, ResourceID: a.ResourceID, Severity: a.Severity, State: a.State,
		Value: a.Value, CreatedAt: a.CreatedAt.UTC().Format(time.RFC3339), UpdatedAt: a.UpdatedAt.UTC().Format(time.RFC3339), Allowed: allowed}
}

func (h *Handler) alertActionsOn() bool { return h.deps.Creation != nil && h.deps.Creation.Enabled }

// hostAlerts is Host.observed.alerts.
func (h *Handler) hostAlerts(ctx context.Context) hostAlertsJSON {
	out := hostAlertsJSON{Webhook: "none"}
	v := h.deps.Alerts
	if v == nil {
		return out
	}
	if v.Webhook {
		out.Webhook = "configured"
	}
	if v.Source != nil {
		if open, err := v.Source.Open(ctx); err == nil {
			for _, a := range open {
				if a.State == alerts.StateOpen {
					out.Open++
				}
			}
		}
	}
	return out
}

func (h *Handler) listEvents(w http.ResponseWriter, r *http.Request) {
	if h.deps.Auth == nil {
		h.reject(w, categoryUnauthenticated)
		return
	}
	sess, _, ok, failed := h.session(r)
	switch {
	case failed:
		h.reject(w, categoryUnavailable)
		return
	case !ok:
		h.reject(w, categoryUnauthenticated)
		return
	}
	limit, after := defaultPageSize, ""
	for k, v := range r.URL.Query() {
		if len(v) != 1 {
			h.reject(w, categoryValidation)
			return
		}
		switch k {
		case "limit":
			if !limitRE.MatchString(v[0]) {
				h.reject(w, categoryValidation)
				return
			}
			limit, _ = strconv.Atoi(v[0])
		case "cursor":
			raw, err := base64.RawURLEncoding.DecodeString(v[0])
			if !cursorRE.MatchString(v[0]) || err != nil || !alerts.ValidID(string(raw)) {
				h.reject(w, categoryValidation)
				return
			}
			after = string(raw)
		default:
			h.reject(w, categoryValidation)
			return
		}
	}
	items := []eventJSON{}
	var next *string
	if v := h.deps.Alerts; v != nil && v.Source != nil {
		page, more, err := v.Source.List(r.Context(), "", limit, after)
		if err != nil {
			h.reject(w, categoryUnavailable)
			return
		}
		for _, a := range page {
			items = append(items, toEventJSON(a, sess.Role, h.alertActionsOn()))
		}
		if more && len(page) > 0 {
			c := base64.RawURLEncoding.EncodeToString([]byte(page[len(page)-1].ID))
			next = &c
		}
	}
	writeJSON(w, http.StatusOK, struct {
		Items   []eventJSON `json:"items"`
		Allowed []string    `json:"allowed_actions"`
		Next    *string     `json:"next_cursor"`
	}{Items: items, Allowed: []string{}, Next: next})
}

func (h *Handler) readEvent(w http.ResponseWriter, r *http.Request) {
	if h.deps.Auth == nil {
		h.reject(w, categoryUnauthenticated)
		return
	}
	sess, _, ok, failed := h.session(r)
	switch {
	case failed:
		h.reject(w, categoryUnavailable)
		return
	case !ok:
		h.reject(w, categoryUnauthenticated)
		return
	}
	if len(r.URL.Query()) != 0 {
		h.reject(w, categoryValidation)
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/api/v1/events/")
	if !alerts.ValidID(id) || h.deps.Alerts == nil || h.deps.Alerts.Source == nil {
		h.reject(w, categoryNotFound)
		return
	}
	a, found, err := h.deps.Alerts.Source.ByID(r.Context(), id)
	switch {
	case err != nil:
		h.reject(w, categoryUnavailable)
	case !found:
		h.reject(w, categoryNotFound)
	default:
		writeJSON(w, http.StatusOK, toEventJSON(a, sess.Role, h.alertActionsOn()))
	}
}

// alertPrechecks answers an acknowledge request for an alert that does not exist or is already resolved, before anything is stored.
func (h *Handler) alertPrechecks(w http.ResponseWriter, r *http.Request, req operation.Request) bool {
	if h.deps.Alerts == nil || h.deps.Alerts.Source == nil || !alerts.ValidID(req.ResourceID) {
		h.reject(w, categoryNotFound)
		return false
	}
	a, found, err := h.deps.Alerts.Source.ByID(r.Context(), req.ResourceID)
	switch {
	case err != nil:
		h.reject(w, categoryUnavailable)
		return false
	case !found:
		h.reject(w, categoryNotFound)
		return false
	case a.State == alerts.StateResolved:
		h.reject(w, categoryConflict)
		return false
	}
	return true
}

type nightlyJSON struct {
	At      string `json:"at"`
	Result  string `json:"result"`
	Seconds int    `json:"seconds"`
}

type bridgeJSON struct {
	State       string `json:"state"`
	Bridge      string `json:"bridge"`
	Interface   string `json:"interface"`
	SecondsLeft *int   `json:"seconds_left"`
}

var bridgeNameRE = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9_.:-]{0,14}$`)

// hostBridge is Host.observed.bridge: the recorded state, or null when no bridge work is in progress. Anything outside the closed vocabulary is hidden.
func (h *Handler) hostBridge() *bridgeJSON {
	if h.deps.Bridge == nil {
		return nil
	}
	b := h.deps.Bridge()
	if b == nil || !bridgeNameRE.MatchString(b.Bridge) || !bridgeNameRE.MatchString(b.Interface) {
		return nil
	}
	switch b.State {
	case "planned", "active":
		return &bridgeJSON{State: b.State, Bridge: b.Bridge, Interface: b.Interface}
	case "pending_confirmation":
		left := 0
		if b.SecondsLeft != nil && *b.SecondsLeft > 0 {
			left = *b.SecondsLeft
		}
		if left > 3600 {
			return nil
		}
		return &bridgeJSON{State: b.State, Bridge: b.Bridge, Interface: b.Interface, SecondsLeft: &left}
	}
	return nil
}

// nightlyBoot is Host.observed.nightly_boot.
func (h *Handler) nightlyBoot() *nightlyJSON {
	if h.deps.NightlyBoot == nil {
		return nil
	}
	r := h.deps.NightlyBoot()
	if r == nil || (r.Result != "pass" && r.Result != "fail" && r.Result != "skipped") || r.Seconds < 0 || r.Seconds > 86400 {
		return nil
	}
	return &nightlyJSON{At: r.At.UTC().Format(time.RFC3339), Result: r.Result, Seconds: r.Seconds}
}
