package api

import (
	"net/http"
	"slices"

	"example.invalid/dedicatedcloud/backend/internal/auth"
	"example.invalid/dedicatedcloud/backend/internal/operation"
)

// Roles (DR-023 D1). viewer reads everything and cannot submit an operation or open the serial console. operator may also do the VM, volume,
// snapshot, backup, restore, reinstall, compute and address operations and use the console. admin may also manage networks and delete a backup.
// The browser is shown only the actions its role may take; the server enforces the same rule on every submit.

// roleMay reports whether role may submit an operation of this type on this kind.
func roleMay(role auth.Role, t operation.Type, k string) bool {
	switch {
	case role.AtLeast(auth.RoleAdmin):
		return true
	case !role.AtLeast(auth.RoleOperator):
		return false
	}
	if networkType(t) {
		return false
	}
	if k == operation.KindBackup && t == operation.Delete {
		return false
	}
	return true
}

// roleOf resolves the caller's role again from the session cookie ("" when there is no valid session).
func (h *Handler) roleOf(r *http.Request) auth.Role {
	if h.deps.Auth == nil {
		return ""
	}
	sess, _, ok, failed := h.session(r)
	if failed || !ok {
		return ""
	}
	return sess.Role
}

// restrict drops the actions role may not take on a resource of this kind ("VM", "Volume", "Backup", "VirtualNetwork", or "collection" for the create action).
func restrict(role auth.Role, kind string, allowed []string) []string {
	out := []string{}
	for _, a := range allowed {
		switch {
		case role.AtLeast(auth.RoleAdmin):
			out = append(out, a)
		case !role.AtLeast(auth.RoleOperator):
		case kind == "VirtualNetwork":
		case kind == "Backup" && a == "delete":
		case kind == "NetworkCollection":
		default:
			out = append(out, a)
		}
	}
	return slices.Clip(out)
}
