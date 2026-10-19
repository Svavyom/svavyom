package api

import (
	"context"
	"net/http"
	"regexp"
	"time"

	"example.invalid/dedicatedcloud/backend/internal/hostinfo"
	"example.invalid/dedicatedcloud/backend/internal/metrics"
)

// hostJSON is the Host schema. hostinfo.Info is the only source, so a field not listed here cannot leave the process.
type hostJSON struct {
	ID         string       `json:"id"`
	Generation int          `json:"generation"`
	Name       string       `json:"name"`
	Desired    hostDesired  `json:"desired"`
	Observed   hostObserved `json:"observed"`
	Allowed    []string     `json:"allowed_actions"`
}

type hostDesired struct {
	Maintenance bool `json:"maintenance"`
}

type hostObserved struct {
	Reachable          bool           `json:"reachable"`
	AgentVersion       string         `json:"agent_version"`
	CPUCount           int            `json:"cpu_count"`
	MemoryMiB          int64          `json:"memory_mib"`
	CapabilityVerdict  string         `json:"capability_verdict"`
	Virtualization     virtualization `json:"virtualization"`
	Distribution       distribution   `json:"distribution"`
	Creation           creationJSON   `json:"creation"`
	Storage            storageJSON    `json:"storage"`
	Usage              hostUsageJSON  `json:"usage"`
	Alerts             hostAlertsJSON `json:"alerts"`
	NightlyBoot        *nightlyJSON   `json:"nightly_boot"`
	Bridge             *bridgeJSON    `json:"bridge"`
	CapabilityFindings []finding      `json:"capability_findings"`
}

type virtualization struct {
	Hardware        string `json:"hardware"`
	KVMDevice       string `json:"kvm_device"`
	LibvirtPackages string `json:"libvirt_packages"`
	QEMUPackages    string `json:"qemu_packages"`
}

type distribution struct {
	ID        string `json:"id"`
	VersionID string `json:"version_id"`
}

type finding struct {
	Code        string `json:"code"`
	Remediation string `json:"remediation"`
}

type hostUsageJSON struct {
	State           string          `json:"state"`
	IntervalSeconds int             `json:"interval_seconds"`
	CPUPercent      *int            `json:"cpu_percent"`
	MemoryUsedMiB   *int64          `json:"memory_used_mib"`
	DiskKiBs        *int64          `json:"disk_kib_s"`
	NetKiBs         *int64          `json:"net_kib_s"`
	History         []hostPointJSON `json:"history"`
}

type hostPointJSON struct {
	At            string `json:"at"`
	CPUPercent    int    `json:"cpu_percent"`
	MemoryUsedMiB int64  `json:"memory_used_mib"`
	DiskKiBs      int64  `json:"disk_kib_s"`
	NetKiBs       int64  `json:"net_kib_s"`
}

func toHostUsage(u metrics.HostUsage) hostUsageJSON {
	out := hostUsageJSON{State: "unavailable", IntervalSeconds: u.IntervalSeconds, CPUPercent: u.CPUPercent, MemoryUsedMiB: u.MemUsedMiB, DiskKiBs: u.DiskKiBs, NetKiBs: u.NetKiBs, History: []hostPointJSON{}}
	if out.IntervalSeconds < 1 {
		out.IntervalSeconds = int(metrics.DefaultInterval.Seconds())
	}
	if u.Available {
		out.State = "available"
	}
	for _, p := range u.History {
		out.History = append(out.History, hostPointJSON{At: p.At.UTC().Format(time.RFC3339), CPUPercent: p.CPUPercent, MemoryUsedMiB: p.MemUsedMiB, DiskKiBs: p.DiskKiBs, NetKiBs: p.NetKiBs})
	}
	return out
}

func (h *Handler) hostUsage(ctx context.Context) hostUsageJSON {
	if h.deps.Usage == nil {
		return toHostUsage(metrics.HostUsage{})
	}
	return toHostUsage(h.deps.Usage.Host(ctx))
}

func toHostJSON(i hostinfo.Info, creation creationJSON, storage storageJSON, usage hostUsageJSON, extra []FirewallFinding, al hostAlertsJSON, nb *nightlyJSON, br *bridgeJSON) hostJSON {
	fs := make([]finding, 0, len(i.Findings)+len(extra))
	for _, f := range i.Findings {
		fs = append(fs, finding{Code: f.Code, Remediation: f.Remediation})
	}
	for _, f := range extra {
		if len(fs) < 16 {
			fs = append(fs, finding(f))
		}
	}
	return hostJSON{
		ID: i.ID, Generation: 1, Name: i.Name, Allowed: []string{},
		Observed: hostObserved{
			Reachable: true, AgentVersion: i.AgentVersion, CPUCount: i.CPUCount, MemoryMiB: i.MemoryMiB, CapabilityVerdict: i.Verdict,
			Virtualization: virtualization{Hardware: string(i.Hardware), KVMDevice: string(i.KVMDevice),
				LibvirtPackages: string(i.LibvirtPackages), QEMUPackages: string(i.QEMUPackages)},
			Distribution:       distribution{ID: i.DistroID, VersionID: i.DistroVersion},
			Creation:           creation,
			Storage:            storage,
			Usage:              usage,
			Alerts:             al,
			NightlyBoot:        nb,
			Bridge:             br,
			CapabilityFindings: fs,
		},
	}
}

var limitRE = regexp.MustCompile(`^(?:[1-9][0-9]?|1[0-9]{2}|200)$`)

// requireSession answers 401/503 itself and reports whether the caller may proceed.
func (h *Handler) requireSession(w http.ResponseWriter, r *http.Request) bool {
	if h.deps.Auth == nil || h.deps.Hosts == nil {
		h.reject(w, categoryUnauthenticated)
		return false
	}
	_, _, ok, failed := h.session(r)
	switch {
	case failed:
		h.reject(w, categoryUnavailable)
	case !ok:
		h.reject(w, categoryUnauthenticated)
	}
	return ok
}

func (h *Handler) listHosts(w http.ResponseWriter, r *http.Request) {
	if !h.requireSession(w, r) {
		return
	}
	q := r.URL.Query()
	for k, v := range q {
		if len(v) != 1 || (k != "limit" && k != "cursor") || (k == "limit" && !limitRE.MatchString(v[0])) || k == "cursor" {
			// There is exactly one host, so a cursor can never be valid.
			h.reject(w, categoryValidation)
			return
		}
	}
	info, err := h.deps.Hosts.Host(r.Context())
	if err != nil {
		h.reject(w, categoryUnavailable)
		return
	}
	writeJSON(w, http.StatusOK, struct {
		Items   []hostJSON `json:"items"`
		Allowed []string   `json:"allowed_actions"`
		Next    *string    `json:"next_cursor"`
	}{Items: []hostJSON{toHostJSON(info, h.creationFor(r.Context(), info), h.storageFor(r.Context()), h.hostUsage(r.Context()), h.firewallFindings(), h.hostAlerts(r.Context()), h.nightlyBoot(), h.hostBridge())}, Allowed: []string{}})
}

func (h *Handler) readHost(w http.ResponseWriter, r *http.Request) {
	if !h.requireSession(w, r) {
		return
	}
	if len(r.URL.Query()) != 0 {
		h.reject(w, categoryValidation)
		return
	}
	info, err := h.deps.Hosts.Host(r.Context())
	if err != nil {
		h.reject(w, categoryUnavailable)
		return
	}
	if r.PathValue("id") != "" || r.URL.Path != "/api/v1/hosts/"+info.ID {
		h.reject(w, categoryNotFound)
		return
	}
	writeJSON(w, http.StatusOK, toHostJSON(info, h.creationFor(r.Context(), info), h.storageFor(r.Context()), h.hostUsage(r.Context()), h.firewallFindings(), h.hostAlerts(r.Context()), h.nightlyBoot(), h.hostBridge()))
}

func (h *Handler) firewallFindings() []FirewallFinding {
	if h.deps.Firewall == nil {
		return nil
	}
	return h.deps.Firewall()
}
