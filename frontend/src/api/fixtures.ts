// TEST-ONLY typed fixtures for the browser-api shapes (M0-E01-S04, DR-012). Each builder returns a value of a
// generated type, so `tsc` checks the shape; src/api/conformance.test.ts validates every one of them against the
// schema at runtime. Never imported by production code (tools/check_frontend.py checks the bundle).
import type { ApiError, ErrorCategory, Host, Operation, VM, VMList } from "./schema";

/** No usage samples yet: the shape every Host and VM carries when the sampler has nothing to report. */
export const NO_HOST_USAGE: Host["observed"]["usage"] = { state: "unavailable", interval_seconds: 30, cpu_percent: null, memory_used_mib: null, disk_kib_s: null, net_kib_s: null, history: [] };
export const NO_VM_USAGE: VM["observed"]["usage"] = { state: "unavailable", cpu_percent: null, memory_used_mib: null, disk_kib_s: null, net_kib_s: null, history: [] };
/** The size and usage fields of a VM nothing is known about. */
export const NO_BACKUP: VM["observed"]["backup"] = { next_run_at: null, last_run: null };
export const NO_SIZE = { vcpus: null, memory_mib: null, iso: null, usage: NO_VM_USAGE, backup: NO_BACKUP, graphical_console: "absent", rescue: false } as const;

export const HOST: Host = {
  id: "local", generation: 1, name: "local-host", desired: { maintenance: false },
  observed: {
    reachable: true, agent_version: "0.0.0-dev", cpu_count: 8, memory_mib: 16384, capability_verdict: "supported",
    virtualization: { hardware: "available", kvm_device: "available", libvirt_packages: "available", qemu_packages: "available" },
    distribution: { id: "debian", version_id: "13" }, capability_findings: [], usage: NO_HOST_USAGE, alerts: { open: 0, webhook: "none" }, nightly_boot: null, bridge: null,
    creation: { enabled: false, network: "unknown", storage: "unknown", vcpu_options: [], memory_mib_options: [], disk_gib_options: [], ready: false, reasons: ["mutation_disabled"] },
    storage: { state: "unknown", pool_total_gib: null, pool_free_gib: null, images_gib: null, backups_configured: false, backups_gib: null, backups_free_gib: null, snapshots: "unknown", backup_targets: [], allocation_note: "Disk sizes shown for a VM are virtual sizes. Real usage is lower while the disk is thinly allocated; the pool free figure is what counts." },
  },
  allowed_actions: [],
};

export const VM_RUNNING: VM = {
  id: "vm-a", project_id: "default", generation: 3, name: "web-1", desired: { power: "running", backup_schedule: null },
  observed: { power: "running", last_seen_at: "2026-10-08T10:00:00Z", managed: false, ip_address: null, login_user: null, disk_gib: null, snapshots: [], network: null, vcpus: null, memory_mib: null, iso: null, usage: NO_VM_USAGE, backup: NO_BACKUP, graphical_console: "absent", rescue: false }, allowed_actions: ["start", "stop", "delete"],
};

export const vm = (overrides: Partial<VM> = {}): VM => ({ ...VM_RUNNING, ...overrides });

export const vmList = (items: VM[] = [VM_RUNNING], allowed_actions: VMList["allowed_actions"] = []): VMList =>
  ({ items, allowed_actions, next_cursor: null });

export const operation = (overrides: Partial<Operation> = {}): Operation => ({
  id: "op-1", project_id: "default", resource_kind: "VM", resource_id: "vm-a", type: "start", status: "pending",
  requested_by: "owner", generation: 1, attempts: 0, error_category: null,
  created_at: "2026-10-08T10:00:00Z", updated_at: "2026-10-08T10:00:00Z", allowed_actions: ["cancel"], ...overrides,
});

const RETRYABLE: ReadonlySet<ErrorCategory> = new Set(["rate_limited", "unavailable", "timeout"]);
export const CORRELATION_ID = "0123456789abcdef0123456789abcdef";

/** The error envelope for a category: `retryable` is fixed per category (errors.json). */
export const apiError = (category: ErrorCategory, correlation_id = CORRELATION_ID): ApiError =>
  ({ category, retryable: RETRYABLE.has(category), correlation_id });
