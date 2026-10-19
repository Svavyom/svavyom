// Words for operations, shared by the dashboard card and the Activity page.
import type { Operation } from "../api/schema";

export const OP_LABEL: Record<Operation["type"], string> = {
  create: "Create", start: "Start", stop: "Stop", reboot: "Reboot", force_off: "Force off", delete: "Delete", resize: "Resize disk", reinstall: "Reinstall",
  snapshot: "Snapshot", restore_snapshot: "Restore snapshot", delete_snapshot: "Delete snapshot", backup: "Back up", restore: "Restore",
  network_create: "Create network", network_start: "Start network", network_stop: "Stop network", network_autostart: "Network autostart", network_delete: "Delete network",
  compute: "Change size", reserve_ip: "Reserve address", release_ip: "Release address",
  eject_iso: "Eject installation media", backup_export: "Copy backup off the host", volume_create: "Create volume", volume_attach: "Attach volume", volume_detach: "Detach volume", volume_delete: "Delete volume",
  graphics_enable: "Enable graphical console", iso_attach: "Attach installation media", rescue: "Start rescue mode", unrescue: "Leave rescue mode",
  alert_acknowledge: "Acknowledge alert", schedule_set: "Set backup schedule", schedule_clear: "Clear backup schedule",
};
export const OP_STATUS: Record<Operation["status"], { text: string; tone: "ok" | "warn" | "bad" | "neutral" }> = {
  pending: { text: "Queued", tone: "warn" }, running: { text: "Running", tone: "warn" }, succeeded: { text: "Done", tone: "ok" }, failed: { text: "Failed", tone: "bad" },
  retryable_failure: { text: "Retrying", tone: "warn" }, cancelled: { text: "Cancelled", tone: "neutral" },
};


/** What a failed operation's closed category means to a person. */
export const OP_FAILURE: Record<NonNullable<Operation["error_category"]>, string> = {
  validation: "The request was not valid.", unauthenticated: "The session had ended.", forbidden: "The role of the person who asked does not allow it.",
  not_found: "The resource was not there.", conflict: "The resource was not in a state this applies to.", rate_limited: "Too many requests at once.",
  prohibited: "Svavyom does not do this.", unavailable: "The host service was not available.", timeout: "The host did not answer in time.",
  host_error: "The host refused or failed the step.", internal: "An internal error. The service log has the correlation details.",
};
