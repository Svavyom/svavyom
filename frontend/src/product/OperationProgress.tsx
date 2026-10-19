// Operation progress (VM create / start): polls the typed operation endpoint and shows queued, working, checking, retrying and
// the safe typed outcome. It never shows server text; the reason comes from the closed error category.
import { useEffect, useRef, useState } from "react";
import { Alert, StatusMessage } from "../design-system";
import { read } from "../api/client";
import { decodeOperation } from "../api/decoders";
import type { Operation } from "../api/schema";

export interface Described { label: string; tone: "progress" | "success" | "failure"; terminal: boolean; detail: string | null }

const FAILURE_TEXT: Record<string, string> = {
  conflict: "The host holds a resource that conflicts with this action, or the VM is not in the right state. Nothing was overwritten or removed.",
  unavailable: "The host was not ready (its network or storage is unavailable). Nothing was changed.",
  validation: "The host did not accept the request. Nothing was changed.",
  not_found: "The VM could not be found on the host.",
  host_error: "The host reported a failure, or its answer could not be trusted. Check the VM list before trying again.",
  forbidden: "This action is not permitted.",
  prohibited: "This action is not available.",
  internal: "Something went wrong inside Svavyom.",
};

export function describeOperation(op: Pick<Operation, "type" | "status" | "attempts" | "error_category"> & { resource_kind?: Operation["resource_kind"] }): Described {
  const backupDelete = op.type === "delete" && op.resource_kind === "Backup";
  const verb = backupDelete ? "Deleting the backup" : ({ create: "Creating the VM", start: "Starting the VM", stop: "Waiting for the guest to shut down", reboot: "Asking the guest to reboot",
    force_off: "Powering the VM off", delete: "Deleting the VM and its disks", resize: "Growing the root disk", reinstall: "Reinstalling the VM from the image",
    snapshot: "Taking a snapshot", restore_snapshot: "Restoring the snapshot", delete_snapshot: "Deleting the snapshot", backup: "Copying the disk to the backup store",
    restore: "Restoring the backup as a new VM", network_create: "Creating the network", network_start: "Starting the network", network_stop: "Stopping the network",
    network_autostart: "Changing autostart", network_delete: "Deleting the network", compute: "Changing the VM's size", reserve_ip: "Reserving the address",
    release_ip: "Releasing the address", volume_create: "Creating the data volume", volume_attach: "Attaching the data volume", volume_detach: "Detaching the data volume",
    volume_delete: "Deleting the data volume", eject_iso: "Ejecting the installation media", backup_export: "Copying the backup to the target and checking it there", graphics_enable: "Adding the graphical console devices", iso_attach: "Attaching the installation media", rescue: "Putting the VM in rescue mode", unrescue: "Taking the VM out of rescue mode", alert_acknowledge: "Acknowledging the alert", schedule_set: "Saving the backup schedule", schedule_clear: "Clearing the backup schedule" } as Record<string, string>)[op.type] ?? "Working";
  switch (op.status) {
    case "pending": return { label: "Queued", tone: "progress", terminal: false, detail: null };
    case "running":
      return op.error_category === "timeout"
        ? { label: "Checking the host", tone: "progress", terminal: false, detail: "The host did not answer in time. Svavyom is looking at its state before doing anything else." }
        : { label: verb, tone: "progress", terminal: false, detail: null };
    case "retryable_failure":
      return { label: `Retrying (attempt ${op.attempts})`, tone: "progress", terminal: false,
        detail: op.error_category === "unavailable" ? "The host was not ready; Svavyom will try again."
          : op.type === "stop" ? "The guest has not powered off. Svavyom will not force it off; use Force off if you want that." : null };
    case "succeeded": return { label: backupDelete ? "Backup deleted" : ({ create: "VM created (stopped)", start: "VM started", stop: "VM stopped", reboot: "VM rebooted", force_off: "VM powered off", delete: "VM deleted",
      resize: "Root disk grown (the guest's partition and filesystem are not changed)", reinstall: "VM reinstalled (stopped)", snapshot: "Snapshot taken", restore_snapshot: "Snapshot restored",
      delete_snapshot: "Snapshot deleted", backup: "Backup complete", restore: "Backup restored as a new VM (stopped)",
      network_create: "Network created and started", network_start: "Network started", network_stop: "Network stopped", network_autostart: "Autostart changed", network_delete: "Network deleted",
      compute: "Size changed (applies when the VM next starts)", reserve_ip: "Address reserved (a VM that already has a lease keeps it until it expires)", release_ip: "Reservation released",
      volume_create: "Data volume created (empty)", volume_attach: "Volume attached (it appears when the VM next starts)", volume_detach: "Volume detached (its data is kept)", volume_delete: "Volume deleted", eject_iso: "Installation media ejected (the VM boots from its disk)", backup_export: "Backup copied off the host and verified there", graphics_enable: "Graphical console enabled (it is available once the VM runs)", iso_attach: "Media attached (it takes effect when the VM next starts)", rescue: "Rescue mode set (start the VM to boot the rescue system)", unrescue: "Left rescue mode (the definition is as it was)", alert_acknowledge: "Alert acknowledged", schedule_set: "Backup schedule saved", schedule_clear: "Backup schedule cleared" } as Record<string, string>)[op.type] ?? "Done", tone: "success", terminal: true, detail: null };
    case "cancelled": return { label: "Cancelled", tone: "failure", terminal: true, detail: null };
    default: return { label: "Failed", tone: "failure", terminal: true, detail: FAILURE_TEXT[op.error_category ?? ""] ?? "The operation did not complete." };
  }
}

/** The final (or any single) state of an operation, without polling. */
export function OperationStatus({ op }: { op: Operation }) {
  const d = describeOperation(op);
  return (
    <section aria-label="Operation result" aria-live="polite">
      {d.tone === "failure" ? <Alert title={d.label}>{d.detail ? <p>{d.detail}</p> : null}</Alert> : <StatusMessage tone="success">{d.label}</StatusMessage>}
    </section>
  );
}

export function OperationProgress(props: { id: string; intervalMs?: number; onDone: (op: Operation) => void; onSessionEnded: () => void }) {
  const [op, setOp] = useState<Operation | null>(null);
  const [lost, setLost] = useState(false);
  const done = useRef(props.onDone);
  const ended = useRef(props.onSessionEnded);
  done.current = props.onDone;
  ended.current = props.onSessionEnded;

  useEffect(() => {
    let alive = true;
    let timer: ReturnType<typeof setTimeout> | undefined;
    const tick = async () => {
      const r = await read(`/api/v1/operations/${props.id}`, decodeOperation);
      if (!alive) return;
      if (r.kind === "ok") {
        setLost(false);
        setOp(r.data);
        if (describeOperation(r.data).terminal) { done.current(r.data); return; }
      } else if (r.kind === "error" && r.category === "unauthenticated") {
        ended.current();
        return;
      } else {
        setLost(true); // keep polling: the operation continues on the server whatever the browser sees
      }
      timer = setTimeout(() => { void tick(); }, props.intervalMs ?? 1000);
    };
    void tick();
    return () => { alive = false; if (timer) clearTimeout(timer); };
  }, [props.id, props.intervalMs]);

  const d = op ? describeOperation(op) : { label: "Queued", tone: "progress" as const, terminal: false, detail: null };
  return (
    <section aria-label="Operation progress" aria-live="polite">
      {d.tone === "failure" ? (
        <Alert title={d.label}>{d.detail ? <p>{d.detail}</p> : null}</Alert>
      ) : (
        <StatusMessage tone={d.tone === "success" ? "success" : "warning"}>{d.label}{d.detail ? `. ${d.detail}` : ""}</StatusMessage>
      )}
      {lost ? <p>Svavyom cannot be reached right now. The operation keeps running on the host; this page keeps checking.</p> : null}
    </section>
  );
}
