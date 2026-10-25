// Shared submit-and-follow logic for the lifecycle and the storage/recovery actions (VM list and Storage view). One idempotency key per
// intent (the type, target and every parameter): pressing the same button again after an unknown outcome reuses it, so the server can
// recognise the replay; changing a parameter is a different request and gets a new key. Failure wording is from closed categories only.
import { useRef, useState } from "react";
import { newIdempotencyKey } from "../api/client";
import { submitOperation } from "../api/session";
import type { Operation } from "../api/schema";

export interface Intent { type: string; kind: "VM" | "Backup" | "VirtualNetwork" | "Volume" | "Event"; id: string; params?: Record<string, unknown> }

const REFUSED: Record<string, string> = {
  conflict: "The resource is no longer in a state this action applies to (for example the VM is running, has snapshots, or a name is taken). Refresh and check.",
  prohibited: "This action is not available here (it may not be enabled, or backups are not configured on this host).",
  validation: "Some details were not accepted. Check them and try again.",
  not_found: "The target no longer exists. Refresh the list.",
  forbidden: "The request was refused. Reload the page and sign in again if this persists.",
};

// Wording that is specific to an operation, still from closed categories only (DR-031). Anything not listed here uses REFUSED.
const REFUSED_BY_TYPE: Record<string, Record<string, string>> = {
  iso_attach: {
    conflict: "Two installation media are attached already, or this one is: eject one first, and make sure the VM is stopped and not in rescue mode.",
    validation: "A second medium is only attached, it does not boot. Eject the first one to boot from this one.",
  },
  eject_iso: {
    conflict: "That medium is no longer attached, or the VM is running or in rescue mode. Refresh and check.",
    validation: "Two media are attached: choose which one to eject.",
  },
};

export function useRunner(onSessionEnded: () => void, onDone: () => void) {
  const keys = useRef<Map<string, string>>(new Map());
  const [op, setOp] = useState<{ id: string; target: string } | null>(null);
  const [finished, setFinished] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [pending, setPending] = useState<string | null>(null);
  const sig = (i: Intent) => JSON.stringify([i.type, i.kind, i.id, i.params ?? null]);

  async function run(i: Intent): Promise<boolean> {
    setError(null);
    setFinished(false);
    const s = sig(i);
    setPending(`${i.id}:${i.type}`);
    if (!keys.current.has(s)) keys.current.set(s, newIdempotencyKey());
    const body: Record<string, unknown> = { type: i.type, kind: i.kind, id: i.id, idempotency_key: keys.current.get(s) };
    if (i.params) body.params = i.params;
    const r = await submitOperation(body);
    setPending(null);
    if (r.kind === "ok") { setOp({ id: r.data.id, target: i.id }); return true; }
    if (r.kind === "unreachable") { setError("Svavyom could not confirm that the request arrived. Refresh to see whether it took effect; submitting again is safe."); return false; }
    if (r.category === "unauthenticated") { onSessionEnded(); return false; }
    keys.current.delete(s);
    setError(REFUSED_BY_TYPE[i.type]?.[r.category] ?? REFUSED[r.category] ?? "The action could not be started. Try again later.");
    return false;
  }

  function finish(o: Operation) {
    setFinished(true);
    if (o.status === "succeeded") for (const [k] of keys.current) if (k.includes(JSON.stringify(o.resource_id)) && k.includes(JSON.stringify(o.type))) keys.current.delete(k);
    onDone();
  }

  return { run, finish, op, finished, error, pending, busy: op !== null && !finished };
}
