// TEST-ONLY journey skeletons J1-J10 (M0-E02-S06 r5 section 1): compositions of design-system primitives, one
// per catalogue step, driven by schema-conformant fixtures through the real client (src/api/client.ts). Never in the
// production build; not product views; M1-E04 stories must pass the same keyboard paths against the real API.
import { useEffect, useRef, useState } from "react";
import {
  Button, Checkbox, ConfirmDestructive, DataTable, Dialog, EmptyState, ErrorState, ErrorSummary, LoadingRegion,
  OutcomeUnknown, RadioGroup, StaleNotice, StatusMessage, TextField, UnreachableBanner, ViewHeading, Link,
} from "../design-system";
import { mutate, newIdempotencyKey, read, type MutationResult, type ReadResult } from "../api/client";
import { OPERATION_STATUS_LABEL, operationFlags, type ErrorCategory, type OperationStatus } from "../api/errors";
import { decodeHost, decodeOperation, decodeVm, decodeVmList } from "../api/decoders";
import type { Operation, VM as Vm } from "../api/schema";

const ID_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$/;

/** One idempotency key per user intent (r5 section 6, review M3): the same key is reused only when the same
 *  payload is retried after `outcome_unknown`; a changed payload or a definitive outcome starts a new intent. */
function useIntentKeys() {
  const ref = useRef<Map<string, string>>(new Map());
  return {
    keyFor(payload: Record<string, unknown>): string {
      const sig = JSON.stringify(payload);
      // Keys of intents still in outcome_unknown are kept, so retrying any of them later reuses its key
      // (review cycle 2 N1); a definitive outcome removes the key in settle().
      if (!ref.current.has(sig)) ref.current.set(sig, newIdempotencyKey());
      return ref.current.get(sig)!;
    },
    settle(payload: Record<string, unknown>, result: MutationResult<unknown>) {
      if (result.kind !== "outcome_unknown") ref.current.delete(JSON.stringify(payload));
    },
  };
}

/** Read with last-known data: a failed refresh keeps data visible and marks it stale (r5 section 7). */
function useRead<T>(path: string) {
  const [state, setState] = useState<{ loading: boolean; result: ReadResult<T> | null; last: T | null; lastAt: Date | null }>(
    { loading: true, result: null, last: null, lastAt: null });
  const load = async (decode: (v: unknown) => T | null) => {
    setState((s) => ({ ...s, loading: true }));
    const r = await read(path, decode);
    setState((s) => r.kind === "ok"
      ? { loading: false, result: r, last: r.data, lastAt: new Date() }
      : { ...s, loading: false, result: r });
  };
  return { state, load };
}

function Failure({ result, onRetry }: { result: ReadResult<unknown> | null; onRetry: () => void }) {
  if (!result || result.kind === "ok") return null;
  if (result.kind === "unreachable") return null; // rendered by the caller with last-known data (J8)
  return result.category === "unauthenticated"
    ? <AuthNotConfigured />
    : <ErrorState category={result.category} correlationId={result.correlationId} onRetry={onRetry} onRecover={() => { location.hash = "#/"; }} recoverLabel="Back to the journey index" />;
}

/** J2 M0 state; also how any 401 renders in M0 (D5 = A, DR-012). */
function AuthNotConfigured() {
  return (
    <StatusMessage tone="warning">
      Authentication not configured. Sign-in does not exist yet in this development build, so no account actions are available.
    </StatusMessage>
  );
}

export function J1HostStatus() {
  const { state, load } = useRead("/api/v1/hosts/local");
  useEffect(() => { void load(decodeHost); }, []);
  const host = state.last as ReturnType<typeof decodeHost>;
  return (
    <>
      <ViewHeading title="Host status" />
      {state.result?.kind === "unreachable" ? <UnreachableBanner lastKnown={state.lastAt} onRetry={() => load(decodeHost)} /> : null}
      <Failure result={state.result} onRetry={() => load(decodeHost)} />
      <LoadingRegion label="Host status" loading={state.loading && !host}>
        {host ? (
          <section aria-labelledby="host-heading">
            <h2 id="host-heading">{host.name}</h2>
            {state.result && state.result.kind !== "ok" && state.lastAt ? <StaleNotice lastUpdated={state.lastAt} now={new Date()} /> : null}
            <p>Distribution check: <strong>{host.observed.capability_verdict}</strong>. Qualification: none (matrix conformance only; not host qualification).</p>
            <p>Agent reachable: {host.observed.reachable ? "yes" : "no"}.</p>
          </section>
        ) : null}
      </LoadingRegion>
      <div className="ds-button-row"><Button onClick={() => load(decodeHost)}>Refresh</Button></div>
    </>
  );
}

export function J2AuthState() {
  const { state, load } = useRead("/api/v1/projects");
  useEffect(() => { void load(() => null); }, []);
  return (
    <>
      <ViewHeading title="Account" />
      {state.loading ? <LoadingRegion label="Account" loading /> : null}
      {state.result?.kind === "unreachable" ? <UnreachableBanner lastKnown={null} onRetry={() => load(() => null)} /> : null}
      {state.result && state.result.kind !== "unreachable" ? (state.result.kind === "error" && state.result.category !== "unauthenticated"
        ? <Failure result={state.result} onRetry={() => load(() => null)} /> : <AuthNotConfigured />) : null}
      <p><Link href="#/">Back to the journey index</Link></p>
    </>
  );
}

export function J3Dashboard() {
  const { state, load } = useRead("/api/v1/vms");
  const [paused, setPaused] = useState(false);
  useEffect(() => { void load(decodeVmList); }, []);
  const list = state.last as ReturnType<typeof decodeVmList>;
  return (
    <>
      <ViewHeading title="Dashboard" />
      {state.result?.kind === "unreachable" ? <UnreachableBanner lastKnown={state.lastAt} onRetry={() => load(decodeVmList)} /> : null}
      <Failure result={state.result} onRetry={() => load(decodeVmList)} />
      {/* No automatic refresh exists; updates are manual, and the pause control is visible (2.2.2). */}
      <Checkbox label="Pause updates" checked={paused} onChange={setPaused} />
      <div className="ds-button-row"><Button onClick={() => load(decodeVmList)} disabled={paused}>Refresh</Button></div>
      <LoadingRegion label="VMs" loading={state.loading && !list}>
        {list && state.result && state.result.kind !== "ok" && state.lastAt ? <StaleNotice lastUpdated={state.lastAt} now={new Date()} /> : null}
        {list && list.items.length === 0 ? (
          <EmptyState title="No VMs" reason={list.allowed_actions.includes("create")
            ? "There are no VMs in this project yet." : "There are no VMs in this project, and you are not allowed to create one."}
            action={list.allowed_actions.includes("create") ? <Button variant="primary" onClick={() => { location.hash = "#/journey/J4"; }}>Create VM</Button> : undefined} />
        ) : null}
        {list && list.items.length > 0 ? (
          <DataTable caption="VMs" rows={list.items} rowKey={(v) => v.id} columns={[
            { header: "Name", cell: (v: Vm) => <a className="ds-link" href={`#/journey/J7?vm=${encodeURIComponent(v.id)}`}>{v.name}</a>, rowHeader: true },
            { header: "Observed power", cell: (v: Vm) => v.observed.power },
          ]} />
        ) : null}
      </LoadingRegion>
    </>
  );
}

export function J4Wizard() {
  const [name, setName] = useState("");
  const [image, setImage] = useState("");
  const [step, setStep] = useState<"form" | "review" | "done">("form");
  const [errors, setErrors] = useState<Array<{ fieldId: string; message: string }>>([]);
  const [pending, setPending] = useState(false);
  const [result, setResult] = useState<MutationResult<Operation> | null>(null);
  const keys = useIntentKeys();
  const reviewRef = useRef<HTMLHeadingElement>(null);
  const cont = () => {
    const e = [];
    if (!ID_RE.test(name)) e.push({ fieldId: "vm-name", message: "Enter a VM name using letters, digits, dot, dash or underscore" });
    if (!image) e.push({ fieldId: "image-debian-13", message: "Choose an image" });
    setErrors(e);
    if (e.length === 0) {
      setStep("review");
      setTimeout(() => reviewRef.current?.focus(), 0);
    }
  };
  const submit = async () => {
    if (pending) return;
    const payload = { type: "create", kind: "VM", id: name };
    const intent = { ...payload, image }; // the intent includes every user choice, even ones not yet in the body
    setPending(true);
    const r = await mutate("/api/v1/operations", payload, keys.keyFor(intent), decodeOperation);
    keys.settle(intent, r);
    setPending(false);
    setResult(r);
    if (r.kind === "ok") setStep("done");
  };
  return (
    <>
      <ViewHeading title="Create a VM" />
      {step === "form" ? (
        <form noValidate onSubmit={(e) => { e.preventDefault(); cont(); }}>
          <ErrorSummary errors={errors} />
          <TextField id="vm-name" label="VM name" required value={name} onChange={setName}
            description="Letters, digits, dot, dash and underscore; up to 63 characters."
            error={errors.find((x) => x.fieldId === "vm-name")?.message} />
          <RadioGroup legend="Image" name="image" value={image} onChange={setImage}
            options={[{ value: "debian-13", label: "Debian 13" }, { value: "ubuntu-24.04", label: "Ubuntu 24.04" }]}
            error={errors.find((x) => x.fieldId === "image-debian-13")?.message} />
          <div className="ds-button-row"><Button type="submit" variant="primary">Continue to review</Button></div>
        </form>
      ) : null}
      {step === "review" ? (
        <section aria-labelledby="review-heading">
          <h2 id="review-heading" ref={reviewRef} tabIndex={-1}>Review</h2>
          <p>Name: {name}. Image: {image}.</p>
          {result?.kind === "outcome_unknown" ? <OutcomeUnknown onCheckStatus={() => { location.hash = "#/journey/J5"; }} /> : null}
          {result?.kind === "error" ? <ErrorState category={result.category} correlationId={result.correlationId} onRetry={submit} /> : null}
          <div className="ds-button-row">
            <Button variant="primary" pending={pending} onClick={submit}>Create VM</Button>
            <Button onClick={() => setStep("form")}>Back</Button>
          </div>
        </section>
      ) : null}
      {step === "done" && result?.kind === "ok" ? (
        <StatusMessage focusOnMount>
          Request accepted. <a className="ds-link" href={`#/journey/J5/operations/${encodeURIComponent(result.data.id)}`}>Follow operation {result.data.id}</a>
        </StatusMessage>
      ) : null}
    </>
  );
}

export function J5Operation({ id }: { id: string | null }) {
  const path = id ? `/api/v1/operations/${id}` : null;
  const [state, setState] = useState<{ loading: boolean; result: ReadResult<Operation> | null; last: Operation | null; lastAt: Date | null }>(
    { loading: Boolean(path), result: null, last: null, lastAt: null });
  const load = async () => {
    if (!path || !ID_RE.test(id!)) return;
    setState((s) => ({ ...s, loading: true }));
    const r = await read(path, decodeOperation);
    setState((s) => r.kind === "ok" ? { loading: false, result: r, last: r.data, lastAt: new Date() } : { ...s, loading: false, result: r });
  };
  useEffect(() => { void load(); }, [id]);
  if (!id || !ID_RE.test(id)) {
    return (
      <>
        <ViewHeading title="Operation" />
        <StatusMessage tone="warning">No operation id is known for this request. Check recent operations (not available in M0; owned by M1-E04-S03).</StatusMessage>
      </>
    );
  }
  const op = state.last;
  const flags = op ? operationFlags(op.status as OperationStatus) : null;
  return (
    <>
      <ViewHeading title={`Operation ${id}`} />
      {state.result?.kind === "unreachable" ? <UnreachableBanner lastKnown={state.lastAt} onRetry={load} /> : null}
      {state.result?.kind === "error" ? <Failure result={state.result} onRetry={load} /> : null}
      {state.result && state.result.kind !== "ok" && state.lastAt ? <StaleNotice lastUpdated={state.lastAt} now={new Date()} /> : null}
      <LoadingRegion label="Operation" loading={state.loading && !op}>
        {op && flags ? (
          <dl>
            <dt>Status</dt><dd data-status={op.status}>{OPERATION_STATUS_LABEL[op.status as OperationStatus]}</dd>
            <dt>Finished</dt><dd>{flags.terminal ? "Yes" : "No"}</dd>
            <dt>Will be retried</dt><dd>{!flags.terminal && flags.retryable ? "Yes" : "No"}</dd>
          </dl>
        ) : null}
      </LoadingRegion>
      <div className="ds-button-row"><Button onClick={load}>Refresh status</Button></div>
    </>
  );
}

export function J6Errors() {
  const { state, load } = useRead("/api/v1/vms/vm-x");
  useEffect(() => { void load(decodeVm); }, []);
  return (
    <>
      <ViewHeading title="VM details" />
      {state.loading ? <LoadingRegion label="VM" loading /> : null}
      {state.result?.kind === "unreachable" ? <UnreachableBanner lastKnown={state.lastAt} onRetry={() => load(decodeVm)} /> : null}
      <Failure result={state.result} onRetry={() => load(decodeVm)} />
      {state.result?.kind === "ok" ? <p>VM {(state.last as Vm).name} loaded.</p> : null}
    </>
  );
}

function useVm(id: string) {
  const { state, load } = useRead<Vm>(`/api/v1/vms/${id}`);
  useEffect(() => { void load(decodeVm); }, [id]);
  return { state, reload: () => load(decodeVm) };
}

export function J7Delete({ id }: { id: string }) {
  const { state, reload } = useVm(id);
  const [open, setOpen] = useState(false);
  const [pending, setPending] = useState(false);
  const [result, setResult] = useState<MutationResult<Operation> | null>(null);
  const keys = useIntentKeys();
  const vm = state.last;
  const confirm = async () => {
    if (pending || !vm) return;
    const payload = { type: "delete", kind: "VM", id: vm.id };
    setPending(true);
    const r = await mutate("/api/v1/operations", payload, keys.keyFor(payload), decodeOperation);
    keys.settle(payload, r);
    setPending(false);
    setOpen(false);
    setResult(r);
  };
  return (
    <>
      <ViewHeading title={vm ? `VM ${vm.name}` : "VM"} />
      {state.result?.kind === "unreachable" ? <UnreachableBanner lastKnown={state.lastAt} onRetry={reload} /> : null}
      {state.result && state.result.kind !== "ok" && state.lastAt ? <StaleNotice lastUpdated={state.lastAt} now={new Date()} /> : null}
      <Failure result={state.result} onRetry={reload} />
      {vm ? <p>Observed power: {vm.observed.power}.</p> : null}
      {result?.kind === "ok" ? <StatusMessage focusOnMount>Deletion requested for {vm?.name}. Operation {result.data.id}. Its volumes are kept.</StatusMessage> : null}
      {result?.kind === "outcome_unknown" ? <OutcomeUnknown onCheckStatus={() => { location.hash = "#/journey/J5"; }} /> : null}
      {result?.kind === "error" ? <ErrorState category={result.category} correlationId={result.correlationId} /> : null}
      {vm && vm.allowed_actions.includes("delete") && result?.kind !== "ok"
        ? <div className="ds-button-row"><Button variant="destructive" onClick={() => setOpen(true)}>Delete VM</Button></div> : null}
      {vm ? (
        <ConfirmDestructive open={open} title={`Delete VM ${vm.name}`} targetName={vm.name} confirmLabel="Delete permanently"
          warning={vm.observed.power === "running" ? "This VM is running. It will be forced off before it is deleted." : undefined}
          consequence="The VM definition is removed. Volumes are not deleted." pending={pending}
          onConfirm={confirm} onCancel={() => setOpen(false)} />
      ) : null}
    </>
  );
}

export function J9Power({ id }: { id: string }) {
  const { state, reload } = useVm(id);
  const [pending, setPending] = useState<string | null>(null);
  const [confirmOff, setConfirmOff] = useState(false);
  const [result, setResult] = useState<MutationResult<Operation> | null>(null);
  const keys = useIntentKeys();
  const vm = state.last;
  const act = async (type: string) => {
    if (pending || !vm) return;
    const payload = { type, kind: "VM", id: vm.id };
    setPending(type);
    const r = await mutate("/api/v1/operations", payload, keys.keyFor(payload), decodeOperation);
    keys.settle(payload, r);
    setPending(null);
    setConfirmOff(false);
    setResult(r);
  };
  return (
    <>
      <ViewHeading title={vm ? `Power: ${vm.name}` : "Power"} />
      {/* If reads also fail after an unknown outcome, the J8 banner is shown with last-known data (review M2). */}
      {state.result?.kind === "unreachable" ? <UnreachableBanner lastKnown={state.lastAt} onRetry={reload} /> : null}
      {state.result && state.result.kind !== "ok" && state.lastAt ? <StaleNotice lastUpdated={state.lastAt} now={new Date()} /> : null}
      <Failure result={state.result} onRetry={reload} />
      {vm ? <p>Observed power: {vm.observed.power}. The display changes only when the host reports a new state.</p> : null}
      {result?.kind === "ok" ? <StatusMessage>Request accepted. Operation {result.data.id}.</StatusMessage> : null}
      {result?.kind === "outcome_unknown" ? <OutcomeUnknown onCheckStatus={reload} /> : null}
      {result?.kind === "error" ? <ErrorState category={result.category} correlationId={result.correlationId} /> : null}
      <div className="ds-button-row">
        <Button onClick={() => act("start")} pending={pending === "start"} disabled={Boolean(pending) && pending !== "start"}>Start</Button>
        <Button onClick={() => act("stop")} pending={pending === "stop"} disabled={Boolean(pending) && pending !== "stop"}>Stop</Button>
        <Button onClick={() => act("reboot")} pending={pending === "reboot"} disabled={Boolean(pending) && pending !== "reboot"}>Reboot</Button>
        <Button variant="destructive" onClick={() => setConfirmOff(true)} disabled={Boolean(pending)}>Force off</Button>
      </div>
      <Dialog title="Force off this VM?" open={confirmOff} onClose={() => setConfirmOff(false)}>
        <p>Force off cuts power immediately. Unsaved data in the VM is lost.</p>
        <div className="ds-button-row">
          <Button variant="destructive" pending={pending === "force_off"} onClick={() => act("force_off")}>Confirm force off</Button>
          <Button onClick={() => setConfirmOff(false)}>Cancel</Button>
        </div>
      </Dialog>
    </>
  );
}

export function J10Console({ id, opened }: { id: string; opened: boolean }) {
  const { state, reload } = useVm(id);
  return (
    <>
      <ViewHeading title={opened ? "Console" : "VM console"} />
      {state.result?.kind === "unreachable" ? <UnreachableBanner lastKnown={state.lastAt} onRetry={reload} /> : null}
      <Failure result={state.result} onRetry={reload} />
      {state.result?.kind !== "ok" ? null : opened
        ? <StatusMessage tone="warning">The console is not available in M0 (owned by M1-E02-S04). No connection was made.</StatusMessage>
        : <p><a className="ds-link" href={`#/journey/J10/console?vm=${encodeURIComponent(id)}`}>Open console</a></p>}
    </>
  );
}

export type { ErrorCategory };
