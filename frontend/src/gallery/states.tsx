// TEST-ONLY gallery renderings of every manifest state (M0-E02-S06 r5 section 2). Never part of the production build.
import { useState, type ReactNode } from "react";
import manifest from "../design-system/states.json";
import {
  Alert, AppShell, Button, Checkbox, ConfirmDestructive, DataTable, Dialog, EmptyState, ErrorState, ErrorSummary,
  Link, LoadingRegion, OutcomeUnknown, Progress, RadioGroup, Select, StaleNotice, StatusMessage, Tabs,
  TextArea, TextField, UnreachableBanner,
} from "../design-system";
import type { ErrorCategory } from "../api/errors";

const noop = () => undefined;
const FIXED_NOW = new Date("2026-10-07T12:00:00Z");
const EARLIER = new Date("2026-10-07T11:55:00Z");

function Controlled<T>({ initial, render }: { initial: T; render: (v: T, set: (v: T) => void) => ReactNode }) {
  const [v, set] = useState<T>(initial);
  return <>{render(v, set)}</>;
}

function ConfirmPreview({ name, typed }: { name: string; typed: string }) {
  return (
    <Controlled initial={true} render={(open, setOpen) => (
      <>
        <Button onClick={() => setOpen(true)}>Delete VM</Button>
        <ConfirmDestructiveWithInitial open={open} name={name} typed={typed} onClose={() => setOpen(false)} />
      </>
    )} />
  );
}

function ConfirmDestructiveWithInitial({ open, name, typed, onClose }: { open: boolean; name: string; typed: string; onClose: () => void }) {
  // Pre-fill by remounting with a key; typing is still live for browser tests.
  return (
    <ConfirmDestructive key={typed} open={open} title="Delete VM" targetName={name}
      consequence="The VM definition is removed. Its volumes are kept (VM-deletion owner pending sponsor decision)." confirmLabel="Delete permanently"
      onConfirm={noop} onCancel={onClose} initialTyped={typed} />
  );
}

type Renderer = () => ReactNode;

const rows = [
  { id: "vm-a", name: "web-1", power: "running" },
  { id: "vm-b", name: "db-1", power: "stopped" },
];

export const RENDERERS: Record<string, Record<string, Renderer>> = {
  Button: {
    default: () => <Button>Save draft</Button>,
    primary: () => <Button variant="primary">Create VM</Button>,
    destructive: () => <Button variant="destructive">Delete VM</Button>,
    disabled: () => <Button disabled>Create VM</Button>,
    pending: () => <Button variant="primary" pending>Create VM</Button>,
  },
  Link: { default: () => <Link href="#/">Back to the gallery index</Link> },
  TextField: {
    empty: () => <Controlled initial="" render={(v, s) => <TextField label="VM name" value={v} onChange={s} />} />,
    filled: () => <Controlled initial="web-1" render={(v, s) => <TextField label="VM name" value={v} onChange={s} />} />,
    described: () => <Controlled initial="" render={(v, s) => <TextField label="VM name" description="Letters, digits, dot, dash and underscore." value={v} onChange={s} />} />,
    invalid: () => <Controlled initial="bad name!" render={(v, s) => <TextField label="VM name" value={v} onChange={s} error="Use only letters, digits, dot, dash and underscore." />} />,
    disabled: () => <TextField label="VM name" value="web-1" onChange={noop} disabled />,
  },
  TextArea: {
    empty: () => <Controlled initial="" render={(v, s) => <TextArea label="Notes" value={v} onChange={s} />} />,
    invalid: () => <Controlled initial="x" render={(v, s) => <TextArea label="Notes" value={v} onChange={s} error="Notes must be at least 3 characters." />} />,
  },
  Select: {
    default: () => <Controlled initial="debian-13" render={(v, s) => <Select label="Image" value={v} onChange={s}
      options={[{ value: "debian-13", label: "Debian 13" }, { value: "ubuntu-24.04", label: "Ubuntu 24.04" }]} />} />,
    invalid: () => <Select label="Image" value="" onChange={noop} error="Choose an image." options={[{ value: "", label: "Choose…" }]} />,
  },
  Checkbox: {
    unchecked: () => <Controlled initial={false} render={(v, s) => <Checkbox label="Pause updates" checked={v} onChange={s} />} />,
    checked: () => <Controlled initial={true} render={(v, s) => <Checkbox label="Pause updates" checked={v} onChange={s} />} />,
    disabled: () => <Checkbox label="Pause updates" checked={false} onChange={noop} disabled />,
  },
  RadioGroup: {
    default: () => <Controlled initial="small" render={(v, s) => <RadioGroup legend="Size" name="size" value={v} onChange={s}
      options={[{ value: "small", label: "Small" }, { value: "medium", label: "Medium" }, { value: "large", label: "Large" }]} />} />,
    invalid: () => <RadioGroup legend="Size" name="size-invalid" value="" onChange={noop} error="Choose a size."
      options={[{ value: "small", label: "Small" }, { value: "large", label: "Large" }]} />,
  },
  Tabs: {
    first: () => <Tabs label="VM details" tabs={[{ id: "overview", label: "Overview", panel: <p>Overview panel</p> },
      { id: "volumes", label: "Volumes", panel: <p>Volumes panel</p> }, { id: "history", label: "History", panel: <p>History panel</p> }]} />,
    second: () => <Tabs label="VM details" initial="volumes" tabs={[{ id: "overview", label: "Overview", panel: <p>Overview panel</p> },
      { id: "volumes", label: "Volumes", panel: <p>Volumes panel</p> }, { id: "history", label: "History", panel: <p>History panel</p> }]} />,
  },
  Dialog: {
    open: () => <Controlled initial={true} render={(open, setOpen) => (
      <>
        <Button onClick={() => setOpen(true)}>Open dialog</Button>
        <Dialog title="Rename VM" open={open} onClose={() => setOpen(false)}>
          <p>Dialogs keep focus inside until closed. Press Escape to close.</p>
          <div className="ds-button-row"><Button variant="primary" onClick={() => setOpen(false)}>Done</Button></div>
        </Dialog>
      </>
    )} />,
  },
  ConfirmDestructive: {
    empty: () => <ConfirmPreview name="web-1" typed="" />,
    mismatch: () => <ConfirmPreview name="web-1" typed="web-l" />,
    match: () => <ConfirmPreview name="web-1" typed="web-1" />,
    "invisible-characters": () => <ConfirmPreview name={"web​-1‮"} typed="" />,
  },
  Alert: { default: () => <Alert title="Something needs attention"><p>Blocking problem text.</p></Alert> },
  StatusMessage: {
    success: () => <StatusMessage>The VM was deleted.</StatusMessage>,
    warning: () => <StatusMessage tone="warning">Updates are paused.</StatusMessage>,
  },
  LoadingRegion: {
    loading: () => <LoadingRegion label="VMs" loading>{null}</LoadingRegion>,
    loaded: () => <LoadingRegion label="VMs" loading={false}><p>2 VMs</p></LoadingRegion>,
  },
  Progress: { partial: () => <Progress label="Image download" value={40} /> },
  EmptyState: {
    "no-action": () => <EmptyState title="No VMs" reason="There are no VMs in this project, and you are not allowed to create one." />,
    "with-action": () => <EmptyState title="No VMs" reason="There are no VMs in this project yet." action={<Button variant="primary">Create VM</Button>} />,
  },
  ErrorState: Object.fromEntries(manifest.primitives.ErrorState.map((c) => [c, () =>
    <ErrorState category={c as ErrorCategory} correlationId="corr-0001" onRetry={noop} onRecover={noop} recoverLabel="Back to the list" />])),
  ErrorSummary: {
    "two-errors": () => (
      <>
        <ErrorSummary errors={[{ fieldId: "gname", message: "Enter a VM name" }, { fieldId: "gimage", message: "Choose an image" }]} />
        <TextField id="gname" label="VM name" value="" onChange={noop} error="Enter a VM name" />
        <Select id="gimage" label="Image" value="" onChange={noop} error="Choose an image" options={[{ value: "", label: "Choose…" }]} />
      </>
    ),
  },
  DataTable: {
    rows: () => <DataTable caption="VMs" rows={rows} rowKey={(r) => r.id}
      columns={[{ header: "Name", cell: (r) => r.name, rowHeader: true }, { header: "Power", cell: (r) => r.power }]} />,
    wide: () => <DataTable caption="Hosts" rows={rows} rowKey={(r) => r.id} columns={["Name", "Power", "Address", "Agent", "Kernel", "Uptime", "Verdict"].map(
      (h, i) => ({ header: h, cell: (r: typeof rows[number]) => (i === 0 ? r.name : `${h.toLowerCase()}-value-${r.id}`), rowHeader: i === 0 }))} />,
  },
  // The shell around every gallery page already renders the skip link as its first focus stop.
  SkipLink: { default: () => <p>Press Tab: the first stop is the skip link, which moves focus to the main content.</p> },
  AppShell: { default: () => null },
  StaleNotice: { default: () => <StaleNotice lastUpdated={EARLIER} now={FIXED_NOW} /> },
  UnreachableBanner: {
    never: () => <UnreachableBanner lastKnown={null} onRetry={noop} />,
    "last-known": () => <UnreachableBanner lastKnown={EARLIER} onRetry={noop} />,
  },
  OutcomeUnknown: { default: () => <OutcomeUnknown onCheckStatus={noop} /> },
};
