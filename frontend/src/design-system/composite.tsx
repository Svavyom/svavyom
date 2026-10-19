// Composite widgets (M0-E02-S06 r5 sections 4, 5): Tabs (roving tabindex), modal Dialog (focus containment
// released by Esc, focus return), ConfirmDestructive (exact code-point typed-name confirmation).
import { useEffect, useId, useRef, useState, type KeyboardEvent, type ReactNode } from "react";
import { Button, TextField } from "./controls";

export function Tabs(props: { label: string; tabs: ReadonlyArray<{ id: string; label: string; panel: ReactNode }>; initial?: string }) {
  const [selected, setSelected] = useState(props.initial ?? props.tabs[0]?.id);
  const refs = useRef<Record<string, HTMLButtonElement | null>>({});
  const base = useId().replace(/[^A-Za-z0-9]/g, "");
  const move = (to: number) => {
    const t = props.tabs[(to + props.tabs.length) % props.tabs.length];
    setSelected(t.id);
    refs.current[t.id]?.focus();
  };
  const onKey = (e: KeyboardEvent, i: number) => {
    const keys: Record<string, () => void> = {
      ArrowRight: () => move(i + 1), ArrowLeft: () => move(i - 1), Home: () => move(0), End: () => move(props.tabs.length - 1),
    };
    if (keys[e.key]) {
      e.preventDefault();
      keys[e.key]();
    }
  };
  return (
    <div>
      <div role="tablist" aria-label={props.label} className="ds-tabs-list">
        {props.tabs.map((t, i) => (
          <button key={t.id} ref={(el) => { refs.current[t.id] = el; }} role="tab" type="button" className="ds-tab"
            id={`${base}-tab-${t.id}`} aria-selected={selected === t.id} aria-controls={`${base}-panel-${t.id}`}
            tabIndex={selected === t.id ? 0 : -1} onClick={() => setSelected(t.id)} onKeyDown={(e) => onKey(e, i)}>
            {t.label}
          </button>
        ))}
      </div>
      {props.tabs.map((t) => (
        <div key={t.id} role="tabpanel" id={`${base}-panel-${t.id}`} aria-labelledby={`${base}-tab-${t.id}`}
          hidden={selected !== t.id} tabIndex={0} className="ds-tab-panel">
          {selected === t.id ? t.panel : null}
        </div>
      ))}
    </div>
  );
}

const FOCUSABLE = 'a[href], button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex="0"]';

/** Modal dialog. On open, focus moves to its heading; Tab/Shift+Tab stay inside; Esc closes;
 *  on close focus returns to the element that opened it (r5 section 5). */
export function Dialog(props: { title: string; open: boolean; onClose: () => void; children: ReactNode }) {
  const ref = useRef<HTMLDivElement>(null);
  const heading = useRef<HTMLHeadingElement>(null);
  const opener = useRef<Element | null>(null);
  const titleId = useId().replace(/[^A-Za-z0-9]/g, "") + "-title";
  useEffect(() => {
    if (!props.open) return;
    opener.current = document.activeElement;
    heading.current?.focus();
    return () => {
      const el = opener.current as HTMLElement | null;
      if (el && typeof el.focus === "function" && document.contains(el)) el.focus();
    };
  }, [props.open]);
  if (!props.open) return null;
  const onKeyDown = (e: KeyboardEvent<HTMLDivElement>) => {
    if (e.key === "Escape") {
      e.stopPropagation();
      props.onClose();
      return;
    }
    if (e.key !== "Tab" || !ref.current) return;
    const items = Array.from(ref.current.querySelectorAll<HTMLElement>(FOCUSABLE));
    if (items.length === 0) return;
    const first = items[0];
    const last = items[items.length - 1];
    const active = document.activeElement;
    if (e.shiftKey && (active === first || active === heading.current)) {
      e.preventDefault();
      last.focus();
    } else if (!e.shiftKey && active === last) {
      e.preventDefault();
      first.focus();
    }
  };
  return (
    <div className="ds-dialog-backdrop">
      <div ref={ref} role="dialog" aria-modal="true" aria-labelledby={titleId} className="ds-dialog" onKeyDown={onKeyDown}>
        <h2 id={titleId} ref={heading} tabIndex={-1}>{props.title}</h2>
        {props.children}
      </div>
    </div>
  );
}

const INVISIBLE = new RegExp("[\\u0000-\\u001f\\u007f-\\u009f\\u00ad\\u034f\\u061c\\u115f\\u1160\\u17b4\\u17b5\\u180b-\\u180f" +
  "\\u200b-\\u200f\\u2028-\\u202e\\u2060-\\u206f\\u3164\\ufe00-\\ufe0f\\ufeff\\uffa0\\ufff9-\\ufffb]|\\udb40[\\udc00-\\udc7f]", "g");

/** Make bidi controls, zero-width and other invisible characters visible as U+XXXX markers (r5 section 10). */
export function visibleCodepoints(s: string): string {
  return s.replace(INVISIBLE, (c) => `⟨U+${c.codePointAt(0)!.toString(16).toUpperCase().padStart(4, "0")}⟩`);
}

/** Exact code-point equality: no trimming, no case folding, no Unicode normalisation (r5 section 10). */
export function exactMatch(typed: string, expected: string): boolean {
  return typed.length === expected.length && Array.from(typed).every((c, i) => c === Array.from(expected)[i]);
}

export function ConfirmDestructive(props: {
  open: boolean; title: string; targetName: string; consequence: string; confirmLabel: string;
  onConfirm: () => void; onCancel: () => void; pending?: boolean; initialTyped?: string; warning?: string;
}) {
  const [typed, setTyped] = useState(props.initialTyped ?? "");
  // A cancelled confirmation starts empty next time (review N5): reopening is never pre-confirmed.
  useEffect(() => { if (!props.open) setTyped(props.initialTyped ?? ""); }, [props.open]);
  const matches = exactMatch(typed, props.targetName);
  const shown = visibleCodepoints(props.targetName);
  return (
    <Dialog title={props.title} open={props.open} onClose={props.onCancel}>
      {props.warning ? <p className="ds-alert-title">{props.warning}</p> : null}
      <p>{props.consequence}</p>
      <p>
        To confirm, type the exact name: <span className="ds-visible-codepoints">{shown}</span>
        {shown !== props.targetName ? " (the name contains invisible characters, shown as ⟨U+…⟩; they must be typed too)" : null}
      </p>
      <TextField label="Name to confirm" value={typed} onChange={setTyped} required
        error={typed && !matches ? "The name does not match exactly." : undefined} />
      <div className="ds-button-row">
        <Button variant="destructive" disabled={!matches} pending={props.pending} onClick={props.onConfirm}>{props.confirmLabel}</Button>
        <Button onClick={props.onCancel}>Cancel</Button>
      </div>
    </Dialog>
  );
}
