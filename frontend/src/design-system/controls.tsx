// Form controls and actions (M0-E02-S06 r5 sections 2, 4, 5). Native elements first: they bring keyboard
// behaviour (Enter/Space, arrow keys in radio groups) and accessible names for free.
import { useId, type ReactNode, type MouseEvent, type ChangeEvent } from "react";

type ButtonVariant = "secondary" | "primary" | "destructive";

export interface ButtonProps {
  children: ReactNode;
  onClick?: (e: MouseEvent<HTMLButtonElement>) => void;
  variant?: ButtonVariant;
  disabled?: boolean;
  /** Pending: stays focusable (focus is not lost) but is inert and announced busy (r5 section 6). */
  pending?: boolean;
  type?: "button" | "submit";
  describedBy?: string;
  id?: string;
  /** Accessible name when it is longer than the visible text (it must still contain the visible text). */
  ariaLabel?: string;
  size?: "md" | "sm";
}

export function Button({ children, onClick, variant = "secondary", disabled, pending, type = "button", describedBy, id, ariaLabel, size = "md" }: ButtonProps) {
  const inert = Boolean(disabled || pending);
  return (
    <button
      id={id}
      type={type}
      className={`ds-button ds-button--${variant}${size === "sm" ? " ds-button--sm" : ""}`}
      aria-label={ariaLabel}
      aria-disabled={inert ? "true" : undefined}
      aria-busy={pending ? "true" : undefined}
      aria-describedby={describedBy}
      onClick={(e) => {
        if (inert) {
          e.preventDefault();
          return;
        }
        onClick?.(e);
      }}
    >
      {children}
      {pending ? <span className="ds-visually-hidden"> (in progress)</span> : null}
    </button>
  );
}

export function Link({ href, children }: { href: string; children: ReactNode }) {
  // Same-origin, relative links only (r5 section 9).
  if (!href.startsWith("#") && !href.startsWith("/")) throw new Error("Link: only relative links are allowed");
  return (
    <a className="ds-link" href={href}>
      {children}
    </a>
  );
}

interface FieldBase {
  label: string;
  description?: string;
  error?: string;
  id?: string;
  disabled?: boolean;
  required?: boolean;
}

function useFieldIds(id?: string) {
  const auto = useId();
  const base = id ?? `f${auto.replace(/[^A-Za-z0-9]/g, "")}`;
  return { input: base, description: `${base}-description`, error: `${base}-error` };
}

function describedBy(ids: { description: string; error: string }, description?: string, error?: string) {
  return [description ? ids.description : null, error ? ids.error : null].filter(Boolean).join(" ") || undefined;
}

export function TextField(props: FieldBase & { value: string; onChange: (v: string) => void; autoComplete?: string; secret?: boolean }) {
  const ids = useFieldIds(props.id);
  return (
    <div className="ds-field">
      <label className="ds-label" htmlFor={ids.input}>
        {props.label}
        {props.required ? " (required)" : ""}
      </label>
      {props.description ? <span id={ids.description} className="ds-description">{props.description}</span> : null}
      <input
        id={ids.input}
        className="ds-input"
        type={props.secret ? "password" : "text"}
        value={props.value}
        disabled={props.disabled}
        required={props.required}
        autoComplete={props.autoComplete ?? "off"}
        spellCheck={props.secret ? false : undefined}
        autoCapitalize={props.secret ? "off" : undefined}
        aria-invalid={props.error ? "true" : undefined}
        aria-describedby={describedBy(ids, props.description, props.error)}
        onChange={(e: ChangeEvent<HTMLInputElement>) => props.onChange(e.target.value)}
      />
      {props.error ? <span id={ids.error} className="ds-field-error">{props.error}</span> : null}
    </div>
  );
}

export function TextArea(props: FieldBase & { value: string; onChange: (v: string) => void }) {
  const ids = useFieldIds(props.id);
  return (
    <div className="ds-field">
      <label className="ds-label" htmlFor={ids.input}>{props.label}</label>
      {props.description ? <span id={ids.description} className="ds-description">{props.description}</span> : null}
      {/* Enter inserts a newline here; it never submits the form (r5 section 4). */}
      <textarea
        id={ids.input}
        className="ds-textarea"
        value={props.value}
        disabled={props.disabled}
        aria-invalid={props.error ? "true" : undefined}
        aria-describedby={describedBy(ids, props.description, props.error)}
        onChange={(e) => props.onChange(e.target.value)}
      />
      {props.error ? <span id={ids.error} className="ds-field-error">{props.error}</span> : null}
    </div>
  );
}

export function Select(props: FieldBase & { value: string; options: ReadonlyArray<{ value: string; label: string }>; onChange: (v: string) => void }) {
  const ids = useFieldIds(props.id);
  return (
    <div className="ds-field">
      <label className="ds-label" htmlFor={ids.input}>{props.label}</label>
      {props.description ? <span id={ids.description} className="ds-description">{props.description}</span> : null}
      <select
        id={ids.input}
        className="ds-select"
        value={props.value}
        disabled={props.disabled}
        aria-invalid={props.error ? "true" : undefined}
        aria-describedby={describedBy(ids, props.description, props.error)}
        onChange={(e) => props.onChange(e.target.value)}
      >
        {props.options.map((o) => (
          <option key={o.value} value={o.value}>{o.label}</option>
        ))}
      </select>
      {props.error ? <span id={ids.error} className="ds-field-error">{props.error}</span> : null}
    </div>
  );
}

export function Checkbox(props: { label: string; checked: boolean; onChange: (v: boolean) => void; disabled?: boolean; id?: string }) {
  const ids = useFieldIds(props.id);
  return (
    <div className="ds-check">
      <input id={ids.input} type="checkbox" checked={props.checked} disabled={props.disabled}
        onChange={(e) => props.onChange(e.target.checked)} />
      <label htmlFor={ids.input}>{props.label}</label>
    </div>
  );
}

/** Native radios in a fieldset: one tab stop, arrow keys move and select (roving behaviour is native). */
export function RadioGroup(props: { legend: string; name: string; value: string; options: ReadonlyArray<{ value: string; label: string }>;
  onChange: (v: string) => void; disabled?: boolean; error?: string }) {
  const errId = useFieldIds().error;
  return (
    <fieldset className="ds-fieldset" aria-describedby={props.error ? errId : undefined}>
      <legend className="ds-label">{props.legend}</legend>
      {props.options.map((o) => {
        const id = `${props.name}-${o.value}`;
        return (
          <div className="ds-check" key={o.value}>
            <input id={id} type="radio" name={props.name} value={o.value} checked={props.value === o.value}
              disabled={props.disabled} onChange={() => props.onChange(o.value)}
              aria-invalid={props.error ? "true" : undefined} aria-describedby={props.error ? errId : undefined} />
            <label htmlFor={id}>{o.label}</label>
          </div>
        );
      })}
      {props.error ? <span id={errId} className="ds-field-error">{props.error}</span> : null}
    </fieldset>
  );
}
