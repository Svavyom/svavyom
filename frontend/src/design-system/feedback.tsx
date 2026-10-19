// Feedback primitives (M0-E02-S06 r5 sections 6, 7): announcements, loading, empty, error, stale, unreachable.
import { useEffect, useRef, useState, type ReactNode } from "react";
import { Button } from "./controls";
import { ERROR_PRESENTATION, isRetryable, type ErrorCategory } from "../api/errors";
import { loadingIndicatorDelayMs } from "./tokens";

/** A short state label with a dot. The word carries the meaning; the colour only reinforces it. */
export function StatusPill({ tone = "neutral", children }: { tone?: "ok" | "warn" | "bad" | "neutral"; children: ReactNode }) {
  return <span className={`ds-pill${tone === "neutral" ? "" : ` ds-pill--${tone}`}`}>{children}</span>;
}

/** Blocking error: role="alert". */
export function Alert({ title, children }: { title: string; children?: ReactNode }) {
  return (
    <div role="alert" className="ds-alert">
      <p className="ds-alert-title">{title}</p>
      {children}
    </div>
  );
}

/** Non-blocking notice: role="status" (polite). Optionally focusable, for post-destructive focus. */
export function StatusMessage({ children, tone = "success", focusOnMount = false }: { children: ReactNode; tone?: "success" | "warning"; focusOnMount?: boolean }) {
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (focusOnMount) ref.current?.focus();
  }, [focusOnMount]);
  return (
    <div ref={ref} role="status" className={`ds-status${tone === "warning" ? " ds-status--warning" : ""}`} tabIndex={focusOnMount ? -1 : undefined}>
      {children}
    </div>
  );
}

/** Loading: aria-busy, a text status always present, a visual indicator only after 300 ms (no flash). */
export function LoadingRegion({ label, loading, children }: { label: string; loading: boolean; children?: ReactNode }) {
  const [showIndicator, setShow] = useState(false);
  useEffect(() => {
    if (!loading) {
      setShow(false);
      return;
    }
    const t = setTimeout(() => setShow(true), loadingIndicatorDelayMs);
    return () => clearTimeout(t);
  }, [loading]);
  return (
    <section aria-busy={loading ? "true" : "false"} aria-label={label}>
      {loading ? (
        <p role="status">
          {showIndicator ? <span className="ds-loading-indicator" aria-hidden="true" data-testid="loading-indicator" /> : null} Loading {label.toLowerCase()}…
        </p>
      ) : children}
    </section>
  );
}

export function Progress({ label, value, max = 100 }: { label: string; value: number; max?: number }) {
  return (
    <div className="ds-field">
      <label className="ds-label">
        {label}
        <progress className="ds-progress" value={value} max={max}>{Math.round((value / max) * 100)}%</progress>
      </label>
    </div>
  );
}

/** Empty state: explains why; offers the primary action only when allowed (from the allowed_actions of the collection). */
export function EmptyState({ title, reason, action }: { title: string; reason: string; action?: ReactNode }) {
  return (
    <div className="ds-empty">
      <h2>{title}</h2>
      <p>{reason}</p>
      {action ?? null}
    </div>
  );
}

/** Error state for a typed category: product text and correlation id only; retry only when retryable. */
export function ErrorState({ category, correlationId, onRetry, onRecover, recoverLabel }: {
  category: ErrorCategory; correlationId?: string | null; onRetry?: () => void; onRecover?: () => void; recoverLabel?: string;
}) {
  const p = ERROR_PRESENTATION[category];
  return (
    <Alert title={p.title}>
      <p>{p.recovery}</p>
      {correlationId ? <p>Correlation id: <span className="ds-badge">{correlationId}</span></p> : null}
      <div className="ds-button-row">
        {onRetry && isRetryable(category) ? <Button onClick={onRetry}>Try again</Button> : null}
        {onRecover ? <Button onClick={onRecover}>{recoverLabel ?? "Go back"}</Button> : null}
      </div>
    </Alert>
  );
}

/** Error summary after a failed submit: receives focus, links to the fields (r5 section 5). */
export function ErrorSummary({ errors }: { errors: ReadonlyArray<{ fieldId: string; message: string }> }) {
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    ref.current?.focus();
  }, [errors]);
  if (errors.length === 0) return null;
  return (
    <div ref={ref} className="ds-error-summary" tabIndex={-1} role="alert" aria-labelledby="error-summary-title">
      <h2 id="error-summary-title">There is a problem</h2>
      <ul>
        {errors.map((e) => (
          <li key={e.fieldId}>
            <a className="ds-link" href={`#${e.fieldId}`}
              onClick={(ev) => { ev.preventDefault(); document.getElementById(e.fieldId)?.focus(); }}>{e.message}</a>
          </li>
        ))}
      </ul>
    </div>
  );
}

export function ageText(sinceMs: number): string {
  const s = Math.max(0, Math.round(sinceMs / 1000));
  if (s < 60) return `${s} second${s === 1 ? "" : "s"} ago`;
  const m = Math.round(s / 60);
  return `${m} minute${m === 1 ? "" : "s"} ago`;
}

/** Stale data marker (r5 section 7): data stays visible, marked with its age. */
export function StaleNotice({ lastUpdated, now }: { lastUpdated: Date; now: Date }) {
  return (
    <StatusMessage tone="warning">
      This information may be out of date. Last updated {ageText(now.getTime() - lastUpdated.getTime())} (<time dateTime={lastUpdated.toISOString()}>{lastUpdated.toISOString()}</time>).
    </StatusMessage>
  );
}

/** J8: honest unreachable state (r5 section 6, review R-M4 wording). */
export function UnreachableBanner({ lastKnown, onRetry }: { lastKnown: Date | null; onRetry: () => void }) {
  return (
    <Alert title="Control plane unreachable">
      <p>
        A control-plane outage does not stop your VMs, but their current state cannot be confirmed. Last known:{" "}
        {lastKnown ? <time dateTime={lastKnown.toISOString()}>{lastKnown.toISOString()}</time> : "never"}.
      </p>
      <Button onClick={onRetry}>Retry now</Button>
    </Alert>
  );
}

/** outcome_unknown for a mutation: offers a status check, never an automatic re-send (r5 section 6). */
export function OutcomeUnknown({ onCheckStatus }: { onCheckStatus: () => void }) {
  return (
    <Alert title="The outcome is unknown">
      <p>The request did not complete in time. It may or may not have taken effect. Check the status before doing anything again.</p>
      <Button onClick={onCheckStatus}>Check status</Button>
    </Alert>
  );
}

/** One summary figure: a label, a value, an optional note and an optional bar (used of max). */
export function StatTile(props: { label: string; value: string; note?: string; meter?: { used: number; max: number } }) {
  return (
    <li className="ds-tile">
      <span className="ds-tile-label">{props.label}</span>
      <span className="ds-tile-value">{props.value}</span>
      {props.note ? <span className="ds-tile-note">{props.note}</span> : null}
      {props.meter && props.meter.max > 0 ? <meter className="ds-meter" min={0} max={props.meter.max} value={Math.min(props.meter.used, props.meter.max)} aria-label={`${props.label} in use`} /> : null}
    </li>
  );
}

/** A named row of summary tiles. */
export function StatTiles({ label, children }: { label: string; children: ReactNode }) {
  return <ul className="ds-tiles" aria-label={label}>{children}</ul>;
}
