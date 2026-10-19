// Alerts (DR-024 D2): what the platform noticed by itself, newest first, with what to do. The page only reads; acknowledging is a request like any other.
// Thresholds and the webhook are the operator's, set in the provisioning configuration, so this page shows them as facts and offers no setting.
import { useCallback, useEffect, useRef, useState } from "react";
import { Button, DataTable, EmptyState, ErrorState, LoadingRegion, PageHead, StaleNotice, StatusMessage, StatusPill, UnreachableBanner } from "../design-system";
import { read, type ReadResult } from "../api/client";
import { decodeEventList, decodeHost } from "../api/decoders";
import type { Event, Host } from "../api/schema";
import { ruleOf, SEVERITY, STATE_TEXT } from "./alertparts";
import { OperationProgress } from "./OperationProgress";
import { useRunner } from "./runner";

type Filter = "open" | "acknowledged" | "resolved" | "all";
const FILTERS: { id: Filter; label: string }[] = [{ id: "open", label: "Open" }, { id: "acknowledged", label: "Acknowledged" }, { id: "resolved", label: "Resolved" }, { id: "all", label: "All" }];

const when = (iso: string) => iso.replace("T", " ").replace("Z", " UTC");

export function Alerts(props: { query: string; refresh: number; onSessionEnded: () => void }) {
  const [loading, setLoading] = useState(true);
  const [items, setItems] = useState<Event[] | null>(null);
  const [more, setMore] = useState<string | null>(null);
  const [webhook, setWebhook] = useState<Host["observed"]["alerts"]["webhook"] | null>(null);
  const [lastAt, setLastAt] = useState<Date | null>(null);
  const [failure, setFailure] = useState<ReadResult<unknown> | null>(null);
  const [filter, setFilter] = useState<Filter>("open");
  const alive = useRef(true);

  const load = useCallback(async (cursor: string | null) => {
    setLoading(true);
    const r = await read(`/api/v1/events?limit=100${cursor ? `&cursor=${encodeURIComponent(cursor)}` : ""}`, decodeEventList);
    if (!alive.current) return;
    setLoading(false);
    if (r.kind === "ok") {
      setItems((prev) => (cursor && prev ? [...prev, ...r.data.items] : r.data.items));
      setMore(r.data.next_cursor);
      setLastAt(new Date());
      setFailure(null);
      if (!cursor) {
        const h = await read("/api/v1/hosts/local", decodeHost); // only for the webhook line: a failure here changes nothing else
        if (alive.current) setWebhook(h.kind === "ok" ? h.data.observed.alerts.webhook : null);
      }
    } else if (r.kind === "error" && r.category === "unauthenticated") {
      props.onSessionEnded();
    } else {
      setFailure(r);
    }
  }, [props]);

  const runner = useRunner(props.onSessionEnded, () => { void load(null); });

  useEffect(() => {
    alive.current = true;
    void load(null);
    return () => { alive.current = false; };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);
  const firstRefresh = useRef(true);
  useEffect(() => {
    if (firstRefresh.current) { firstRefresh.current = false; return; }
    void load(null);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [props.refresh]);

  const q = props.query.trim().toLowerCase();
  const inFilter = (e: Event) => filter === "all" || e.state === filter;
  const shown = (items ?? []).filter((e) => inFilter(e) && (q === "" || e.resource_id.toLowerCase().includes(q) || ruleOf(e.type).title.toLowerCase().includes(q)));
  const count = (f: Filter) => (items ?? []).filter((e) => f === "all" || e.state === f).length;

  return (
    <>
      <PageHead title="Alerts"><p>What Svavyom noticed by itself, and what to do about it.</p></PageHead>
      {failure?.kind === "unreachable" ? <UnreachableBanner lastKnown={lastAt} onRetry={() => load(null)} /> : null}
      {failure?.kind === "error" ? <ErrorState category={failure.category} correlationId={failure.correlationId} onRetry={() => load(null)} /> : null}
      {runner.error ? <StatusMessage tone="warning">{runner.error}</StatusMessage> : null}
      {runner.op ? <OperationProgress key={runner.op.id} id={runner.op.id} onDone={runner.finish} onSessionEnded={props.onSessionEnded} /> : null}
      <LoadingRegion label="Alerts" loading={loading && !items}>
        {items && failure && lastAt ? <StaleNotice lastUpdated={lastAt} now={new Date()} /> : null}
        {items ? (
          <>
            <p className="ds-muted">
              {webhook === "configured" ? "Each new alert and each recovery is also sent to the webhook the operator configured (best effort, not guaranteed)."
                : webhook === "none" ? "No webhook is configured, so alerts are shown here only. The operator can set one in the provisioning configuration."
                  : "Whether a webhook is configured could not be read."}
              {" "}Thresholds are set there too.
            </p>
            {items.length === 0 ? <EmptyState title="No alerts" reason="Nothing has needed attention since this host started." /> : (
              <>
                <div className="ds-filter" role="group" aria-label="Filter by state">
                  {FILTERS.map((f) => <button key={f.id} type="button" aria-pressed={filter === f.id} onClick={() => setFilter(f.id)}>{`${f.label} ${count(f.id)}`}</button>)}
                </div>
                {shown.length === 0 ? <p className="ds-spaced">No alert matches{q !== "" ? ` “${props.query.trim()}”` : " this filter"}.</p> : (
                  <DataTable caption="Alerts on this host" rows={shown} rowKey={(e) => e.id} columns={[
                    { header: "Severity", cell: (e: Event) => <StatusPill tone={SEVERITY[e.severity].tone}>{SEVERITY[e.severity].text}</StatusPill> },
                    { header: "What happened", cell: (e: Event) => <><strong>{ruleOf(e.type).title}</strong>{ruleOf(e.type).detail(e) ? <> {ruleOf(e.type).detail(e)}</> : null}</>, rowHeader: true },
                    { header: "Where", cell: (e: Event) => (e.resource_kind === "VM" ? <a className="ds-link" href={`#/vms/${e.resource_id}`}>{e.resource_id}</a> : e.resource_kind === "Host" ? "This host" : e.resource_id) },
                    { header: "Since", cell: (e: Event) => when(e.created_at) },
                    { header: "State", cell: (e: Event) => STATE_TEXT[e.state] },
                    { header: "What to do", cell: (e: Event) => (e.state === "resolved" ? "Nothing: it has cleared." : ruleOf(e.type).todo || "-") },
                    { header: "Action", cell: (e: Event) => (e.allowed_actions.includes("acknowledge")
                      ? <Button disabled={runner.busy} onClick={() => { void runner.run({ type: "alert_acknowledge", kind: "Event", id: e.id }); }}>{`Acknowledge ${ruleOf(e.type).title}${e.resource_kind === "VM" ? ` on ${e.resource_id}` : ""}`}</Button> : "-") },
                  ]} />
                )}
              </>
            )}
          </>
        ) : null}
        {more ? <div className="ds-button-row"><button type="button" className="ds-button" onClick={() => { void load(more); }}>Show more</button></div> : null}
      </LoadingRegion>
    </>
  );
}
