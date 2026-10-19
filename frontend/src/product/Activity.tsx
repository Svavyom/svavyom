// Activity (M1-E04-S03): the history of what was asked of this host, newest first, with the outcome of each request. It reads the operations list
// (paged by cursor) and filters it in the browser; it never runs anything. A failed row says in words what the closed failure category means.
import { useCallback, useEffect, useRef, useState } from "react";
import { DataTable, EmptyState, ErrorState, LoadingRegion, PageHead, StaleNotice, StatusPill, UnreachableBanner } from "../design-system";
import { read, type ReadResult } from "../api/client";
import { decodeOperationList } from "../api/decoders";
import type { Operation } from "../api/schema";
import { OP_FAILURE, OP_LABEL, OP_STATUS } from "./operations";

type Filter = "all" | "active" | "done" | "failed";
const FILTERS: { id: Filter; label: string }[] = [{ id: "all", label: "All" }, { id: "active", label: "In progress" }, { id: "done", label: "Done" }, { id: "failed", label: "Failed or cancelled" }];
const IN: Record<Filter, ReadonlyArray<Operation["status"]>> = {
  all: ["pending", "running", "succeeded", "failed", "retryable_failure", "cancelled"],
  active: ["pending", "running", "retryable_failure"], done: ["succeeded"], failed: ["failed", "cancelled"],
};

export const when = (iso: string) => iso.replace("T", " ").replace("Z", " UTC");

export function Activity(props: { query: string; refresh: number; onSessionEnded: () => void }) {
  const [loading, setLoading] = useState(true);
  const [ops, setOps] = useState<Operation[] | null>(null);
  const [more, setMore] = useState<string | null>(null);
  const [lastAt, setLastAt] = useState<Date | null>(null);
  const [failure, setFailure] = useState<ReadResult<unknown> | null>(null);
  const [filter, setFilter] = useState<Filter>("all");
  const alive = useRef(true);

  const load = useCallback(async (cursor: string | null) => {
    setLoading(true);
    const r = await read(`/api/v1/operations?limit=100${cursor ? `&cursor=${encodeURIComponent(cursor)}` : ""}`, decodeOperationList);
    if (!alive.current) return;
    setLoading(false);
    if (r.kind === "ok") {
      setOps((prev) => (cursor && prev ? [...prev, ...r.data.items] : r.data.items));
      setMore(r.data.next_cursor);
      setLastAt(new Date());
      setFailure(null);
    } else if (r.kind === "error" && r.category === "unauthenticated") {
      props.onSessionEnded();
    } else {
      setFailure(r);
    }
  }, [props]);

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
  const shown = (ops ?? []).filter((o) => IN[filter].includes(o.status) && (q === "" || o.resource_id.toLowerCase().includes(q) || OP_LABEL[o.type].toLowerCase().includes(q)));
  const count = (f: Filter) => (ops ?? []).filter((o) => IN[f].includes(o.status)).length;
  return (
    <>
      <PageHead title="Activity"><p>What was asked of this host, newest first, and how each request ended.</p></PageHead>
      {failure?.kind === "unreachable" ? <UnreachableBanner lastKnown={lastAt} onRetry={() => load(null)} /> : null}
      {failure?.kind === "error" ? <ErrorState category={failure.category} correlationId={failure.correlationId} onRetry={() => load(null)} /> : null}
      <LoadingRegion label="Activity" loading={loading && !ops}>
        {ops && failure && lastAt ? <StaleNotice lastUpdated={lastAt} now={new Date()} /> : null}
        {ops && ops.length === 0 ? <EmptyState title="Nothing yet" reason="No request has been made on this host yet." /> : null}
        {ops && ops.length > 0 ? (
          <>
            <div className="ds-filter" role="group" aria-label="Filter by outcome">
              {FILTERS.map((f) => <button key={f.id} type="button" aria-pressed={filter === f.id} onClick={() => setFilter(f.id)}>{`${f.label} ${count(f.id)}`}</button>)}
            </div>
            {shown.length === 0 ? <p className="ds-spaced">No request matches{q !== "" ? ` “${props.query.trim()}”` : " this filter"}{more ? " among those loaded; show more to look further back" : ""}.</p> : (
              <DataTable caption="Requests made on this host" rows={shown} rowKey={(o) => o.id} columns={[
                { header: "When", cell: (o: Operation) => when(o.created_at), rowHeader: true },
                { header: "Action", cell: (o: Operation) => OP_LABEL[o.type] },
                { header: "Resource", cell: (o: Operation) => (o.resource_kind === "VM" && o.type !== "delete" ? <a className="ds-link" href={`#/vms/${o.resource_id}`}>{o.resource_id}</a> : o.resource_id) },
                { header: "Outcome", cell: (o: Operation) => <StatusPill tone={OP_STATUS[o.status].tone}>{OP_STATUS[o.status].text}</StatusPill> },
                { header: "Requested by", cell: (o: Operation) => o.requested_by },
                { header: "Detail", cell: (o: Operation) => (o.error_category ? OP_FAILURE[o.error_category] : o.attempts > 1 ? `${o.attempts} attempts` : "-") },
              ]} />
            )}
          </>
        ) : null}
        {more ? <div className="ds-button-row"><button type="button" className="ds-button" onClick={() => { void load(more); }}>Show more</button></div> : null}
      </LoadingRegion>
    </>
  );
}
