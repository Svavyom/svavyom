// Virtual machines (journey J3): every VM on the host as a filterable list. A row opens the VM's own page (VmDetail), where the
// lifecycle and storage actions live. The list is read-only; it shows observation only and never runs anything.
import { useCallback, useEffect, useRef, useState } from "react";
import { DataTable, EmptyState, ErrorState, LoadingRegion, PageHead, StaleNotice, StatusMessage, StatusPill, UnreachableBanner } from "../design-system";
import { read, type ReadResult } from "../api/client";
import { decodeHost, decodeVmList } from "../api/decoders";
import type { Host, VM } from "../api/schema";
import { readiness } from "./Dashboard";
import { Connection, NetworkInfo } from "./VmDetail";
import { atLeast, useRole } from "./role";
import { POWER_LABEL, POWER_TONE } from "./vmparts";

type Filter = "all" | "running" | "stopped" | "attention";
const FILTERS: { id: Filter; label: string }[] = [
  { id: "all", label: "All" }, { id: "running", label: "Running" }, { id: "stopped", label: "Stopped" }, { id: "attention", label: "Needs attention" },
];
const matches = (v: VM, f: Filter) => f === "all" || (f === "running" ? v.observed.power === "running" : f === "stopped" ? v.observed.power === "stopped" : v.observed.power !== "running" && v.observed.power !== "stopped");

export function Inventory(props: { query: string; refresh: number; onSessionEnded: () => void }) {
  const [loading, setLoading] = useState(true);
  const [vms, setVms] = useState<VM[] | null>(null);
  const [more, setMore] = useState<string | null>(null);
  const [host, setHost] = useState<Host | null>(null);
  const [lastAt, setLastAt] = useState<Date | null>(null);
  const [failure, setFailure] = useState<ReadResult<unknown> | null>(null);
  const [filter, setFilter] = useState<Filter>("all");
  const alive = useRef(true);

  const load = useCallback(async (cursor: string | null) => {
    setLoading(true);
    const path = `/api/v1/vms?limit=200${cursor ? `&cursor=${encodeURIComponent(cursor)}` : ""}`;
    const [r, h] = await Promise.all([read(path, decodeVmList), cursor ? Promise.resolve(null) : read("/api/v1/hosts/local", decodeHost)]);
    if (!alive.current) return;
    setLoading(false);
    if (h && h.kind === "ok") setHost(h.data);
    if (r.kind === "ok") {
      setVms((prev) => (cursor && prev ? [...prev, ...r.data.items] : r.data.items));
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

  // The header's Refresh bumps `refresh`: reload in place, so what was last shown stays (marked stale on failure).
  const firstRefresh = useRef(true);
  useEffect(() => {
    if (firstRefresh.current) { firstRefresh.current = false; return; }
    void load(null);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [props.refresh]);

  const notReady = host ? readiness(host) : null;
  const enabled = host?.observed.creation.enabled === true;
  const role = useRole();
  const canCreate = host?.observed.creation.ready === true && atLeast(role, "operator");
  const q = props.query.trim().toLowerCase();
  const shown = (vms ?? []).filter((v) => matches(v, filter) && (q === "" || v.name.toLowerCase().includes(q)));
  const count = (f: Filter) => (vms ?? []).filter((v) => matches(v, f)).length;
  return (
    <>
      <PageHead title="Virtual machines" actions={canCreate ? <a className="ds-button ds-button--primary" href="#/create">Create VM</a> : undefined}>
        <p>Select a VM to see its details and manage it.</p>
      </PageHead>
      {enabled ? <StatusMessage tone="warning">Development Preview: creating and starting VMs is experimental and has not been qualified on real hardware.</StatusMessage> : null}
      {notReady && notReady.tone === "warning" ? <StatusMessage tone="warning">{notReady.text}</StatusMessage> : null}
      {failure?.kind === "unreachable" ? <UnreachableBanner lastKnown={lastAt} onRetry={() => load(null)} /> : null}
      {failure?.kind === "error" ? (
        <ErrorState category={failure.category} correlationId={failure.correlationId} onRetry={() => load(null)} />
      ) : null}
      {failure?.kind === "error" && failure.category === "internal" ? (
        <p>
          One possible cause: this host has a virtual machine whose name Svavyom cannot represent yet (it supports only letters,
          digits, &quot;.&quot;, &quot;_&quot; and &quot;-&quot;, up to 63 characters). The inventory is reported as failed rather than shown
          with that machine missing.
        </p>
      ) : null}
      <LoadingRegion label="Virtual machines" loading={loading && !vms}>
        {vms && failure && lastAt ? <StaleNotice lastUpdated={lastAt} now={new Date()} /> : null}
        {vms && vms.length === 0 ? (
          <EmptyState title="No VMs yet" reason={canCreate ? "There are no virtual machines on this host yet." : "There are no virtual machines on this host. Creating virtual machines is not available yet."}
            action={canCreate ? <a className="ds-button ds-button--primary" href="#/create">Create VM</a> : undefined} />
        ) : null}
        {vms && vms.length > 0 ? (
          <>
            <div className="ds-filter" role="group" aria-label="Filter by state">
              {FILTERS.map((f) => (
                <button key={f.id} type="button" aria-pressed={filter === f.id} onClick={() => setFilter(f.id)}>{`${f.label} ${count(f.id)}`}</button>
              ))}
            </div>
            {shown.length === 0 ? <p className="ds-spaced">No VM matches{q !== "" ? ` “${props.query.trim()}”` : " this filter"}.</p> : (
              <DataTable caption="Virtual machines on this host" rows={shown} rowKey={(v) => v.id} columns={[
                { header: "Name", cell: (v: VM) => <a className="ds-link" href={`#/vms/${v.id}`}>{v.name}</a>, rowHeader: true },
                { header: "Power state", cell: (v: VM) => <StatusPill tone={POWER_TONE[v.observed.power]}>{POWER_LABEL[v.observed.power]}</StatusPill> },
                { header: "Disk (virtual size)", cell: (v: VM) => (v.observed.disk_gib === null ? "-" : `${v.observed.disk_gib} GiB`) },
                { header: "Connection", cell: (v: VM) => <Connection vm={v} /> },
                { header: "Network", cell: (v: VM) => <NetworkInfo vm={v} /> },
                { header: "Last seen", cell: (v: VM) => v.observed.last_seen_at },
              ]} />
            )}
          </>
        ) : null}
        {more ? <div className="ds-button-row"><button type="button" className="ds-button" onClick={() => { void load(more); }}>Show more</button></div> : null}
      </LoadingRegion>
    </>
  );
}
