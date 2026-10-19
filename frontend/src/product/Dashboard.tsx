// Single-host dashboard (M1-E04-S01, journey J1/J3 host part): the managed host's basic capacity and virtualization
// readiness, read-only. "Ready" is a configuration check on package/device/CPU facts, never a host qualification.
import { useCallback, useEffect, useRef, useState } from "react";
import { DataTable, ErrorState, LoadingRegion, PageHead, StaleNotice, StatusMessage, StatTile, StatTiles, StatusPill, UnreachableBanner, UsageChart } from "../design-system";
import { read, type ReadResult } from "../api/client";
import { decodeHost, decodeOperationList, decodeVmList } from "../api/decoders";
import type { Host, Operation, VM } from "../api/schema";
import { OP_LABEL, OP_STATUS } from "./operations";
import { formatRate, POWER_LABEL, POWER_TONE } from "./vmparts";

const STATE_LABEL = { available: "Available", unavailable: "Not available", unknown: "Could not be determined" } as const;
type State = keyof typeof STATE_LABEL;

export function readiness(h: Host): { tone: "success" | "warning"; text: string } {
  const v = h.observed.virtualization;
  if (v.hardware === "unavailable") {
    return { tone: "warning", text: "This host's processor does not offer hardware virtualization, so virtual machines cannot run here." };
  }
  const all: State[] = [v.hardware, v.kvm_device, v.libvirt_packages, v.qemu_packages];
  if (all.every((s) => s === "available")) {
    return { tone: "success", text: "This host looks ready to run virtual machines. This is a configuration check, not a qualification of the host." };
  }
  if (all.some((s) => s === "unavailable")) {
    return { tone: "warning", text: "Some virtualization components are missing. See the details below." };
  }
  return { tone: "warning", text: "Virtualization readiness could not be fully determined from this account. See the details below." };
}

export function gib(mib: number): string {
  return `${(mib / 1024).toFixed(1)} GiB`;
}

const VERDICT_TEXT: Record<Host["observed"]["capability_verdict"], string> = {
  supported: "Supported distribution and configuration",
  unsupported: "Not a supported configuration",
  unknown: "Support status could not be determined",
};

export function Dashboard(props: { refresh: number; onSessionEnded: () => void }) {
  const [loading, setLoading] = useState(true);
  const [host, setHost] = useState<Host | null>(null);
  const [vms, setVms] = useState<VM[] | null>(null);
  const [ops, setOps] = useState<Operation[] | null>(null);
  const [lastAt, setLastAt] = useState<Date | null>(null);
  const [failure, setFailure] = useState<ReadResult<unknown> | null>(null);
  const alive = useRef(true);

  const load = useCallback(async () => {
    setLoading(true);
    const r = await read("/api/v1/hosts/local", decodeHost);
    if (!alive.current) return;
    setLoading(false);
    if (r.kind === "ok") {
      // The VM count is a convenience for the summary tiles: if it cannot be read the tile says so and nothing else changes.
      const [v, o] = await Promise.all([read("/api/v1/vms?limit=200", decodeVmList), read("/api/v1/operations?limit=8", decodeOperationList)]);
      if (!alive.current) return;
      setVms(v.kind === "ok" ? v.data.items : null);
      setOps(o.kind === "ok" ? o.data.items : null);
      setHost(r.data);
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
    void load();
    return () => { alive.current = false; };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // The header's Refresh bumps `refresh`: reload in place, so what was last shown stays (marked stale on failure).
  const firstRefresh = useRef(true);
  useEffect(() => {
    if (firstRefresh.current) { firstRefresh.current = false; return; }
    void load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [props.refresh]);

  const summary = host ? readiness(host) : null;
  return (
    <>
      <PageHead title="Dashboard"><p>What this host is doing and whether it is ready.</p></PageHead>
      {failure?.kind === "unreachable" ? <UnreachableBanner lastKnown={lastAt} onRetry={load} /> : null}
      {failure?.kind === "error" ? <ErrorState category={failure.category} correlationId={failure.correlationId} onRetry={load} /> : null}
      <LoadingRegion label="Host status" loading={loading && !host}>
        {host && summary ? (
          <>
            {failure && lastAt ? <StaleNotice lastUpdated={lastAt} now={new Date()} /> : null}
            <section aria-labelledby="host-heading">
              <div className="ds-heading-row"><h2 id="host-heading">{host.name}</h2><StatusPill tone={summaryTone(host)}>{summaryTone(host) === "ok" ? "Ready" : "Needs attention"}</StatusPill></div>
              <StatusMessage tone={summary.tone}>{summary.text}</StatusMessage>
              <Tiles host={host} vms={vms} />
              <section className="ds-card" aria-labelledby="dash-load">
                <h2 id="dash-load">Host load, last hour</h2>
                <UsageChart label="Host CPU and memory use over the last hour"
                  series={hostSeries(host)}
                  empty={host.observed.usage.state === "unavailable" ? "No usage has been sampled yet. The first reading appears within a minute of the service starting." : "No readings in the last hour."} />
              </section>
              <div className="ds-grid2">
                <VmCard vms={vms} />
                <ActivityCard ops={ops} />
              </div>
              <DataTable caption="Capacity and software" rows={[
                ["Processors", `${host.observed.cpu_count} logical`],
                ["Memory", gib(host.observed.memory_mib)],
                ["Operating system", host.observed.distribution.id === "" ? "Not determined" : `${host.observed.distribution.id} ${host.observed.distribution.version_id}`],
                ["Svavyom version", host.observed.agent_version],
                ["Distribution check", VERDICT_TEXT[host.observed.capability_verdict]],
              ] as ReadonlyArray<[string, string]>} rowKey={(r) => r[0]} columns={[
                { header: "Item", cell: (r) => r[0], rowHeader: true },
                { header: "Value", cell: (r) => r[1] },
              ]} />
              <p>The distribution check is matrix conformance only; it is not host qualification.</p>
              <DataTable caption="Virtualization readiness" rows={[
                ["Hardware virtualization (CPU)", host.observed.virtualization.hardware],
                ["KVM device", host.observed.virtualization.kvm_device],
                ["libvirt installed", host.observed.virtualization.libvirt_packages],
                ["QEMU installed", host.observed.virtualization.qemu_packages],
              ] as ReadonlyArray<[string, State]>} rowKey={(r) => r[0]} columns={[
                { header: "Component", cell: (r) => r[0], rowHeader: true },
                { header: "Status", cell: (r) => <StatusPill tone={r[1] === "available" ? "ok" : r[1] === "unavailable" ? "bad" : "warn"}>{STATE_LABEL[r[1]]}</StatusPill> },
              ]} />
              {host.observed.capability_findings.length > 0 ? (
                <>
                  <h3>What needs attention</h3>
                  <ul>
                    {host.observed.capability_findings.map((f) => (
                      <li key={f.code}>{f.remediation !== "" ? f.remediation : FINDING_TEXT[f.code] ?? "See the distribution check above."}</li>
                    ))}
                  </ul>
                </>
              ) : null}
            </section>
          </>
        ) : null}
      </LoadingRegion>
    </>
  );
}

function VmCard({ vms }: { vms: VM[] | null }) {
  return (
    <section className="ds-card" aria-labelledby="dash-vms">
      <div className="ds-cardhead"><h2 id="dash-vms">Virtual machines</h2><a className="ds-button ds-button--sm" href="#/vms">View all</a></div>
      {vms === null ? <p>The VM list could not be read.</p> : vms.length === 0 ? <p>No virtual machines yet.</p> : (
        <DataTable caption="First five virtual machines" rows={vms.slice(0, 5)} rowKey={(v) => v.id} columns={[
          { header: "Name", cell: (v: VM) => <a className="ds-link" href={`#/vms/${v.id}`}>{v.name}</a>, rowHeader: true },
          { header: "State", cell: (v: VM) => <StatusPill tone={POWER_TONE[v.observed.power]}>{POWER_LABEL[v.observed.power]}</StatusPill> },
          { header: "Address", cell: (v: VM) => v.observed.ip_address ?? "-" },
        ]} />
      )}
    </section>
  );
}

/** Recent activity: the latest operations, newest first. */
function ActivityCard({ ops }: { ops: Operation[] | null }) {
  return (
    <section className="ds-card" aria-labelledby="dash-activity">
      <div className="ds-cardhead"><h2 id="dash-activity">Recent activity</h2><a className="ds-button ds-button--sm" href="#/activity">View all</a></div>
      {ops === null ? <p>Recent activity could not be read.</p> : ops.length === 0 ? <p>Nothing has been done on this host yet.</p> : (
        <ul className="ds-list">
          {ops.map((o) => (
            <li key={o.id}>
              <strong>{OP_LABEL[o.type]}</strong> {o.resource_id} <StatusPill tone={OP_STATUS[o.status].tone}>{OP_STATUS[o.status].text}</StatusPill>{" "}
              <span className="ds-muted">{o.created_at.replace("T", " ").replace("Z", " UTC")}</span>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}

function hostSeries(h: Host) {
  const u = h.observed.usage;
  const mem = h.observed.memory_mib;
  return [
    { id: "cpu" as const, label: "CPU", points: u.history.map((p) => ({ at: p.at, value: p.cpu_percent })) },
    ...(mem > 0 ? [{ id: "mem" as const, label: "Memory", points: u.history.map((p) => ({ at: p.at, value: Math.min(100, Math.round((p.memory_used_mib * 100) / mem)) })) }] : []),
  ];
}

/** Summary tiles: only facts the API reports. Nothing here is a live utilisation figure. */
export function Tiles({ host, vms }: { host: Host; vms: VM[] | null }) {
  const st = host.observed.storage;
  const u = host.observed.usage;
  const running = vms ? vms.filter((v) => v.observed.power === "running").length : 0;
  const total = st.pool_total_gib, free = st.pool_free_gib;
  return (
    <StatTiles label="Host summary">
      <StatTile label="Virtual machines" value={vms ? `${running} running` : "Not available"} note={vms ? `of ${vms.length}` : "Not read"} meter={vms && vms.length > 0 ? { used: running, max: vms.length } : undefined} />
      {u.state === "available" && u.cpu_percent !== null
        ? <StatTile label="CPU" value={`${u.cpu_percent}%`} note={`of ${host.observed.cpu_count} logical processors`} meter={{ used: u.cpu_percent, max: 100 }} />
        : <StatTile label="Processors" value={String(host.observed.cpu_count)} note="logical" />}
      {u.state === "available" && u.memory_used_mib !== null && host.observed.memory_mib > 0
        ? <StatTile label="Memory" value={`${gib(u.memory_used_mib)} used`} note={`of ${gib(host.observed.memory_mib)}`} meter={{ used: u.memory_used_mib, max: host.observed.memory_mib }} />
        : <StatTile label="Memory" value={gib(host.observed.memory_mib)} note="installed" />}
      {u.state === "available" && u.disk_kib_s !== null ? <StatTile label="Disk activity" value={formatRate(u.disk_kib_s)} note="read plus write, physical disks" /> : null}
      {u.state === "available" && u.net_kib_s !== null ? <StatTile label="Network traffic" value={formatRate(u.net_kib_s)} note="in plus out, physical interfaces" /> : null}
      <StatTile label="Alerts" value={host.observed.alerts.open === 0 ? "None open" : `${host.observed.alerts.open} open`} note={host.observed.alerts.webhook === "configured" ? "also sent to the webhook" : "shown here only"} />
      {host.observed.nightly_boot ? <StatTile label="Nightly boot check" value={host.observed.nightly_boot.result === "pass" ? "Passed" : host.observed.nightly_boot.result === "fail" ? "Failed" : "Skipped"} note={`${host.observed.nightly_boot.at.replace("T", " ").replace("Z", " UTC")}, ${host.observed.nightly_boot.seconds} s`} /> : null}
      {st.state === "available" && total !== null && free !== null
        ? <StatTile label="Storage pool" value={`${total - free} GiB used`} note={`of ${total} GiB (${free} GiB free)`} meter={{ used: total - free, max: total }} />
        : <StatTile label="Storage pool" value="Not available" note="State unknown" />}
    </StatTiles>
  );
}

function summaryTone(h: Host): "ok" | "warn" {
  return readiness(h).tone === "success" ? "ok" : "warn";
}

/** Plain-language text for reason codes that carry no remediation sentence from the checker. */
const FINDING_TEXT: Record<string, string> = {
  CONTAINERIZED: "Svavyom is running inside a container, so the host itself cannot be checked from here.",
  VIRTUALIZED_HOST: "This host is itself a virtual machine; dedicated (bare-metal) hosts are required.",
};
