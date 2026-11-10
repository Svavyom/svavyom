// System (status page): which Svavyom is running, which services it depends on, whether each one answers, and what to do when one does not.
// The API can only say whether a peer's socket answered; the unit's own state, the journal and the fix are on the host, so each row names the exact commands
// to run there. Words live here and are keyed by the closed ids the server sends: no path or message from the host reaches the page.
import { useCallback, useEffect, useRef, useState } from "react";
import { DataTable, ErrorState, LoadingRegion, PageHead, StaleNotice, StatusMessage, StatusPill, UnreachableBanner } from "../design-system";
import { read, type ReadResult } from "../api/client";
import { decodeHost } from "../api/decoders";
import type { Host } from "../api/schema";

type Service = Host["observed"]["services"][number];

const WHAT: Record<Service["id"], { name: string; does: string; unit: string }> = {
  api: { name: "Web console and API", does: "Serves this page and every request it makes.", unit: "svavyom-api" },
  agent: { name: "Host agent", does: "Reads virtual machines and host facts from libvirt, read-only.", unit: "svavyom-agent" },
  mutation: { name: "Mutation service", does: "Makes the changes: create, start, stop, snapshot, back up, restore.", unit: "svavyom-mutation" },
  console: { name: "Console broker", does: "Carries the serial and graphical consoles.", unit: "svavyom-console" },
  offsite: { name: "Off-host backup service", does: "Copies backups to the off-host targets you declared.", unit: "svavyom-offsite" },
};

const OFF: Partial<Record<Service["id"], string>> = {
  mutation: "Turned off: this installation was made without --enable-mutation, so virtual machines can be viewed but not created or changed.",
  console: "Turned off: this installation was made without --enable-console, so there is no console.",
  offsite: "Not configured: no off-host backup target is declared, so backups stay on this host.",
  agent: "Not configured: the API was started without the host agent, so no virtual machine is listed.",
};

function fix(s: Service): string {
  const u = WHAT[s.id].unit;
  if (s.state === "ok") return "Nothing to do.";
  if (s.state === "not_enabled") return OFF[s.id] ?? "Turned off.";
  return `Not answering. On the host: sudo svavyom-ctl status, then journalctl -u ${u} -n 100 --no-pager for the cause. When it is fixed: sudo systemctl restart ${u}.`;
}

const PILL: Record<Service["state"], { tone: "ok" | "warn" | "bad" | "neutral"; text: string }> = {
  ok: { tone: "ok", text: "Answering" }, unreachable: { tone: "bad", text: "Not answering" }, not_enabled: { tone: "neutral", text: "Turned off" },
};

const when = (iso: string) => iso.replace("T", " ").replace("Z", " UTC");

export function System(props: { refresh: number; onSessionEnded: () => void }) {
  const [loading, setLoading] = useState(true);
  const [host, setHost] = useState<Host | null>(null);
  const [lastAt, setLastAt] = useState<Date | null>(null);
  const [failure, setFailure] = useState<ReadResult<unknown> | null>(null);
  const alive = useRef(true);

  const load = useCallback(async () => {
    setLoading(true);
    const r = await read("/api/v1/hosts/local", decodeHost);
    if (!alive.current) return;
    setLoading(false);
    if (r.kind === "ok") { setHost(r.data); setLastAt(new Date()); setFailure(null); }
    else if (r.kind === "error" && r.category === "unauthenticated") props.onSessionEnded();
    else setFailure(r);
  }, [props]);

  useEffect(() => {
    alive.current = true;
    void load();
    const t = setInterval(() => { void load(); }, 15000);
    return () => { alive.current = false; clearInterval(t); };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);
  const first = useRef(true);
  useEffect(() => {
    if (first.current) { first.current = false; return; }
    void load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [props.refresh]);

  const o = host?.observed;
  const down = (o?.services ?? []).filter((s) => s.state === "unreachable");
  return (
    <>
      <PageHead title="System"><p>Which Svavyom is running here, which services it depends on, and what to do when one is not answering.</p></PageHead>
      {failure?.kind === "unreachable" ? <UnreachableBanner lastKnown={lastAt} onRetry={() => load()} /> : null}
      {failure?.kind === "error" ? <ErrorState category={failure.category} correlationId={failure.correlationId} onRetry={() => load()} /> : null}
      <LoadingRegion label="System" loading={loading && !host}>
        {host && failure && lastAt ? <StaleNotice lastUpdated={lastAt} now={new Date()} /> : null}
        {o ? (
          <>
            {down.length > 0 ? <StatusMessage tone="warning">{down.map((s) => WHAT[s.id].name).join(", ")} {down.length === 1 ? "is" : "are"} not answering. See what to do in the table below.</StatusMessage> : <StatusMessage>Every service that is turned on is answering.</StatusMessage>}
            <section aria-labelledby="sys-version-title">
              <h2 id="sys-version-title">This installation</h2>
              <DataTable caption="This installation" rows={[
                ["Svavyom version", o.agent_version === "dev" ? "dev (a development build; a release reports its version)" : o.agent_version],
                ["API running since", o.started_at ? when(o.started_at) : "Not known"],
                ["Operating system", o.distribution.id === "" ? "Not determined" : `${o.distribution.id} ${o.distribution.version_id}`],
              ] as ReadonlyArray<[string, string]>} rowKey={(r) => r[0]} columns={[
                { header: "Item", cell: (r) => r[0], rowHeader: true },
                { header: "Value", cell: (r) => r[1] },
              ]} />
            </section>
            <section aria-labelledby="sys-services-title">
              <h2 id="sys-services-title">Services</h2>
              <p>This is what the API sees: it connects to each service and reports whether it answered a few seconds ago. It does not read the service&apos;s unit state, which is on the host.</p>
              <DataTable caption="Services Svavyom depends on" rows={o.services} rowKey={(s: Service) => s.id} columns={[
                { header: "Service", cell: (s: Service) => WHAT[s.id].name, rowHeader: true },
                { header: "What it does", cell: (s: Service) => WHAT[s.id].does },
                { header: "State", cell: (s: Service) => <StatusPill tone={PILL[s.state].tone}>{PILL[s.state].text}</StatusPill> },
                { header: "What to do", cell: (s: Service) => fix(s) },
              ]} />
            </section>
            <section className="ds-card" aria-labelledby="sys-help-title">
              <h2 id="sys-help-title">If something is wrong</h2>
              <ol>
                <li>On the host run <code>sudo svavyom-ctl status</code>. It lists every unit and socket with PASS, NOT_READY or FAIL, and a remedy for each.</li>
                <li>For the unit that failed, read the cause: <code>journalctl -u svavyom-UNIT -n 100 --no-pager</code>. A service refuses to start when a file it trusts is owned or writable by the wrong user.</li>
                <li>Run <code>sudo svavyom-ctl validate-config</code> to check the configuration, fix what it names, then <code>sudo systemctl restart svavyom-UNIT</code>.</li>
                <li>If an upgrade caused it, <code>sudo svavyom-ctl rollback</code> returns to the backup the upgrade made (see INSTALLING.md).</li>
              </ol>
            </section>
            {o.capability_findings.length > 0 ? (
              <section aria-labelledby="sys-find-title">
                <h2 id="sys-find-title">Host findings</h2>
                <ul>{o.capability_findings.map((f) => <li key={f.code}>{f.remediation}</li>)}</ul>
              </section>
            ) : null}
          </>
        ) : null}
      </LoadingRegion>
    </>
  );
}
