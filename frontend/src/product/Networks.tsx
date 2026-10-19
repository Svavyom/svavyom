// Networks (M3): every libvirt network the host reports, marked Svavyom-managed or foreign, and the actions Svavyom offers on its own networks:
// create a managed NAT network, start, stop, autostart on/off and delete. Foreign networks (including the host's pre-existing default network) are shown
// and never changed. A reservation is a static DHCP reservation: the guest still uses DHCP; nothing is configured inside the guest.
import { useCallback, useEffect, useRef, useState } from "react";
import { Button, DataTable, Dialog, EmptyState, ErrorState, LoadingRegion, PageHead, Select, StatTile, StatTiles, StatusMessage, StatusPill, TextField } from "../design-system";
import { read, type ReadResult } from "../api/client";
import { decodeHost, decodeNetworkList } from "../api/decoders";
import type { Host, VirtualNetwork } from "../api/schema";
import { HostBridgeCard } from "./HostBridge";
import { OperationProgress } from "./OperationProgress";
import { useRunner } from "./runner";
import { atLeast, useRole } from "./role";

const NAME_RE = /^[a-z][a-z0-9-]{1,30}[a-z0-9]$/;
const IPV4_RE = /^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)$/;
const CIDR_RE = /^((?:\d{1,3}\.){3}\d{1,3})\/(\d{1,2})$/;

const toInt = (ip: string) => ip.split(".").reduce((n, p) => n * 256 + Number(p), 0);
const RFC1918: ReadonlyArray<[number, number]> = [[toInt("10.0.0.0"), 8], [toInt("172.16.0.0"), 12], [toInt("192.168.0.0"), 16]];

/** Local checks only; the server and the host repeat every one of them. Returns a message, or null when the inputs look right. */
export function checkNetworkInputs(name: string, subnet: string, start: string, end: string): { field: "name" | "subnet" | "dhcp"; message: string } | null {
  if (!NAME_RE.test(name)) return { field: "name", message: "Use 3-32 lower-case letters, digits or hyphens, starting with a letter and not ending with a hyphen." };
  const m = CIDR_RE.exec(subnet);
  if (!m || !IPV4_RE.test(m[1]!)) return { field: "subnet", message: "Enter an IPv4 network such as 10.77.0.0/24." };
  const bits = Number(m[2]);
  const base = toInt(m[1]!);
  const size = 2 ** (32 - bits);
  if (bits < 16 || bits > 29) return { field: "subnet", message: "The prefix length must be between 16 and 29." };
  if (base % size !== 0) return { field: "subnet", message: `Write the network address itself (the host bits must be zero), for example ${[24, 16, 8, 0].map((s) => (base >>> s) & 255).join(".")}/${bits}.` };
  if (!RFC1918.some(([net, b]) => bits >= b && Math.floor(base / 2 ** (32 - b)) === Math.floor(net / 2 ** (32 - b)))) return { field: "subnet", message: "Use a private (RFC 1918) range: 10.0.0.0/8, 172.16.0.0/12 or 192.168.0.0/16." };
  if (!IPV4_RE.test(start) || !IPV4_RE.test(end)) return { field: "dhcp", message: "Enter the first and last address of the DHCP range." };
  const a = toInt(start);
  const b = toInt(end);
  if (a < base + 2 || b > base + size - 2 || a > b) return { field: "dhcp", message: "The DHCP range must lie inside the network, after the gateway (the first address) and before the broadcast address, and start no later than it ends." };
  return null;
}

type Dlg = { kind: "delete" | "stop"; net: VirtualNetwork };

export function Networks(props: { query: string; refresh: number; onSessionEnded: () => void }) {
  const [loading, setLoading] = useState(true);
  const [host, setHost] = useState<Host | null>(null);
  const [nets, setNets] = useState<VirtualNetwork[] | null>(null);
  const [failure, setFailure] = useState<ReadResult<unknown> | null>(null);
  const [name, setName] = useState("");
  const [subnet, setSubnet] = useState("");
  const [start, setStart] = useState("");
  const [end, setEnd] = useState("");
  const [problem, setProblem] = useState<{ field: "name" | "subnet" | "dhcp"; message: string } | null>(null);
  const [dlg, setDlg] = useState<Dlg | null>(null);
  const [kind, setKind] = useState<"nat" | "bridge">("nat");
  const alive = useRef(true);

  const load = useCallback(async () => {
    const [h, n] = await Promise.all([read("/api/v1/hosts/local", decodeHost), read("/api/v1/virtual-networks", decodeNetworkList)]);
    if (!alive.current) return;
    setLoading(false);
    for (const r of [h, n]) if (r.kind === "error" && r.category === "unauthenticated") { props.onSessionEnded(); return; }
    if (h.kind === "ok") setHost(h.data);
    if (n.kind === "ok") setNets(n.data.items);
    setFailure([h, n].find((r) => r.kind !== "ok") ?? null);
  }, [props]);

  const runner = useRunner(props.onSessionEnded, () => { void load(); });
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

  const role = useRole();
  const enabled = host?.observed.creation.enabled === true && atLeast(role, "admin");

  const hostBridge = host?.observed.bridge?.state === "active" ? host.observed.bridge.bridge : null;

  async function create() {
    if (kind === "bridge" && hostBridge) {
      const bad = NAME_RE.test(name) ? null : { field: "name" as const, message: "Use 3-32 lower-case letters, digits or hyphens, starting with a letter and not ending with a hyphen." };
      setProblem(bad);
      if (bad) return;
      const ok = await runner.run({ type: "network_create", kind: "VirtualNetwork", id: name, params: { bridge: hostBridge } });
      if (ok) setName("");
      return;
    }
    const p = checkNetworkInputs(name, subnet, start, end);
    setProblem(p);
    if (p) return;
    const ok = await runner.run({ type: "network_create", kind: "VirtualNetwork", id: name, params: { subnet, dhcp_start: start, dhcp_end: end } });
    if (ok) { setName(""); setSubnet(""); setStart(""); setEnd(""); }
  }

  const act = (n: VirtualNetwork, action: string) => {
    switch (action) {
      case "start": void runner.run({ type: "network_start", kind: "VirtualNetwork", id: n.id }); break;
      case "stop": setDlg({ kind: "stop", net: n }); break;
      case "delete": setDlg({ kind: "delete", net: n }); break;
      case "enable_autostart": void runner.run({ type: "network_autostart", kind: "VirtualNetwork", id: n.id, params: { autostart: "on" } }); break;
      case "disable_autostart": void runner.run({ type: "network_autostart", kind: "VirtualNetwork", id: n.id, params: { autostart: "off" } }); break;
    }
  };
  const LABEL: Record<string, string> = { start: "Start", stop: "Stop", delete: "Delete", enable_autostart: "Turn autostart on", disable_autostart: "Turn autostart off" };

  async function confirm() {
    if (!dlg) return;
    const { kind, net } = dlg;
    setDlg(null);
    await runner.run({ type: kind === "delete" ? "network_delete" : "network_stop", kind: "VirtualNetwork", id: net.id });
  }

  return (
    <>
      <PageHead title="Networks"><p>Managed NAT networks and the host's own networks.</p></PageHead>
      {enabled ? <StatusMessage tone="warning">Development Preview: creating and changing networks is experimental.</StatusMessage> : null}
      {failure?.kind === "unreachable" ? <StatusMessage tone="warning">Svavyom could not be reached. Try again.</StatusMessage> : null}
      {failure?.kind === "error" ? <ErrorState category={failure.category} correlationId={failure.correlationId} onRetry={() => load()} /> : null}
      {runner.error ? <StatusMessage tone="warning">{runner.error}</StatusMessage> : null}
      {runner.op ? <OperationProgress key={runner.op.id} id={runner.op.id} onDone={runner.finish} onSessionEnded={props.onSessionEnded} /> : null}
      <LoadingRegion label="Networks" loading={loading}>
        <p>Networks Svavyom created are marked <strong>Svavyom-managed</strong>. Every other network on the host, including the one that existed before Svavyom, is shown for information and is never changed.</p>
        {nets === null || nets.length === 0 ? null : (
          <StatTiles label="Network summary">
            <StatTile label="Networks" value={String(nets.length)} note={`${nets.filter((x) => x.observed.managed).length} managed by Svavyom`} />
            <StatTile label="Active" value={String(nets.filter((x) => x.observed.state === "active").length)} note={`of ${nets.length}`} meter={{ used: nets.filter((x) => x.observed.state === "active").length, max: nets.length }} />
            <StatTile label="VMs attached" value={String(nets.reduce((n, x) => n + x.observed.attached_vms, 0))} note="across all networks" />
            <StatTile label="Reserved addresses" value={String(nets.reduce((n, x) => n + x.observed.reservations.length, 0))} note="static DHCP reservations" />
          </StatTiles>
        )}
        {nets === null ? null : nets.length === 0 ? <EmptyState title="No networks" reason="The host reports no libvirt networks." /> : (
          <DataTable caption="Networks on this host" rows={nets.filter((x) => props.query.trim() === "" || x.name.toLowerCase().includes(props.query.trim().toLowerCase()))} rowKey={(n) => n.id} columns={[
            { header: "Name", cell: (n: VirtualNetwork) => n.name, rowHeader: true },
            { header: "Owner", cell: (n: VirtualNetwork) => <StatusPill tone={n.observed.managed ? "ok" : "neutral"}>{n.observed.managed ? "Svavyom-managed" : "Foreign (read-only)"}</StatusPill> },
            { header: "State", cell: (n: VirtualNetwork) => <StatusPill tone={n.observed.state === "active" ? "ok" : n.observed.state === "inactive" ? "neutral" : "warn"}>{`${n.observed.state === "active" ? "Active" : n.observed.state === "inactive" ? "Inactive" : "Unknown"}${n.desired.autostart ? ", autostart" : ""}`}</StatusPill> },
            { header: "Mode", cell: (n: VirtualNetwork) => n.desired.mode },
            { header: "Subnet and gateway", cell: (n: VirtualNetwork) => (n.observed.subnet ? `${n.observed.subnet}, gateway ${n.observed.gateway ?? "-"}` : "No IPv4 address") },
            { header: "DHCP range", cell: (n: VirtualNetwork) => (n.observed.dhcp_start ? `${n.observed.dhcp_start} - ${n.observed.dhcp_end ?? "-"}` : "-") },
            { header: "VMs attached", cell: (n: VirtualNetwork) => String(n.observed.attached_vms) },
            { header: "Reserved addresses", cell: (n: VirtualNetwork) => (n.observed.reservations.length === 0 ? "-" : n.observed.reservations.map((r) => `${r.ip} (${r.mac})`).join(", ")) },
            ...(enabled ? [{ header: "Actions", cell: (n: VirtualNetwork) => (n.allowed_actions.length === 0 ? <span>-</span> : (
              <span className="ds-button-row">
                {n.allowed_actions.map((a) => (
                  <Button key={a} variant={a === "delete" ? "destructive" : undefined} disabled={runner.busy} pending={runner.pending === `${n.id}:${a}`} onClick={() => act(n, a)}>{`${LABEL[a] ?? a} ${n.name}`}</Button>
                ))}
              </span>)) }] : []),
          ]} />
        )}
      </LoadingRegion>
      {host ? <HostBridgeCard bridge={host.observed.bridge} onExpired={() => { void load(); }} /> : null}
      {enabled ? (
        <section className="ds-card">
          <h2>{hostBridge ? "Create a managed network" : "Create a managed NAT network"}</h2>
          {kind === "bridge" && hostBridge
            ? <p>A bridge network puts its VMs on the host&apos;s own network through the bridge <strong>{hostBridge}</strong>. They get their addresses from that network (its DHCP server or their own configuration), not from Svavyom, so Svavyom cannot show their addresses or reserve one. The bridge is not changed.</p>
            : <p>A NAT network lets its VMs reach outside through the host and be reached from the host. Svavyom defines it in libvirt with its own bridge; it does not edit the host&apos;s network interfaces or routes, and it refuses a range that overlaps another network or the host&apos;s own.</p>}
          <form onSubmit={(e) => { e.preventDefault(); void create(); }} noValidate aria-label="Create network">
            {hostBridge ? <Select label="Network type" value={kind} onChange={(v) => { setKind(v === "bridge" ? "bridge" : "nat"); setProblem(null); }} options={[{ value: "nat", label: "NAT (private network behind the host)" }, { value: "bridge", label: `Bridge (on the host network through ${hostBridge})` }]} /> : null}
            <TextField id="net-name" label="Name" value={name} onChange={setName} required error={problem?.field === "name" ? problem.message : undefined} />
            {kind === "bridge" && hostBridge ? null : <>
            <TextField id="net-subnet" label="Subnet" value={subnet} onChange={setSubnet} required description="A private IPv4 network in CIDR form, for example 10.77.0.0/24. The gateway is its first address." error={problem?.field === "subnet" ? problem.message : undefined} />
            <TextField id="net-start" label="DHCP range start" value={start} onChange={setStart} required error={problem?.field === "dhcp" ? problem.message : undefined} />
            <TextField id="net-end" label="DHCP range end" value={end} onChange={setEnd} required />
            </>}
            <div className="ds-button-row"><Button type="submit" variant="primary" disabled={runner.busy}>Create network</Button></div>
          </form>
        </section>
      ) : null}
      <Dialog title={dlg?.kind === "delete" ? `Delete ${dlg.net.name}?` : `Stop ${dlg?.net.name ?? ""}?`} open={dlg !== null} onClose={() => setDlg(null)}>
        {dlg?.kind === "delete" ? <p>Deleting {dlg.net.name} removes this Svavyom-managed network and its static reservations. No VM is attached to it. This cannot be undone.</p>
          : dlg ? <p>Stopping {dlg.net.name} takes the network down. No attached VM is running; VMs on it cannot start until the network is started again.</p> : null}
        <div className="ds-button-row">
          <Button variant="destructive" onClick={() => { void confirm(); }}>{dlg?.kind === "delete" ? "Delete network permanently" : "Stop network"}</Button>
          <Button onClick={() => setDlg(null)}>Cancel</Button>
        </div>
      </Dialog>
    </>
  );
}
