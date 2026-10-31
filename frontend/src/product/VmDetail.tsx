// VM inventory (journey J3, VM panel half of M1-E04-S01): which virtual machines exist on the managed host, their observed power
// state, how to reach them, and the lifecycle actions the server offers for a Svavyom-managed VM (Start, Stop, Reboot, Force off,
// Delete), only when the operator has enabled the Development Preview mutation switch. Force off and Delete ask for confirmation;
// Stop never escalates to Force off by itself.
import { useCallback, useEffect, useRef, useState } from "react";
import { Button, DataTable, Dialog, EmptyState, ErrorState, LoadingRegion, PageHead, Select, StaleNotice, StatusMessage, StatusPill, TextArea, TextField, UnreachableBanner, UsageChart } from "../design-system";
import { newIdempotencyKey, read, type ReadResult } from "../api/client";
import { decodeBackupList, decodeHost, decodeImageList, decodeVmList, decodeVolumeList } from "../api/decoders";
import { submitOperation } from "../api/session";
import type { Backup, Host, Image, Operation, VM, Volume } from "../api/schema";
import { readiness } from "./Dashboard";
import { formatRate, POWER_LABEL, POWER_TONE } from "./vmparts";
import { atLeast, useRole } from "./role";
import { OperationProgress } from "./OperationProgress";
import { guidance, imageStateLabel } from "./guidance";
import { useRunner } from "./runner";
import { BackupScheduleCard } from "./BackupSchedule";

/** Connection hint for a VM: the observed lease and the image's login user. Observation only; Svavyom never runs SSH. */
export function Connection({ vm }: { vm: VM }) {
  const o = vm.observed;
  const [copied, setCopied] = useState(false);
  if (o.power !== "running" || !o.managed) return <span>-</span>;
  if (!o.ip_address) return <span>Waiting for an address</span>;
  if (!o.login_user) return <span>{o.ip_address}</span>;
  const hint = `ssh ${o.login_user}@${o.ip_address}`;
  return (
    <span>
      <code>{hint}</code>{" "}
      <Button size="sm" ariaLabel={copied ? undefined : `Copy SSH command for ${vm.name}`} onClick={() => { void navigator.clipboard?.writeText(hint).then(() => setCopied(true), () => setCopied(false)); }}>{copied ? "Copied" : "Copy"}</Button>
    </span>
  );
}

type Action = "start" | "stop" | "reboot" | "force_off" | "delete";
const ACTIONS: { type: Action; label: string; confirm: boolean }[] = [
  { type: "start", label: "Start", confirm: false }, { type: "stop", label: "Stop", confirm: false }, { type: "reboot", label: "Reboot", confirm: false },
  { type: "force_off", label: "Force off", confirm: true }, { type: "delete", label: "Delete", confirm: true },
];

// M2 storage actions on a Stopped VM. Snapshot and back up run directly; resize and reinstall ask for their inputs first.
type StorageAction = "resize" | "reinstall" | "snapshot" | "backup" | "compute" | "reserve_ip" | "release_ip" | "eject_iso" | "graphics_enable" | "iso_attach" | "rescue" | "unrescue";
const STORAGE_ACTIONS: { type: StorageAction; label: string; short?: string }[] = [
  { type: "resize", label: "Resize" }, { type: "snapshot", label: "Snapshot" }, { type: "backup", label: "Back up" }, { type: "reinstall", label: "Reinstall" },
  { type: "compute", label: "Change size of", short: "Change size" }, { type: "reserve_ip", label: "Reserve address for", short: "Reserve address" }, { type: "release_ip", label: "Release address of", short: "Release address" },
  { type: "eject_iso", label: "Eject installation media of", short: "Eject installation media" },
  { type: "graphics_enable", label: "Enable the graphical console of", short: "Enable graphical console" },
  { type: "iso_attach", label: "Attach installation media to", short: "Attach installation media" },
  { type: "rescue", label: "Start rescue mode for", short: "Start rescue mode" },
  { type: "unrescue", label: "Leave rescue mode of", short: "Leave rescue mode" },
];

/** What a VM reports about its network, with the plain diagnosis of a missing address. Observation only; Svavyom never reaches into the guest. */
export function NetworkInfo({ vm }: { vm: VM }) {
  const n = vm.observed.network;
  if (!n) return <span>-</span>;
  let hint: string | null = null;
  if (n.state === "inactive") hint = "The network is not active, so the VM cannot get an address.";
  else if (vm.observed.power === "running" && !vm.observed.ip_address) hint = "No address yet: the VM is waiting for a DHCP lease (it can take a minute after boot).";
  return (
    <span>
      {n.name} <code>{n.mac}</code>
      {n.reserved_ip ? <> reserved {n.reserved_ip}</> : null}
      {hint ? <span className="ds-block">{hint}</span> : null}
    </span>
  );
}

function looksLikePublicKey(k: string): boolean { return /^(ssh-|ecdsa-)\S+ \S+/.test(k) && !/[\r\n]/.test(k) && !/PRIVATE KEY/.test(k); }

export function VmDetail(props: { vmId: string; refresh: number; onSessionEnded: () => void }) {
  const [loading, setLoading] = useState(true);
  const [vms, setVms] = useState<VM[] | null>(null);
  const [backups, setBackups] = useState<Backup[]>([]);
  const [host, setHost] = useState<Host | null>(null);
  const [lastAt, setLastAt] = useState<Date | null>(null);
  const [failure, setFailure] = useState<ReadResult<unknown> | null>(null);
  const [startOp, setStartOp] = useState<{ vm: string; id: string } | null>(null);
  const [startDone, setStartDone] = useState(false);
  const [deleted, setDeleted] = useState(false);
  const [startError, setStartError] = useState<string | null>(null);
  const [starting, setStarting] = useState<string | null>(null);
  const [confirm, setConfirm] = useState<{ vm: VM; type: Action } | null>(null);
  const [dialog, setDialog] = useState<{ vm: VM; type: "resize" | "reinstall" | "compute" | "reserve_ip" | "iso_attach" | "rescue" } | null>(null);
  const [isos, setIsos] = useState<Image[]>([]);
  const [isoId, setIsoId] = useState("");
  const [boot, setBoot] = useState<"cdrom" | "disk">("cdrom");
  const [cpus, setCpus] = useState("");
  const [mem, setMem] = useState("");
  const [ip, setIp] = useState("");
  const [newSize, setNewSize] = useState("");
  const [imageId, setImageId] = useState("");
  const [images, setImages] = useState<Image[]>([]);
  const [volumes, setVolumes] = useState<Volume[]>([]);
  const [key, setKey] = useState("");
  const [formError, setFormError] = useState<string | null>(null);
  const [mediaNames, setMediaNames] = useState<Record<string, string>>({});
  const alive = useRef(true);
  const startKeys = useRef<Map<string, string>>(new Map());

  const load = useCallback(async (cursor: string | null) => {
    setLoading(true);
    const path = `/api/v1/vms?limit=200${cursor ? `&cursor=${encodeURIComponent(cursor)}` : ""}`;
    const [r, h, b, vo] = await Promise.all([read(path, decodeVmList), cursor ? Promise.resolve(null) : read("/api/v1/hosts/local", decodeHost), read("/api/v1/backups?limit=200", decodeBackupList), read("/api/v1/volumes?limit=200", decodeVolumeList)]);
    if (!alive.current) return;
    setLoading(false);
    if (vo.kind === "ok") setVolumes(vo.data.items);
    if (h && h.kind === "ok") setHost(h.data);
    if (b.kind === "ok") setBackups(b.data.items);
    if (r.kind === "ok") {
      setVms((prev) => (cursor && prev ? [...prev, ...r.data.items] : r.data.items));
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

  async function run(vm: VM, type: Action) {
    setStartError(null);
    setStartDone(false);
    setConfirm(null);
    setStarting(`${vm.id}:${type}`);
    // One key per VM and intent: pressing the button again after an unknown outcome reuses it, so the server can recognise the replay.
    const k = `${vm.id}:${type}`;
    if (!startKeys.current.has(k)) startKeys.current.set(k, newIdempotencyKey());
    const r = await submitOperation({ type, kind: "VM", id: vm.id, idempotency_key: startKeys.current.get(k) });
    setStarting(null);
    if (r.kind === "ok") { setStartOp({ vm: vm.id, id: r.data.id }); return; }
    if (r.kind === "unreachable") { setStartError("Svavyom could not confirm that the request arrived. Refresh the list to see whether it took effect."); return; }
    if (r.category === "unauthenticated") { props.onSessionEnded(); return; }
    startKeys.current.delete(k);
    setStartError(r.category === "conflict" ? "The VM is no longer in a state this action applies to. Refresh the list." : r.category === "prohibited" ? "This action is not available for this VM." : "The action could not be started. Try again later.");
  }

  function started(op: Operation) {
    setStartDone(true);
    if (op.status === "succeeded") startKeys.current.delete(`${op.resource_id}:${op.type}`);
    if (op.status === "succeeded" && op.type === "delete") setDeleted(true);
    void load(null);
  }

  const storage = useRunner(props.onSessionEnded, () => { void load(null); });

  async function openDialog(vm: VM, type: "resize" | "reinstall" | "compute" | "reserve_ip" | "iso_attach" | "rescue") {
    setFormError(null);
    setNewSize("");
    setKey("");
    setIp("");
    setCpus(String(host?.observed.creation.vcpu_options[0] ?? ""));
    setMem(String(host?.observed.creation.memory_mib_options[0] ?? ""));
    setDialog({ vm, type });
    if (type === "iso_attach" || type === "rescue") {
      setBoot("cdrom");
      const r = await read("/api/v1/images", decodeImageList);
      if (!alive.current) return;
      // A medium that is attached already is not offered again (DR-031); rescue needs none attached, so the filter changes nothing for it.
      const media = r.kind === "ok" ? r.data.items.filter((i) => i.observed.media === "iso" && !vm.observed.isos.includes(i.id)) : [];
      setIsos(media);
      setIsoId(media[0]?.id ?? "");
    }
    if (type === "reinstall") {
      const r = await read("/api/v1/images", decodeImageList);
      if (!alive.current) return;
      const usable = r.kind === "ok" ? r.data.items.filter((i) => i.observed.qualification === "qualified") : [];
      setImages(usable);
      setImageId(usable[0]?.id ?? "");
    }
  }

  async function submitDialog() {
    if (!dialog) return;
    const { vm, type } = dialog;
    if (type === "compute") {
      const c = host?.observed.creation;
      if (!c || !c.vcpu_options.includes(Number(cpus)) || !c.memory_mib_options.includes(Number(mem))) { setFormError("Choose one of the sizes this host offers."); return; }
      setDialog(null);
      await storage.run({ type: "compute", kind: "VM", id: vm.id, params: { vcpus: Number(cpus), memory_mib: Number(mem) } });
      return;
    }
    if (type === "reserve_ip") {
      if (!/^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)$/.test(ip)) { setFormError("Enter an IPv4 address inside the network, for example 10.77.0.50."); return; }
      setDialog(null);
      await storage.run({ type: "reserve_ip", kind: "VM", id: vm.id, params: { ip_address: ip } });
      return;
    }
    if (type === "iso_attach" || type === "rescue") {
      if (isoId === "") { setFormError("No installation media has been imported on this host yet. The host administrator imports an ISO with register-image."); return; }
      setDialog(null);
      await storage.run(type === "rescue" ? { type: "rescue", kind: "VM", id: vm.id, params: { image_id: isoId } } : { type: "iso_attach", kind: "VM", id: vm.id, params: { image_id: isoId, boot: vm.observed.isos.length > 0 ? "disk" : boot } });
      return;
    }
    if (type === "resize") {
      const cur = vm.observed.disk_gib ?? 0;
      const n = Number(newSize);
      if (!/^\d{1,4}$/.test(newSize) || n <= cur || n > 4096) { setFormError(`Enter a whole number of GiB larger than the current ${cur} GiB (at most 4096). A disk can only grow.`); return; }
      setDialog(null);
      await storage.run({ type: "resize", kind: "VM", id: vm.id, params: { disk_gib: n } });
      return;
    }
    const k = key.trim();
    if (imageId === "") { setFormError("No image has been qualified on real hardware yet, so there is nothing to reinstall from."); return; }
    if (!looksLikePublicKey(k)) { setFormError("This must be one public key on one line, starting with ssh-ed25519, ssh-rsa or ecdsa-. Never paste a private key."); if (/PRIVATE KEY/.test(k)) setKey(""); return; }
    setDialog(null);
    await storage.run({ type: "reinstall", kind: "VM", id: vm.id, params: { image_id: imageId, ssh_public_key: k } });
  }

  // The header's Refresh bumps `refresh`: reload in place, so what was last shown stays (marked stale on failure).
  const firstRefresh = useRef(true);
  useEffect(() => {
    if (firstRefresh.current) { firstRefresh.current = false; return; }
    void load(null);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [props.refresh]);

  const role = useRole();
  const vm = vms?.find((v) => v.id === props.vmId) ?? null;
  // The names of the attached media come from the catalog; the image id stands in until they are read (or when they cannot be).
  const mediaKey = vm?.observed.isos.join(",") ?? "";
  useEffect(() => {
    if (mediaKey === "") return;
    let live = true;
    void read("/api/v1/images", decodeImageList).then((r) => {
      if (live && alive.current && r.kind === "ok") setMediaNames(Object.fromEntries(r.data.items.filter((i) => i.observed.media === "iso").map((i) => [i.id, i.name])));
    });
    return () => { live = false; };
  }, [mediaKey]);
  const mediaName = (id: string) => mediaNames[id] ?? id;
  const notReady = host ? readiness(host) : null;
  const enabled = host?.observed.creation.enabled === true;
  const unqualified = host?.observed.creation.reasons.includes("image_unqualified") === true;
  const idle = (startOp === null || startDone) && !storage.busy;
  const offered = vm ? ACTIONS.filter((a) => vm.allowed_actions.includes(a.type)) : [];
  const offeredStorage = vm ? STORAGE_ACTIONS.filter((a) => (vm.allowed_actions as string[]).includes(a.type) && (a.type !== "backup" || host?.observed.storage.backups_configured === true)) : [];
  const lifecycle = (type: Action) => {
    const a = offered.find((x) => x.type === type);
    if (!a || !vm) return null;
    return (
      <Button key={a.type} variant={a.confirm ? "destructive" : type === "start" ? "primary" : undefined} ariaLabel={`${a.label} ${vm.name}`}
        pending={starting === `${vm.id}:${a.type}`} disabled={(startOp !== null && !startDone) || storage.busy}
        onClick={() => { if (a.confirm) setConfirm({ vm, type: a.type }); else void run(vm, a.type); }}>{a.label}</Button>
    );
  };
  const manage = (types: StorageAction[]) => offeredStorage.filter((a) => types.includes(a.type)).map((a) => vm && (
    <Button key={a.type} size="sm" ariaLabel={`${a.label} ${vm.name}`} variant={a.type === "reinstall" ? "destructive" : undefined}
      pending={storage.pending === `${vm.id}:${a.type}`} disabled={!idle}
      onClick={() => { if (a.type === "resize" || a.type === "reinstall" || a.type === "compute" || a.type === "reserve_ip" || a.type === "iso_attach" || a.type === "rescue") void openDialog(vm, a.type); else void storage.run({ type: a.type, kind: "VM", id: vm.id }); }}>{a.short ?? a.label}</Button>
  ));
  const myBackups = vm ? backups.filter((b) => b.desired.source_volume_id === `${vm.id}-root`) : [];
  return (
    <>
      <PageHead title={vm?.name ?? props.vmId} actions={vm && enabled ? (
        <>
          {lifecycle("start")}{lifecycle("stop")}{lifecycle("reboot")}
          {vm.observed.managed && atLeast(role, "operator") ? <a className="ds-button" aria-label={`Console ${vm.name}`} href={`#/console/${vm.id}`}>Console</a> : null}
          {vm.observed.managed && atLeast(role, "operator") && vm.observed.graphical_console === "present" && vm.observed.power === "running" ? <a className="ds-button ds-button--primary" aria-label={`Graphical console ${vm.name}`} href={`#/graphics/${vm.id}`}>Graphical console</a> : null}
          {lifecycle("force_off")}{lifecycle("delete")}
        </>
      ) : null}>
        <p className="ds-crumb"><a className="ds-link" href="#/vms">Virtual machines</a>{vm ? <> <StatusPill tone={POWER_TONE[vm.observed.power]}>{POWER_LABEL[vm.observed.power]}</StatusPill></> : null}</p>
      </PageHead>
      {enabled ? <StatusMessage tone="warning">Development Preview: creating and starting VMs is experimental and has not been qualified on real hardware.</StatusMessage> : null}
      {notReady && notReady.tone === "warning" ? <StatusMessage tone="warning">{notReady.text}</StatusMessage> : null}
      {failure?.kind === "unreachable" ? <UnreachableBanner lastKnown={lastAt} onRetry={() => load(null)} /> : null}
      {failure?.kind === "error" ? <ErrorState category={failure.category} correlationId={failure.correlationId} onRetry={() => load(null)} /> : null}
      {anyAddress(vm) && unqualified ? <StatusMessage tone="warning">An address was observed for a running VM. That does not prove SSH works: no image on this installation has been qualified on real hardware, so the VM may not have booted fully or accepted your key. Svavyom never connects to the VM for you.</StatusMessage> : null}
      {startError ? <StatusMessage tone="warning">{startError}</StatusMessage> : null}
      {startOp ? <OperationProgress key={startOp.id} id={startOp.id} onDone={started} onSessionEnded={props.onSessionEnded} /> : null}
      {storage.error ? <StatusMessage tone="warning">{storage.error}</StatusMessage> : null}
      {storage.op ? <OperationProgress key={storage.op.id} id={storage.op.id} onDone={storage.finish} onSessionEnded={props.onSessionEnded} /> : null}
      <LoadingRegion label="Virtual machine" loading={loading && !vms}>
        {vms && failure && lastAt ? <StaleNotice lastUpdated={lastAt} now={new Date()} /> : null}
        {vms && !vm ? <EmptyState title={deleted ? "This VM was removed" : "VM not found"} reason={deleted ? "The VM, its disk and its cloud-init seed are gone from the host. The base image was not touched." : "No virtual machine with this name exists on this host. It may have been deleted."} action={<a className="ds-button ds-button--primary" href="#/vms">Back to the VM list</a>} /> : null}
        {vm ? (
          <div className="ds-grid2">
            <section className="ds-card ds-span" aria-labelledby="vm-usage">
              <h2 id="vm-usage">CPU use, last hour</h2>
              <UsageChart label={`CPU use of ${vm.name} over the last hour`}
                series={[{ id: "cpu", label: "CPU of this VM", points: vm.observed.usage.history.map((p) => ({ at: p.at, value: p.cpu_percent })) }]}
                empty={vm.observed.power !== "running" ? "Usage is sampled while the VM is running." : "No samples yet. The first appears within a minute of the VM starting."} />
            </section>
            <section className="ds-card" aria-labelledby="vm-details">
              <h2 id="vm-details">Details</h2>
              <dl>
                <dt>State</dt><dd>{POWER_LABEL[vm.observed.power]}</dd>
                {vm.observed.managed ? <><dt>Guest type</dt><dd>{vm.observed.guest_profile === "windows" ? "Windows" : "Linux"}</dd></> : null}
                <dt>Size</dt><dd>{vm.observed.vcpus === null || vm.observed.memory_mib === null ? "-" : `${vm.observed.vcpus} vCPU, ${vm.observed.memory_mib} MiB memory`}</dd>
                {vm.observed.managed && vm.observed.isos.length > 0 ? <><dt>Installation media</dt><dd>{vm.observed.isos.map(mediaName).join(", ")}{vm.observed.power === "stopped" ? "" : " (stop the VM to eject it)"}</dd></> : null}
                <dt>Memory in use</dt><dd>{vm.observed.usage.state === "available" && vm.observed.usage.memory_used_mib !== null && vm.observed.usage.memory_used_mib > 0 ? `${vm.observed.usage.memory_used_mib} MiB` : "-"}</dd>
                <dt>Disk activity</dt><dd>{vm.observed.usage.state === "available" && vm.observed.usage.disk_kib_s !== null ? formatRate(vm.observed.usage.disk_kib_s) : "-"}</dd>
                <dt>Network traffic</dt><dd>{vm.observed.usage.state === "available" && vm.observed.usage.net_kib_s !== null ? formatRate(vm.observed.usage.net_kib_s) : "-"}</dd>
                <dt>Connection</dt><dd><Connection vm={vm} /></dd>
                <dt>Network</dt><dd><NetworkInfo vm={vm} /></dd>
                <dt>Disk (virtual size)</dt><dd>{vm.observed.disk_gib === null ? "-" : `${vm.observed.disk_gib} GiB`}</dd>
                <dt>Last seen</dt><dd>{vm.observed.last_seen_at}</dd>
              </dl>
              {enabled ? <div className="ds-button-row">{manage(["resize", "compute", "reserve_ip", "release_ip", "reinstall"])}</div> : null}
            </section>
            <section className="ds-card" aria-labelledby="vm-snapshots">
              <h2 id="vm-snapshots">Snapshots</h2>
              {vm.observed.snapshots.length === 0 ? <p>No snapshots. A snapshot is a restore point inside the disk file, not a backup.</p> : (
                <ul className="ds-list">{vm.observed.snapshots.map((s) => <li key={s.id}><code>{s.id}</code> <span className="ds-muted">{s.created_at}</span></li>)}</ul>
              )}
              {enabled ? <div className="ds-button-row">{manage(["snapshot"])}<a className="ds-link" href="#/storage">Restore or delete in Storage and recovery</a></div> : null}
            </section>
            {vm.observed.managed ? (
              <section className="ds-card" aria-labelledby="vm-media">
                <h2 id="vm-media">Installation media and rescue</h2>
                {vm.observed.rescue ? <StatusMessage tone="warning">This VM is in rescue mode: next time it starts it boots the rescue system, and its own disk is attached as an extra disk. Leave rescue mode when you are done.</StatusMessage> : null}
                <dl>
                  <dt>Installation media</dt>
                  <dd>
                    {vm.observed.isos.length === 0 ? "None attached" : (
                      <ul className="ds-list">
                        {vm.observed.isos.map((id) => (
                          <li key={id}>
                            {mediaName(id)}{" "}
                            {enabled && (vm.allowed_actions as string[]).includes("eject_iso")
                              ? <Button size="sm" ariaLabel={`Eject ${mediaName(id)} from ${vm.name}`} disabled={!idle}
                                  onClick={() => { void storage.run({ type: "eject_iso", kind: "VM", id: vm.id, params: { image_id: id } }); }}>Eject</Button>
                              : null}
                          </li>
                        ))}
                      </ul>
                    )}
                    {vm.observed.isos.length > 0 && vm.observed.power !== "stopped" ? <span className="ds-muted"> (stop the VM to eject it)</span> : null}
                  </dd>
                  <dt>Graphical console</dt><dd>{vm.observed.graphical_console === "present" ? "Available while the VM runs" : "Not enabled for this VM"}</dd>
                </dl>
                <p className="ds-muted">Attach an installer or a tool ISO while the VM is stopped, then start it and use the graphical console. Rescue mode boots a rescue ISO with the VM&apos;s own disk attached, for example to reset a password or repair a boot loader.</p>
                {enabled ? <div className="ds-button-row">{manage(["graphics_enable", "iso_attach", "rescue", "unrescue"])}</div> : null}
              </section>
            ) : null}
            <section className="ds-card" aria-labelledby="vm-volumes">
              <h2 id="vm-volumes">Data volumes</h2>
              {vm.observed.managed && vm.observed.guest_profile === "windows" ? <p className="ds-muted">Volumes attach as virtio disks. Windows shows them only after the virtio storage driver is installed in the VM.</p> : null}
              {volumes.filter((v) => v.desired.attached_to === vm.name && !v.id.endsWith("-root")).length === 0
                ? <p>No data volumes are attached. A data volume is an extra disk you attach while the VM is stopped.</p>
                : <ul className="ds-list">{volumes.filter((v) => v.desired.attached_to === vm.name && !v.id.endsWith("-root")).map((v) => <li key={v.id}>{v.name} <span className="ds-muted">{v.desired.size_gib} GiB</span></li>)}</ul>}
              <a className="ds-link" href="#/storage">Create, attach, detach or delete in Storage and recovery</a>
            </section>
            <section className="ds-card" aria-labelledby="vm-backups">
              <h2 id="vm-backups">Backups</h2>
              {myBackups.length === 0 ? <p>No backups of this VM. Backups are local to this host and need the VM stopped.</p> : (
                <ul className="ds-list">{myBackups.map((b) => <li key={b.id}><code>{b.id}</code> <StatusPill tone={b.observed.state === "complete" ? "ok" : b.observed.state === "failed" ? "bad" : "warn"}>{b.observed.state === "complete" ? "Complete" : b.observed.state === "failed" ? "Damaged" : "In progress"}</StatusPill></li>)}</ul>
              )}
              {enabled ? <div className="ds-button-row">{manage(["backup"])}</div> : null}
            </section>
            {vm.observed.managed ? <BackupScheduleCard vm={vm} host={host} busy={!idle} run={storage.run} /> : null}
          </div>
        ) : null}
      </LoadingRegion>
      <Dialog title={confirm?.type === "delete" ? `Delete ${confirm.vm.name}?` : `Force off ${confirm?.vm.name ?? ""}?`} open={confirm !== null} onClose={() => setConfirm(null)}>
        {confirm?.type === "delete"
          ? <p>Delete permanently removes this stopped VM, its disk and its cloud-init seed from the host. The base image is not touched. This cannot be undone.</p>
          : <p>Force off cuts power immediately, like pulling the plug. Unsaved data in the VM is lost. Nothing is deleted.</p>}
        <div className="ds-button-row">
          <Button variant="destructive" onClick={() => { if (confirm) void run(confirm.vm, confirm.type); }}>{confirm?.type === "delete" ? "Delete permanently" : "Confirm force off"}</Button>
          <Button onClick={() => setConfirm(null)}>Cancel</Button>
        </div>
      </Dialog>
      <Dialog title={dialog?.type === "reinstall" ? `Reinstall ${dialog.vm.name}?` : dialog?.type === "compute" ? `Change the size of ${dialog.vm.name}` : dialog?.type === "reserve_ip" ? `Reserve an address for ${dialog.vm.name}` : dialog?.type === "iso_attach" ? `Attach installation media to ${dialog.vm.name}` : dialog?.type === "rescue" ? `Start rescue mode for ${dialog.vm.name}` : `Grow the disk of ${dialog?.vm.name ?? ""}`} open={dialog !== null} onClose={() => setDialog(null)}>
        {dialog?.type === "compute" ? (
          <>
            <p>The vCPU count and memory of this stopped VM change in its stored definition; the VM boots with them next time. There is no hot-plug. The disk size is changed separately (Resize).</p>
            <Select label="vCPUs" value={cpus} onChange={setCpus} options={(host?.observed.creation.vcpu_options ?? []).map((v) => ({ value: String(v), label: String(v) }))} />
            <Select label="Memory" value={mem} onChange={setMem} options={(host?.observed.creation.memory_mib_options ?? []).map((m) => ({ value: String(m), label: `${m} MiB` }))} />
            {formError ? <StatusMessage tone="warning">{formError}</StatusMessage> : null}
          </>
        ) : dialog?.type === "iso_attach" || dialog?.type === "rescue" ? (
          <>
            {dialog.type === "rescue"
              ? <p>The VM boots the media you choose the next time it starts. Its own disk stays attached, so the rescue system can reach it (a live Linux ISO sees it as an extra disk). Nothing on the disk is changed by this step. Use <strong>Leave rescue mode</strong> afterwards to put the definition back exactly as it was.</p>
              : dialog.vm.observed.isos.length > 0
                ? <p>A second medium is only attached, read-only, as another CD (a driver disc, for example): it does not boot. To boot from it, eject both media, then attach it again and choose to boot from it.</p>
                : <p>The media is attached read-only as a CD. Choose whether the VM boots from it the next time it starts (an installer) or just attaches it (a tools disc).</p>}
            {isos.length === 0 ? <StatusMessage tone="warning">No installation media has been imported on this host yet. The host administrator imports an ISO with <code>register-image</code>.</StatusMessage> : (
              <Select label="Media" value={isoId} onChange={setIsoId} options={isos.map((i) => ({ value: i.id, label: i.name }))} error={formError ?? undefined} />
            )}
            {dialog.type === "iso_attach" && dialog.vm.observed.isos.length === 0 ? <Select label="Boot" value={boot} onChange={(v) => setBoot(v === "disk" ? "disk" : "cdrom")} options={[{ value: "cdrom", label: "From the media next time (installer)" }, { value: "disk", label: "From the disk as before (just attach)" }]} /> : null}
          </>
        ) : dialog?.type === "reserve_ip" ? (
          <>
            <p>This is a <strong>DHCP reservation</strong>: the VM keeps using DHCP, and the reservation is bound to its MAC address. Nothing is configured inside the guest. A reservation does not re-address a VM that already holds an active lease; it governs a later address allocation, after the existing lease no longer controls the guest's address.</p>
            <TextField id="reserve-ip" label="IPv4 address" value={ip} onChange={setIp} required error={formError ?? undefined} />
          </>
        ) : dialog?.type === "resize" ? (
          <>
            <p>The root disk of this stopped VM is {dialog.vm.observed.disk_gib ?? "?"} GiB (virtual size). A disk can only grow, never shrink, and not while the VM has snapshots. Growing the disk does not grow the partition or filesystem inside the guest: that is done in the guest afterwards.</p>
            <TextField id="resize-gib" label="New size in GiB" value={newSize} onChange={setNewSize} required error={formError ?? undefined} />
          </>
        ) : dialog?.type === "reinstall" ? (
          <>
            <p>Reinstall replaces this stopped VM&apos;s disk with a fresh copy of the chosen image. <strong>Everything stored on the current disk is deleted and cannot be recovered</strong> unless you have a backup. The VM keeps its name, size and network. Only images qualified on real hardware can be chosen.</p>
            {images.length === 0 ? <StatusMessage tone="warning">No image has been qualified on real hardware yet.</StatusMessage> : (
              <Select label="Image" value={imageId} onChange={setImageId} options={images.map((i) => ({ value: i.id, label: `${i.name} (${imageStateLabel(i.observed.qualification)})` }))} />
            )}
            <TextArea id="reinstall-key" label="SSH public key" value={key} onChange={setKey} description="One public key; it becomes the only way to sign in to the reinstalled VM." error={formError ?? undefined} />
          </>
        ) : null}
        <div className="ds-button-row">
          <Button variant={dialog?.type === "reinstall" ? "destructive" : "primary"} onClick={() => { void submitDialog(); }}>{dialog?.type === "reinstall" ? "Reinstall and erase the disk" : dialog?.type === "compute" ? "Change size" : dialog?.type === "reserve_ip" ? "Reserve the address" : dialog?.type === "iso_attach" ? "Attach the media" : dialog?.type === "rescue" ? "Start rescue mode" : "Grow the disk"}</Button>
          <Button onClick={() => setDialog(null)}>Cancel</Button>
        </div>
      </Dialog>
    </>
  );
}

function anyAddress(vm: VM | null): boolean { return vm !== null && vm.observed.power === "running" && vm.observed.ip_address !== null; }
