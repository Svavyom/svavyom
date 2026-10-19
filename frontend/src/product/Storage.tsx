// Storage and recovery (M2): what the pool and the backup store hold, the image catalog, each VM's own snapshots and the backups,
// with restore and delete. Disk sizes are VIRTUAL sizes; the pool's free figure is the one that counts. Snapshots live inside the
// VM's disk file and are not a backup. A backup is a copy in the host's local backup store: it protects against VM or disk loss,
// not against losing the host. Restoring a backup always creates a NEW VM; it never overwrites an existing one.
import { useCallback, useEffect, useRef, useState } from "react";
import { Button, DataTable, Dialog, EmptyState, ErrorState, LoadingRegion, PageHead, Select, StatTile, StatTiles, StatusMessage, StatusPill, TextArea, TextField } from "../design-system";
import { read, type ReadResult } from "../api/client";
import { decodeBackupList, decodeHost, decodeImageList, decodeVmList, decodeVolumeList } from "../api/decoders";
import type { Backup, Host, Image, VM, Volume } from "../api/schema";
import { OperationProgress } from "./OperationProgress";
import { guidance, imageStateLabel } from "./guidance";
import { useRunner } from "./runner";
import { DOWNTIME_WARNING, describeSchedule } from "./BackupSchedule";
import { atLeast, useRole } from "./role";

const NAME_RE = /^[a-z]([a-z0-9-]{0,61}[a-z0-9])?$/;
const gib = (n: number | null) => (n === null ? "unknown" : `${n} GiB`);
const VOLUME_RE = /^[a-z][a-z0-9-]{1,30}[a-z0-9]$/;
/** A data volume is any volume that is not a VM's own root disk (ids "<vm>-root"). */
const isData = (v: Volume) => !v.id.endsWith("-root");

type Dlg =
  | { kind: "restore"; backup: Backup }
  | { kind: "delete_backup"; backup: Backup }
  | { kind: "restore_snapshot" | "delete_snapshot"; vm: VM; snapshot: string }
  | { kind: "create_volume" }
  | { kind: "export_backup"; backup: Backup }
  | { kind: "attach_volume" | "detach_volume" | "delete_volume"; volume: Volume };

export function Storage(props: { query: string; refresh: number; onSessionEnded: () => void }) {
  const [loading, setLoading] = useState(true);
  const [host, setHost] = useState<Host | null>(null);
  const [vms, setVms] = useState<VM[] | null>(null);
  const [backups, setBackups] = useState<Backup[] | null>(null);
  const [images, setImages] = useState<Image[]>([]);
  const [volumes, setVolumes] = useState<Volume[] | null>(null);
  const [canCreateVolume, setCanCreateVolume] = useState(false);
  const [volName, setVolName] = useState("");
  const [volSize, setVolSize] = useState("10");
  const [volVm, setVolVm] = useState("");
  const [typed, setTyped] = useState("");
  const [target, setTarget] = useState("");
  const [failure, setFailure] = useState<ReadResult<unknown> | null>(null);
  const [dlg, setDlg] = useState<Dlg | null>(null);
  const [name, setName] = useState("");
  const [key, setKey] = useState("");
  const [formError, setFormError] = useState<string | null>(null);
  const alive = useRef(true);

  const load = useCallback(async () => {
    const [h, v, b, i, vo] = await Promise.all([read("/api/v1/hosts/local", decodeHost), read("/api/v1/vms?limit=200", decodeVmList), read("/api/v1/backups?limit=200", decodeBackupList), read("/api/v1/images", decodeImageList), read("/api/v1/volumes?limit=200", decodeVolumeList)]);
    if (!alive.current) return;
    setLoading(false);
    for (const r of [h, v, b, i, vo]) {
      if (r.kind === "error" && r.category === "unauthenticated") { props.onSessionEnded(); return; }
    }
    if (h.kind === "ok") setHost(h.data);
    if (v.kind === "ok") setVms(v.data.items);
    if (b.kind === "ok") setBackups(b.data.items);
    if (i.kind === "ok") setImages(i.data.items);
    if (vo.kind === "ok") { setVolumes(vo.data.items); setCanCreateVolume(vo.data.allowed_actions.includes("create")); }
    setFailure([h, v, b, i, vo].find((r) => r.kind !== "ok") ?? null);
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

  const st = host?.observed.storage;
  const role = useRole();
  const enabled = host?.observed.creation.enabled === true && atLeast(role, "operator");
  const open = (d: Dlg) => {
    setFormError(null); setName(""); setKey(""); setVolName(""); setVolSize("10"); setTyped("");
    setTarget(d.kind === "export_backup" ? (host?.observed.storage.backup_targets.find((t) => t.state === "ready")?.id ?? "") : "");
    setVolVm(d.kind === "attach_volume" ? ((vms ?? []).find((v) => v.observed.managed && v.observed.power === "stopped")?.id ?? "") : "");
    setDlg(d);
  };

  async function confirm() {
    if (!dlg) return;
    if (dlg.kind === "restore") {
      const k = key.trim();
      if (!NAME_RE.test(name)) { setFormError("Use 1-63 lower-case letters, digits or hyphens, starting with a letter and not ending with a hyphen."); return; }
      if (!/^(ssh-|ecdsa-)\S+ \S+/.test(k) || /[\r\n]/.test(k) || /PRIVATE KEY/.test(k)) {
        if (/PRIVATE KEY/.test(k)) setKey(""); // never keep a private key in the page
        setFormError("This must be one public key on one line, starting with ssh-ed25519, ssh-rsa or ecdsa-. Never paste a private key.");
        return;
      }
      const b = dlg.backup;
      setDlg(null);
      await runner.run({ type: "restore", kind: "Backup", id: b.id, params: { new_name: name, ssh_public_key: k } });
    } else if (dlg.kind === "export_backup") {
      if (target === "") { setFormError("Choose a target."); return; }
      const b = dlg.backup;
      setDlg(null);
      await runner.run({ type: "backup_export", kind: "Backup", id: b.id, params: { target_id: target } });
    } else if (dlg.kind === "create_volume") {
      const size = Number(volSize);
      if (!VOLUME_RE.test(volName) || volName.endsWith("-root")) { setFormError("Use 3-32 lower-case letters, digits or hyphens, starting with a letter, not ending with a hyphen or with -root."); return; }
      if (!Number.isInteger(size) || size < 1 || size > 4096) { setFormError("The size is a whole number of GiB from 1 to 4096."); return; }
      setDlg(null);
      await runner.run({ type: "volume_create", kind: "Volume", id: volName, params: { disk_gib: size } });
    } else if (dlg.kind === "attach_volume") {
      if (volVm === "") { setFormError("Choose a stopped VM."); return; }
      const v = dlg.volume;
      setDlg(null);
      await runner.run({ type: "volume_attach", kind: "Volume", id: v.id, params: { vm_id: volVm } });
    } else if (dlg.kind === "detach_volume") {
      const v = dlg.volume;
      setDlg(null);
      await runner.run({ type: "volume_detach", kind: "Volume", id: v.id });
    } else if (dlg.kind === "delete_volume") {
      if (typed !== dlg.volume.id) { setFormError("Type the volume's name exactly to confirm."); return; }
      const v = dlg.volume;
      setDlg(null);
      await runner.run({ type: "volume_delete", kind: "Volume", id: v.id });
    } else if (dlg.kind === "delete_backup") {
      const b = dlg.backup;
      setDlg(null);
      await runner.run({ type: "delete", kind: "Backup", id: b.id });
    } else if (dlg.kind === "restore_snapshot" || dlg.kind === "delete_snapshot") {
      const { vm, snapshot, kind } = dlg;
      setDlg(null);
      await runner.run({ type: kind, kind: "VM", id: vm.id, params: { snapshot_id: snapshot } });
    }
  }

  const q = props.query.trim().toLowerCase();
  const snapshots = (vms ?? []).filter((v) => q === "" || v.name.toLowerCase().includes(q)).flatMap((v) => v.observed.snapshots.map((s) => ({ vm: v, ...s })));
  const title = dlg?.kind === "restore" ? "Restore as a new VM" : dlg?.kind === "delete_backup" ? "Delete this backup?" : dlg?.kind === "restore_snapshot" ? "Restore this snapshot?" : dlg?.kind === "delete_snapshot" ? "Delete this snapshot?"
    : dlg?.kind === "export_backup" ? "Copy this backup off the host" : dlg?.kind === "create_volume" ? "Create a data volume" : dlg?.kind === "attach_volume" ? `Attach ${dlg.volume.name}` : dlg?.kind === "detach_volume" ? `Detach ${dlg.volume.name}?` : dlg?.kind === "delete_volume" ? `Delete ${dlg.volume.name}?` : "";
  const data = (volumes ?? []).filter((v) => isData(v) && (q === "" || v.name.toLowerCase().includes(q)));
  const stoppedVms = (vms ?? []).filter((v) => v.observed.managed && v.observed.power === "stopped");
  return (
    <>
      <PageHead title="Storage and recovery"><p>Pool, images, snapshots and backups on this host.</p></PageHead>
      {enabled ? <StatusMessage tone="warning">Development Preview: resize, snapshots, backup, restore and reinstall are experimental.</StatusMessage> : null}
      {failure?.kind === "unreachable" ? <StatusMessage tone="warning">Svavyom could not be reached. Try again.</StatusMessage> : null}
      {failure?.kind === "error" ? <ErrorState category={failure.category} correlationId={failure.correlationId} onRetry={() => load()} /> : null}
      {runner.error ? <StatusMessage tone="warning">{runner.error}</StatusMessage> : null}
      {runner.op ? <OperationProgress key={runner.op.id} id={runner.op.id} onDone={runner.finish} onSessionEnded={props.onSessionEnded} /> : null}
      <LoadingRegion label="Storage" loading={loading}>
        {st ? (
          <section aria-labelledby="pool-heading">
            <h2 id="pool-heading">Pool and backup store</h2>
            <StatTiles label="Storage summary">
              {st.state === "available" && st.pool_total_gib !== null && st.pool_free_gib !== null
                ? <StatTile label="Storage pool" value={`${st.pool_total_gib - st.pool_free_gib} GiB used`} note={`${gib(st.pool_free_gib)} free of ${gib(st.pool_total_gib)}`} meter={{ used: st.pool_total_gib - st.pool_free_gib, max: st.pool_total_gib }} />
                : <StatTile label="Storage pool" value={st.state === "unavailable" ? "Unavailable" : "Unknown"} />}
              <StatTile label="Images" value={gib(st.images_gib)} note={`${images.length} in the catalog`} />
              {st.backups_configured
                ? <StatTile label="Backup store" value={gib(st.backups_gib)} note={`${gib(st.backups_gib)} used, ${gib(st.backups_free_gib)} free`} meter={st.backups_gib !== null && st.backups_free_gib !== null ? { used: st.backups_gib, max: st.backups_gib + st.backups_free_gib } : undefined} />
                : <StatTile label="Backup store" value="Not set up" note="Not configured on this host" />}
              <StatTile label="Snapshots" value={String(snapshots.length)} note="restore points inside disk files" />
            </StatTiles>
            <p>{st.allocation_note}</p>
            {st.snapshots !== "available" ? <StatusMessage tone="warning">{st.snapshots === "unavailable"
              ? "Snapshots are not offered: the storage pool on this host is block-backed, and Svavyom's snapshots live inside a qcow2 disk file. Use a file-backed pool (directory) or back VMs up instead."
              : "Snapshots are not offered because this host could not confirm that its storage pool can hold them."}</StatusMessage> : null}
            {st.backups_configured && st.backup_targets.length > 0 ? (
              <p>Off-host targets: {st.backup_targets.map((t) => `${t.id} (${t.kind === "ssh" ? "SSH" : "directory"}, ${t.state === "ready" ? "ready" : "not usable now"})`).join("; ")}.</p>
            ) : st.backups_configured ? <p>No off-host backup target is declared, so backups stay on this host. The host administrator declares targets in the provisioning configuration.</p> : null}
            {!st.backups_configured ? <StatusMessage tone="warning">No backup store is configured, so backups cannot be made. The host administrator configures one in the provisioning configuration.</StatusMessage> : null}
          </section>
        ) : null}
        <section>
          <h2>Images</h2>
          {images.length === 0 ? <EmptyState title="No images" reason="The host administrator imports images with the api register-image command." /> : (
            <DataTable caption="Image catalog" rows={images.filter((i) => q === "" || i.name.toLowerCase().includes(q))} rowKey={(i) => i.id} columns={[
              { header: "Name", cell: (i: Image) => i.name, rowHeader: true },
              { header: "Kind", cell: (i: Image) => (i.observed.media === "iso" ? "Installation media (ISO)" : "Cloud image") },
              { header: "Distribution", cell: (i: Image) => `${i.observed.distribution} ${i.observed.version}` },
              { header: "State", cell: (i: Image) => <StatusPill tone={i.observed.qualification === "qualified" ? "ok" : "neutral"}>{i.observed.media === "iso" ? "digest verified" : imageStateLabel(i.observed.qualification)}</StatusPill> },
              { header: "Minimum disk", cell: (i: Image) => `${i.observed.min_disk_gib} GiB` },
              { header: "Login user", cell: (i: Image) => i.observed.login_user ?? "-" },
              { header: "Digest", cell: (i: Image) => <code title={i.desired.source_digest}>{i.desired.source_digest.slice(0, 19)}…</code> },
              { header: "Qualification evidence", cell: (i: Image) => i.observed.qualification_evidence ?? "-" },
            ]} />
          )}
          {host && !host.observed.creation.ready ? <StatusMessage tone="warning">Creating a VM is not available right now. {guidance(host.observed.creation.reasons).blocking.join(" ")}</StatusMessage> : null}
          <p>Only an image qualified on real hardware can be used to reinstall a VM. Images are read-only: restoring, resizing and reinstalling never change them.</p>
        </section>
        <section>
          <h2>Data volumes</h2>
          <p>A data volume is an extra disk of its own. It is attached to a <strong>stopped</strong> VM and shows up inside the guest as another disk, empty until you partition and format it there. Deleting a VM never deletes its data volumes; deleting a volume is a separate step. Backups copy a VM&apos;s root disk only, not its data volumes.</p>
          {enabled && canCreateVolume ? <div className="ds-button-row"><Button variant="primary" disabled={runner.busy} onClick={() => open({ kind: "create_volume" })}>Create data volume</Button></div> : null}
          {volumes === null ? null : data.length === 0 ? <EmptyState title="No data volumes" reason={enabled ? "Create one to give a VM a second disk." : "No data volume exists on this host."} /> : (
            <DataTable caption="Data volumes" rows={data} rowKey={(v) => v.id} columns={[
              { header: "Volume", cell: (v: Volume) => v.name, rowHeader: true },
              { header: "Size (virtual)", cell: (v: Volume) => `${v.desired.size_gib} GiB` },
              { header: "Attached to", cell: (v: Volume) => (v.desired.attached_to ? <a className="ds-link" href={`#/vms/${v.desired.attached_to}`}>{v.desired.attached_to}</a> : "Not attached") },
              ...(enabled ? [{ header: "Actions", cell: (v: Volume) => (
                <span className="ds-button-row">
                  {v.allowed_actions.includes("attach") ? <Button disabled={runner.busy || stoppedVms.length === 0} onClick={() => open({ kind: "attach_volume", volume: v })}>{`Attach ${v.name}`}</Button> : null}
                  {v.allowed_actions.includes("detach") ? <Button disabled={runner.busy} onClick={() => open({ kind: "detach_volume", volume: v })}>{`Detach ${v.name}`}</Button> : null}
                  {v.allowed_actions.includes("delete") ? <Button variant="destructive" disabled={runner.busy} onClick={() => open({ kind: "delete_volume", volume: v })}>{`Delete ${v.name}`}</Button> : null}
                </span>) }] : []),
            ]} />
          )}
          {enabled && volumes !== null && data.some((v) => v.desired.attached_to !== null) ? <p className="ds-muted">To detach a volume its VM must be stopped.</p> : null}
        </section>
        <section>
          <h2>Snapshots</h2>
          <p>A snapshot saves a stopped VM&apos;s disk at one moment, inside the same disk file. It is not a backup: it is lost if the disk is lost. A VM with snapshots cannot be resized, backed up or reinstalled until they are deleted.</p>
          {vms === null ? null : snapshots.length === 0 ? <EmptyState title="No snapshots" reason="Take one from the VM's page while it is stopped." /> : (
            <DataTable caption="Snapshots" rows={snapshots} rowKey={(s) => `${s.vm.id}/${s.id}`} columns={[
              { header: "VM", cell: (s) => s.vm.name, rowHeader: true },
              { header: "Snapshot", cell: (s) => s.id },
              { header: "Taken", cell: (s) => s.created_at },
              ...(enabled ? [{ header: "Actions", cell: (s: (typeof snapshots)[number]) => (
                <span className="ds-button-row">
                  <Button disabled={runner.busy || s.vm.observed.power !== "stopped"} onClick={() => open({ kind: "restore_snapshot", vm: s.vm, snapshot: s.id })}>{`Restore ${s.id}`}</Button>
                  <Button variant="destructive" disabled={runner.busy || s.vm.observed.power !== "stopped"} onClick={() => open({ kind: "delete_snapshot", vm: s.vm, snapshot: s.id })}>{`Delete ${s.id}`}</Button>
                </span>) }] : []),
            ]} />
          )}
        </section>
        {(vms ?? []).some((v) => v.desired.backup_schedule !== null) ? (
          <section>
            <h2>Scheduled backups</h2>
            <p>{DOWNTIME_WARNING}</p>
            <DataTable caption="Scheduled backups" rows={(vms ?? []).filter((v) => v.desired.backup_schedule !== null && (q === "" || v.name.toLowerCase().includes(q)))} rowKey={(v) => v.id} columns={[
              { header: "Virtual machine", cell: (v: VM) => <a className="ds-link" href={`#/vms/${v.id}`}>{v.name}</a>, rowHeader: true },
              { header: "Schedule and retention", cell: (v: VM) => describeSchedule(v.desired.backup_schedule!) },
              { header: "Next window", cell: (v: VM) => (v.observed.backup.next_run_at ? v.observed.backup.next_run_at.replace("T", " ").replace("Z", " UTC") : "-") },
              { header: "Last window", cell: (v: VM) => (v.observed.backup.last_run ? <StatusPill tone={v.observed.backup.last_run.result === "ok" ? "ok" : v.observed.backup.last_run.result === "failed" ? "bad" : "neutral"}>{{ ok: "Completed", failed: "Failed", skipped: "Skipped" }[v.observed.backup.last_run.result]}</StatusPill> : "None yet") },
            ]} />
          </section>
        ) : null}
        <section>
          <h2>Backups</h2>
          <p>A backup is a verified copy of a stopped VM&apos;s disk in this host&apos;s local backup store. It protects against losing a VM or its disk, <strong>not against losing the host</strong>. It never contains an SSH key. Restoring creates a new VM.</p>
          {backups === null ? null : backups.length === 0 ? <EmptyState title="No backups" reason="Back up a stopped VM from its page." /> : (
            <DataTable caption="Backups" rows={backups.filter((b) => q === "" || b.name.toLowerCase().includes(q))} rowKey={(b) => b.id} columns={[
              { header: "Backup", cell: (b: Backup) => b.name, rowHeader: true },
              { header: "Id", cell: (b: Backup) => b.id },
              { header: "State", cell: (b: Backup) => <StatusPill tone={b.observed.state === "complete" ? "ok" : b.observed.state === "failed" ? "bad" : "warn"}>{b.observed.state === "complete" ? "Complete" : b.observed.state === "failed" ? "Damaged: cannot be restored" : "In progress"}</StatusPill> },
              { header: "Off-host copies", cell: (b: Backup) => (b.observed.copies.length === 0 ? "None" : b.observed.copies.join(", ")) },
              ...(enabled ? [{ header: "Actions", cell: (b: Backup) => (
                <span className="ds-button-row">
                  {b.allowed_actions.includes("export") ? <Button disabled={runner.busy || b.observed.state !== "complete"} onClick={() => open({ kind: "export_backup", backup: b })}>{`Copy ${b.id} off the host`}</Button> : null}
                  {b.allowed_actions.includes("restore") ? <Button disabled={runner.busy || b.observed.state !== "complete"} onClick={() => open({ kind: "restore", backup: b })}>{`Restore ${b.id}`}</Button> : null}
                  {b.allowed_actions.includes("delete") ? <Button variant="destructive" disabled={runner.busy} onClick={() => open({ kind: "delete_backup", backup: b })}>{`Delete ${b.id}`}</Button> : null}
                </span>) }] : []),
            ]} />
          )}
        </section>
      </LoadingRegion>
      <Dialog title={title} open={dlg !== null} onClose={() => setDlg(null)}>
        {dlg?.kind === "restore" ? (
          <>
            <p>This creates a <strong>new</strong> stopped VM from {dlg.backup.name}. No existing VM is changed. The guest starts as a new instance, so it gets new SSH host keys and may get a different address.</p>
            <TextField id="restore-name" label="Name of the new VM" value={name} onChange={setName} required error={formError && !NAME_RE.test(name) ? formError : undefined} />
            <TextArea id="restore-key" label="SSH public key" value={key} onChange={setKey} description="One public key; the backup itself holds none." error={formError && NAME_RE.test(name) ? formError : undefined} />
          </>
        ) : null}
        {dlg?.kind === "export_backup" ? (
          <>
            <p>The backup is copied to the target and checked there by its SHA-256. A copy that does not match is removed and reported. The copy is <strong>not encrypted</strong> by Svavyom: encrypt it at the target, or use an encrypted share.</p>
            <Select id="export-target" label="Target" value={target} onChange={setTarget} options={(st?.backup_targets ?? []).filter((t) => t.state === "ready").map((t) => ({ value: t.id, label: `${t.id} (${t.kind === "ssh" ? "another host over SSH" : "a mounted directory"})` }))} error={formError ?? undefined} />
          </>
        ) : null}
        {dlg?.kind === "create_volume" ? (
          <>
            <p>This creates an empty disk in the storage pool. It uses space only as the guest writes to it.</p>
            <TextField id="vol-name" label="Volume name" value={volName} onChange={setVolName} required error={formError && (!VOLUME_RE.test(volName) || volName.endsWith("-root")) ? formError : undefined} />
            <TextField id="vol-size" label="Size in GiB" value={volSize} onChange={setVolSize} required error={formError && VOLUME_RE.test(volName) && !volName.endsWith("-root") ? formError : undefined} />
          </>
        ) : null}
        {dlg?.kind === "attach_volume" ? (
          <>
            <p>The volume is added to the VM&apos;s definition and appears as another disk the next time the VM starts.</p>
            <Select id="vol-vm" label="Stopped VM" value={volVm} onChange={setVolVm} options={stoppedVms.map((v) => ({ value: v.id, label: v.name }))} error={formError ?? undefined} />
          </>
        ) : null}
        {dlg?.kind === "detach_volume" ? <p>{dlg.volume.name} is removed from {dlg.volume.desired.attached_to}&apos;s definition. Its data stays in the volume. Anything inside the guest that expects the disk will not find it.</p> : null}
        {dlg?.kind === "delete_volume" ? (
          <>
            <p>Deleting {dlg.volume.name} removes the disk and everything on it for good. No VM uses it. This cannot be undone.</p>
            <TextField id="vol-confirm" label={`Type ${dlg.volume.id} to confirm`} value={typed} onChange={setTyped} error={formError ?? undefined} />
          </>
        ) : null}
        {dlg?.kind === "delete_backup" ? <p>Deleting this backup removes it from the backup store for good. VMs are not affected. This cannot be undone.</p> : null}
        {dlg?.kind === "restore_snapshot" ? <p>The disk of {dlg.vm.name} returns to the moment of {dlg.snapshot}. Everything written since is lost. The snapshot itself stays.</p> : null}
        {dlg?.kind === "delete_snapshot" ? <p>Deleting {dlg.snapshot} of {dlg.vm.name} removes that saved moment. The VM&apos;s current disk is not changed.</p> : null}
        <div className="ds-button-row">
          <Button variant={dlg?.kind === "restore" || dlg?.kind === "export_backup" || dlg?.kind === "create_volume" || dlg?.kind === "attach_volume" || dlg?.kind === "detach_volume" ? "primary" : "destructive"} onClick={() => { void confirm(); }}>{dlg?.kind === "restore" ? "Restore as a new VM" : dlg?.kind === "delete_backup" ? "Delete backup permanently" : dlg?.kind === "restore_snapshot" ? "Restore the snapshot" : dlg?.kind === "export_backup" ? "Copy and verify" : dlg?.kind === "create_volume" ? "Create volume" : dlg?.kind === "attach_volume" ? "Attach" : dlg?.kind === "detach_volume" ? "Detach" : dlg?.kind === "delete_volume" ? "Delete volume permanently" : "Delete snapshot"}</Button>
          <Button onClick={() => setDlg(null)}>Cancel</Button>
        </div>
      </Dialog>
    </>
  );
}
