// The backup schedule card of a VM (DR-024 D3). A scheduled backup is a maintenance window: the VM is stopped gracefully, backed up and started again.
// The person scheduling must say, before saving, that they understand the VM is down during the window; the server refuses a schedule without it.
import { useState } from "react";
import { Button, Checkbox, Dialog, RadioGroup, Select, StatusMessage, StatusPill, TextField } from "../design-system";
import type { Host, VM } from "../api/schema";
import type { Intent } from "./runner";

export const DOWNTIME_WARNING = "During the backup window this VM is stopped (gracefully) and started again afterwards. Services in it will be unavailable for the duration of the backup.";

const RESULT: Record<"ok" | "failed" | "skipped", { text: string; tone: "ok" | "bad" | "neutral" }> = {
  ok: { text: "Completed", tone: "ok" }, failed: { text: "Failed", tone: "bad" }, skipped: { text: "Skipped", tone: "neutral" },
};
const when = (iso: string) => iso.replace("T", " ").replace("Z", " UTC");

export function describeSchedule(s: NonNullable<VM["desired"]["backup_schedule"]>): string {
  const cadence = s.every_hours !== null ? (s.every_hours === 1 ? "Every hour" : `Every ${s.every_hours} hours`) : `Every day at ${s.at} (host time)`;
  return `${cadence}. Keeps the newest ${s.keep_local} on this host${s.target_id !== null && s.keep_offsite > 0 ? `, and the newest ${s.keep_offsite} on ${s.target_id}` : ""}.`;
}

export function BackupScheduleCard(props: { vm: VM; host: Host | null; busy: boolean; run: (i: Intent) => Promise<boolean> }) {
  const { vm, host } = props;
  const sched = vm.desired.backup_schedule;
  const canSet = (vm.allowed_actions as string[]).includes("set_schedule");
  const canClear = (vm.allowed_actions as string[]).includes("clear_schedule");
  const configured = host?.observed.storage.backups_configured === true;
  const targets = (host?.observed.storage.backup_targets ?? []).filter((t) => t.state === "ready");
  const [open, setOpen] = useState(false);
  const [mode, setMode] = useState<"hours" | "daily">("daily");
  const [hours, setHours] = useState("24");
  const [time, setTime] = useState("02:30");
  const [keep, setKeep] = useState("3");
  const [target, setTarget] = useState("");
  const [keepOff, setKeepOff] = useState("3");
  const [ack, setAck] = useState(false);
  const [errors, setErrors] = useState<string[]>([]);

  function show() {
    setErrors([]);
    setAck(false);
    if (sched) {
      setMode(sched.every_hours !== null ? "hours" : "daily");
      setHours(String(sched.every_hours ?? 24));
      setTime(sched.at ?? "02:30");
      setKeep(String(sched.keep_local));
      setTarget(sched.target_id ?? "");
      setKeepOff(String(sched.keep_offsite > 0 ? sched.keep_offsite : 3));
    }
    setOpen(true);
  }

  async function save() {
    const problems: string[] = [];
    const h = Number(hours), k = Number(keep), ko = Number(keepOff);
    if (mode === "hours" && !(/^\d{1,3}$/.test(hours) && h >= 1 && h <= 168)) problems.push("Hours between backups must be a whole number from 1 to 168.");
    if (mode === "daily" && !/^([01]\d|2[0-3]):[0-5]\d$/.test(time)) problems.push("The time must be written as HH:MM, for example 02:30.");
    if (!(/^\d{1,2}$/.test(keep) && k >= 1 && k <= 30)) problems.push("Keep between 1 and 30 backups on this host.");
    if (target !== "" && !(/^\d{1,2}$/.test(keepOff) && ko >= 1 && ko <= 30)) problems.push("Keep between 1 and 30 copies on the target.");
    if (!ack) problems.push("Tick the box to confirm that you understand the VM will be stopped during the backup window.");
    setErrors(problems);
    if (problems.length > 0) return;
    const params: Record<string, unknown> = { keep_local: k, keep_offsite: target !== "" ? ko : 0, downtime_acknowledged: true };
    if (mode === "hours") params.every_hours = h; else params.at = time;
    if (target !== "") params.target_id = target;
    setOpen(false);
    await props.run({ type: "schedule_set", kind: "VM", id: vm.id, params });
  }

  return (
    <section className="ds-card" aria-labelledby="vm-schedule">
      <h2 id="vm-schedule">Backup schedule</h2>
      {sched ? (
        <>
          <p>{describeSchedule(sched)}</p>
          <dl>
            <dt>Next window</dt><dd>{vm.observed.backup.next_run_at ? when(vm.observed.backup.next_run_at) : "-"}</dd>
            <dt>Last window</dt><dd>{vm.observed.backup.last_run ? <><StatusPill tone={RESULT[vm.observed.backup.last_run.result].tone}>{RESULT[vm.observed.backup.last_run.result].text}</StatusPill> <span className="ds-muted">{when(vm.observed.backup.last_run.at)}</span></> : "None yet"}</dd>
          </dl>
        </>
      ) : <p>No schedule. This VM is not backed up automatically.</p>}
      <StatusMessage tone="warning">{DOWNTIME_WARNING}</StatusMessage>
      {!configured && (canSet || canClear) ? <p className="ds-muted">Backups are not configured on this host, so a schedule cannot run.</p> : null}
      {canSet || canClear ? (
        <div className="ds-button-row">
          {canSet && configured ? <Button disabled={props.busy} ariaLabel={sched ? `Change backup schedule of ${vm.name}` : `Set backup schedule of ${vm.name}`} onClick={show}>{sched ? "Change schedule" : "Set schedule"}</Button> : null}
          {canClear && sched ? <Button disabled={props.busy} ariaLabel={`Clear backup schedule of ${vm.name}`} onClick={() => { void props.run({ type: "schedule_clear", kind: "VM", id: vm.id }); }}>Clear schedule</Button> : null}
        </div>
      ) : null}
      <Dialog title={`Backup schedule of ${vm.name}`} open={open} onClose={() => setOpen(false)}>
        <StatusMessage tone="warning">{DOWNTIME_WARNING}</StatusMessage>
        <RadioGroup legend="How often" name="sched-mode" value={mode} onChange={(v) => setMode(v === "hours" ? "hours" : "daily")}
          options={[{ value: "daily", label: "Every day at a set time" }, { value: "hours", label: "Every so many hours" }]} />
        {mode === "daily" ? <TextField id="sched-time" label="Time of day (HH:MM, host time)" value={time} onChange={setTime} required />
          : <TextField id="sched-hours" label="Hours between backups (1 to 168)" value={hours} onChange={setHours} required />}
        <TextField id="sched-keep" label="Backups to keep on this host (1 to 30)" value={keep} onChange={setKeep} required />
        {targets.length > 0 ? (
          <>
            <Select label="Also copy each backup to" value={target} onChange={setTarget} options={[{ value: "", label: "Nowhere (keep them on this host only)" }, ...targets.map((t) => ({ value: t.id, label: t.id }))]} />
            {target !== "" ? <TextField id="sched-keep-off" label="Copies to keep on the target (1 to 30)" value={keepOff} onChange={setKeepOff} required /> : null}
          </>
        ) : null}
        <p className="ds-muted">Only backups made by this schedule are ever removed to stay within these limits, oldest first. The newest good backup is always kept.</p>
        <Checkbox id="sched-ack" label="I understand that this VM will be stopped during each backup window." checked={ack} onChange={setAck} />
        {errors.length > 0 ? <StatusMessage tone="warning">{errors.join(" ")}</StatusMessage> : null}
        <div className="ds-button-row">
          <Button variant="primary" onClick={() => { void save(); }}>Save schedule</Button>
          <Button onClick={() => setOpen(false)}>Cancel</Button>
        </div>
      </Dialog>
    </section>
  );
}
