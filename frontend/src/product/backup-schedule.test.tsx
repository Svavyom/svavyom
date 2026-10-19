// fe-unit: the backup schedule card (DR-024 D3): the downtime warning, the required acknowledgement, the request it sends, and what it shows.
import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { BackupScheduleCard, DOWNTIME_WARNING, describeSchedule } from "./BackupSchedule";
import { HOST, NO_SIZE, vm } from "../api/fixtures";
import { axeViolations } from "../test-axe";
import type { Host, VM } from "../api/schema";

const STORAGE = { ...HOST.observed.storage, state: "available" as const, backups_configured: true, backup_targets: [{ id: "usb-disk", kind: "path" as const, state: "ready" as const }, { id: "nas", kind: "ssh" as const, state: "unavailable" as const }] };
const HOST_OK: Host = { ...HOST, observed: { ...HOST.observed, storage: STORAGE } };
const SCHEDULE: NonNullable<VM["desired"]["backup_schedule"]> = { every_hours: null, at: "02:30", keep_local: 3, keep_offsite: 2, target_id: "usb-disk", downtime_acknowledged: true };
const base = (over: Partial<VM> = {}, actions: string[] = ["set_schedule"]): VM => vm({ id: "web-1", name: "web-1", allowed_actions: actions as VM["allowed_actions"],
  observed: { ...NO_SIZE, power: "running", last_seen_at: "2026-10-15T09:00:00Z", managed: true, ip_address: null, login_user: null, disk_gib: 20, snapshots: [], network: null }, ...over });

afterEach(cleanup);

describe("BackupScheduleCard", () => {
  it("always tells the person the VM goes down during the window", async () => {
    render(<BackupScheduleCard vm={base({}, [])} host={HOST_OK} busy={false} run={vi.fn()} />);
    expect(screen.getByText(DOWNTIME_WARNING)).toBeTruthy();
    expect(screen.getByText(/No schedule/)).toBeTruthy();
    expect(screen.queryByRole("button")).toBeNull(); // a viewer sees the facts and no control
    expect(await axeViolations(document.body)).toEqual([]);
  });

  it("refuses to save until the downtime is acknowledged, and sends nothing", async () => {
    const run = vi.fn(async () => true);
    render(<BackupScheduleCard vm={base()} host={HOST_OK} busy={false} run={run} />);
    await userEvent.click(screen.getByRole("button", { name: "Set backup schedule of web-1" }));
    expect(screen.getAllByText(DOWNTIME_WARNING).length).toBe(2); // on the card and in the dialog
    await userEvent.click(screen.getByRole("button", { name: "Save schedule" }));
    expect(screen.getByText(/Tick the box to confirm that you understand the VM will be stopped/)).toBeTruthy();
    expect(run).not.toHaveBeenCalled();
  });

  it("sends a daily schedule with the acknowledgement", async () => {
    const run = vi.fn(async () => true);
    render(<BackupScheduleCard vm={base()} host={HOST_OK} busy={false} run={run} />);
    await userEvent.click(screen.getByRole("button", { name: "Set backup schedule of web-1" }));
    await userEvent.click(screen.getByLabelText(/I understand that this VM will be stopped/));
    await userEvent.click(screen.getByRole("button", { name: "Save schedule" }));
    await waitFor(() => expect(run).toHaveBeenCalledTimes(1));
    expect(run).toHaveBeenCalledWith({ type: "schedule_set", kind: "VM", id: "web-1", params: { at: "02:30", keep_local: 3, keep_offsite: 0, downtime_acknowledged: true } });
  });

  it("sends an hours schedule with an off-host target, offering only ready targets", async () => {
    const run = vi.fn(async () => true);
    render(<BackupScheduleCard vm={base()} host={HOST_OK} busy={false} run={run} />);
    await userEvent.click(screen.getByRole("button", { name: "Set backup schedule of web-1" }));
    await userEvent.click(screen.getByLabelText("Every so many hours"));
    fireEvent.change(screen.getByLabelText(/Hours between backups/), { target: { value: "12" } });
    fireEvent.change(screen.getByLabelText(/Backups to keep on this host/), { target: { value: "4" } });
    const select = screen.getByLabelText("Also copy each backup to") as HTMLSelectElement;
    expect(Array.from(select.options).map((o) => o.value)).toEqual(["", "usb-disk"]); // "nas" is unavailable
    fireEvent.change(select, { target: { value: "usb-disk" } });
    fireEvent.change(screen.getByLabelText(/Copies to keep on the target/), { target: { value: "2" } });
    await userEvent.click(screen.getByLabelText(/I understand that this VM will be stopped/));
    await userEvent.click(screen.getByRole("button", { name: "Save schedule" }));
    await waitFor(() => expect(run).toHaveBeenCalledTimes(1));
    expect(run).toHaveBeenCalledWith({ type: "schedule_set", kind: "VM", id: "web-1", params: { every_hours: 12, keep_local: 4, keep_offsite: 2, target_id: "usb-disk", downtime_acknowledged: true } });
  });

  it("rejects values outside the limits before sending", async () => {
    const run = vi.fn(async () => true);
    render(<BackupScheduleCard vm={base()} host={HOST_OK} busy={false} run={run} />);
    await userEvent.click(screen.getByRole("button", { name: "Set backup schedule of web-1" }));
    fireEvent.change(screen.getByLabelText(/Time of day/), { target: { value: "25:00" } });
    fireEvent.change(screen.getByLabelText(/Backups to keep on this host/), { target: { value: "0" } });
    await userEvent.click(screen.getByLabelText(/I understand that this VM will be stopped/));
    await userEvent.click(screen.getByRole("button", { name: "Save schedule" }));
    expect(screen.getByText(/must be written as HH:MM/)).toBeTruthy();
    expect(screen.getByText(/Keep between 1 and 30 backups/)).toBeTruthy();
    expect(run).not.toHaveBeenCalled();
  });

  it("shows the schedule, the next window and how the last one ended, and can clear it", async () => {
    const run = vi.fn(async () => true);
    const v = base({ desired: { power: "running", backup_schedule: SCHEDULE } }, ["set_schedule", "clear_schedule"]);
    v.observed.backup = { next_run_at: "2026-10-16T02:30:00Z", last_run: { at: "2026-10-15T02:31:00Z", result: "failed" } };
    render(<BackupScheduleCard vm={v} host={HOST_OK} busy={false} run={run} />);
    expect(screen.getByText(describeSchedule(SCHEDULE))).toBeTruthy();
    expect(screen.getByText("2026-10-16 02:30:00 UTC")).toBeTruthy();
    expect(screen.getByText("Failed")).toBeTruthy();
    await userEvent.click(screen.getByRole("button", { name: "Clear backup schedule of web-1" }));
    expect(run).toHaveBeenCalledWith({ type: "schedule_clear", kind: "VM", id: "web-1" });
    expect(describeSchedule({ ...SCHEDULE, every_hours: 1, at: null, target_id: null, keep_offsite: 0 })).toBe("Every hour. Keeps the newest 3 on this host.");
  });

  it("says a schedule cannot run when backups are not configured, and offers no Set button", () => {
    const noBackups: Host = { ...HOST, observed: { ...HOST.observed, storage: { ...STORAGE, backups_configured: false } } };
    render(<BackupScheduleCard vm={base()} host={noBackups} busy={false} run={vi.fn()} />);
    expect(screen.getByText(/Backups are not configured on this host/)).toBeTruthy();
    expect(screen.queryByRole("button", { name: /Set backup schedule/ })).toBeNull();
  });

  it("disables the buttons while another request is running", () => {
    render(<BackupScheduleCard vm={base()} host={HOST_OK} busy run={vi.fn()} />);
    expect(screen.getByRole("button", { name: "Set backup schedule of web-1" }).getAttribute("aria-disabled")).toBe("true");
  });
});
