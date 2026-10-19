// fe-unit: usage and activity (DR-022): the dashboard tiles, the one-hour chart, the VM page's size and CPU chart, the operations feed,
// and the honest empty states when nothing has been sampled.
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen, within } from "@testing-library/react";
import { Root } from "./Root";
import { HOST, NO_SIZE, VM_RUNNING, apiError, operation, vm, vmList } from "../api/fixtures";
import { forgetCsrf } from "../api/session";
import { axeViolations } from "../test-axe";
import { summarize, UsageChart } from "../design-system";
import type { Host, Operation, VM } from "../api/schema";

const TOKEN = (c: string) => c.repeat(43);
const IN = { authenticated: true, username: "admin", expires_at: "2026-10-09T08:30:00Z", role: "admin" };

const POINTS = [0, 1, 2, 3].map((i) => ({ at: `2026-10-13T09:0${i}:00Z`, cpu_percent: 20 + i * 10, memory_used_mib: 4096 + i * 100, disk_kib_s: 100 + i, net_kib_s: 50 + i }));
const usageHost = (): Host => ({ ...HOST, observed: { ...HOST.observed, memory_mib: 16384, usage: { state: "available", interval_seconds: 30, cpu_percent: 50, memory_used_mib: 4396, disk_kib_s: 103, net_kib_s: 53, history: POINTS } } });
const sizedVm = (): VM => vm({ id: "web-1", name: "web-1", observed: { ...VM_RUNNING.observed, ...NO_SIZE, power: "running", managed: true, vcpus: 2, memory_mib: 2048,
  usage: { state: "available", cpu_percent: 33, memory_used_mib: 700, disk_kib_s: 2048, net_kib_s: 12, history: POINTS.map((p) => ({ at: p.at, cpu_percent: p.cpu_percent, memory_used_mib: 700, disk_kib_s: 2048, net_kib_s: 12 })) } } });

let host: Host, vms: VM[], ops: Operation[] | "fail";
const respond = (status: number, body: unknown, csrf?: string) => new Response(JSON.stringify(body), { status, headers: csrf ? { "X-CSRF-Token": csrf } : {} });

beforeEach(() => {
  forgetCsrf();
  host = HOST; vms = []; ops = [];
  location.hash = "";
  vi.stubGlobal("fetch", vi.fn(async (url: string) => {
    if (url === "/api/v1/auth/session") return respond(200, IN, TOKEN("S"));
    if (url === "/api/v1/hosts/local") return respond(200, host);
    if (url.startsWith("/api/v1/vms")) return respond(200, vmList(vms));
    if (url.startsWith("/api/v1/operations")) return ops === "fail" ? respond(503, apiError("unavailable")) : respond(200, { items: ops, allowed_actions: [], next_cursor: null });
    return respond(404, apiError("not_found"));
  }));
});
afterEach(() => { cleanup(); vi.unstubAllGlobals(); });

describe("chart", () => {
  it("summarises a series in numbers and says so when there is none", () => {
    expect(summarize([])).toBeNull();
    expect(summarize(POINTS.map((p) => ({ at: p.at, value: p.cpu_percent })))).toEqual({ now: 50, avg: 35, peak: 50 });
    render(<UsageChart label="x" series={[]} empty="Nothing sampled yet." />);
    expect(screen.getByText("Nothing sampled yet.")).toBeTruthy();
    expect(screen.queryByRole("img")).toBeNull();
  });

  it("names the figures in text as well as in the drawing", () => {
    render(<UsageChart label="CPU over the last hour" empty="none" series={[{ id: "cpu", label: "CPU", points: POINTS.map((p) => ({ at: p.at, value: p.cpu_percent })) }]} />);
    expect(screen.getByRole("img", { name: /CPU over the last hour\. CPU: now 50%, average 35%, peak 50%/ })).toBeTruthy();
    expect(screen.getByText(/CPU: now 50%, average 35%, peak 50%\. Times are UTC\./)).toBeTruthy();
  });
});

describe("dashboard usage", () => {
  it("shows CPU and memory in use with the one-hour chart, and passes axe", async () => {
    host = usageHost();
    render(<Root />);
    const tiles = within(await screen.findByRole("list", { name: "Host summary" }));
    expect(await tiles.findByText("50%")).toBeTruthy();
    expect(tiles.getByText(/of 8 logical processors/)).toBeTruthy();
    expect(tiles.getByText("4.3 GiB used")).toBeTruthy();
    expect(screen.getByRole("img", { name: /Host CPU and memory use over the last hour\. CPU: now 50%.*Memory: now 27%/ })).toBeTruthy();
    expect(await axeViolations(document.body)).toEqual([]);
  });

  it("says plainly that nothing has been sampled yet instead of drawing a chart", async () => {
    render(<Root />);
    expect(await screen.findByText(/No usage has been sampled yet/)).toBeTruthy();
    expect(screen.queryByRole("img", { name: /Host CPU/ })).toBeNull();
    expect(within(screen.getByRole("list", { name: "Host summary" })).getByText("Processors")).toBeTruthy(); // the capacity tiles stay: no figure is invented
  });

  it("lists the latest operations, newest first, with their state", async () => {
    ops = [operation({ id: "op-2", type: "start", resource_id: "web-1", status: "succeeded", created_at: "2026-10-13T09:05:00Z" }),
      operation({ id: "op-1", type: "snapshot", resource_id: "db-1", status: "failed", created_at: "2026-10-13T09:01:00Z" })];
    render(<Root />);
    const card = (await screen.findByRole("heading", { name: "Recent activity" })).closest("section")!;
    const items = within(card).getAllByRole("listitem");
    expect(items[0]!.textContent).toContain("Start");
    expect(items[0]!.textContent).toContain("web-1");
    expect(items[0]!.textContent).toContain("Done");
    expect(items[1]!.textContent).toContain("Snapshot");
    expect(items[1]!.textContent).toContain("Failed");
  });

  it("reports an unreadable feed and an empty one honestly", async () => {
    ops = "fail";
    const { unmount } = render(<Root />);
    expect(await screen.findByText("Recent activity could not be read.")).toBeTruthy();
    unmount();
    ops = [];
    render(<Root />);
    expect(await screen.findByText("Nothing has been done on this host yet.")).toBeTruthy();
  });
});

describe("VM page usage", () => {
  beforeEach(() => { location.hash = "#/vms/web-1"; });

  it("shows the configured size and the CPU chart", async () => {
    vms = [sizedVm()];
    render(<Root />);
    expect(await screen.findByText("2 vCPU, 2048 MiB memory")).toBeTruthy();
    expect(screen.getByRole("img", { name: /CPU use of web-1 over the last hour\. CPU of this VM: now 50%/ })).toBeTruthy();
    expect(await axeViolations(document.body)).toEqual([]);
  });

  it("explains an empty chart by the VM's state", async () => {
    vms = [vm({ id: "web-1", name: "web-1", observed: { ...VM_RUNNING.observed, ...NO_SIZE, power: "stopped" } })];
    const { unmount } = render(<Root />);
    expect(await screen.findByText("Usage is sampled while the VM is running.")).toBeTruthy();
    unmount();
    vms = [vm({ id: "web-1", name: "web-1", observed: { ...VM_RUNNING.observed, ...NO_SIZE, power: "running" } })];
    render(<Root />);
    expect(await screen.findByText(/No samples yet\. The first appears within a minute/)).toBeTruthy();
  });
});
