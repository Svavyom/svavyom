// fe-unit: the Alerts page and the header badge (DR-024 D2): states, filters, plain words, acknowledging, and no setting in the browser.
import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { Alerts } from "./Alerts";
import { AppShell } from "../design-system";
import { HOST, operation } from "../api/fixtures";
import { forgetCsrf } from "../api/session";
import { axeViolations } from "../test-axe";
import type { Event } from "../api/schema";

const ev = (i: number, over: Partial<Event> = {}): Event => ({
  id: `al-000000000000000${i}`, project_id: "default", type: "pool_free_low", resource_kind: "Host", resource_id: "local", severity: "warning", state: "open", value: 18,
  created_at: `2026-10-15T09:0${i}:00Z`, updated_at: `2026-10-15T09:0${i}:30Z`, allowed_actions: ["acknowledge"], ...over,
});
const events = (items: Event[], next: string | null = null) => new Response(JSON.stringify({ items, allowed_actions: [], next_cursor: next }), { status: 200 });
const host = (webhook: "none" | "configured", open = 1) => new Response(JSON.stringify({ ...HOST, observed: { ...HOST.observed, alerts: { open, webhook } } }), { status: 200 });
const route = (items: Event[], webhook: "none" | "configured" = "none") => vi.fn(async (url: string) => (String(url).startsWith("/api/v1/events") ? events(items) : host(webhook)));
const show = (query = "") => render(<Alerts query={query} refresh={0} onSessionEnded={() => undefined} />);

afterEach(() => { cleanup(); vi.unstubAllGlobals(); forgetCsrf(); });

describe("Alerts", () => {
  it("says in words what happened, how bad it is and what to do", async () => {
    vi.stubGlobal("fetch", route([ev(1, { severity: "critical", value: 7 }), ev(2, { type: "vm_crashed", resource_kind: "VM", resource_id: "web-1", severity: "critical", value: null })]));
    show();
    expect(await screen.findByRole("table", { name: "Alerts on this host" })).toBeTruthy();
    expect(screen.getByText("Storage pool space is low")).toBeTruthy();
    expect(screen.getByText(/7% of the storage pool is free/)).toBeTruthy();
    expect(screen.getByRole("link", { name: "web-1" }).getAttribute("href")).toBe("#/vms/web-1");
    expect(screen.getAllByText("Critical").length).toBe(2);
    expect(screen.getByText(/Delete virtual machines, snapshots or data volumes/)).toBeTruthy();
    expect(await axeViolations(document.body)).toEqual([]);
  });

  it("never shows a setting: thresholds and the webhook belong to the operator", async () => {
    vi.stubGlobal("fetch", route([ev(1)], "configured"));
    show();
    expect(await screen.findByText(/also sent to the webhook the operator configured/)).toBeTruthy();
    expect(screen.queryByRole("textbox")).toBeNull();
    expect(screen.queryByLabelText(/webhook|threshold/i)).toBeNull();
    cleanup();
    vi.stubGlobal("fetch", route([ev(1)], "none"));
    show();
    expect(await screen.findByText(/No webhook is configured/)).toBeTruthy();
  });

  it("filters by state with counts and by the search text", async () => {
    vi.stubGlobal("fetch", route([ev(1), ev(2, { state: "acknowledged", allowed_actions: [], resource_kind: "VM", resource_id: "db-1", type: "vm_stopped_unexpectedly" }), ev(3, { state: "resolved", allowed_actions: [], resource_kind: "VM", resource_id: "old-1", type: "vm_crashed" })]));
    const { rerender } = show();
    await screen.findByRole("table");
    expect(screen.getByRole("button", { name: "Open 1" })).toBeTruthy();
    expect(screen.queryByText("db-1")).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: "Acknowledged 1" }));
    expect(screen.getByText("db-1")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Resolved 1" }));
    expect(screen.getByText("Nothing: it has cleared.")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "All 3" }));
    rerender(<Alerts query="old-1" refresh={0} onSessionEnded={() => undefined} />);
    expect(screen.queryByText("db-1")).toBeNull();
    expect(screen.getByText("old-1")).toBeTruthy();
  });

  it("offers Acknowledge only where the server allows it", async () => {
    vi.stubGlobal("fetch", route([ev(1), ev(2, { allowed_actions: [], resource_kind: "VM", resource_id: "web-2", type: "vm_crashed" })]));
    show();
    await screen.findByRole("table");
    expect(screen.getAllByRole("button", { name: /^Acknowledge / })).toHaveLength(1);
  });

  it("acknowledges with one request and follows it", async () => {
    const posted: unknown[] = [];
    const f = vi.fn(async (url: string, init: RequestInit = {}) => {
      const u = String(url);
      if (u === "/api/v1/auth/session") return new Response(JSON.stringify({ authenticated: true, username: "admin", expires_at: "2026-10-16T08:30:00Z", role: "admin" }), { status: 200, headers: { "X-CSRF-Token": "S".repeat(43) } });
      if (u === "/api/v1/operations" && init.method === "POST") { posted.push(JSON.parse(init.body as string)); return new Response(JSON.stringify(operation({ id: "op-9", type: "alert_acknowledge", resource_kind: "Event", resource_id: "al-0000000000000001", status: "succeeded", allowed_actions: [] })), { status: 202 }); }
      if (u.startsWith("/api/v1/operations/")) return new Response(JSON.stringify(operation({ id: "op-9", type: "alert_acknowledge", resource_kind: "Event", resource_id: "al-0000000000000001", status: "succeeded", allowed_actions: [] })), { status: 200 });
      return String(url).startsWith("/api/v1/events") ? events([ev(1)]) : host("none");
    });
    vi.stubGlobal("fetch", f);
    const { sessionStatus } = await import("../api/session");
    await sessionStatus();
    show();
    fireEvent.click(await screen.findByRole("button", { name: "Acknowledge Storage pool space is low" }));
    await waitFor(() => expect(posted).toHaveLength(1));
    expect(posted[0]).toMatchObject({ type: "alert_acknowledge", kind: "Event", id: "al-0000000000000001" });
    expect(await screen.findByText("Alert acknowledged")).toBeTruthy();
  });

  it("says so when there are no alerts, and when they cannot be read", async () => {
    vi.stubGlobal("fetch", route([]));
    show();
    expect(await screen.findByText("No alerts")).toBeTruthy();
    cleanup();
    vi.stubGlobal("fetch", vi.fn(async () => { throw new TypeError("network"); }));
    show();
    expect(await screen.findByRole("button", { name: /try again|retry/i })).toBeTruthy();
  });

  it("shows an unknown rule by its id instead of inventing words", async () => {
    vi.stubGlobal("fetch", route([ev(1, { type: "something_new", allowed_actions: [] })]));
    show();
    expect(await screen.findByText("something_new")).toBeTruthy();
  });
});

describe("the open-alerts badge in the header", () => {
  const shell = (open: number) => render(<AppShell nav={[]} alerts={{ open, href: "#/alerts" }}><p>x</p></AppShell>);
  it("is a link with the count in words, and absent when nothing is open", async () => {
    shell(0);
    expect(screen.queryByRole("link", { name: /open alert/ })).toBeNull();
    cleanup();
    shell(1);
    expect(screen.getByRole("link", { name: "1 open alert" }).getAttribute("href")).toBe("#/alerts");
    cleanup();
    shell(3);
    expect(screen.getByRole("link", { name: "3 open alerts" })).toBeTruthy();
    expect(await axeViolations(document.body)).toEqual([]);
  });
});
