// fe-unit: the Activity page (M1-E04-S03): history, outcome filters, paging and plain-words failures.
import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { Activity, CANCEL_TEXT } from "./Activity";
import { RoleContext } from "./role";
import { sessionStatus } from "../api/session";
import { apiError, operation } from "../api/fixtures";
import { axeViolations } from "../test-axe";
import type { Operation } from "../api/schema";

const op = (i: number, over: Partial<Operation> = {}): Operation => operation({
  id: `op-${i}`, resource_id: `web-${i}`, type: "start", status: "succeeded", requested_by: "admin", generation: 1, attempts: 1,
  created_at: `2026-10-14T09:0${i}:00Z`, updated_at: `2026-10-14T09:0${i}:05Z`, allowed_actions: [], ...over,
});
const page = (items: Operation[], next: string | null) => new Response(JSON.stringify({ items, allowed_actions: [], next_cursor: next }), { status: 200 });
const show = (query = "") => render(<Activity query={query} refresh={0} onSessionEnded={() => undefined} />);

afterEach(() => { cleanup(); vi.unstubAllGlobals(); });

describe("Activity", () => {
  it("lists requests with their outcome and says in words why one failed", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => page([op(1), op(2, { status: "failed", type: "stop", error_category: "conflict" }), op(3, { status: "running", type: "reboot" })], null)));
    show();
    expect(await screen.findByRole("table", { name: "Requests made on this host" })).toBeTruthy();
    expect(screen.getByText("The resource was not in a state this applies to.")).toBeTruthy();
    expect(screen.getByRole("button", { name: "Failed or cancelled 1" })).toBeTruthy();
    expect(screen.getByRole("button", { name: "In progress 1" })).toBeTruthy();
  });

  it("filters by outcome and by the search text", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => page([op(1), op(2, { status: "failed", type: "stop", error_category: "timeout" })], null)));
    const { rerender } = show();
    await screen.findByRole("table");
    fireEvent.click(screen.getByRole("button", { name: "Failed or cancelled 1" }));
    expect(screen.queryByText("web-1")).toBeNull();
    expect(screen.getByText("web-2")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "All 2" }));
    rerender(<Activity query="web-1" refresh={0} onSessionEnded={() => undefined} />);
    expect(screen.queryByText("web-2")).toBeNull();
    expect(screen.getByText("web-1")).toBeTruthy();
  });

  it("loads older requests with Show more", async () => {
    const f = vi.fn().mockResolvedValueOnce(page([op(1)], "b3AtMQ")).mockResolvedValueOnce(page([op(2)], null));
    vi.stubGlobal("fetch", f);
    show();
    fireEvent.click(await screen.findByRole("button", { name: "Show more" }));
    await waitFor(() => expect(screen.getByText("web-2")).toBeTruthy());
    expect(String(f.mock.calls[1]![0])).toContain("cursor=b3AtMQ");
    expect(screen.queryByRole("button", { name: "Show more" })).toBeNull();
  });

  it("says so when nothing has been done", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => page([], null)));
    show();
    expect(await screen.findByText("Nothing yet")).toBeTruthy();
  });
});

describe("Activity: cancelling an exhausted operation (DR-036)", () => {
  const exhaustedOp = op(1, { status: "retryable_failure", type: "start", attempts: 3, error_category: "unavailable" });
  const retrying = op(2, { status: "retryable_failure", type: "stop", attempts: 1, error_category: "unavailable" });
  const asRole = (role: "admin" | "operator" | "viewer") => render(
    <RoleContext.Provider value={role}><Activity query="" refresh={0} onSessionEnded={() => undefined} /></RoleContext.Provider>);

  it("offers Cancel on an operation that used all its attempts, to an administrator only", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => page([exhaustedOp, retrying, op(3)], null)));
    const { unmount } = asRole("admin");
    expect(await screen.findByRole("button", { name: "Cancel Start web-1" })).toBeTruthy();
    expect(screen.queryByRole("button", { name: /Cancel Stop web-2/ })).toBeNull(); // still retrying: nothing to free yet
    unmount();
    for (const role of ["operator", "viewer"] as const) {
      const r = asRole(role);
      await screen.findByRole("table", { name: "Requests made on this host" });
      expect(screen.queryByRole("button", { name: /^Cancel / })).toBeNull();
      r.unmount();
    }
  });

  it("asks first with the fixed text, then cancels with the CSRF token and refreshes; 'Keep it' sends nothing", async () => {
    const calls: Array<{ method: string; url: string; csrf: string | undefined }> = [];
    let cancelled = false;
    vi.stubGlobal("fetch", vi.fn(async (url: string, init: RequestInit = {}) => {
      calls.push({ method: init.method ?? "GET", url, csrf: ((init.headers ?? {}) as Record<string, string>)["X-CSRF-Token"] });
      if (url === "/api/v1/auth/session") return new Response(JSON.stringify({ authenticated: true, username: "admin", expires_at: "2026-10-09T08:30:00Z", role: "admin" }), { status: 200, headers: { "X-CSRF-Token": "S".repeat(43) } });
      if (init.method === "POST") { cancelled = true; return new Response(JSON.stringify({ ...exhaustedOp, status: "cancelled" }), { status: 200 }); }
      return page([cancelled ? { ...exhaustedOp, status: "cancelled" } : exhaustedOp], null);
    }));
    await sessionStatus();
    asRole("admin");
    fireEvent.click(await screen.findByRole("button", { name: "Cancel Start web-1" }));
    expect(screen.getByText(CANCEL_TEXT)).toBeTruthy();
    expect(await axeViolations(document.body)).toEqual([]);
    fireEvent.click(screen.getByRole("button", { name: "Keep it" }));
    expect(calls.filter((c) => c.method === "POST")).toHaveLength(0);
    fireEvent.click(screen.getByRole("button", { name: "Cancel Start web-1" }));
    fireEvent.click(screen.getByRole("button", { name: "Cancel this operation" }));
    await waitFor(() => expect(calls.some((c) => c.method === "POST")).toBe(true));
    const post = calls.find((c) => c.method === "POST")!;
    expect(post.url).toBe("/api/v1/operations/op-1/cancel");
    expect(post.csrf).toMatch(/^[A-Za-z0-9_-]{43}$/);
    await waitFor(() => expect(screen.queryByRole("button", { name: "Cancel Start web-1" })).toBeNull());
    expect(await screen.findByText("Cancelled")).toBeTruthy();
  });

  it("says in words when the operation has moved on (409)", async () => {
    vi.stubGlobal("fetch", vi.fn(async (url: string, init: RequestInit = {}) => {
      if (url === "/api/v1/auth/session") return new Response(JSON.stringify({ authenticated: true, username: "admin", expires_at: "2026-10-09T08:30:00Z", role: "admin" }), { status: 200, headers: { "X-CSRF-Token": "S".repeat(43) } });
      if (init.method === "POST") return new Response(JSON.stringify(apiError("conflict")), { status: 409 });
      return page([exhaustedOp], null);
    }));
    await sessionStatus();
    asRole("admin");
    fireEvent.click(await screen.findByRole("button", { name: "Cancel Start web-1" }));
    fireEvent.click(screen.getByRole("button", { name: "Cancel this operation" }));
    expect(await screen.findByText(/has moved on and can no longer be cancelled/)).toBeTruthy();
  });
});
