// fe-unit: the Activity page (M1-E04-S03): history, outcome filters, paging and plain-words failures.
import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { Activity } from "./Activity";
import { operation } from "../api/fixtures";
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
