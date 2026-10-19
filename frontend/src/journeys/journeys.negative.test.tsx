// fe-negative: journey skeletons under failed, unauthorized, unknown-outcome and hostile responses (AC02).
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { act, cleanup, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { J3Dashboard, J4Wizard, J6Errors, J7Delete, J9Power } from "./journeys";
import { ConfirmDestructive, exactMatch, visibleCodepoints } from "../design-system";
import { VM_RUNNING as VM, apiError, operation, vm, vmList } from "../api/fixtures";

type Handler = (url: string, init: RequestInit) => Promise<Response> | Response;
let handler: Handler;
const calls: Array<{ url: string; body: unknown }> = [];
const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status });
let spies: ReturnType<typeof vi.spyOn>[] = [];

beforeEach(() => {
  calls.length = 0;
  vi.stubGlobal("fetch", vi.fn(async (u: string, init: RequestInit) => {
    calls.push({ url: u, body: init.body ? JSON.parse(init.body as string) : null });
    return handler(u, init);
  }));
  spies = (["log", "info", "warn", "error"] as const).map((m) => vi.spyOn(console, m).mockImplementation(() => undefined));
  localStorage.clear();
  sessionStorage.clear();
});
afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
  for (const s of spies) expect(s).not.toHaveBeenCalled();
  expect(localStorage.length + sessionStorage.length).toBe(0);
});

async function completeWizard() {
  await userEvent.type(screen.getByLabelText(/VM name/), "web-1");
  await userEvent.click(screen.getByLabelText("Debian 13"));
  await userEvent.click(screen.getByRole("button", { name: "Continue to review" }));
}

describe("journey negative cases", () => {
  it("forbidden is handled when the control is shown", async () => {
    handler = (u) => u.startsWith("/api/v1/vms/") ? json(VM) : json(apiError("forbidden"), 403);
    render(<J7Delete id="vm-a" />);
    await userEvent.click(await screen.findByRole("button", { name: "Delete VM" }));
    await userEvent.type(screen.getByLabelText(/Name to confirm/), "web-1");
    await userEvent.click(screen.getByRole("button", { name: "Delete permanently" }));
    expect(await screen.findByText("You are not allowed to do this")).toBeTruthy();
    expect(screen.queryByText(/Deletion requested/)).toBeNull();
  });

  it("submit is inert while pending", async () => {
    let release: () => void = () => undefined;
    handler = () => new Promise((r) => { release = () => r(json(operation())); });
    render(<J4Wizard />);
    await completeWizard();
    const create = screen.getByRole("button", { name: /Create VM/ });
    await userEvent.click(create);
    await userEvent.click(create);
    await userEvent.keyboard("{Enter}");
    expect(calls).toHaveLength(1);
    expect(create.getAttribute("aria-disabled")).toBe("true");
    await act(async () => release());
  });

  it("outcome unknown never re-sends and a user retry reuses the idempotency key", async () => {
    handler = () => { throw new TypeError("network"); };
    render(<J4Wizard />);
    await completeWizard();
    await userEvent.click(screen.getByRole("button", { name: /Create VM/ }));
    expect(await screen.findByText("The outcome is unknown")).toBeTruthy();
    await act(async () => { await new Promise((r) => setTimeout(r, 50)); });
    expect(calls).toHaveLength(1);
    await userEvent.click(screen.getByRole("button", { name: /Create VM/ }));
    await waitFor(() => expect(calls).toHaveLength(2));
    expect((calls[1].body as { idempotency_key: string }).idempotency_key).toBe((calls[0].body as { idempotency_key: string }).idempotency_key);
  });

  it("a changed payload or a definitive outcome starts a new idempotency key", async () => {
    handler = () => { throw new TypeError("network"); };
    render(<J4Wizard />);
    await completeWizard();
    await userEvent.click(screen.getByRole("button", { name: /Create VM/ }));
    expect(await screen.findByText("The outcome is unknown")).toBeTruthy();
    await userEvent.click(screen.getByRole("button", { name: "Back" }));
    await userEvent.clear(screen.getByLabelText(/VM name/));
    await userEvent.type(screen.getByLabelText(/VM name/), "web-2");
    await userEvent.click(screen.getByRole("button", { name: "Continue to review" }));
    handler = () => json(apiError("conflict"), 409);
    await userEvent.click(screen.getByRole("button", { name: /Create VM/ }));
    await screen.findByText("Changed by someone else");
    await userEvent.click(screen.getByRole("button", { name: /Create VM/ }));
    await waitFor(() => expect(calls).toHaveLength(3));
    const keys = calls.map((c) => (c.body as { idempotency_key: string }).idempotency_key);
    expect(keys[1]).not.toBe(keys[0]); // different VM name: a new intent
    expect(keys[2]).not.toBe(keys[1]); // after a definitive error: a new intent
    expect((calls[1].body as { id: string }).id).toBe("web-2");
  });

  it("outcome unknown followed by an unreachable read shows the J8 banner with last-known data", async () => {
    handler = (u, init) => (init.method === "GET" ? json(VM) : (() => { throw new TypeError("network"); })());
    render(<J9Power id="vm-a" />);
    await userEvent.click(await screen.findByRole("button", { name: "Stop" }));
    expect(await screen.findByText("The outcome is unknown")).toBeTruthy();
    handler = () => { throw new TypeError("network"); };
    await userEvent.click(screen.getByRole("button", { name: "Check status" }));
    expect(await screen.findByText("Control plane unreachable")).toBeTruthy();
    expect(screen.getByText(/Observed power: running/)).toBeTruthy();
    expect(screen.getByText(/may be out of date/)).toBeTruthy();
  });

  it("no optimistic success on failure", async () => {
    handler = (u) => u.startsWith("/api/v1/vms/") ? json(VM) : json(apiError("conflict"), 409);
    render(<J7Delete id="vm-a" />);
    await userEvent.click(await screen.findByRole("button", { name: "Delete VM" }));
    await userEvent.type(screen.getByLabelText(/Name to confirm/), "web-1");
    await userEvent.click(screen.getByRole("button", { name: "Delete permanently" }));
    expect(await screen.findByText("Changed by someone else")).toBeTruthy();
    expect(screen.queryByText(/Deletion requested/)).toBeNull();
    expect(screen.getByText(/Observed power: running/)).toBeTruthy();
  });

  it("server text, stacks and credential fields are never rendered", async () => {
    handler = () => json({ category: "internal", message: "panic at /srv/app/main.go:42", stack: "Error\n at x", idempotency_key: "SECRET-KEY" }, 500);
    render(<J6Errors />);
    expect(await screen.findByText("Something went wrong")).toBeTruthy();
    expect(document.body.textContent).not.toMatch(/panic|main\.go|stack|SECRET-KEY/);
  });

  it("hostile names render as text only", async () => {
    handler = () => json(vmList([vm({ name: "<img src=x onerror=alert(1)>" })]));
    render(<J3Dashboard />);
    expect(await screen.findByText("<img src=x onerror=alert(1)>")).toBeTruthy();
    expect(document.querySelector("img")).toBeNull();
  });

  it("empty state offers create only when allowed", async () => {
    handler = () => json(vmList([]));
    const { unmount } = render(<J3Dashboard />);
    expect(await screen.findByText(/not allowed to create one/)).toBeTruthy();
    expect(screen.queryByRole("button", { name: "Create VM" })).toBeNull();
    unmount();
    handler = () => json(vmList([], ["create"]));
    render(<J3Dashboard />);
    expect(await screen.findByRole("button", { name: "Create VM" })).toBeTruthy();
  });

  it("confirm destructive requires an exact code-point match", async () => {
    const name = "web​-1";
    expect(exactMatch("web-1", name)).toBe(false);
    expect(exactMatch(" web​-1", name)).toBe(false);
    expect(exactMatch("WEB​-1", name)).toBe(false);
    expect(exactMatch("web​-1", name)).toBe(true);
    expect(exactMatch("é", "é")).toBe(false);
    expect(visibleCodepoints("a‮b​c")).toBe("a⟨U+202E⟩b⟨U+200B⟩c");
    let confirmed = 0;
    render(<ConfirmDestructive open title="Delete" targetName={name} consequence="Gone." confirmLabel="Delete permanently"
      onConfirm={() => { confirmed += 1; }} onCancel={() => undefined} />);
    expect(screen.getByText("web⟨U+200B⟩-1")).toBeTruthy();
    await userEvent.type(screen.getByLabelText(/Name to confirm/), "web-1");
    await userEvent.click(screen.getByRole("button", { name: "Delete permanently" }));
    expect(confirmed).toBe(0);
    expect(screen.getByText(/does not match exactly/)).toBeTruthy();
  });

  it("unreachable reads keep last-known data and mark it stale", async () => {
    handler = () => json(vmList([VM]));
    render(<J3Dashboard />);
    expect(await screen.findByText("web-1")).toBeTruthy();
    handler = () => { throw new TypeError("network"); };
    await userEvent.click(screen.getByRole("button", { name: "Refresh" }));
    expect(await screen.findByText("Control plane unreachable")).toBeTruthy();
    expect(screen.getByText("web-1")).toBeTruthy();
    expect(screen.getByText(/may be out of date/)).toBeTruthy();
  });
});
