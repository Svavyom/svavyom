// fe-unit: the graphical console page (DR-026 D1): acknowledgement, the ticket and the socket address, controls, endings, and that a ticket never
// reaches a URL. noVNC itself is replaced by a controllable stand-in; the browser tier runs the real library against the simulated VNC server.
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { act, cleanup, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { GraphicsConsole } from "./GraphicsConsole";
import { apiError, NO_SIZE, vm } from "../api/fixtures";
import { forgetCsrf } from "../api/session";
import { axeViolations } from "../test-axe";
import type { VM } from "../api/schema";

const TICKET = "A".repeat(43);

class FakeRFB extends EventTarget {
  static last: FakeRFB | null = null;
  viewOnly = false;
  scaleViewport = false;
  disconnected = 0;
  ctrlAltDel = 0;
  constructor(public target: HTMLElement, public url: string, public opts: { wsProtocols: string[]; shared: boolean }) {
    super();
    FakeRFB.last = this;
  }
  disconnect() { this.disconnected++; this.dispatchEvent(new CustomEvent("disconnect", { detail: { clean: true } })); }
  sendCtrlAltDel() { this.ctrlAltDel++; }
  focus() {}
}
const loadViewer = async () => FakeRFB as never;

const running = (over: Partial<VM["observed"]> = {}): VM => vm({ id: "web-1", name: "web-1", allowed_actions: [],
  observed: { ...NO_SIZE, power: "running", last_seen_at: "2026-10-16T09:00:00Z", managed: true, ip_address: "10.0.0.5", login_user: "debian", disk_gib: 20, snapshots: [], network: null, graphical_console: "present", ...over } });

let machine: VM;
let ticketStatus = 200;
let posts: string[] = [];
beforeEach(() => {
  forgetCsrf();
  FakeRFB.last = null;
  ticketStatus = 200;
  posts = [];
  machine = running();
  vi.stubGlobal("fetch", vi.fn(async (url: string, init: RequestInit = {}) => {
    if (url === "/api/v1/auth/session") return new Response(JSON.stringify({ authenticated: true, username: "admin", expires_at: "2026-10-17T08:30:00Z", role: "admin" }), { status: 200, headers: { "X-CSRF-Token": "S".repeat(43) } });
    if (url === "/api/v1/vms/web-1") return new Response(JSON.stringify(machine), { status: 200 });
    if (url === "/console/v1/vms/web-1/graphics-tickets" && init.method === "POST") {
      posts.push(url);
      return ticketStatus === 200 ? new Response(JSON.stringify({ ticket: TICKET, expires_at: "2026-10-16T09:00:30Z" }), { status: 200 })
        : new Response(JSON.stringify(apiError(ticketStatus === 409 ? "conflict" : ticketStatus === 422 ? "prohibited" : "forbidden")), { status: ticketStatus });
    }
    return new Response(JSON.stringify(apiError("not_found")), { status: 404 });
  }));
});
afterEach(() => { cleanup(); vi.unstubAllGlobals(); });

async function mount(m: VM = machine) {
  machine = m;
  const { sessionStatus } = await import("../api/session");
  await sessionStatus();
  return render(<GraphicsConsole vm="web-1" onSessionEnded={() => undefined} loadViewer={loadViewer} />);
}
const open = () => userEvent.click(screen.getByRole("button", { name: "Open graphical console" }));

describe("GraphicsConsole", () => {
  it("warns that it is a full-power channel and passes axe", async () => {
    await mount();
    expect(await screen.findByText(/full-power channel into the VM/)).toBeTruthy();
    expect(await axeViolations(document.body)).toEqual([]);
  });

  it("opens nothing until the person has acknowledged, and only for a running VM that has the device", async () => {
    await mount();
    const btn = await screen.findByRole("button", { name: "Open graphical console" });
    expect(btn.getAttribute("aria-disabled")).toBe("true");
    await userEvent.click(btn);
    expect(posts).toHaveLength(0);
    cleanup();
    await mount(running({ power: "stopped" }));
    expect(await screen.findByText(/not running, so there is no screen to show/)).toBeTruthy();
    expect(screen.getByRole("button", { name: "Open graphical console" }).getAttribute("aria-disabled")).toBe("true");
    cleanup();
    await mount(running({ graphical_console: "absent" }));
    expect(await screen.findByText(/no graphical console device/)).toBeTruthy();
    await userEvent.click(screen.getByLabelText(/I understand/));
    expect(screen.getByRole("button", { name: "Open graphical console" }).getAttribute("aria-disabled")).toBe("true");
  });

  it("mints a ticket, opens a same-origin socket with the ticket only in the protocol list, and shows the controls once connected", async () => {
    await mount();
    await userEvent.click(await screen.findByLabelText(/I understand/));
    await open();
    await waitFor(() => expect(FakeRFB.last).not.toBeNull());
    const r = FakeRFB.last!;
    expect(r.url).toMatch(/^wss?:\/\/[^/]+\/console\/v1\/vms\/web-1\/graphics-socket$/);
    expect(r.url).not.toContain(TICKET);
    expect(r.opts.wsProtocols).toEqual(["svavyom.graphics.v1", `t.${TICKET}`]);
    expect(r.opts.shared).toBe(false);
    expect(r.scaleViewport).toBe(true);
    expect(document.body.innerHTML).not.toContain(TICKET);
    act(() => { r.dispatchEvent(new Event("connect")); r.dispatchEvent(new CustomEvent("desktopname", { detail: { name: "sim:web-1" } })); });
    await userEvent.click(await screen.findByRole("button", { name: "Send Ctrl-Alt-Del" }));
    expect(r.ctrlAltDel).toBe(1);
    expect(screen.getByText(/Connected to sim:web-1/)).toBeTruthy();
    await userEvent.click(screen.getByLabelText(/View only/));
    expect(r.viewOnly).toBe(true);
    await userEvent.click(screen.getByRole("button", { name: "Disconnect" }));
    expect(r.disconnected).toBe(1);
    expect(await screen.findByText("The console was closed.")).toBeTruthy();
    expect(screen.getByRole("button", { name: "Open the console again" })).toBeTruthy();
  });

  it("says an unclean ending in words, and a new connection needs a new ticket", async () => {
    await mount();
    await userEvent.click(await screen.findByLabelText(/I understand/));
    await open();
    await waitFor(() => expect(FakeRFB.last).not.toBeNull());
    act(() => { FakeRFB.last!.dispatchEvent(new Event("connect")); FakeRFB.last!.dispatchEvent(new CustomEvent("disconnect", { detail: { clean: false } })); });
    expect(await screen.findByText(/the VM stopped, the time limit was reached, your session ended, or another viewer has it open/)).toBeTruthy();
    await userEvent.click(screen.getByRole("button", { name: "Open the console again" }));
    await waitFor(() => expect(posts).toHaveLength(2));
  });

  it("refuses a server that asks for credentials: nothing is typed into a prompt", async () => {
    await mount();
    await userEvent.click(await screen.findByLabelText(/I understand/));
    await open();
    await waitFor(() => expect(FakeRFB.last).not.toBeNull());
    act(() => { FakeRFB.last!.dispatchEvent(new Event("credentialsrequired")); });
    expect(FakeRFB.last!.disconnected).toBe(1);
  });

  it("explains each refusal of the ticket", async () => {
    for (const [status, text] of [[409, /not running or has no graphical console/], [422, /switched off on this installation/], [403, /Only operators and administrators/]] as const) {
      ticketStatus = status;
      await mount();
      await userEvent.click(await screen.findByLabelText(/I understand/));
      await open();
      expect(await screen.findByText(text)).toBeTruthy();
      expect(FakeRFB.last).toBeNull();
      cleanup();
    }
  });

  it("closes the connection when the page goes away", async () => {
    const view = await mount();
    await userEvent.click(await screen.findByLabelText(/I understand/));
    await open();
    await waitFor(() => expect(FakeRFB.last).not.toBeNull());
    const r = FakeRFB.last!;
    view.unmount();
    expect(r.disconnected).toBe(1);
  });
});
