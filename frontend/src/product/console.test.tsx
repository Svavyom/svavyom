// fe-unit: the VM recovery view (M1-D-S04) and the console client. A stateful fake of the console route family and a fake WebSocket:
// typed serial states, what Svavyom knows about SSH, the ticket in the subprotocol (never the URL), input/ output over the socket,
// the confirmation, the refusals, and the close reasons.
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen, waitFor, act } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { ConsoleView, sshKnowledge } from "./Console";
import { VM_RUNNING, apiError } from "../api/fixtures";
import { appendTerminal, decodeSerial, decodeTicket, socketProtocols, CONSOLE_SUBPROTOCOL } from "../api/console";
import { openSocket } from "../api/client";
import { forgetCsrf, sessionStatus } from "../api/session";
import { axeViolations } from "../test-axe";
import type { VM } from "../api/schema";

const TICKET = "A".repeat(43);

class FakeSocket {
  static instances: FakeSocket[] = [];
  static OPEN = 1;
  readyState = 0;
  binaryType = "blob";
  sent: Uint8Array[] = [];
  onopen: (() => void) | null = null;
  onmessage: ((e: { data: ArrayBuffer }) => void) | null = null;
  onclose: ((e: { code: number }) => void) | null = null;
  onerror: (() => void) | null = null;
  closedWith: number | null = null;
  constructor(public url: string, public protocols: string[]) { FakeSocket.instances.push(this); }
  send(d: Uint8Array) { this.sent.push(d); }
  close(code = 1000) { this.closedWith = code; this.readyState = 3; }
  open() { this.readyState = 1; this.onopen?.(); }
  push(text: string) { this.onmessage?.({ data: new TextEncoder().encode(text).buffer as ArrayBuffer }); }
  end(code: number) { this.readyState = 3; this.onclose?.({ code }); }
}

type Serial = { state: string; text: string; truncated: boolean; running: boolean };
let serial: Serial;
let ticketReply: "ok" | Parameters<typeof apiError>[0];
let machine: VM;
const calls: Array<{ method: string; url: string; csrf: string | undefined }> = [];

const STATUS: Record<string, number> = { unauthenticated: 401, forbidden: 403, not_found: 404, conflict: 409, prohibited: 422, unavailable: 503 };
const failure = (cat: Parameters<typeof apiError>[0]) => json(STATUS[cat]!, apiError(cat));

function json(status: number, body: unknown) {
  return new Response(JSON.stringify(body), { status, headers: { "X-CSRF-Token": "S".repeat(43) } });
}

beforeEach(async () => {
  FakeSocket.instances = [];
  calls.length = 0;
  serial = { state: "available", text: "[    0.1] kernel\nweb-1 login: ", truncated: false, running: true };
  ticketReply = "ok";
  machine = { ...VM_RUNNING, id: "web-1", name: "web-1", observed: { ...VM_RUNNING.observed, power: "running", managed: true, ip_address: "192.168.122.23", login_user: "ubuntu", disk_gib: null, snapshots: [], network: null } };
  vi.stubGlobal("WebSocket", FakeSocket);
  vi.stubGlobal("fetch", vi.fn(async (url: string, init: RequestInit = {}) => {
    const headers = (init.headers ?? {}) as Record<string, string>;
    calls.push({ method: init.method ?? "GET", url, csrf: headers["X-CSRF-Token"] });
    if (url === "/api/v1/auth/session") return json(200, { authenticated: true, username: "admin", expires_at: "2026-10-09T08:30:00Z", role: "admin" });
    if (url === "/api/v1/vms/web-1") return json(200, machine);
    if (url === "/console/v1/vms/web-1/serial") return json(200, serial);
    if (url === "/console/v1/vms/web-1/tickets") return ticketReply === "ok" ? json(200, { ticket: TICKET, expires_at: "2026-10-11T09:00:30Z" }) : failure(ticketReply);
    return json(404, {});
  }));
  forgetCsrf();
  await sessionStatus(); // the page has the CSRF token before any state-changing request
});
afterEach(() => { cleanup(); vi.unstubAllGlobals(); });

describe("console client", () => {
  it("decodes the serial and ticket shapes strictly", () => {
    expect(decodeSerial({ state: "available", text: "x", truncated: false, running: true })).not.toBeNull();
    for (const bad of [null, [], {}, { state: "weird", text: "", truncated: false, running: true }, { state: "available", text: 5, truncated: false, running: true },
      { state: "available", text: "", truncated: false, running: true, extra: 1 }, { state: "available", text: "x".repeat(200_000), truncated: false, running: true }]) {
      expect(decodeSerial(bad)).toBeNull();
    }
    expect(decodeTicket({ ticket: TICKET, expires_at: "2026-10-11T09:00:30Z" })).not.toBeNull();
    for (const bad of [{ ticket: "short", expires_at: "2026-10-11T09:00:30Z" }, { ticket: TICKET, expires_at: "nope" }, { ticket: TICKET }, { ticket: TICKET, expires_at: "2026-10-11T09:00:30Z", x: 1 }]) {
      expect(decodeTicket(bad)).toBeNull();
    }
  });

  it("puts the ticket in the subprotocol list and never in the URL", () => {
    expect(socketProtocols(TICKET)).toEqual([CONSOLE_SUBPROTOCOL, `t.${TICKET}`]);
    expect(() => socketProtocols("bad ticket")).toThrow();
    const ws = openSocket("/console/v1/vms/web-1/socket", socketProtocols(TICKET), { protocol: "https:", host: "svavyom.example:8443" }, FakeSocket as unknown as typeof WebSocket) as unknown as FakeSocket;
    expect(ws.url).toBe("wss://svavyom.example:8443/console/v1/vms/web-1/socket");
    expect(ws.url).not.toContain(TICKET);
    expect(() => openSocket("/console/v1/vms/web-1/socket?t=x", [], undefined, FakeSocket as unknown as typeof WebSocket)).toThrow();
    expect(() => openSocket("//evil.example/x", [], undefined, FakeSocket as unknown as typeof WebSocket)).toThrow();
    const plain = openSocket("/console/v1/vms/web-1/socket", [], { protocol: "http:", host: "127.0.0.1:8081" }, FakeSocket as unknown as typeof WebSocket) as unknown as FakeSocket;
    expect(plain.url).toBe("ws://127.0.0.1:8081/console/v1/vms/web-1/socket");
  });

  it("renders terminal output as text: no escape sequences, backspace erases, bounded", () => {
    expect(appendTerminal("", "\x1b[31mred\x1b[0m ok\r\n")).toBe("red ok\n");
    expect(appendTerminal("pass", "\b\bxx")).toBe("paxx");
    expect(appendTerminal("a\n", "\b")).toBe("a\n");
    expect(appendTerminal("", "\x1b]0;title\x07text")).toBe("text");
    expect(appendTerminal("", "x".repeat(300_000)).length).toBe(200_000);
    expect(appendTerminal("", "<img src=x onerror=alert(1)>")).toBe("<img src=x onerror=alert(1)>");
  });

  it("states only what was observed about SSH", () => {
    expect(sshKnowledge(null)).toMatch(/Unknown/);
    expect(sshKnowledge({ ...machine, observed: { ...machine.observed, power: "stopped" } })).toMatch(/not running/);
    expect(sshKnowledge({ ...machine, observed: { ...machine.observed, ip_address: null } })).toMatch(/no address/);
    expect(sshKnowledge({ ...machine, observed: { ...machine.observed, login_user: null, disk_gib: null, snapshots: [], network: null } })).toMatch(/login user is not known/);
    expect(sshKnowledge(machine)).toMatch(/does not prove SSH works/);
  });
});

describe("recovery view", () => {
  it("shows the boot output, the SSH knowledge and the release limits, and passes axe", async () => {
    const { container } = render(<ConsoleView vm="web-1" onSessionEnded={() => {}} />);
    expect(await screen.findByText(/web-1 login:/)).toBeTruthy();
    expect(screen.getByText(/Boot output is available/)).toBeTruthy();
    expect(screen.getByText(/192\.168\.122\.23 and login user ubuntu observed/)).toBeTruthy();
    expect(screen.getByText(/rescue mode on the VM's page boots a rescue system/i)).toBeTruthy();
    expect(await axeViolations(container)).toEqual([]);
  });

  it.each([
    ["no_output", /No output has been received yet/], ["not_configured", /no serial console Svavyom can use/], ["unavailable", /not reachable/],
  ])("tells the %s state in plain words and shows no output", async (state, text) => {
    serial = { state, text: "", truncated: false, running: false };
    render(<ConsoleView vm="web-1" onSessionEnded={() => {}} />);
    expect(await screen.findByText(text)).toBeTruthy();
    expect(screen.queryByLabelText("Serial boot output text")).toBeNull();
  });

  it("says when only the most recent output is shown", async () => {
    serial = { ...serial, truncated: true };
    render(<ConsoleView vm="web-1" onSessionEnded={() => {}} />);
    expect(await screen.findByText(/Only the most recent output is shown/)).toBeTruthy();
  });

  it("ends the session view on a 401", async () => {
    const ended = vi.fn();
    (fetch as unknown as ReturnType<typeof vi.fn>).mockImplementation(async (url: string) => (url.startsWith("/console") ? failure("unauthenticated") : json(200, machine)));
    render(<ConsoleView vm="web-1" onSessionEnded={ended} />);
    await waitFor(() => expect(ended).toHaveBeenCalled());
  });

  it("does not offer the console for a VM that is not running", async () => {
    machine = { ...machine, observed: { ...machine.observed, power: "stopped" } };
    render(<ConsoleView vm="web-1" onSessionEnded={() => {}} />);
    await screen.findByText(/web-1 login:/);
    await userEvent.click(screen.getByRole("checkbox", { name: /I understand/ }));
    expect(screen.getByRole("button", { name: "Open serial console" }).getAttribute("aria-disabled")).toBe("true");
  });
});

describe("interactive console", () => {
  async function opened() {
    render(<ConsoleView vm="web-1" onSessionEnded={() => {}} />);
    await screen.findByText(/web-1 login:/);
    const open = screen.getByRole("button", { name: "Open serial console" });
    expect(open.getAttribute("aria-disabled")).toBe("true"); // needs the explicit acknowledgement first
    await userEvent.click(screen.getByRole("checkbox", { name: /I understand/ }));
    await userEvent.click(open);
    await waitFor(() => expect(FakeSocket.instances).toHaveLength(1));
    act(() => FakeSocket.instances[0]!.open());
    return FakeSocket.instances[0]!;
  }

  it("mints a ticket with the CSRF token, connects with the ticket in the subprotocol, shows output and sends input", async () => {
    const ws = await opened();
    expect(calls.find((c) => c.url.endsWith("/tickets"))).toMatchObject({ method: "POST", csrf: "S".repeat(43) });
    expect(ws.url).toMatch(/^ws:\/\/[^?]+\/console\/v1\/vms\/web-1\/socket$/);
    expect(ws.protocols).toEqual([CONSOLE_SUBPROTOCOL, `t.${TICKET}`]);
    expect(ws.binaryType).toBe("arraybuffer");
    act(() => ws.push("Ubuntu 24.04\r\nweb-1 login: "));
    await waitFor(() => expect(screen.getByLabelText("Serial console output").textContent).toBe("Ubuntu 24.04\nweb-1 login: "));
    await userEvent.type(screen.getByLabelText(/Send to the console/), "ubuntu{Enter}");
    expect(new TextDecoder().decode(ws.sent[0])).toBe("ubuntu\r");
    await userEvent.click(screen.getByRole("button", { name: "Send Ctrl-C" }));
    expect(ws.sent[1]![0]).toBe(3);
    await userEvent.click(screen.getByRole("button", { name: "Send Ctrl-D" }));
    expect(ws.sent[2]![0]).toBe(4);
    await userEvent.click(screen.getByRole("button", { name: "Disconnect" }));
    expect(ws.closedWith).toBe(1000);
  });

  it("explains each way the connection can end and allows a new connection with a new ticket", async () => {
    const ws = await opened();
    act(() => ws.end(1001));
    expect(await screen.findByText(/the VM stopped, or the time limit/)).toBeTruthy();
    await userEvent.click(screen.getByRole("button", { name: "Open the console again" }));
    await waitFor(() => expect(FakeSocket.instances).toHaveLength(2));
    expect(calls.filter((c) => c.url.endsWith("/tickets"))).toHaveLength(2);
  });

  it("closes the page's session view when the server ends the console because the session ended", async () => {
    const ended = vi.fn();
    render(<ConsoleView vm="web-1" onSessionEnded={ended} />);
    await screen.findByText(/web-1 login:/);
    await userEvent.click(screen.getByRole("checkbox", { name: /I understand/ }));
    await userEvent.click(screen.getByRole("button", { name: "Open serial console" }));
    await waitFor(() => expect(FakeSocket.instances).toHaveLength(1));
    act(() => { FakeSocket.instances[0]!.open(); FakeSocket.instances[0]!.end(1008); });
    await waitFor(() => expect(ended).toHaveBeenCalled());
  });

  it.each([
    ["prohibited", /switched off on this installation/], ["conflict", /not running/], ["forbidden", /refused/], ["unavailable", /could not be opened/],
  ] as const)("shows a plain message when the ticket is refused (%s) and opens no socket", async (cat, text) => {
    ticketReply = cat;
    render(<ConsoleView vm="web-1" onSessionEnded={() => {}} />);
    await screen.findByText(/web-1 login:/);
    await userEvent.click(screen.getByRole("checkbox", { name: /I understand/ }));
    await userEvent.click(screen.getByRole("button", { name: "Open serial console" }));
    expect(await screen.findByText(text)).toBeTruthy();
    expect(FakeSocket.instances).toHaveLength(0);
  });

  it("closes the socket when the view is left", async () => {
    const ws = await opened();
    cleanup();
    expect(ws.closedWith).toBe(1000);
  });
});
