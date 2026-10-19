// fe-unit: the first signed-in journey (M1-E04-S05 + M1-E04-S01): sign in -> dashboard (capacity, readiness) -> sign out,
// with loading, failure, unreachable and session-expired states, driven through the real client against a stateful
// fake of the browser-api. Request shapes are checked against the generated schemas.
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { Root } from "./Root";
import { HOST, apiError, NO_SIZE } from "../api/fixtures";
import { forgetCsrf } from "../api/session";
import { validate } from "../api/validate";
import { axeViolations } from "../test-axe";
import type { Host, VM } from "../api/schema";
import { VM_RUNNING, vm, vmList } from "../api/fixtures";

const TOKEN = (c: string) => c.repeat(43);
const ANON = { authenticated: false, username: null, expires_at: null, role: null };
const IN = { authenticated: true, username: "admin", expires_at: "2026-10-09T08:30:00Z", role: "admin" };

type Call = { method: string; url: string; csrf: string | null; body: unknown };

class FakeApi {
  calls: Call[] = [];
  signedIn = false;
  host: Host = HOST;
  password = "correct horse battery";
  down = false;
  hostStatus = 200;
  rateLimited = false;
  vms: VM[] = [];
  vmStatus = 200;
  nextCursor: string | null = null;
  json(status: number, body: unknown, csrf?: string) {
    return new Response(JSON.stringify(body), { status, headers: csrf ? { "X-CSRF-Token": csrf } : {} });
  }
  fetch = vi.fn(async (url: string, init: RequestInit = {}) => {
    const headers = (init.headers ?? {}) as Record<string, string>;
    const call: Call = { method: init.method ?? "GET", url, csrf: headers["X-CSRF-Token"] ?? null, body: init.body ? JSON.parse(init.body as string) : null };
    this.calls.push(call);
    if (this.down) throw new TypeError("network");
    const want = this.signedIn ? TOKEN("S") : TOKEN("L");
    if (url === "/api/v1/auth/session") {
      if (call.method === "GET") return this.json(200, this.signedIn ? IN : ANON, want);
      if (call.csrf !== want) return this.json(403, apiError("forbidden"));
      if (call.method === "POST" && this.rateLimited) return this.json(429, apiError("rate_limited"));
      if (call.method === "DELETE") { this.signedIn = false; return this.json(200, ANON, TOKEN("L")); }
      const b = call.body as { username: string; password: string };
      if (b.username !== "admin" || b.password !== this.password) return this.json(401, apiError("unauthenticated"));
      this.signedIn = true;
      return this.json(200, IN, TOKEN("S"));
    }
    if (url === "/api/v1/hosts/local") return this.signedIn ? this.json(this.hostStatus, this.hostStatus === 200 ? this.host : apiError("unavailable")) : this.json(401, apiError("unauthenticated"));
    if (url.startsWith("/api/v1/vms")) {
      if (!this.signedIn) return this.json(401, apiError("unauthenticated"));
      if (this.vmStatus !== 200) return this.json(this.vmStatus, apiError(this.vmStatus === 503 ? "unavailable" : "internal"));
      const more = url.includes("cursor=");
      return this.json(200, more ? vmList([vm({ id: "vm-z", name: "vm-z" })]) : { ...vmList(this.vms), next_cursor: this.nextCursor });
    }
    return this.json(404, apiError("not_found"));
  });
}

let api: FakeApi;
beforeEach(() => { api = new FakeApi(); forgetCsrf(); location.hash = ""; vi.stubGlobal("fetch", api.fetch); });
afterEach(() => { cleanup(); vi.unstubAllGlobals(); });

async function signInAs(password = "correct horse battery") {
  await userEvent.type(await screen.findByLabelText(/Username/), "admin");
  await userEvent.type(screen.getByLabelText(/Password/), password);
  await userEvent.click(screen.getByRole("button", { name: "Sign in" }));
}

describe("signed-out", () => {
  it("shows a loading state, then the sign-in form with no secret in the page", async () => {
    render(<Root />);
    expect(screen.getByRole("status").textContent).toMatch(/Loading your session/);
    expect(await screen.findByRole("heading", { name: "Sign in" })).toBeTruthy();
    const pw = screen.getByLabelText(/Password/) as HTMLInputElement;
    expect(pw.type).toBe("password");
    expect(pw.autocomplete).toBe("current-password");
    expect(document.body.innerHTML).not.toContain(TOKEN("L"));
    expect(await axeViolations(document.body)).toEqual([]);
  });

  it("validates empty fields locally with an error summary and sends nothing", async () => {
    render(<Root />);
    await userEvent.click(await screen.findByRole("button", { name: "Sign in" }));
    expect((await screen.findAllByText("Enter your username")).length).toBeGreaterThan(0);
    expect(screen.getAllByText("Enter your password").length).toBeGreaterThan(0);
    expect(api.calls.filter((c) => c.method === "POST")).toHaveLength(0);
  });

  it("a wrong password gives one generic message, keeps the form, and clears the password field", async () => {
    render(<Root />);
    await signInAs("wrong password here");
    expect(await screen.findByText("The username or password is incorrect.")).toBeTruthy();
    expect(screen.getByText("Sign-in failed")).toBeTruthy();
    expect((screen.getByLabelText(/Password/) as HTMLInputElement).value).toBe("");
    expect(await axeViolations(document.body)).toEqual([]);
  });

  it("sign-in sends a SignInRequest-conformant body with the login CSRF token and nothing else", async () => {
    render(<Root />);
    await signInAs();
    await screen.findByRole("heading", { name: "Dashboard" });
    const post = api.calls.find((c) => c.method === "POST")!;
    expect(validate("SignInRequest", post.body)).toEqual({ ok: true });
    expect(post.csrf).toBe(TOKEN("L"));
    expect(post.url).toBe("/api/v1/auth/session");
  });

  it("reports an unreachable server without losing the form", async () => {
    render(<Root />);
    await screen.findByRole("heading", { name: "Sign in" });
    api.down = true;
    await signInAs();
    expect(await screen.findByText(/could not be reached/)).toBeTruthy();
    expect(screen.getByLabelText(/Username/)).toBeTruthy();
  });

  it("shows the unreachable state with a retry when the first status call fails", async () => {
    api.down = true;
    render(<Root />);
    expect(await screen.findByText(/could not be reached/)).toBeTruthy();
    api.down = false;
    await userEvent.click(screen.getByRole("button", { name: "Try again" }));
    expect(await screen.findByRole("heading", { name: "Sign in" })).toBeTruthy();
  });

  it("a rate-limited sign-in shows the product text for the category, not server text", async () => {
    render(<Root />);
    await screen.findByRole("heading", { name: "Sign in" });
    api.rateLimited = true;
    await signInAs();
    expect(await screen.findByText("Too many requests")).toBeTruthy();
    expect(screen.getByText("Wait a moment, then try again.")).toBeTruthy();
  });
});

describe("dashboard", () => {
  it("restores an existing session on load and shows capacity and readiness", async () => {
    api.signedIn = true;
    render(<Root />);
    expect(await screen.findByRole("heading", { name: "Dashboard" })).toBeTruthy();
    expect(await screen.findByRole("heading", { name: "local-host" })).toBeTruthy();
    expect(screen.getByText("8 logical")).toBeTruthy();
    expect(screen.getAllByText("16.0 GiB").length).toBeGreaterThanOrEqual(1); // summary tile and capacity table
    expect(screen.getByText("debian 13")).toBeTruthy();
    expect(screen.getByText(/looks ready to run virtual machines/)).toBeTruthy();
    expect(screen.getByText(/not a qualification/)).toBeTruthy();
    expect(screen.getByText(/matrix conformance only; it is not host qualification/)).toBeTruthy();
    expect(screen.getAllByText("Available").length).toBe(4);
    expect(screen.getByText("admin", { selector: "strong" }).tagName).toBe("STRONG");
    expect(await axeViolations(document.body)).toEqual([]);
  });

  it("states what is missing and never claims readiness when virtualization is unavailable", async () => {
    api.signedIn = true;
    api.host = { ...HOST, observed: { ...HOST.observed, capability_verdict: "unsupported", virtualization: { hardware: "unavailable", kvm_device: "unavailable", libvirt_packages: "unavailable", qemu_packages: "unknown" },
      capability_findings: [{ code: "NO_HW_VIRT", remediation: "Enable hardware virtualization (Intel VT-x / AMD-V) in the system firmware." }] } };
    render(<Root />);
    expect(await screen.findByText(/does not offer hardware virtualization/)).toBeTruthy();
    expect(screen.queryByText(/looks ready/)).toBeNull();
    expect(screen.getByText(/Intel VT-x/)).toBeTruthy();
    expect(screen.getAllByText("Not available").length).toBe(4); // three table rows and the storage tile
    expect(screen.getByText("Could not be determined")).toBeTruthy();
    expect(screen.getByText("Not a supported configuration")).toBeTruthy();
  });

  it("an unknown state (for example inside a container) is never shown as ready", async () => {
    api.signedIn = true;
    api.host = { ...HOST, observed: { ...HOST.observed, capability_verdict: "unknown", virtualization: { hardware: "available", kvm_device: "unknown", libvirt_packages: "unknown", qemu_packages: "unknown" },
      capability_findings: [{ code: "CONTAINERIZED", remediation: "" }] } };
    render(<Root />);
    expect(await screen.findByText(/could not be fully determined/)).toBeTruthy();
    expect(screen.queryByText(/looks ready/)).toBeNull();
    expect(screen.getByText(/running inside a container/)).toBeTruthy();
  });

  it("a host read failure shows a typed error with retry and keeps the session", async () => {
    api.signedIn = true;
    api.hostStatus = 503;
    render(<Root />);
    expect(await screen.findByText("Service temporarily unavailable")).toBeTruthy();
    api.hostStatus = 200;
    await userEvent.click(screen.getByRole("button", { name: "Try again" }));
    expect(await screen.findByRole("heading", { name: "local-host" })).toBeTruthy();
  });

  it("when the session expires, the next read returns to sign-in with an explanation", async () => {
    api.signedIn = true;
    render(<Root />);
    await screen.findByRole("heading", { name: "local-host" });
    api.signedIn = false; // the server ended the session (idle or absolute timeout)
    await userEvent.click(screen.getByRole("button", { name: "Refresh" }));
    expect(await screen.findByText("Your session has ended. Sign in again to continue.")).toBeTruthy();
    expect(screen.getByRole("heading", { name: "Sign in" })).toBeTruthy();
    expect(await axeViolations(document.body)).toEqual([]);
    await signInAs();
    expect(await screen.findByRole("heading", { name: "local-host" })).toBeTruthy();
  });
});

describe("sign out", () => {
  it("signs out with the session CSRF token and returns to the sign-in form", async () => {
    render(<Root />);
    await signInAs();
    await screen.findByRole("heading", { name: "local-host" });
    await userEvent.click(screen.getByRole("button", { name: "Sign out" }));
    expect(await screen.findByRole("heading", { name: "Sign in" })).toBeTruthy();
    const del = api.calls.find((c) => c.method === "DELETE")!;
    expect(del.csrf).toBe(TOKEN("S"));
    expect(del.body).toBeNull();
    expect(api.signedIn).toBe(false);
    expect(screen.queryByText("local-host")).toBeNull();
  });

  it("a stale token is refreshed once and sign-out is retried", async () => {
    api.signedIn = true;
    render(<Root />);
    await screen.findByRole("heading", { name: "local-host" });
    forgetCsrf(); // this tab lost its token (reload in another tab)
    await userEvent.click(screen.getByRole("button", { name: "Sign out" }));
    await waitFor(() => expect(screen.getByRole("heading", { name: "Sign in" })).toBeTruthy());
    expect(api.signedIn).toBe(false);
  });

  it("never stores anything in the browser", async () => {
    const setItem = vi.spyOn(Storage.prototype, "setItem");
    render(<Root />);
    await signInAs();
    await screen.findByRole("heading", { name: "local-host" });
    expect(setItem).not.toHaveBeenCalled();
    expect(document.cookie).toBe("");
  });
});

describe("VM inventory (read-only)", () => {
  async function openInventory() {
    api.signedIn = true;
    render(<Root />);
    await screen.findByRole("heading", { name: "local-host" });
    await userEvent.click(screen.getByRole("link", { name: "Virtual machines" }));
    return screen.findByRole("heading", { level: 1, name: "Virtual machines" });
  }

  it("shows 'No VMs yet' for an empty host", async () => {
    api.vms = [];
    await openInventory();
    expect(await screen.findByText("No VMs yet")).toBeTruthy();
    expect(await axeViolations(document.body)).toEqual([]);
  });

  it("lists the machines with their observed power state and offers no lifecycle controls", async () => {
    api.vms = [VM_RUNNING, vm({ id: "db-1", name: "db-1", observed: { ...NO_SIZE, power: "stopped", last_seen_at: "2026-10-09T09:00:00Z", managed: false, ip_address: null, login_user: null, disk_gib: null, snapshots: [], network: null } }),
      vm({ id: "wk-1", name: "wk-1", observed: { ...NO_SIZE, power: "paused", last_seen_at: "2026-10-09T09:00:00Z", managed: false, ip_address: null, login_user: null, disk_gib: null, snapshots: [], network: null } }),
      vm({ id: "cr-1", name: "cr-1", observed: { ...NO_SIZE, power: "crashed", last_seen_at: "2026-10-09T09:00:00Z", managed: false, ip_address: null, login_user: null, disk_gib: null, snapshots: [], network: null } })];
    await openInventory();
    const table = await screen.findByRole("table", { name: "Virtual machines on this host" });
    expect(table.textContent).toContain("web-1");
    for (const label of ["Running", "Stopped", "Paused", "Crashed"]) expect(table.textContent).toContain(label);
    // Read-only: no mutation control of any kind, not even a disabled one.
    const names = screen.getAllByRole("button").map((b) => b.textContent ?? "").filter((n) => !/^(All|Running|Stopped|Needs attention) \d+$/.test(n));
    expect(names.join("|")).not.toMatch(/create|start|stop|reboot|force|delete|remove/i);
    expect(await axeViolations(document.body)).toEqual([]);
    expect(api.calls.every((c) => c.method === "GET" || c.url === "/api/v1/auth/session")).toBe(true);
  });

  it("filters by state and by the search box, with counts", async () => {
    api.vms = [VM_RUNNING, vm({ id: "db-1", name: "db-1", observed: { ...NO_SIZE, power: "stopped", last_seen_at: "2026-10-09T09:00:00Z", managed: false, ip_address: null, login_user: null, disk_gib: null, snapshots: [], network: null } })];
    await openInventory();
    await screen.findByRole("table", { name: "Virtual machines on this host" });
    expect(screen.getByRole("button", { name: "All 2" }).getAttribute("aria-pressed")).toBe("true");
    await userEvent.click(screen.getByRole("button", { name: "Stopped 1" }));
    const table = screen.getByRole("table", { name: "Virtual machines on this host" });
    expect(table.textContent).toContain("db-1");
    expect(table.textContent).not.toContain("web-1");
    await userEvent.click(screen.getByRole("button", { name: "All 2" }));
    await userEvent.type(screen.getByRole("searchbox", { name: /Search virtual machines/ }), "web");
    expect(screen.getByRole("table", { name: "Virtual machines on this host" }).textContent).not.toContain("db-1");
    await userEvent.clear(screen.getByRole("searchbox", { name: /Search virtual machines/ }));
    await userEvent.type(screen.getByRole("searchbox", { name: /Search virtual machines/ }), "zzz");
    expect(await screen.findByText(/No VM matches/)).toBeTruthy();
  });

  it("opens a VM's own page from the list and offers one global Refresh and one Sign out", async () => {
    api.vms = [VM_RUNNING];
    await openInventory();
    await userEvent.click(await screen.findByRole("link", { name: "web-1" }));
    expect(await screen.findByRole("heading", { level: 1, name: "web-1" })).toBeTruthy();
    expect(screen.getAllByRole("button", { name: "Refresh" })).toHaveLength(1);
    expect(screen.getAllByRole("button", { name: "Sign out" })).toHaveLength(1);
  });

  it("pages with 'Show more' using the cursor", async () => {
    api.vms = [VM_RUNNING];
    api.nextCursor = "dm0tYQ";
    await openInventory();
    await userEvent.click(await screen.findByRole("button", { name: "Show more" }));
    expect(await screen.findByText("vm-z")).toBeTruthy();
    expect(api.calls.some((c) => c.url.includes("cursor=dm0tYQ"))).toBe(true);
  });

  it("an unavailable agent is a typed error with retry, and recovers", async () => {
    api.vmStatus = 503;
    await openInventory();
    expect(await screen.findByText("Service temporarily unavailable")).toBeTruthy();
    expect(screen.queryByText("No VMs yet")).toBeNull();
    api.vmStatus = 200;
    api.vms = [VM_RUNNING];
    await userEvent.click(screen.getByRole("button", { name: "Try again" }));
    expect(await screen.findByRole("table", { name: "Virtual machines on this host" })).toBeTruthy();
  });

  it("an unexpected inventory failure explains the unsupported-name limitation instead of showing a partial list", async () => {
    api.vmStatus = 500;
    await openInventory();
    expect(await screen.findByText("Something went wrong")).toBeTruthy();
    expect(screen.getByText(/cannot represent yet/)).toBeTruthy();
    expect(screen.queryByRole("table", { name: "Virtual machines on this host" })).toBeNull();
    expect(screen.queryByText("No VMs yet")).toBeNull();
  });

  it("warns when the host is not virtualization-ready", async () => {
    api.host = { ...HOST, observed: { ...HOST.observed, virtualization: { hardware: "unavailable", kvm_device: "unavailable", libvirt_packages: "unknown", qemu_packages: "unknown" } } };
    await openInventory();
    expect(await screen.findByText(/does not offer hardware virtualization/)).toBeTruthy();
  });

  it("a session that ended returns to sign-in", async () => {
    await openInventory();
    api.signedIn = false;
    await userEvent.click(screen.getByRole("button", { name: "Refresh" }));
    expect(await screen.findByText("Your session has ended. Sign in again to continue.")).toBeTruthy();
  });

  it("can sign out from the inventory view", async () => {
    await openInventory();
    await userEvent.click(screen.getByRole("button", { name: "Sign out" }));
    expect(await screen.findByRole("heading", { name: "Sign in" })).toBeTruthy();
  });
});
