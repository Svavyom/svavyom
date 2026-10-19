// fe-unit: the M3 networking journeys against a stateful fake of the browser-api: the network inventory (managed vs foreign), create-network validation,
// start/stop/autostart/delete with confirmations, the Network column and diagnosis in the VM list, compute and reservation dialogs, the network and size
// profile choices of the create form, closed operation types and typed params, and that nothing path- or XML-like is ever sent.
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { act, cleanup, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { Root } from "./Root";
import { checkNetworkInputs } from "./Networks";
import { availableProfiles, PROFILES } from "./profiles";
import { HOST, apiError, operation, vm, vmList, NO_SIZE } from "../api/fixtures";
import { forgetCsrf } from "../api/session";
import { validate } from "../api/validate";
import { axeViolations } from "../test-axe";
import type { Host, Image, Operation, VM, VirtualNetwork } from "../api/schema";

const KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGg4Zgd2sQ0v9i6Y0bq7n3m9c1m3k3Qm8iH6m3f3b2yd admin@laptop";
const IN = { authenticated: true, username: "admin", expires_at: "2026-10-09T08:30:00Z", role: "admin" };
const IMAGE: Image = {
  id: "debian-13", project_id: "default", generation: 1, name: "Debian 13", allowed_actions: [],
  desired: { source_digest: "sha256:" + "a".repeat(64) },
  observed: { state: "available", distribution: "Debian", version: "13", architecture: "x86_64", login_user: "debian", media: "disk", min_disk_gib: 3, qualification: "verified", qualification_evidence: null },
};
const STORAGE = { state: "available" as const, pool_total_gib: 457, pool_free_gib: 456, images_gib: 1, backups_configured: false, backups_gib: null, backups_free_gib: null, snapshots: "available" as const, backup_targets: [], allocation_note: "note" };
const ENABLED: Host = { ...HOST, observed: { ...HOST.observed, storage: STORAGE, creation: { enabled: true, network: "available", storage: "available", vcpu_options: [1, 2, 4], memory_mib_options: [512, 1024, 2048, 4096], disk_gib_options: [5, 10, 20, 40], ready: true, reasons: [] } } };

const net = (over: Partial<Omit<VirtualNetwork, "observed">> & { observed?: Partial<VirtualNetwork["observed"]> } = {}): VirtualNetwork => ({
  id: "lab-net", project_id: "default", generation: 1, name: "lab-net", allowed_actions: ["stop", "delete", "disable_autostart"],
  desired: { mode: "nat", autostart: true },
  observed: { state: "active", managed: true, bridge: "svbr7a7a7a7a", subnet: "10.77.0.0/24", gateway: "10.77.0.1", dhcp_start: "10.77.0.10", dhcp_end: "10.77.0.200", attached_vms: 0, reservations: [], ...over.observed },
  ...(({ observed: _o, ...rest }) => rest)(over),
});
const DEFAULT_NET: VirtualNetwork = net({ id: "svavyom-nat", name: "svavyom-nat", allowed_actions: [], desired: { mode: "nat", autostart: true }, observed: { managed: false, bridge: "virbr0", subnet: "192.168.122.0/24", gateway: "192.168.122.1", dhcp_start: "192.168.122.10", dhcp_end: "192.168.122.250" } });

const stopped = (n: VM["observed"]["network"], allowed = ["start", "delete", "compute", "reserve_ip"], ip: string | null = null): VM => vm({ id: "db-1", name: "db-1", allowed_actions: allowed as VM["allowed_actions"],
  observed: { ...NO_SIZE, power: "stopped", last_seen_at: "2026-10-10T09:00:00Z", managed: true, ip_address: ip, login_user: "debian", disk_gib: 20, snapshots: [], network: n } });
const NET_OBS = { name: "lab-net", mac: "52:54:00:aa:bb:cc", reserved_ip: null, state: "active" as const };

type Call = { method: string; url: string; headers: Record<string, string>; body: any };

class Fake {
  calls: Call[] = [];
  host: Host = ENABLED;
  nets: VirtualNetwork[] = [DEFAULT_NET, net()];
  netsFail = false;
  n = 0;
  images: Image[] = [IMAGE];
  vms: VM[] = [];
  submit: Array<"ok" | "unreachable" | Parameters<typeof apiError>[0]> = ["ok"];
  ops: Operation[] = [operation({ id: "op-1", status: "succeeded", attempts: 1, allowed_actions: [] })];
  json(status: number, body: unknown) { return new Response(JSON.stringify(body), { status, headers: { "X-CSRF-Token": "S".repeat(43) } }); }
  fetch = vi.fn(async (url: string, init: RequestInit = {}) => {
    const headers = (init.headers ?? {}) as Record<string, string>;
    const call: Call = { method: init.method ?? "GET", url, headers, body: init.body ? JSON.parse(init.body as string) : null };
    this.calls.push(call);
    if (url === "/api/v1/auth/session") return this.json(200, IN);
    if (url === "/api/v1/hosts/local") return this.json(200, this.host);
    if (url === "/api/v1/images") return this.json(200, { items: this.images, allowed_actions: [], next_cursor: null });
    if (url.startsWith("/api/v1/virtual-networks")) return this.netsFail ? this.json(503, apiError("unavailable")) : this.json(200, { items: this.nets, allowed_actions: ["create"], next_cursor: null });
    if (url.startsWith("/api/v1/vms")) return this.json(200, vmList(this.vms));
    if (url === "/api/v1/operations" && call.method === "POST") {
      const next = this.submit.length > 1 ? this.submit.shift()! : this.submit[0]!;
      if (next === "unreachable") throw new TypeError("network");
      if (next !== "ok") return this.json(next === "conflict" ? 409 : next === "prohibited" ? 422 : 400, apiError(next));
      this.n += 1;
      return this.json(202, operation({ id: `op-${this.n}`, type: call.body.type, resource_kind: call.body.kind, resource_id: call.body.id, status: "pending" }));
    }
    const m = /^\/api\/v1\/operations\/(op-\d+)$/.exec(url);
    if (m) {
      const base = this.ops.length > 1 ? this.ops.shift()! : this.ops[0]!;
      const post = this.posts()[Number(m[1]!.slice(3)) - 1]?.body;
      return this.json(200, { ...base, id: m[1], ...(post ? { type: post.type, resource_kind: post.kind, resource_id: post.id } : {}) });
    }
    return this.json(404, apiError("not_found"));
  });
  posts() { return this.calls.filter((c) => c.method === "POST" && c.url === "/api/v1/operations"); }
}

let api: Fake;
beforeEach(() => { api = new Fake(); forgetCsrf(); vi.stubGlobal("fetch", api.fetch); });
afterEach(() => { cleanup(); vi.unstubAllGlobals(); });

describe("fixtures are valid", () => {
  it("validates the fake's network, VM and host against the schemas", () => {
    expect(validate("VirtualNetwork", net()).ok).toBe(true);
    expect(validate("VirtualNetwork", DEFAULT_NET).ok).toBe(true);
    expect(validate("VM", stopped(NET_OBS)).ok).toBe(true);
    expect(validate("Host", ENABLED).ok).toBe(true);
  });
});

describe("local network checks", () => {
  const ok = (n = "lab-net", s = "10.77.0.0/24", a = "10.77.0.10", b = "10.77.0.200") => checkNetworkInputs(n, s, a, b);
  it("accepts a sound specification", () => expect(ok()).toBeNull());
  it("refuses what the server and host would refuse", () => {
    expect(ok("Lab")?.field).toBe("name");
    expect(ok("x")?.field).toBe("name");
    expect(ok("lab-net", "8.8.8.0/24", "8.8.8.10", "8.8.8.20")?.message).toMatch(/private/);
    expect(ok("lab-net", "10.0.0.0/8", "10.0.0.10", "10.0.0.20")?.message).toMatch(/prefix/);
    expect(ok("lab-net", "10.77.0.5/24")?.message).toMatch(/network address/);
    expect(ok("lab-net", "10.77.0.0")?.field).toBe("subnet");
    expect(ok("lab-net", "10.77.0.0/24", "10.77.0.1", "10.77.0.20")?.field).toBe("dhcp");
    expect(ok("lab-net", "10.77.0.0/24", "10.77.0.10", "10.77.0.255")?.field).toBe("dhcp");
    expect(ok("lab-net", "10.77.0.0/24", "10.77.0.50", "10.77.0.20")?.field).toBe("dhcp");
    expect(ok("lab-net", "10.77.0.0/24", "10.78.0.10", "10.78.0.20")?.field).toBe("dhcp");
    expect(ok("lab-net", "172.20.0.0/16", "172.20.0.10", "172.20.0.20")).toBeNull();
    expect(ok("lab-net", "172.40.0.0/16", "172.40.0.10", "172.40.0.20")?.message).toMatch(/private/);
    expect(ok("lab-net", "192.168.5.0/24'/><x", "a", "b")?.field).toBe("subnet");
  });
});

describe("network inventory", () => {
  beforeEach(() => { location.hash = "#/networks"; });

  it("lists managed and foreign networks honestly, offers actions only on managed ones, and passes axe", async () => {
    api.nets = [DEFAULT_NET, net({ observed: { attached_vms: 1, reservations: [{ mac: "52:54:00:aa:bb:cc", ip: "10.77.0.50" }] }, allowed_actions: ["stop", "disable_autostart"] })];
    render(<Root />);
    expect(await screen.findByRole("heading", { level: 1, name: "Networks" })).toBeTruthy();
    const table = await screen.findByRole("region", { name: "Networks on this host" });
    expect(within(table).getByText("Foreign (read-only)")).toBeTruthy();
    expect(within(table).getByText("Svavyom-managed")).toBeTruthy();
    expect(within(table).getByText("10.77.0.0/24, gateway 10.77.0.1")).toBeTruthy();
    expect(within(table).getByText("10.77.0.50 (52:54:00:aa:bb:cc)")).toBeTruthy();
    expect(screen.queryByRole("button", { name: /svavyom-nat/ })).toBeNull();
    expect(screen.getByRole("button", { name: "Stop lab-net" })).toBeTruthy();
    expect(screen.queryByRole("button", { name: "Delete lab-net" })).toBeNull();
    expect(await axeViolations(document.body)).toEqual([]);
  });

  it("reports the host bridge in each state, with the countdown, and never offers to apply anything", async () => {
    const cases: Array<[Host["observed"]["bridge"], RegExp, RegExp?]> = [
      [null, /No host bridge/],
      [{ state: "planned", bridge: "svbr0", interface: "eno1", seconds_left: null }, /Nothing on the host network has changed yet/],
      [{ state: "pending_confirmation", bridge: "svbr0", interface: "eno1", seconds_left: 87 }, /87 seconds left/, /bridge confirm/],
      [{ state: "active", bridge: "svbr0", interface: "eno1", seconds_left: null }, /carries the host.s network/, /bridge rollback/],
    ];
    for (const [bridge, text, extra] of cases) {
      api.host = { ...ENABLED, observed: { ...ENABLED.observed, bridge } };
      const { unmount } = render(<Root />);
      const card = await screen.findByRole("region", { name: "Host bridge" });
      expect(within(card).getByText(text)).toBeTruthy();
      if (extra) expect(card.textContent).toMatch(extra);
      expect(within(card).queryByRole("button")).toBeNull();
      expect(await axeViolations(document.body)).toEqual([]);
      unmount();
      cleanup();
    }
  });

  it("counts down on its own and reloads when the countdown ends", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    try {
      api.host = { ...ENABLED, observed: { ...ENABLED.observed, bridge: { state: "pending_confirmation", bridge: "svbr0", interface: "eno1", seconds_left: 3 } } };
      render(<Root />);
      const card = await screen.findByRole("region", { name: "Host bridge" });
      expect(card.textContent).toMatch(/3 seconds left/);
      for (let i = 0; i < 4; i += 1) await act(async () => { await vi.advanceTimersByTimeAsync(1000); });
      expect(card.textContent).toMatch(/no time left/);
      api.host = { ...ENABLED, observed: { ...ENABLED.observed, bridge: null } };
      for (let i = 0; i < 5; i += 1) await act(async () => { await vi.advanceTimersByTimeAsync(1000); });
      await waitFor(() => expect(within(screen.getByRole("region", { name: "Host bridge" })).getByText(/No host bridge/)).toBeTruthy());
    } finally {
      vi.useRealTimers();
    }
  });

  it("shows no actions and no create form while the switch is closed", async () => {
    api.host = { ...HOST, observed: { ...HOST.observed, storage: STORAGE } };
    render(<Root />);
    await screen.findByRole("region", { name: "Networks on this host" });
    expect(screen.queryByRole("button", { name: /Stop|Delete|Create network/ })).toBeNull();
    expect(screen.queryByLabelText(/^Subnet/)).toBeNull();
  });

  it("creates a managed network only from valid inputs, with the typed params", async () => {
    render(<Root />);
    await userEvent.type(await screen.findByLabelText(/^Name/), "Lab Net");
    await userEvent.type(screen.getByLabelText(/^Subnet/), "10.77.0.0/24");
    await userEvent.type(screen.getByLabelText(/^DHCP range start/), "10.77.0.10");
    await userEvent.type(screen.getByLabelText(/^DHCP range end/), "10.77.0.200");
    await userEvent.click(screen.getByRole("button", { name: "Create network" }));
    expect(await screen.findByText(/lower-case letters/)).toBeTruthy();
    expect(api.posts()).toHaveLength(0);
    await userEvent.clear(screen.getByLabelText(/^Name/));
    await userEvent.type(screen.getByLabelText(/^Name/), "lab-net");
    await userEvent.clear(screen.getByLabelText(/^Subnet/));
    await userEvent.type(screen.getByLabelText(/^Subnet/), "8.8.8.0/24");
    await userEvent.click(screen.getByRole("button", { name: "Create network" }));
    expect(await screen.findByText(/private \(RFC 1918\)/)).toBeTruthy();
    expect(api.posts()).toHaveLength(0);
    await userEvent.clear(screen.getByLabelText(/^Subnet/));
    await userEvent.type(screen.getByLabelText(/^Subnet/), "10.77.0.0/24");
    api.ops = [operation({ id: "op-1", type: "network_create", resource_kind: "VirtualNetwork", resource_id: "lab-net", status: "succeeded", attempts: 1, allowed_actions: [] })];
    await userEvent.click(screen.getByRole("button", { name: "Create network" }));
    await waitFor(() => expect(api.posts()).toHaveLength(1));
    expect(api.posts()[0]!.body).toMatchObject({ type: "network_create", kind: "VirtualNetwork", id: "lab-net", params: { subnet: "10.77.0.0/24", dhcp_start: "10.77.0.10", dhcp_end: "10.77.0.200" } });
    expect(JSON.stringify(api.posts()[0]!.body)).not.toMatch(/xml|bridge|<network/i);
  });

  it("offers a bridge network only while the host bridge is active, and sends just the bridge name for it", async () => {
    render(<Root />);
    await screen.findByLabelText(/^Name/);
    expect(screen.queryByLabelText("Network type")).toBeNull(); // no host bridge: NAT only
    cleanup();
    api.host = { ...ENABLED, observed: { ...ENABLED.observed, bridge: { state: "pending_confirmation", bridge: "svbr0", interface: "eno1", seconds_left: 60 } } };
    render(<Root />);
    await screen.findByLabelText(/^Name/);
    expect(screen.queryByLabelText("Network type")).toBeNull(); // an unconfirmed bridge may still be rolled back
    cleanup();
    api.host = { ...ENABLED, observed: { ...ENABLED.observed, bridge: { state: "active", bridge: "svbr0", interface: "eno1", seconds_left: null } } };
    render(<Root />);
    await userEvent.selectOptions(await screen.findByLabelText("Network type"), "bridge");
    expect(screen.queryByLabelText(/^Subnet/)).toBeNull();
    expect(screen.queryByLabelText(/^DHCP range/)).toBeNull();
    expect(screen.getByText(/cannot show their addresses/)).toBeTruthy();
    await userEvent.type(screen.getByLabelText(/^Name/), "Lan Net");
    await userEvent.click(screen.getByRole("button", { name: "Create network" }));
    expect(await screen.findByText(/lower-case letters/)).toBeTruthy();
    expect(api.posts()).toHaveLength(0);
    await userEvent.clear(screen.getByLabelText(/^Name/));
    await userEvent.type(screen.getByLabelText(/^Name/), "lan");
    api.ops = [operation({ id: "op-1", type: "network_create", resource_kind: "VirtualNetwork", resource_id: "lan", status: "succeeded", attempts: 1, allowed_actions: [] })];
    await userEvent.click(screen.getByRole("button", { name: "Create network" }));
    await waitFor(() => expect(api.posts()).toHaveLength(1));
    expect(api.posts()[0]!.body).toMatchObject({ type: "network_create", kind: "VirtualNetwork", id: "lan", params: { bridge: "svbr0" } });
    expect(Object.keys(api.posts()[0]!.body.params)).toEqual(["bridge"]);
    expect(await axeViolations(document.body)).toEqual([]);
  });

  it("starts, toggles autostart without a dialog; stop and delete ask first and send nothing on Cancel", async () => {
    api.nets = [DEFAULT_NET, net({ observed: { state: "inactive" }, allowed_actions: ["start", "delete", "enable_autostart"], desired: { mode: "nat", autostart: false } })];
    api.ops = [operation({ id: "op-1", type: "network_start", resource_kind: "VirtualNetwork", resource_id: "lab-net", status: "succeeded", attempts: 1, allowed_actions: [] })];
    render(<Root />);
    await userEvent.click(await screen.findByRole("button", { name: "Start lab-net" }));
    await waitFor(() => expect(api.posts()).toHaveLength(1));
    expect(api.posts()[0]!.body).toMatchObject({ type: "network_start", kind: "VirtualNetwork", id: "lab-net" });
    expect(api.posts()[0]!.body.params).toBeUndefined();
    await screen.findByText("Network started", {}, { timeout: 5000 });
    await userEvent.click(screen.getByRole("button", { name: "Turn autostart on lab-net" }));
    await waitFor(() => expect(api.posts()).toHaveLength(2));
    expect(api.posts()[1]!.body).toMatchObject({ type: "network_autostart", params: { autostart: "on" } });
    await screen.findByText("Autostart changed", {}, { timeout: 5000 });
    await userEvent.click(await screen.findByRole("button", { name: "Delete lab-net" }));
    expect(await screen.findByText(/removes this Svavyom-managed network/)).toBeTruthy();
    await userEvent.click(screen.getByRole("button", { name: "Cancel" }));
    expect(api.posts()).toHaveLength(2);
    await userEvent.click(screen.getByRole("button", { name: "Delete lab-net" }));
    await userEvent.click(await screen.findByRole("button", { name: "Delete network permanently" }));
    await waitFor(() => expect(api.posts()).toHaveLength(3));
    expect(api.posts()[2]!.body).toMatchObject({ type: "network_delete", kind: "VirtualNetwork", id: "lab-net" });
  });

  it("explains a refusal from the closed category and keeps the idempotency key on an unknown outcome", async () => {
    api.submit = ["unreachable", "ok"];
    render(<Root />);
    await userEvent.click(await screen.findByRole("button", { name: "Stop lab-net" }));
    await userEvent.click(await screen.findByRole("button", { name: "Stop network" }));
    expect(await screen.findByText(/could not confirm that the request arrived/)).toBeTruthy();
    await userEvent.click(screen.getByRole("button", { name: "Stop lab-net" }));
    await userEvent.click(await screen.findByRole("button", { name: "Stop network" }));
    await waitFor(() => expect(api.posts()).toHaveLength(2));
    expect(api.posts()[1]!.body.idempotency_key).toBe(api.posts()[0]!.body.idempotency_key);
  });

  it("says when the network list cannot be read instead of showing none", async () => {
    api.netsFail = true;
    render(<Root />);
    expect(await screen.findByText(/Service temporarily unavailable|temporarily unavailable/i)).toBeTruthy();
    expect(screen.queryByText("No networks")).toBeNull();
  });
});

describe("VM list and page: network, diagnosis, size and reservation", () => {
  beforeEach(() => { location.hash = "#/vms"; });

  it("shows the network, MAC and reservation, and diagnoses a missing address", async () => {
    api.vms = [
      stopped({ ...NET_OBS, reserved_ip: "10.77.0.50" }, ["start", "delete", "compute", "release_ip"]),
      vm({ id: "wait-1", name: "wait-1", allowed_actions: [], observed: { ...NO_SIZE, power: "running", last_seen_at: "2026-10-10T09:00:00Z", managed: true, ip_address: null, login_user: "debian", disk_gib: 10, snapshots: [], network: NET_OBS } }),
      vm({ id: "down-1", name: "down-1", allowed_actions: [], observed: { ...NO_SIZE, power: "stopped", last_seen_at: "2026-10-10T09:00:00Z", managed: true, ip_address: null, login_user: "debian", disk_gib: 10, snapshots: [], network: { ...NET_OBS, state: "inactive" } } }),
    ];
    render(<Root />);
    expect(await screen.findByText(/reserved 10\.77\.0\.50/)).toBeTruthy();
    expect(screen.getAllByText("52:54:00:aa:bb:cc").length).toBe(3);
    expect(screen.getByText(/waiting for a DHCP lease/)).toBeTruthy();
    expect(screen.getByText(/network is not active/)).toBeTruthy();
  });

  it("changes the size of a stopped VM within the host's choices", async () => {
    api.vms = [stopped(NET_OBS)];
    api.ops = [operation({ id: "op-1", type: "compute", resource_id: "db-1", status: "succeeded", attempts: 1, allowed_actions: [] })];
    location.hash = "#/vms/db-1";
    render(<Root />);
    await userEvent.click(await screen.findByRole("button", { name: "Change size of db-1" }));
    expect(await screen.findByText(/no hot-plug/)).toBeTruthy();
    await userEvent.selectOptions(screen.getByLabelText("vCPUs"), "4");
    await userEvent.selectOptions(screen.getByLabelText("Memory"), "2048");
    await userEvent.click(screen.getByRole("button", { name: "Change size" }));
    await waitFor(() => expect(api.posts()).toHaveLength(1));
    expect(api.posts()[0]!.body).toMatchObject({ type: "compute", kind: "VM", id: "db-1", params: { vcpus: 4, memory_mib: 2048 } });
  });

  it("reserves an address only after a valid IPv4 and says what a reservation is", async () => {
    api.vms = [stopped(NET_OBS)];
    location.hash = "#/vms/db-1";
    render(<Root />);
    await userEvent.click(await screen.findByRole("button", { name: "Reserve address for db-1" }));
    expect(await screen.findByText(/nothing is configured inside the guest/i)).toBeTruthy();
    await userEvent.type(screen.getByLabelText(/^IPv4 address/), "10.77.0.x");
    await userEvent.click(screen.getByRole("button", { name: "Reserve the address" }));
    expect(await screen.findByText(/Enter an IPv4 address/)).toBeTruthy();
    expect(api.posts()).toHaveLength(0);
    await userEvent.clear(screen.getByLabelText(/^IPv4 address/));
    await userEvent.type(screen.getByLabelText(/^IPv4 address/), "10.77.0.50");
    await userEvent.click(screen.getByRole("button", { name: "Reserve the address" }));
    await waitFor(() => expect(api.posts()).toHaveLength(1));
    expect(api.posts()[0]!.body).toMatchObject({ type: "reserve_ip", kind: "VM", id: "db-1", params: { ip_address: "10.77.0.50" } });
  });

  it("releases a reservation without a dialog", async () => {
    api.vms = [stopped({ ...NET_OBS, reserved_ip: "10.77.0.50" }, ["start", "delete", "compute", "release_ip"])];
    location.hash = "#/vms/db-1";
    render(<Root />);
    await userEvent.click(await screen.findByRole("button", { name: "Release address of db-1" }));
    await waitFor(() => expect(api.posts()).toHaveLength(1));
    expect(api.posts()[0]!.body).toMatchObject({ type: "release_ip", kind: "VM", id: "db-1" });
    expect(api.posts()[0]!.body.params).toBeUndefined();
  });
});

describe("create form: network and size profile", () => {
  beforeEach(() => { location.hash = "#/create"; });

  it("offers the default network and active managed ones only, and sends the chosen network", async () => {
    api.nets = [DEFAULT_NET, net(), net({ id: "off-net", name: "off-net", observed: { state: "inactive" } })];
    render(<Root />);
    await userEvent.type(await screen.findByLabelText(/^Name/), "web-1");
    await userEvent.click(screen.getByRole("button", { name: "Continue" }));
    const sel = (await screen.findByLabelText("Network")) as HTMLSelectElement;
    expect(Array.from(sel.options).map((o) => o.textContent)).toEqual(["Default network", "lab-net (10.77.0.0/24)"]);
    await userEvent.selectOptions(sel, "lab-net");
    await userEvent.click(screen.getByLabelText(/SSH public key/));
    await userEvent.paste(KEY);
    await userEvent.click(screen.getByRole("button", { name: "Review" }));
    expect(await screen.findByText("lab-net")).toBeTruthy();
    await userEvent.click(screen.getByRole("button", { name: "Create VM" }));
    await waitFor(() => expect(api.posts()).toHaveLength(1));
    expect(api.posts()[0]!.body.create.network).toBe("lab-net");
  });

  it("omits the network for the default and still works when the network list cannot be read", async () => {
    api.netsFail = true;
    render(<Root />);
    await userEvent.type(await screen.findByLabelText(/^Name/), "web-1");
    await userEvent.click(screen.getByRole("button", { name: "Continue" }));
    await screen.findByLabelText("Network");
    await userEvent.click(screen.getByLabelText(/SSH public key/));
    await userEvent.paste(KEY);
    await userEvent.click(screen.getByRole("button", { name: "Review" }));
    await userEvent.click(await screen.findByRole("button", { name: "Create VM" }));
    await waitFor(() => expect(api.posts()).toHaveLength(1));
    expect(api.posts()[0]!.body.create.network).toBeUndefined();
  });

  it("fills the three sizes from a profile and turns into Custom when one is changed", async () => {
    render(<Root />);
    await userEvent.click(await screen.findByRole("button", { name: /^Medium/ }));
    expect(screen.getByRole("button", { name: /^Medium/ }).getAttribute("aria-pressed")).toBe("true");
    expect((screen.getByLabelText("vCPUs") as HTMLSelectElement).value).toBe("2");
    expect((screen.getByLabelText("Memory") as HTMLSelectElement).value).toBe("2048");
    expect((screen.getByLabelText("Root disk") as HTMLSelectElement).value).toBe("20");
    await userEvent.selectOptions(screen.getByLabelText("vCPUs"), "4");
    expect(screen.getByRole("button", { name: "Custom" }).getAttribute("aria-pressed")).toBe("true");
  });
});

describe("profiles", () => {
  const c = ENABLED.observed.creation;
  it("offers only profiles whose every value the host offers, and respects the image minimum", () => {
    expect(availableProfiles(c, 1).map((p) => p.id)).toEqual(["small", "medium", "large"]);
    expect(availableProfiles({ ...c, vcpu_options: [1, 2] }, 1).map((p) => p.id)).toEqual(["small", "medium"]);
    expect(availableProfiles(c, 30).map((p) => p.id)).toEqual(["large"]);
    expect(availableProfiles({ ...c, disk_gib_options: [] }, 1)).toEqual([]);
  });
  it("carries sizes only: no secret, no image, no network", () => {
    for (const p of PROFILES) expect(Object.keys(p).sort()).toEqual(["diskGiB", "id", "label", "memoryMiB", "vcpus"]);
  });
});
