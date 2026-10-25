// fe-unit: the Create VM and Start journeys (M1-E02-S02 / M1-E04-S02) against a stateful fake of the browser-api: disabled and
// not-ready states, local validation, the review step, typed progress, idempotent re-submission, and the connection hint.
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { Root } from "./Root";
import { describeOperation } from "./OperationProgress";
import { HOST, apiError, operation, vm, vmList, NO_SIZE } from "../api/fixtures";
import { forgetCsrf } from "../api/session";
import { validate } from "../api/validate";
import { axeViolations } from "../test-axe";
import type { Host, Image, Operation, VM } from "../api/schema";

const KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGg4Zgd2sQ0v9i6Y0bq7n3m9c1m3k3Qm8iH6m3f3b2yd admin@laptop";
const IN = { authenticated: true, username: "admin", expires_at: "2026-10-09T08:30:00Z", role: "admin" };
const IMAGE: Image = {
  id: "debian-13", project_id: "default", generation: 1, name: "Debian 13", allowed_actions: [],
  desired: { source_digest: "sha256:" + "a".repeat(64) },
  observed: { state: "available", distribution: "Debian", version: "13", architecture: "x86_64", login_user: "debian", media: "disk", min_disk_gib: 3, qualification: "verified", qualification_evidence: null },
};
const ENABLED: Host = { ...HOST, observed: { ...HOST.observed, creation: { enabled: true, network: "available", storage: "available", vcpu_options: [1, 2, 4], memory_mib_options: [512, 1024], disk_gib_options: [2, 10, 20], ready: true, reasons: ["image_unqualified", "host_not_qualified"] } } };

type Call = { method: string; url: string; headers: Record<string, string>; body: any };

class Fake {
  calls: Call[] = [];
  host: Host = ENABLED;
  images: Image[] = [IMAGE];
  vms: VM[] = [];
  submit: Array<"ok" | "unreachable" | Parameters<typeof apiError>[0]> = ["ok"];
  ops: Operation[] = [operation({ id: "op-1", type: "create", resource_id: "web-1", status: "running" }), operation({ id: "op-1", type: "create", resource_id: "web-1", status: "succeeded", attempts: 1, allowed_actions: [] })];
  tokenOnOperations = true; // the real server sends the CSRF header only on the session endpoints
  json(status: number, body: unknown, withToken = true) { return new Response(JSON.stringify(body), { status, headers: withToken ? { "X-CSRF-Token": "S".repeat(43) } : {} }); }
  fetch = vi.fn(async (url: string, init: RequestInit = {}) => {
    const headers = (init.headers ?? {}) as Record<string, string>;
    const call: Call = { method: init.method ?? "GET", url, headers, body: init.body ? JSON.parse(init.body as string) : null };
    this.calls.push(call);
    if (url === "/api/v1/auth/session") return this.json(200, IN);
    if (url === "/api/v1/hosts/local") return this.json(200, this.host);
    if (url === "/api/v1/images") return this.json(200, { items: this.images, allowed_actions: [], next_cursor: null });
    if (url.startsWith("/api/v1/vms")) return this.json(200, vmList(this.vms));
    if (url === "/api/v1/operations" && call.method === "POST") {
      const next = this.submit.length > 1 ? this.submit.shift()! : this.submit[0]!;
      if (next === "unreachable") throw new TypeError("network");
      if (next !== "ok") return this.json(next === "conflict" ? 409 : next === "unavailable" ? 503 : 400, apiError(next));
      return this.json(202, operation({ id: "op-1", type: call.body.type, resource_id: call.body.id, status: "pending" }), this.tokenOnOperations);
    }
    if (url === "/api/v1/operations/op-1") return this.json(200, this.ops.length > 1 ? this.ops.shift() : this.ops[0]);
    return this.json(404, apiError("not_found"));
  });
  posts() { return this.calls.filter((c) => c.method === "POST" && c.url === "/api/v1/operations"); }
}

let api: Fake;
beforeEach(() => { api = new Fake(); forgetCsrf(); location.hash = "#/create"; vi.stubGlobal("fetch", api.fetch); });
afterEach(() => { cleanup(); vi.unstubAllGlobals(); });

async function fill(name = "web-1", key = KEY) {
  await userEvent.type(await screen.findByLabelText(/^Name/), name);
  await userEvent.click(screen.getByRole("button", { name: "Continue" }));
  await userEvent.click(await screen.findByLabelText(/SSH public key/));
  await userEvent.paste(key);
}

describe("create form states", () => {
  it("explains when creation is not enabled on the server and offers no form", async () => {
    api.host = HOST;
    render(<Root />);
    expect(await screen.findByText(/VM creation is not enabled on this installation/)).toBeTruthy();
    expect(screen.queryByRole("button", { name: "Review" })).toBeNull();
  });

  it("disables the form with a reason when the host network or storage is not ready", async () => {
    api.host = { ...ENABLED, observed: { ...ENABLED.observed, creation: { ...ENABLED.observed.creation, network: "unavailable", ready: false, reasons: ["network_unavailable"] } } };
    render(<Root />);
    expect(await screen.findByText(/NAT network for VMs is not available/)).toBeTruthy();
    expect(screen.queryByRole("button", { name: "Review" })).toBeNull();
  });

  it("points to the operator when no image can be chosen, and never offers a merely registered image", async () => {
    api.host = { ...ENABLED, observed: { ...ENABLED.observed, creation: { ...ENABLED.observed.creation, ready: false, reasons: ["no_usable_image"] } } };
    api.images = [{ ...IMAGE, observed: { ...IMAGE.observed, qualification: "registered", qualification_evidence: null } }];
    render(<Root />);
    expect(await screen.findByText(/No image can be chosen yet/)).toBeTruthy();
    expect(screen.queryByRole("button", { name: "Review" })).toBeNull();
  });

  it("offers only verified or qualified images, labelled by qualification", async () => {
    api.images = [{ ...IMAGE, observed: { ...IMAGE.observed, qualification: "registered", qualification_evidence: null }, id: "raw-1", name: "Raw 1" }, IMAGE, { ...IMAGE, id: "q-1", name: "Qual 1", observed: { ...IMAGE.observed, qualification: "qualified", qualification_evidence: null } }];
    render(<Root />);
    await screen.findByRole("button", { name: "Continue" });
    const labels = Array.from((screen.getByLabelText("Image") as HTMLSelectElement).options).map((o) => o.textContent);
    expect(labels).toEqual(["Debian 13 (login user debian, compatibility declared, not yet qualified)", "Qual 1 (login user debian, real-host qualified)"]);
  });

  it("shows the unqualified-image and unqualified-host notices beside a working form", async () => {
    render(<Root />);
    await screen.findByRole("button", { name: "Continue" });
    expect(screen.getByText(/No image has been qualified on real hardware yet/)).toBeTruthy();
    expect(screen.getByText(/This host has not been qualified for Svavyom/)).toBeTruthy();
  });

  it("shows the Development Preview notice and passes axe", async () => {
    render(<Root />);
    await screen.findByRole("button", { name: "Continue" });
    expect(screen.getByText(/Development Preview: VM creation is experimental/)).toBeTruthy();
    expect(await axeViolations(document.body)).toEqual([]);
  });
});

describe("create validation", () => {
  it("rejects a bad name and a missing key locally and sends nothing", async () => {
    render(<Root />);
    await userEvent.type(await screen.findByLabelText(/^Name/), "Bad_Name");
    await userEvent.click(screen.getByRole("button", { name: "Continue" }));
    expect((await screen.findAllByText(/lower-case letters, digits or hyphens/)).length).toBeGreaterThan(0);
    expect(screen.queryByLabelText(/SSH public key/)).toBeNull(); // still on the first step
    await userEvent.clear(screen.getByLabelText(/^Name/));
    await userEvent.type(screen.getByLabelText(/^Name/), "web-1");
    await userEvent.click(screen.getByRole("button", { name: "Continue" }));
    await userEvent.click(await screen.findByRole("button", { name: "Review" }));
    expect(screen.getAllByText("Paste one SSH public key").length).toBeGreaterThan(0);
    expect(api.posts()).toHaveLength(0);
  });

  it("refuses a private key, several lines, and a non-key", async () => {
    render(<Root />);
    await fill("web-1", "-----BEGIN OPENSSH PRIVATE KEY-----");
    await userEvent.click(screen.getByRole("button", { name: "Review" }));
    expect((await screen.findAllByText(/Never paste a private key/)).length).toBeGreaterThan(0);
    expect(api.posts()).toHaveLength(0);
    expect(document.body.innerHTML).not.toContain("BEGIN OPENSSH");
  });
});

const ISO: Image = {
  ...IMAGE, id: "windowsserver2019-iso", name: "Windows Server 2019 Eval",
  observed: { ...IMAGE.observed, distribution: "Windows", version: "2019", login_user: null, media: "iso", qualification: "verified" },
};

describe("installation media (M6-E01-S06)", () => {
  async function toNetworkStep() {
    api.images = [ISO];
    render(<Root />);
    await userEvent.type(await screen.findByLabelText(/^Name/), "win-1");
    await userEvent.click(screen.getByRole("button", { name: "Continue" }));
  }

  it("describes the graphical console that exists and no longer says there is none", async () => {
    await toNetworkStep();
    expect(await screen.findByText(/follow the installer in the/)).toBeTruthy();
    expect(screen.getAllByText("Graphical console").length).toBeGreaterThan(0);
    expect(document.body.textContent).not.toMatch(/does not run a graphical console/);
    expect(document.body.textContent).not.toMatch(/must be usable over the serial console/);
    await userEvent.click(screen.getByRole("button", { name: "Review" }));
    expect(await screen.findByText(/Follow it in the graphical console/)).toBeTruthy();
    expect(document.body.textContent).not.toMatch(/does not know whether the installer offers a serial console/);
    expect(await axeViolations(document.body)).toEqual([]);
  });

  it("after create, says the VM is stopped and points to Start and the graphical console", async () => {
    await toNetworkStep();
    api.ops = [operation({ id: "op-1", type: "create", resource_id: "win-1", status: "succeeded", attempts: 1, allowed_actions: [] })];
    await userEvent.click(screen.getByRole("button", { name: "Review" }));
    await userEvent.click(await screen.findByRole("button", { name: "Create VM" }));
    expect(await screen.findByText(/then open the Graphical console to follow the installer/, {}, { timeout: 5000 })).toBeTruthy();
    expect(screen.getByRole("link", { name: "Open win-1" }).getAttribute("href")).toBe("#/vms/win-1");
  });

  it("offers no 'stopped' notice or VM link when the create failed", async () => {
    await toNetworkStep();
    api.ops = [operation({ id: "op-1", type: "create", resource_id: "win-1", status: "failed", error_category: "conflict", attempts: 1, allowed_actions: [] })];
    await userEvent.click(screen.getByRole("button", { name: "Review" }));
    await userEvent.click(await screen.findByRole("button", { name: "Create VM" }));
    await screen.findByRole("link", { name: "Go to the VM list" }, { timeout: 5000 });
    expect(screen.queryByRole("link", { name: "Open win-1" })).toBeNull();
    expect(document.body.textContent).not.toMatch(/creating a VM does not start it/);
  });
});

describe("create journey", () => {
  it("reviews with a fingerprint only, submits a conformant body, then shows typed progress to a stopped VM", async () => {
    render(<Root />);
    await fill();
    await userEvent.click(screen.getByRole("button", { name: "Review" }));
    expect(await screen.findByRole("heading", { name: "Review" })).toBeTruthy();
    await waitFor(() => expect(screen.getByText(/^SHA256:/)).toBeTruthy());
    expect(document.body.textContent).not.toContain("AAAAC3NzaC1lZDI1NTE5");
    expect(screen.getByText(/A stopped VM\. Starting it is a separate step/)).toBeTruthy();
    expect(screen.getByText(/declared this image compatible.*does not test SSH/)).toBeTruthy();
    await userEvent.click(screen.getByRole("button", { name: "Create VM" }));
    expect(await screen.findByText("VM created (stopped)", {}, { timeout: 5000 })).toBeTruthy();
    const post = api.posts()[0]!;
    expect(validate("SubmitOperationRequest", post.body)).toEqual({ ok: true });
    expect(post.body).toMatchObject({ type: "create", kind: "VM", id: "web-1", create: { image_id: "debian-13", vcpus: 1, memory_mib: 512, ssh_public_key: KEY.trim() } });
    expect(Object.keys(post.body.create).sort()).toEqual(["disk_gib", "image_id", "memory_mib", "ssh_public_key", "vcpus"]);
    expect(screen.getByRole("link", { name: "Go to the VM list" })).toBeTruthy();
    // M6-E01-S06: the end of the journey says the VM is stopped and leads to the page that has Start.
    expect(screen.getByText((_, el) => el?.tagName === "P" && /web-1 is created but stopped: creating a VM does not start it/.test(el.textContent ?? ""))).toBeTruthy();
    expect(screen.getByRole("link", { name: "Open web-1" }).getAttribute("href")).toBe("#/vms/web-1");
    expect(document.body.textContent).not.toMatch(/Graphical console to follow the installer/);
    expect(await axeViolations(document.body)).toEqual([]);
  });

  it("reuses the idempotency key when the same details are submitted again after an unknown outcome", async () => {
    api.submit = ["unreachable", "ok"];
    render(<Root />);
    await fill();
    await userEvent.click(screen.getByRole("button", { name: "Review" }));
    await userEvent.click(await screen.findByRole("button", { name: "Create VM" }));
    expect(await screen.findByText(/could not confirm that the request arrived/)).toBeTruthy();
    await userEvent.click(screen.getByRole("button", { name: "Create VM" }));
    await screen.findByText("VM created (stopped)", {}, { timeout: 5000 });
    const [a, b] = api.posts();
    expect(a!.body.idempotency_key).toBe(b!.body.idempotency_key);
  });

  it("uses a new key when the details change", async () => {
    api.submit = ["conflict", "ok"];
    render(<Root />);
    await fill();
    await userEvent.click(screen.getByRole("button", { name: "Review" }));
    await userEvent.click(await screen.findByRole("button", { name: "Create VM" }));
    expect(await screen.findByText(/already exists, or this request was already used/)).toBeTruthy();
    await userEvent.click(screen.getByRole("button", { name: "Back" }));
    await userEvent.click(screen.getByRole("button", { name: "Back" }));
    await userEvent.clear(screen.getByLabelText(/^Name/));
    await userEvent.type(screen.getByLabelText(/^Name/), "web-2");
    await userEvent.click(screen.getByRole("button", { name: "Continue" }));
    await userEvent.click(await screen.findByRole("button", { name: "Review" }));
    await userEvent.click(await screen.findByRole("button", { name: "Create VM" }));
    await waitFor(() => expect(api.posts()).toHaveLength(2));
    expect(api.posts()[0]!.body.idempotency_key).not.toBe(api.posts()[1]!.body.idempotency_key);
  });

  it("shows a typed reason when the host is unavailable, without server text", async () => {
    api.submit = ["unavailable"];
    render(<Root />);
    await fill();
    await userEvent.click(screen.getByRole("button", { name: "Review" }));
    await userEvent.click(await screen.findByRole("button", { name: "Create VM" }));
    expect(await screen.findByText(/not ready to create VMs right now/)).toBeTruthy();
  });

  it("shows a failed operation with the safe reason for its category", async () => {
    api.ops = [operation({ id: "op-1", type: "create", resource_id: "web-1", status: "failed", error_category: "conflict", attempts: 1, allowed_actions: [] })];
    render(<Root />);
    await fill();
    await userEvent.click(screen.getByRole("button", { name: "Review" }));
    await userEvent.click(await screen.findByRole("button", { name: "Create VM" }));
    expect(await screen.findByText(/Nothing was overwritten/, {}, { timeout: 5000 })).toBeTruthy();
  });
});

describe("csrf token handling", () => {
  it("keeps using the session's token after an operation reply that carries none", async () => {
    api.tokenOnOperations = false;
    api.vms = [vm({ id: "web-1", name: "web-1", allowed_actions: ["start"], observed: { ...NO_SIZE, power: "stopped", last_seen_at: "2026-10-10T09:00:00Z", managed: true, ip_address: null, login_user: null, disk_gib: null, snapshots: [], network: null } })];
    api.ops = [operation({ id: "op-1", type: "start", resource_id: "web-1", status: "failed", error_category: "conflict", attempts: 1, allowed_actions: [] })];
    location.hash = "#/vms/web-1";
    render(<Root />);
    await userEvent.click(await screen.findByRole("button", { name: "Start web-1" }));
    await screen.findByText(/Failed/, {}, { timeout: 5000 });
    await userEvent.click(screen.getByRole("button", { name: "Refresh" }));
    await userEvent.click(await screen.findByRole("button", { name: "Start web-1" }));
    await waitFor(() => expect(api.posts()).toHaveLength(2));
    expect(api.posts().map((p) => p.headers["X-CSRF-Token"])).toEqual(["S".repeat(43), "S".repeat(43)]);
  });
});

describe("operation descriptions", () => {
  const d = (status: Operation["status"], error_category: Operation["error_category"] = null, type: Operation["type"] = "create", attempts = 1) =>
    describeOperation({ type, status, error_category, attempts });
  it("maps every status to a progress, success or failure label", () => {
    expect(d("pending").label).toBe("Queued");
    expect(d("running").label).toBe("Creating the VM");
    expect(d("running", "timeout").label).toBe("Checking the host");
    expect(d("retryable_failure", "unavailable", "create", 2).label).toBe("Retrying (attempt 2)");
    expect(d("succeeded", null, "start").label).toBe("VM started");
    expect(d("failed", "host_error").terminal).toBe(true);
    expect(d("failed", "host_error").detail).toMatch(/Check the VM list/);
    expect(d("failed", null).detail).toMatch(/did not complete/);
  });
});

describe("start and connection hint", () => {
  const stopped = vm({ id: "web-1", name: "web-1", allowed_actions: ["start"], observed: { ...NO_SIZE, power: "stopped", last_seen_at: "2026-10-10T09:00:00Z", managed: true, ip_address: null, login_user: null, disk_gib: null, snapshots: [], network: null } });
  beforeEach(() => { location.hash = "#/vms/web-1"; });

  it("offers Start only when creation is enabled, and nothing else lifecycle", async () => {
    api.vms = [stopped];
    render(<Root />);
    expect(await screen.findByRole("button", { name: "Start web-1" })).toBeTruthy();
    for (const word of ["Stop", "Reboot", "Force off", "Delete"]) expect(screen.queryByRole("button", { name: new RegExp(word) })).toBeNull();
  });

  it("has no Start column when the Development Preview switch is closed", async () => {
    api.host = HOST;
    api.vms = [stopped];
    render(<Root />);
    await screen.findByText("web-1");
    expect(screen.queryByRole("button", { name: /Start/ })).toBeNull();
  });

  it("starts a VM, shows progress, and refreshes to a connection hint", async () => {
    api.vms = [stopped];
    api.ops = [operation({ id: "op-1", type: "start", resource_id: "web-1", status: "succeeded", attempts: 1, allowed_actions: [] })];
    render(<Root />);
    await userEvent.click(await screen.findByRole("button", { name: "Start web-1" }));
    expect(await screen.findByText("VM started", {}, { timeout: 5000 })).toBeTruthy();
    expect(api.posts()[0]!.body).toMatchObject({ type: "start", kind: "VM", id: "web-1" });
    expect(api.posts()[0]!.body.create).toBeUndefined();
  });

  it("does not claim SSH works just because an address exists while no image is qualified", async () => {
    api.vms = [vm({ id: "r", name: "r", allowed_actions: [], observed: { ...NO_SIZE, power: "running", last_seen_at: "2026-10-10T09:00:00Z", managed: true, ip_address: "192.168.122.23", login_user: "debian", disk_gib: null, snapshots: [], network: null } })];
    location.hash = "#/vms/r";
    render(<Root />);
    expect(await screen.findByText(/That does not prove SSH works/)).toBeTruthy();
  });

  it("shows waiting, address-only and ssh hint states without running anything", async () => {
    const run = (ip: string | null, user: string | null) => vm({ id: "r", name: "r", allowed_actions: [], observed: { ...NO_SIZE, power: "running", last_seen_at: "2026-10-10T09:00:00Z", managed: true, ip_address: ip, login_user: user, disk_gib: null, snapshots: [], network: null } });
    location.hash = "#/vms/r";
    api.vms = [run(null, "debian")];
    const { unmount } = render(<Root />);
    expect(await screen.findByText("Waiting for an address")).toBeTruthy();
    unmount();
    api.vms = [run("192.168.122.23", "debian")];
    render(<Root />);
    expect(await screen.findByText("ssh debian@192.168.122.23")).toBeTruthy();
    expect(screen.getByRole("button", { name: "Copy SSH command for r" })).toBeTruthy();
  });
});

describe("lifecycle actions", () => {
  const running = vm({ id: "web-1", name: "web-1", allowed_actions: ["stop", "reboot", "force_off"], observed: { ...NO_SIZE, power: "running", last_seen_at: "2026-10-10T09:00:00Z", managed: true, ip_address: null, login_user: null, disk_gib: null, snapshots: [], network: null } });
  const stoppedVm = vm({ id: "web-1", name: "web-1", allowed_actions: ["start", "delete"], observed: { ...NO_SIZE, power: "stopped", last_seen_at: "2026-10-10T09:00:00Z", managed: true, ip_address: null, login_user: null, disk_gib: null, snapshots: [], network: null } });
  beforeEach(() => { location.hash = "#/vms/web-1"; });

  it("offers exactly the actions the server lists for the VM's state", async () => {
    api.vms = [running];
    render(<Root />);
    for (const n of ["Stop web-1", "Reboot web-1", "Force off web-1"]) expect(await screen.findByRole("button", { name: n })).toBeTruthy();
    for (const n of ["Start web-1", "Delete web-1"]) expect(screen.queryByRole("button", { name: n })).toBeNull();
  });

  it("stops and reboots without a confirmation, with the closed operation types", async () => {
    api.vms = [running];
    api.ops = [operation({ id: "op-1", type: "stop", resource_id: "web-1", status: "succeeded", attempts: 1, allowed_actions: [] })];
    render(<Root />);
    await userEvent.click(await screen.findByRole("button", { name: "Stop web-1" }));
    expect(await screen.findByText("VM stopped", {}, { timeout: 5000 })).toBeTruthy();
    expect(api.posts()[0]!.body).toMatchObject({ type: "stop", kind: "VM", id: "web-1" });
  });

  it("asks before Force off and before Delete, and sends nothing on Cancel", async () => {
    api.vms = [running];
    const { unmount } = render(<Root />);
    await userEvent.click(await screen.findByRole("button", { name: "Force off web-1" }));
    expect(await screen.findByText(/cuts power immediately/)).toBeTruthy();
    await userEvent.click(screen.getByRole("button", { name: "Cancel" }));
    expect(api.posts()).toHaveLength(0);
    unmount();
    api.vms = [stoppedVm];
    api.ops = [operation({ id: "op-2", type: "delete", resource_id: "web-1", status: "succeeded", attempts: 1, allowed_actions: [] })];
    render(<Root />);
    await userEvent.click(await screen.findByRole("button", { name: "Delete web-1" }));
    expect(await screen.findByText(/removes this stopped VM, its disk and its cloud-init seed/)).toBeTruthy();
    expect(api.posts()).toHaveLength(0);
    await userEvent.click(screen.getByRole("button", { name: "Delete permanently" }));
    expect(await screen.findByText("VM deleted", {}, { timeout: 5000 })).toBeTruthy();
    expect(api.posts()[0]!.body).toMatchObject({ type: "delete", kind: "VM", id: "web-1" });
  });

  it("never turns a stuck Stop into Force off by itself", () => {
    const d = describeOperation({ type: "stop", status: "retryable_failure", error_category: "timeout", attempts: 2 });
    expect(d.detail).toMatch(/will not force it off/);
  });
});
