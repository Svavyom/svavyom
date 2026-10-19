// fe-unit: the M2 storage and recovery journeys against a stateful fake of the browser-api: the storage overview, resize, snapshot,
// backup and reinstall from the VM list, restore and delete from the Storage view. Confirmations, local validation, closed operation
// types and typed params, idempotent re-submission, and that a private key is never kept or sent.
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { Root } from "./Root";
import { describeOperation } from "./OperationProgress";
import { HOST, apiError, operation, vm, vmList, NO_SIZE } from "../api/fixtures";
import { forgetCsrf } from "../api/session";
import { validate } from "../api/validate";
import { axeViolations } from "../test-axe";
import type { Backup, Host, Image, Operation, VM, Volume } from "../api/schema";

const KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGg4Zgd2sQ0v9i6Y0bq7n3m9c1m3k3Qm8iH6m3f3b2yd admin@laptop";
const IN = { authenticated: true, username: "admin", expires_at: "2026-10-09T08:30:00Z", role: "admin" };
const IMAGE = (id: string, q: Image["observed"]["qualification"]): Image => ({
  id, project_id: "default", generation: 1, name: id === "debian-13" ? "Debian 13" : "Ubuntu 24.04", allowed_actions: [],
  desired: { source_digest: "sha256:" + "a".repeat(64) },
  observed: { state: "available", distribution: "Debian", version: "13", architecture: "x86_64", login_user: "debian", media: "disk", min_disk_gib: 3, qualification: q, qualification_evidence: q === "qualified" ? "qr-20261011-5e5e5e" : null },
});
const STORAGE = { state: "available" as const, pool_total_gib: 457, pool_free_gib: 456, images_gib: 1, backups_configured: true, backups_gib: 2, backups_free_gib: 40, snapshots: "available" as const, backup_targets: [], allocation_note: "Disk sizes shown for a VM are virtual sizes. Real usage is lower while the disk is thinly allocated; the pool free figure is what counts." };
const ENABLED: Host = { ...HOST, observed: { ...HOST.observed, storage: STORAGE, creation: { enabled: true, network: "available", storage: "available", vcpu_options: [1, 2], memory_mib_options: [512], disk_gib_options: [10, 20], ready: true, reasons: [] } } };
const stopped = (over: Partial<VM> = {}, snaps: { id: string; created_at: string }[] = []): VM => vm({ id: "web-1", name: "web-1", allowed_actions: ["start", "delete", "resize", "reinstall", "snapshot", "backup"],
  observed: { ...NO_SIZE, power: "stopped", last_seen_at: "2026-10-10T09:00:00Z", managed: true, ip_address: null, login_user: "debian", disk_gib: 20, snapshots: snaps, network: null }, ...over });
const BACKUP: Backup = { id: "bk-0123456789abcdef", project_id: "default", generation: 1, name: "web-1 2026-10-10T08:00:00Z", desired: { source_volume_id: "web-1-root" }, observed: { state: "complete", copies: [] }, allowed_actions: ["restore", "delete"] };

const DATA = (over: Partial<Volume> = {}, attached: string | null = null): Volume => ({
  id: "data-1", project_id: "default", generation: 1, name: "data-1", desired: { size_gib: 20, attached_to: attached }, observed: { state: attached ? "attached" : "available" },
  allowed_actions: attached ? ["detach"] : ["attach", "delete"], ...over,
});

type Call = { method: string; url: string; headers: Record<string, string>; body: any };

class Fake {
  calls: Call[] = [];
  host: Host = ENABLED;
  images: Image[] = [IMAGE("debian-13", "verified"), IMAGE("ubuntu-24.04", "qualified")];
  vms: VM[] = [stopped()];
  backups: Backup[] = [BACKUP];
  volumes: Volume[] = [];
  canCreateVolume = true;
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
    if (url.startsWith("/api/v1/vms")) return this.json(200, vmList(this.vms));
    if (url.startsWith("/api/v1/volumes")) return this.json(200, { items: this.volumes, allowed_actions: this.canCreateVolume ? ["create"] : [], next_cursor: null });
    if (url.startsWith("/api/v1/backups")) return this.json(200, { items: this.backups, allowed_actions: [], next_cursor: null });
    if (url === "/api/v1/operations" && call.method === "POST") {
      const next = this.submit.length > 1 ? this.submit.shift()! : this.submit[0]!;
      if (next === "unreachable") throw new TypeError("network");
      if (next !== "ok") return this.json(next === "conflict" ? 409 : next === "prohibited" ? 422 : 400, apiError(next));
      return this.json(202, operation({ id: "op-1", type: call.body.type, resource_kind: call.body.kind, resource_id: call.body.id, status: "pending" }));
    }
    if (url === "/api/v1/operations/op-1") return this.json(200, this.ops.length > 1 ? this.ops.shift() : this.ops[0]);
    return this.json(404, apiError("not_found"));
  });
  posts() { return this.calls.filter((c) => c.method === "POST" && c.url === "/api/v1/operations"); }
}

let api: Fake;
beforeEach(() => { api = new Fake(); forgetCsrf(); vi.stubGlobal("fetch", api.fetch); });
afterEach(() => { cleanup(); vi.unstubAllGlobals(); });

describe("the contract fixtures used here are valid", () => {
  it("validates the fake's host, VM and backup against the schemas", () => {
    expect(validate("Host", ENABLED).ok).toBe(true);
    expect(validate("VM", stopped()).ok).toBe(true);
    expect(validate("Backup", BACKUP).ok).toBe(true);
  });
});

describe("storage overview", () => {
  beforeEach(() => { location.hash = "#/storage"; });

  it("shows the pool, the backup store, the images, snapshots and backups, honestly worded, and passes axe", async () => {
    api.vms = [stopped({}, [{ id: "snap-aaaaaaaaaaaa", created_at: "2026-10-10T08:30:00Z" }])];
    render(<Root />);
    expect(await screen.findByRole("heading", { level: 1, name: "Storage and recovery" })).toBeTruthy();
    expect(await screen.findByText("456 GiB free of 457 GiB")).toBeTruthy();
    expect(screen.getByText(/Real usage is lower while the disk is thinly allocated/)).toBeTruthy();
    expect(screen.getByText("2 GiB used, 40 GiB free")).toBeTruthy();
    expect(within(screen.getByRole("region", { name: "Image catalog" })).getByText("real-host qualified")).toBeTruthy();
    expect(within(screen.getByRole("region", { name: "Image catalog" })).getByText("qr-20261011-5e5e5e")).toBeTruthy();
    expect(within(screen.getByRole("region", { name: "Image catalog" })).getAllByText(/sha256:aaaaaaaaaaaa/).length).toBe(2);
    expect(screen.getByText(/not against losing the host/)).toBeTruthy();
    expect(screen.getByText(/It is not a backup/)).toBeTruthy();
    expect(screen.getByRole("button", { name: "Restore snap-aaaaaaaaaaaa" })).toBeTruthy();
    expect(screen.getByRole("button", { name: "Restore bk-0123456789abcdef" })).toBeTruthy();
    expect(await axeViolations(document.body)).toEqual([]);
  });

  it("lists the scheduled backups with their next and last window and repeats the downtime warning", async () => {
    const v = stopped();
    v.desired = { power: "stopped", backup_schedule: { every_hours: 12, at: null, keep_local: 3, keep_offsite: 0, target_id: null, downtime_acknowledged: true } };
    v.observed.backup = { next_run_at: "2026-10-16T02:30:00Z", last_run: { at: "2026-10-15T02:31:00Z", result: "ok" } };
    api.vms = [v, { ...stopped(), id: "other-1", name: "other-1" }];
    render(<Root />);
    const table = await screen.findByRole("table", { name: "Scheduled backups" });
    expect(within(table).getByText("Every 12 hours. Keeps the newest 3 on this host.")).toBeTruthy();
    expect(within(table).getByText("2026-10-16 02:30:00 UTC")).toBeTruthy();
    expect(within(table).getByText("Completed")).toBeTruthy();
    expect(within(table).queryByText("other-1")).toBeNull();
    expect(screen.getByText(/stopped \(gracefully\) and started again afterwards/)).toBeTruthy();
    expect(await axeViolations(document.body)).toEqual([]);
  });

  it("says plainly that backups are not configured, and offers no storage action when the switch is closed", async () => {
    api.host = { ...HOST, observed: { ...HOST.observed, storage: { ...STORAGE, backups_configured: false, backups_gib: null, backups_free_gib: null } } };
    api.backups = [];
    render(<Root />);
    expect(await screen.findByText(/No backup store is configured/)).toBeTruthy();
    expect(screen.getByText("Not configured on this host")).toBeTruthy();
    expect(screen.queryByRole("button", { name: /Restore|Delete/ })).toBeNull();
  });

  it("restores a backup as a NEW VM only after a valid name and public key, never sending a private key", async () => {
    render(<Root />);
    await userEvent.click(await screen.findByRole("button", { name: "Restore bk-0123456789abcdef" }));
    expect(await screen.findByText(/No existing VM is changed/)).toBeTruthy();
    await userEvent.type(screen.getByLabelText(/Name of the new VM/), "Bad Name");
    await userEvent.click(screen.getByLabelText(/SSH public key/));
    await userEvent.paste("-----BEGIN OPENSSH PRIVATE KEY-----");
    await userEvent.click(screen.getByRole("button", { name: "Restore as a new VM" }));
    expect(await screen.findByText(/lower-case letters/)).toBeTruthy();
    expect(api.posts()).toHaveLength(0);
    await userEvent.clear(screen.getByLabelText(/Name of the new VM/));
    await userEvent.type(screen.getByLabelText(/Name of the new VM/), "web-2");
    await userEvent.click(screen.getByRole("button", { name: "Restore as a new VM" }));
    expect(await screen.findByText(/Never paste a private key/)).toBeTruthy();
    expect((screen.getByLabelText(/SSH public key/) as HTMLTextAreaElement).value).toBe("");
    expect(api.posts()).toHaveLength(0);
    await userEvent.click(screen.getByLabelText(/SSH public key/));
    await userEvent.paste(KEY);
    api.ops = [operation({ id: "op-1", type: "restore", resource_kind: "Backup", resource_id: "bk-0123456789abcdef", status: "succeeded", attempts: 1, allowed_actions: [] })];
    await userEvent.click(screen.getByRole("button", { name: "Restore as a new VM" }));
    expect(await screen.findByText(/restored as a new VM/, {}, { timeout: 5000 })).toBeTruthy();
    expect(api.posts()[0]!.body).toMatchObject({ type: "restore", kind: "Backup", id: "bk-0123456789abcdef", params: { new_name: "web-2", ssh_public_key: KEY } });
    expect(JSON.stringify(api.posts())).not.toContain("PRIVATE");
  });

  it("asks before deleting a backup, restoring a snapshot or deleting a snapshot, and sends nothing on Cancel", async () => {
    api.vms = [stopped({}, [{ id: "snap-aaaaaaaaaaaa", created_at: "2026-10-10T08:30:00Z" }])];
    render(<Root />);
    await userEvent.click(await screen.findByRole("button", { name: "Delete bk-0123456789abcdef" }));
    expect(await screen.findByText(/removes it from the backup store for good/)).toBeTruthy();
    await userEvent.click(screen.getByRole("button", { name: "Cancel" }));
    await userEvent.click(screen.getByRole("button", { name: "Restore snap-aaaaaaaaaaaa" }));
    expect(await screen.findByText(/Everything written since is lost/)).toBeTruthy();
    await userEvent.click(screen.getByRole("button", { name: "Cancel" }));
    expect(api.posts()).toHaveLength(0);
    api.ops = [operation({ id: "op-1", type: "delete_snapshot", resource_id: "web-1", status: "succeeded", attempts: 1, allowed_actions: [] })];
    await userEvent.click(screen.getByRole("button", { name: "Delete snap-aaaaaaaaaaaa" }));
    await userEvent.click(await screen.findByRole("button", { name: "Delete snapshot" }));
    expect(await screen.findByText("Snapshot deleted", {}, { timeout: 5000 })).toBeTruthy();
    expect(api.posts()[0]!.body).toMatchObject({ type: "delete_snapshot", kind: "VM", id: "web-1", params: { snapshot_id: "snap-aaaaaaaaaaaa" } });
  });

  it("deletes a backup with the Backup kind and no params", async () => {
    api.ops = [operation({ id: "op-1", type: "delete", resource_kind: "Backup", resource_id: "bk-0123456789abcdef", status: "succeeded", attempts: 1, allowed_actions: [] })];
    render(<Root />);
    await userEvent.click(await screen.findByRole("button", { name: "Delete bk-0123456789abcdef" }));
    await userEvent.click(await screen.findByRole("button", { name: "Delete backup permanently" }));
    expect(await screen.findByText("Backup deleted", {}, { timeout: 5000 })).toBeTruthy();
    expect(api.posts()[0]!.body).toMatchObject({ type: "delete", kind: "Backup", id: "bk-0123456789abcdef" });
    expect(api.posts()[0]!.body.params).toBeUndefined();
  });

  it("does not offer restore for a damaged backup", async () => {
    api.backups = [{ ...BACKUP, observed: { state: "failed", copies: [] } }];
    render(<Root />);
    expect(await screen.findByText(/Damaged: cannot be restored/)).toBeTruthy();
    expect(screen.getByRole("button", { name: "Restore bk-0123456789abcdef" }).getAttribute("aria-disabled")).toBe("true");
  });
});

describe("storage actions on the VM page", () => {
  beforeEach(() => { location.hash = "#/vms/web-1"; });

  it("shows the virtual disk size and the actions the server offers", async () => {
    render(<Root />);
    expect(await screen.findByText("20 GiB")).toBeTruthy();
    for (const n of ["Resize web-1", "Snapshot web-1", "Back up web-1", "Reinstall web-1"]) expect(await screen.findByRole("button", { name: n })).toBeTruthy();
  });

  it("grows the disk only to a larger whole number and sends the typed param", async () => {
    render(<Root />);
    await userEvent.click(await screen.findByRole("button", { name: "Resize web-1" }));
    expect(await screen.findByText(/can only grow, never shrink/)).toBeTruthy();
    await userEvent.type(screen.getByLabelText(/New size in GiB/), "10");
    await userEvent.click(screen.getByRole("button", { name: "Grow the disk" }));
    expect(await screen.findByText(/larger than the current 20 GiB/)).toBeTruthy();
    expect(api.posts()).toHaveLength(0);
    await userEvent.clear(screen.getByLabelText(/New size in GiB/));
    await userEvent.type(screen.getByLabelText(/New size in GiB/), "30");
    api.ops = [operation({ id: "op-1", type: "resize", resource_id: "web-1", status: "succeeded", attempts: 1, allowed_actions: [] })];
    await userEvent.click(screen.getByRole("button", { name: "Grow the disk" }));
    expect(await screen.findByText(/Root disk grown/, {}, { timeout: 5000 })).toBeTruthy();
    expect(api.posts()[0]!.body).toMatchObject({ type: "resize", kind: "VM", id: "web-1", params: { disk_gib: 30 } });
  });

  it("snapshots and backs up without a dialog, with no params", async () => {
    render(<Root />);
    api.ops = [operation({ id: "op-1", type: "snapshot", resource_id: "web-1", status: "succeeded", attempts: 1, allowed_actions: [] })];
    await userEvent.click(await screen.findByRole("button", { name: "Snapshot web-1" }));
    expect(await screen.findByText("Snapshot taken", {}, { timeout: 5000 })).toBeTruthy();
    expect(api.posts()[0]!.body).toMatchObject({ type: "snapshot", kind: "VM", id: "web-1" });
    expect(api.posts()[0]!.body.params).toBeUndefined();
  });

  it("reinstalls only from a qualified image, after an erase warning and a valid public key", async () => {
    render(<Root />);
    await userEvent.click(await screen.findByRole("button", { name: "Reinstall web-1" }));
    expect(await screen.findByText(/Everything stored on the current disk is deleted/)).toBeTruthy();
    const labels = Array.from((await screen.findByLabelText("Image") as HTMLSelectElement).options).map((o) => o.textContent);
    expect(labels).toEqual(["Ubuntu 24.04 (real-host qualified)"]);
    await userEvent.click(screen.getByLabelText(/SSH public key/));
    await userEvent.paste("not a key");
    await userEvent.click(screen.getByRole("button", { name: "Reinstall and erase the disk" }));
    expect(await screen.findByText(/one public key on one line/)).toBeTruthy();
    expect(api.posts()).toHaveLength(0);
    await userEvent.clear(screen.getByLabelText(/SSH public key/));
    await userEvent.paste(KEY);
    api.ops = [operation({ id: "op-1", type: "reinstall", resource_id: "web-1", status: "succeeded", attempts: 1, allowed_actions: [] })];
    await userEvent.click(screen.getByRole("button", { name: "Reinstall and erase the disk" }));
    expect(await screen.findByText("VM reinstalled (stopped)", {}, { timeout: 5000 })).toBeTruthy();
    expect(api.posts()[0]!.body).toMatchObject({ type: "reinstall", kind: "VM", id: "web-1", params: { image_id: "ubuntu-24.04", ssh_public_key: KEY } });
  });

  it("cannot reinstall when no image is qualified", async () => {
    api.images = [IMAGE("debian-13", "verified")];
    render(<Root />);
    await userEvent.click(await screen.findByRole("button", { name: "Reinstall web-1" }));
    expect(await screen.findByText(/No image has been qualified on real hardware yet\./)).toBeTruthy();
    await userEvent.click(screen.getByLabelText(/SSH public key/));
    await userEvent.paste(KEY);
    await userEvent.click(screen.getByRole("button", { name: "Reinstall and erase the disk" }));
    expect(api.posts()).toHaveLength(0);
  });

  it("reuses the idempotency key when the same request is repeated after an unknown outcome", async () => {
    api.submit = ["unreachable", "ok"];
    render(<Root />);
    await userEvent.click(await screen.findByRole("button", { name: "Back up web-1" }));
    expect(await screen.findByText(/could not confirm that the request arrived/)).toBeTruthy();
    await userEvent.click(screen.getByRole("button", { name: "Back up web-1" }));
    await waitFor(() => expect(api.posts()).toHaveLength(2));
    expect(api.posts()[1]!.body.idempotency_key).toBe(api.posts()[0]!.body.idempotency_key);
  });

  it("explains a refusal in words from the closed category", async () => {
    api.submit = ["conflict"];
    render(<Root />);
    await userEvent.click(await screen.findByRole("button", { name: "Snapshot web-1" }));
    expect(await screen.findByText(/no longer in a state this action applies to/)).toBeTruthy();
  });
});

describe("data volumes (DR-023 D2)", () => {
  beforeEach(() => { location.hash = "#/storage"; });

  it("lists data volumes with where they are attached and offers only the actions that apply", async () => {
    api.volumes = [DATA({}, null), DATA({ id: "logs", name: "logs", allowed_actions: ["detach"] }, "web-1")];
    render(<Root />);
    const table = await screen.findByRole("region", { name: "Data volumes" });
    expect(within(table).getByText("Not attached")).toBeTruthy();
    expect(within(table).getByRole("link", { name: "web-1" })).toBeTruthy();
    expect(screen.getByRole("button", { name: "Attach data-1" })).toBeTruthy();
    expect(screen.getByRole("button", { name: "Delete data-1" })).toBeTruthy();
    expect(screen.getByRole("button", { name: "Detach logs" })).toBeTruthy();
    expect(screen.queryByRole("button", { name: "Delete logs" })).toBeNull();
    expect(await axeViolations(document.body)).toEqual([]);
  });

  it("creates a volume only with a valid name and size", async () => {
    render(<Root />);
    await userEvent.click(await screen.findByRole("button", { name: "Create data volume" }));
    await userEvent.type(screen.getByLabelText(/Volume name/), "bad-root");
    await userEvent.click(screen.getByRole("button", { name: "Create volume" }));
    expect(await screen.findByText(/not ending with a hyphen or with -root/)).toBeTruthy();
    expect(api.posts()).toHaveLength(0);
    await userEvent.clear(screen.getByLabelText(/Volume name/));
    await userEvent.type(screen.getByLabelText(/Volume name/), "data-2");
    await userEvent.clear(screen.getByLabelText(/Size in GiB/));
    await userEvent.type(screen.getByLabelText(/Size in GiB/), "50");
    await userEvent.click(screen.getByRole("button", { name: "Create volume" }));
    await waitFor(() => expect(api.posts()).toHaveLength(1));
    expect(api.posts()[0]!.body).toMatchObject({ type: "volume_create", kind: "Volume", id: "data-2", params: { disk_gib: 50 } });
  });

  it("attaches to a chosen stopped VM", async () => {
    api.volumes = [DATA()];
    render(<Root />);
    await userEvent.click(await screen.findByRole("button", { name: "Attach data-1" }));
    await userEvent.click(screen.getByRole("button", { name: "Attach" }));
    await waitFor(() => expect(api.posts()).toHaveLength(1));
    expect(api.posts()[0]!.body).toMatchObject({ type: "volume_attach", kind: "Volume", id: "data-1", params: { vm_id: "web-1" } });
  });

  it("deletes only after the volume's name is typed", async () => {
    api.volumes = [DATA()];
    render(<Root />);
    await userEvent.click(await screen.findByRole("button", { name: "Delete data-1" }));
    await userEvent.click(screen.getByRole("button", { name: "Delete volume permanently" }));
    expect(await screen.findByText(/Type the volume's name exactly/)).toBeTruthy();
    expect(api.posts()).toHaveLength(0);
    await userEvent.type(screen.getByLabelText(/Type data-1 to confirm/), "data-1");
    await userEvent.click(screen.getByRole("button", { name: "Delete volume permanently" }));
    await waitFor(() => expect(api.posts()).toHaveLength(1));
    expect(api.posts()[0]!.body).toMatchObject({ type: "volume_delete", kind: "Volume", id: "data-1" });
  });

  it("shows no create button when the role or the switch does not allow it", async () => {
    api.canCreateVolume = false;
    render(<Root />);
    await screen.findByRole("heading", { level: 1, name: "Storage and recovery" });
    expect(screen.queryByRole("button", { name: "Create data volume" })).toBeNull();
  });
});

describe("off-host copies (DR-023 D4)", () => {
  beforeEach(() => { location.hash = "#/storage"; });
  const withTargets = (state: "ready" | "unavailable" = "ready"): Host => ({ ...ENABLED, observed: { ...ENABLED.observed, storage: { ...STORAGE, backup_targets: [{ id: "nas", kind: "ssh" as const, state }] } } });

  it("shows the declared targets, the copies each backup has, and copies one backup after a target is chosen", async () => {
    api.host = withTargets();
    api.backups = [{ ...BACKUP, observed: { state: "complete", copies: ["nas"] }, allowed_actions: ["restore", "delete", "export"] }];
    render(<Root />);
    expect(await screen.findByText(/Off-host targets: nas \(SSH, ready\)/)).toBeTruthy();
    expect(within(screen.getByRole("region", { name: "Backups" })).getByText("nas")).toBeTruthy();
    await userEvent.click(screen.getByRole("button", { name: "Copy bk-0123456789abcdef off the host" }));
    expect(await screen.findByText(/checked there by its SHA-256/)).toBeTruthy();
    await userEvent.click(screen.getByRole("button", { name: "Copy and verify" }));
    await waitFor(() => expect(api.posts()).toHaveLength(1));
    expect(api.posts()[0]!.body).toMatchObject({ type: "backup_export", kind: "Backup", id: "bk-0123456789abcdef", params: { target_id: "nas" } });
  });

  it("says plainly that backups stay on this host when no target is declared", async () => {
    render(<Root />);
    expect(await screen.findByText(/No off-host backup target is declared/)).toBeTruthy();
    expect(screen.queryByRole("button", { name: /off the host/ })).toBeNull();
  });
});

describe("operation wording", () => {
  it("describes every storage operation without server text", () => {
    const d = (type: Operation["type"], status: Operation["status"] = "running") => describeOperation({ type, status, error_category: null, attempts: 1 }).label;
    expect(d("resize")).toBe("Growing the root disk");
    expect(d("backup")).toBe("Copying the disk to the backup store");
    expect(d("restore", "succeeded")).toMatch(/new VM/);
    expect(describeOperation({ type: "backup", status: "failed", error_category: "conflict", attempts: 1 }).detail).toMatch(/Nothing was overwritten/);
  });
});
