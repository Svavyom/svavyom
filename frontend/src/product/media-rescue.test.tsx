// fe-unit: installation media and rescue mode on the VM page (DR-026 D2): what is offered when, the dialogs, the request each sends, and that a
// person is told rescue mode is on.
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { Root } from "./Root";
import { HOST, apiError, operation, vm, vmList, NO_SIZE } from "../api/fixtures";
import { forgetCsrf } from "../api/session";
import { axeViolations } from "../test-axe";
import type { Host, Image, VM } from "../api/schema";

const IN = { authenticated: true, username: "admin", expires_at: "2026-10-17T08:30:00Z", role: "admin" };
const ISO: Image = { id: "alpine-iso", project_id: "default", generation: 1, name: "Alpine installer", allowed_actions: [], desired: { source_digest: "sha256:" + "b".repeat(64) },
  observed: { state: "available", distribution: "Alpine", version: "3.20", architecture: "x86_64", login_user: null, media: "iso", min_disk_gib: 2, qualification: "verified", qualification_evidence: null } };
const DISK: Image = { ...ISO, id: "debian-13", name: "Debian 13", observed: { ...ISO.observed, media: "disk", login_user: "debian" } };
const ENABLED: Host = { ...HOST, observed: { ...HOST.observed, creation: { enabled: true, network: "available", storage: "available", vcpu_options: [1, 2], memory_mib_options: [512], disk_gib_options: [10, 20], ready: true, reasons: [] } } };
const stopped = (actions: string[], over: Partial<VM["observed"]> = {}): VM => vm({ id: "web-1", name: "web-1", allowed_actions: actions as VM["allowed_actions"],
  observed: { ...NO_SIZE, power: "stopped", last_seen_at: "2026-10-16T09:00:00Z", managed: true, ip_address: null, login_user: "debian", disk_gib: 20, snapshots: [], network: null, graphical_console: "present", ...over } });

let machine: VM;
let images: Image[];
let posts: Array<Record<string, unknown>>;
beforeEach(() => {
  forgetCsrf();
  location.hash = "#/vms/web-1";
  images = [DISK, ISO];
  posts = [];
  vi.stubGlobal("fetch", vi.fn(async (url: string, init: RequestInit = {}) => {
    const json = (s: number, b: unknown) => new Response(JSON.stringify(b), { status: s, headers: { "X-CSRF-Token": "S".repeat(43) } });
    if (url === "/api/v1/auth/session") return json(200, IN);
    if (url === "/api/v1/hosts/local") return json(200, ENABLED);
    if (url.startsWith("/api/v1/vms")) return json(200, vmList([machine]));
    if (url.startsWith("/api/v1/images")) return json(200, { items: images, allowed_actions: [], next_cursor: null });
    if (url.startsWith("/api/v1/backups") || url.startsWith("/api/v1/volumes")) return json(200, { items: [], allowed_actions: [], next_cursor: null });
    if (url === "/api/v1/operations" && init.method === "POST") { posts.push(JSON.parse(init.body as string)); return json(202, operation({ id: "op-1", status: "succeeded", allowed_actions: [] })); }
    if (url === "/api/v1/operations/op-1") return json(200, operation({ id: "op-1", status: "succeeded", allowed_actions: [] }));
    return json(404, apiError("not_found"));
  }));
});
afterEach(() => { cleanup(); vi.unstubAllGlobals(); });

describe("installation media, the graphical console and rescue on the VM page", () => {
  it("offers the actions the server offers and nothing else", async () => {
    machine = stopped(["start", "delete", "iso_attach", "rescue"]);
    render(<Root />);
    expect(await screen.findByRole("button", { name: "Attach installation media to web-1" })).toBeTruthy();
    expect(screen.getByRole("button", { name: "Start rescue mode for web-1" })).toBeTruthy();
    expect(screen.queryByRole("button", { name: /Leave rescue mode|Eject installation media|Enable the graphical console/ })).toBeNull();
    expect(screen.getByText("None attached")).toBeTruthy();
    expect(await axeViolations(document.body)).toEqual([]);
  });

  it("attaches media: the catalog's ISOs only, and the request carries the id and the boot choice", async () => {
    machine = stopped(["start", "delete", "iso_attach", "rescue"]);
    render(<Root />);
    await userEvent.click(await screen.findByRole("button", { name: "Attach installation media to web-1" }));
    const media = (await screen.findByLabelText("Media")) as HTMLSelectElement;
    await waitFor(() => expect(Array.from(media.options).map((o) => o.value)).toEqual(["alpine-iso"])); // the disk image is not offered
    await userEvent.selectOptions(screen.getByLabelText("Boot"), "disk");
    await userEvent.click(screen.getByRole("button", { name: "Attach the media" }));
    await waitFor(() => expect(posts).toHaveLength(1));
    expect(posts[0]).toMatchObject({ type: "iso_attach", kind: "VM", id: "web-1", params: { image_id: "alpine-iso", boot: "disk" } });
    expect(Object.keys(posts[0]!.params as object).sort()).toEqual(["boot", "image_id"]);
  });

  it("starts rescue mode with the chosen ISO and nothing else", async () => {
    machine = stopped(["start", "delete", "iso_attach", "rescue"]);
    render(<Root />);
    await userEvent.click(await screen.findByRole("button", { name: "Start rescue mode for web-1" }));
    await screen.findByLabelText("Media");
    expect(screen.getByText(/Nothing on the disk is changed by this step/)).toBeTruthy();
    await userEvent.click(screen.getByRole("button", { name: "Start rescue mode" }));
    await waitFor(() => expect(posts).toHaveLength(1));
    expect(posts[0]).toMatchObject({ type: "rescue", kind: "VM", id: "web-1", params: { image_id: "alpine-iso" } });
    expect(Object.keys(posts[0]!.params as object)).toEqual(["image_id"]);
  });

  it("says plainly when there is no media to choose, and sends nothing", async () => {
    images = [DISK];
    machine = stopped(["start", "iso_attach", "rescue"]);
    render(<Root />);
    await userEvent.click(await screen.findByRole("button", { name: "Attach installation media to web-1" }));
    expect(await screen.findByText(/No installation media has been imported on this host yet/)).toBeTruthy();
    await userEvent.click(screen.getByRole("button", { name: "Attach the media" }));
    expect(posts).toHaveLength(0);
  });

  it("tells the person a VM is in rescue mode and lets them leave it", async () => {
    machine = stopped(["start", "delete", "unrescue"], { rescue: true, iso: "alpine-iso" });
    render(<Root />);
    expect(await screen.findByText(/This VM is in rescue mode/)).toBeTruthy();
    expect(screen.queryByRole("button", { name: /Start rescue mode|Attach installation media/ })).toBeNull();
    await userEvent.click(screen.getByRole("button", { name: "Leave rescue mode of web-1" }));
    await waitFor(() => expect(posts).toHaveLength(1));
    expect(posts[0]).toMatchObject({ type: "unrescue", kind: "VM", id: "web-1" });
    expect(posts[0]!.params).toBeUndefined();
  });

  it("offers Enable graphical console for an old VM and the console link only for a running VM that has it", async () => {
    machine = stopped(["start", "graphics_enable"], { graphical_console: "absent" });
    render(<Root />);
    await userEvent.click(await screen.findByRole("button", { name: "Enable the graphical console of web-1" }));
    await waitFor(() => expect(posts).toHaveLength(1));
    expect(posts[0]).toMatchObject({ type: "graphics_enable", kind: "VM", id: "web-1" });
    expect(screen.queryByRole("link", { name: /Graphical console/ })).toBeNull();
    cleanup();
    machine = vm({ ...stopped(["stop"]), observed: { ...stopped([]).observed, power: "running", ip_address: "10.0.0.5" } });
    render(<Root />);
    const link = await screen.findByRole("link", { name: "Graphical console web-1" });
    expect(link.getAttribute("href")).toBe("#/graphics/web-1");
  });
});
