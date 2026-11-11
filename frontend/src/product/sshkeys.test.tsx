// fe-unit: the SSH keys page and the saved-key picker (DR-040).
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { Root } from "./Root";
import { SshKeyField } from "./SshKeyField";
import { HOST, apiError } from "../api/fixtures";
import { forgetCsrf } from "../api/session";
import { axeViolations } from "../test-axe";
import type { SshKey } from "../api/schema";

const TOKEN = (c: string) => c.repeat(43);
const respond = (status: number, body: unknown, csrf?: string) => new Response(JSON.stringify(body), { status, headers: csrf ? { "X-CSRF-Token": csrf } : {} });
const ED = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHm1Vi6P5lT5QHixEuipi6eQH4U65pW+1+DjkQutBJZk";
const key = (over: Partial<SshKey> = {}): SshKey => ({ id: "k-0123456789abcdef", name: "Olly laptop", type: "ed25519", public_key: ED, fingerprint: "SHA256:" + "a".repeat(43), added_by: "olly", added_at: "2026-11-10T08:00:00Z", allowed_actions: ["delete"], ...over });

let role: "admin" | "operator" | "viewer", keys: SshKey[], allowed: ("add")[], sent: { method: string; url: string; body: string; csrf: string | null }[];
beforeEach(() => {
  forgetCsrf();
  role = "operator"; keys = [key()]; allowed = ["add"]; sent = [];
  location.hash = "#/keys";
  vi.stubGlobal("fetch", vi.fn(async (url: string, init?: RequestInit) => {
    const method = init?.method ?? "GET";
    const headers = new Headers(init?.headers);
    if (method !== "GET" || url.includes("ssh-keys")) sent.push({ method, url, body: String(init?.body ?? ""), csrf: headers.get("X-CSRF-Token") });
    if (url === "/api/v1/auth/session") return respond(200, { authenticated: true, username: "olly", expires_at: "2026-10-09T08:30:00Z", role, must_change_password: false }, TOKEN("S"));
    if (url === "/api/v1/hosts/local") return respond(200, HOST);
    if (url === "/api/v1/ssh-keys" && method === "GET") return respond(200, { items: keys, allowed_actions: role === "viewer" ? [] : allowed });
    if (url === "/api/v1/ssh-keys" && method === "POST") { const b = JSON.parse(String(init?.body)); const k = key({ id: "k-aaaaaaaaaaaaaaaa", name: b.name, public_key: b.public_key }); keys = [...keys, k]; return respond(201, k); }
    if (url.startsWith("/api/v1/ssh-keys/") && method === "DELETE") { const id = url.split("/").pop(); const g = keys.find((k) => k.id === id)!; keys = keys.filter((k) => k.id !== id); return respond(200, g); }
    return respond(404, apiError("not_found"));
  }));
});
afterEach(() => { cleanup(); vi.unstubAllGlobals(); });

describe("SSH keys page", () => {
  it("lists the saved keys and offers adding to an operator", async () => {
    render(<Root />);
    expect(await screen.findByRole("heading", { level: 1, name: "SSH keys" })).toBeTruthy();
    const table = await screen.findByRole("table", { name: "Saved SSH public keys" });
    expect(within(table).getByText("Olly laptop")).toBeTruthy();
    expect(within(table).getByText("SHA256:" + "a".repeat(43))).toBeTruthy();
    expect(screen.getByRole("button", { name: "Delete Olly laptop" })).toBeTruthy();
    expect(screen.getByRole("button", { name: "Save key" })).toBeTruthy();
    expect(await axeViolations(document.body)).toEqual([]);
  });

  it("shows a viewer the list and nothing to change", async () => {
    role = "viewer"; keys = [key({ allowed_actions: [] })];
    render(<Root />);
    await screen.findByRole("table", { name: "Saved SSH public keys" });
    expect(screen.queryByRole("button", { name: "Save key" })).toBeNull();
    expect(screen.queryByRole("button", { name: /^Delete / })).toBeNull();
  });

  it("refuses a private key or a name-less key before anything is sent, then saves a good one with the CSRF token", async () => {
    render(<Root />);
    await screen.findByRole("table", { name: "Saved SSH public keys" });
    await userEvent.type(screen.getByLabelText("Name"), "Work");
    await userEvent.type(screen.getByLabelText("Public key"), "-----BEGIN OPENSSH PRIVATE KEY-----");
    await userEvent.click(screen.getByRole("button", { name: "Save key" }));
    expect((await screen.findAllByText(/Never paste a private key/)).length).toBeGreaterThan(0);
    expect(sent.filter((s) => s.method === "POST")).toHaveLength(0);
    await userEvent.clear(screen.getByLabelText("Public key"));
    await userEvent.type(screen.getByLabelText("Public key"), ED + " me");
    await userEvent.click(screen.getByRole("button", { name: "Save key" }));
    expect(await screen.findByText(/Saved Work/)).toBeTruthy();
    const post = sent.find((s) => s.method === "POST")!;
    expect(JSON.parse(post.body)).toEqual({ name: "Work", public_key: ED + " me" });
    expect(post.csrf).toBe(TOKEN("S"));
  });

  it("asks before deleting and sends the delete only on confirmation", async () => {
    render(<Root />);
    await userEvent.click(await screen.findByRole("button", { name: "Delete Olly laptop" }));
    await userEvent.click(await screen.findByRole("button", { name: "Cancel" }));
    expect(sent.filter((s) => s.method === "DELETE")).toHaveLength(0);
    await userEvent.click(screen.getByRole("button", { name: "Delete Olly laptop" }));
    await userEvent.click(await screen.findByRole("button", { name: "Delete key" }));
    await waitFor(() => expect(sent.filter((s) => s.method === "DELETE").map((s) => s.url)).toEqual(["/api/v1/ssh-keys/k-0123456789abcdef"]));
    expect(await screen.findByText(/Deleted Olly laptop/)).toBeTruthy();
  });

  it("says why it cannot make a key where the browser has no secure context", async () => {
    vi.stubGlobal("isSecureContext", false);
    render(<Root />);
    expect(await screen.findByText(/This page cannot make a key/)).toBeTruthy();
    expect(screen.queryByRole("button", { name: "Make a key pair" })).toBeNull();
  });

  it("makes a pair in the browser: the private key is offered once as a download and appears in no request; only the public line is saved", async () => {
    vi.stubGlobal("isSecureContext", true);
    let blob: Blob | null = null;
    URL.createObjectURL = vi.fn((b: Blob) => { blob = b; return "blob:test"; });
    URL.revokeObjectURL = vi.fn();
    render(<Root />);
    await screen.findByRole("table", { name: "Saved SSH public keys" });
    await userEvent.click(screen.getByRole("button", { name: "Make a key pair" }));
    expect(await screen.findByText(/Give the key a name first/)).toBeTruthy();
    await userEvent.type(screen.getByLabelText("Name for the new key"), "Fresh");
    await userEvent.click(screen.getByRole("button", { name: "Make a key pair" }));
    const dialog = await screen.findByRole("dialog");
    const pub = (within(dialog).getByLabelText("Public key") as HTMLTextAreaElement).value;
    expect(pub).toMatch(/^ssh-ed25519 [A-Za-z0-9+/]+=* Fresh@svavyom$/);
    const save = within(dialog).getByRole("button", { name: "Save public key" });
    expect(save.getAttribute("aria-disabled")).toBe("true"); // not before the private key was downloaded
    expect(sent.filter((s) => s.method !== "GET")).toHaveLength(0);
    await userEvent.click(within(dialog).getByRole("button", { name: "Download private key" }));
    expect(blob).not.toBeNull();
    const file = await new Promise<string>((res) => { const r = new FileReader(); r.onload = () => res(String(r.result)); r.readAsText(blob!); });
    expect(file).toContain("BEGIN OPENSSH PRIVATE KEY");
    await userEvent.click(within(dialog).getByRole("button", { name: "Save public key" }));
    expect(await screen.findByText(/Saved Fresh/)).toBeTruthy();
    // nothing sent to the server contains the private key, in any form
    const secret = file.split("\n").slice(1, -2).join("");
    for (const s of sent) { expect(s.body).not.toContain("PRIVATE KEY"); expect(s.body).not.toContain(secret.slice(0, 40)); expect(s.url).not.toContain(secret.slice(0, 40)); }
    expect(JSON.parse(sent.find((s) => s.method === "POST")!.body)).toEqual({ name: "Fresh", public_key: pub });
    expect(await screen.findByRole("table", { name: "Saved SSH public keys" })).toBeTruthy();
    expect(screen.queryByRole("dialog")).toBeNull();
  });

  it("never stores anything in the browser", async () => {
    vi.stubGlobal("isSecureContext", true);
    const setItem = vi.spyOn(Storage.prototype, "setItem");
    render(<Root />);
    await screen.findByRole("table", { name: "Saved SSH public keys" });
    expect(setItem).not.toHaveBeenCalled();
  });
});

describe("saved-key picker", () => {
  it("offers the saved keys and fills the box with the chosen key's text, and still accepts a pasted key", async () => {
    keys = [key(), key({ id: "k-bbbbbbbbbbbbbbbb", name: "Work", public_key: ED.replace("AAAAC3", "AAAAD4") })];
    let value = "";
    const { rerender } = render(<SshKeyField id="k" label="SSH public key" description="d" value={value} onChange={(v) => { value = v; }} />);
    const select = await screen.findByLabelText("Saved key");
    await userEvent.selectOptions(select, "k-bbbbbbbbbbbbbbbb");
    expect(value).toBe(keys[1].public_key);
    rerender(<SshKeyField id="k" label="SSH public key" description="d" value="ssh-ed25519 pasted" onChange={(v) => { value = v; }} />);
    expect((screen.getByLabelText("SSH public key") as HTMLTextAreaElement).value).toBe("ssh-ed25519 pasted");
  });

  it("shows only the text box when nothing is saved or the list cannot be read", async () => {
    keys = [];
    render(<SshKeyField id="k" label="SSH public key" description="d" value="" onChange={() => undefined} />);
    expect(await screen.findByLabelText("SSH public key")).toBeTruthy();
    await waitFor(() => expect(screen.queryByLabelText("Saved key")).toBeNull());
  });
});
