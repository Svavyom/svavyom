// fe-unit: Users (admin) and Account (everyone), and the forced password change (DR-041).
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { Root } from "./Root";
import { HOST, apiError } from "../api/fixtures";
import { forgetCsrf } from "../api/session";
import { axeViolations } from "../test-axe";
import type { User } from "../api/schema";

const TOKEN = (c: string) => c.repeat(43);
const respond = (status: number, body: unknown, csrf?: string) => new Response(JSON.stringify(body), { status, headers: csrf ? { "X-CSRF-Token": csrf } : {} });
const user = (over: Partial<User> = {}): User => ({ username: "olly", role: "operator", disabled: false, must_change_password: false, created_at: "2026-11-10T08:00:00Z", allowed_actions: ["set_role", "reset_password", "disable"], ...over });

let me: { username: string; role: "admin" | "operator" | "viewer"; must: boolean };
let users: User[], sent: { method: string; url: string; body: string; csrf: string | null }[], pwStatus: number;
beforeEach(() => {
  forgetCsrf();
  me = { username: "admin", role: "admin", must: false };
  users = [user({ username: "admin", role: "admin", allowed_actions: [] }), user()];
  sent = []; pwStatus = 200;
  location.hash = "#/users";
  vi.stubGlobal("fetch", vi.fn(async (url: string, init?: RequestInit) => {
    const method = init?.method ?? "GET";
    const headers = new Headers(init?.headers);
    if (method !== "GET") sent.push({ method, url, body: String(init?.body ?? ""), csrf: headers.get("X-CSRF-Token") });
    const session = () => ({ authenticated: true, username: me.username, expires_at: "2026-10-09T08:30:00Z", role: me.role, must_change_password: me.must });
    if (url === "/api/v1/auth/session") return respond(200, session(), TOKEN("S"));
    if (url === "/api/v1/hosts/local") return respond(200, HOST);
    if (url === "/api/v1/auth/password" && method === "POST") { if (pwStatus === 200) me.must = false; return pwStatus === 200 ? respond(200, session()) : respond(pwStatus, apiError(pwStatus === 403 ? "forbidden" : pwStatus === 429 ? "rate_limited" : "validation")); }
    if (url === "/api/v1/users" && method === "GET") return respond(200, { items: users, allowed_actions: ["create"] });
    if (url === "/api/v1/users" && method === "POST") { const b = JSON.parse(String(init?.body)); const u = user({ username: b.username, role: b.role, must_change_password: true }); users = [...users, u]; return respond(201, u); }
    const m = /^\/api\/v1\/users\/([a-z0-9._-]+)\/(role|disable|enable|password)$/.exec(url);
    if (m && method === "POST") {
      const i = users.findIndex((x) => x.username === m[1]);
      const b = init?.body ? JSON.parse(String(init.body)) : {};
      if (m[2] === "role") users[i] = { ...users[i], role: b.role };
      if (m[2] === "disable") users[i] = { ...users[i], disabled: true, allowed_actions: ["set_role", "reset_password", "enable"] };
      if (m[2] === "enable") users[i] = { ...users[i], disabled: false, allowed_actions: ["set_role", "reset_password", "disable"] };
      if (m[2] === "password") users[i] = { ...users[i], must_change_password: true };
      return respond(200, users[i]);
    }
    return respond(404, apiError("not_found"));
  }));
});
afterEach(() => { cleanup(); vi.unstubAllGlobals(); });

describe("Users page", () => {
  it("lists the users; the administrator's own row offers nothing but a pointer to Account", async () => {
    render(<Root />);
    const table = await screen.findByRole("table", { name: "Users of this installation" });
    expect(within(table).getByText("olly")).toBeTruthy();
    expect(within(table).getByText("You (use Account)")).toBeTruthy();
    expect(screen.getByRole("button", { name: "Reset password of olly" })).toBeTruthy();
    expect(screen.queryByRole("button", { name: /of admin$/ })).toBeNull();
    expect(await axeViolations(document.body)).toEqual([]);
  });

  it("adds a user with a temporary password, with the CSRF token, and never shows the password again", async () => {
    render(<Root />);
    await screen.findByRole("table", { name: "Users of this installation" });
    await userEvent.type(screen.getByLabelText("User name"), "Bad Name");
    await userEvent.type(screen.getByLabelText("Temporary password"), "temporary passphrase 1");
    await userEvent.click(screen.getByRole("button", { name: "Add user" }));
    expect(await screen.findByText(/lower-case letters/)).toBeTruthy();
    expect(sent).toHaveLength(0);
    await userEvent.clear(screen.getByLabelText("User name"));
    await userEvent.type(screen.getByLabelText("User name"), "newbie");
    await userEvent.click(screen.getByRole("button", { name: "Add user" }));
    expect(await screen.findByText(/Created newbie/)).toBeTruthy();
    const post = sent.find((s) => s.url === "/api/v1/users")!;
    expect(JSON.parse(post.body)).toEqual({ username: "newbie", role: "viewer", password: "temporary passphrase 1" });
    expect(post.csrf).toBe(TOKEN("S"));
    expect(document.body.textContent).not.toContain("temporary passphrase 1");
    expect((screen.getByLabelText("Temporary password") as HTMLInputElement).value).toBe("");
    expect(await screen.findByText("Must choose a password")).toBeTruthy();
  });

  it("changes a role, resets a password, disables and enables, each behind a dialog", async () => {
    render(<Root />);
    await userEvent.click(await screen.findByRole("button", { name: "Change role of olly" }));
    await userEvent.selectOptions(await screen.findByLabelText("New role"), "viewer");
    await userEvent.click(screen.getByRole("button", { name: "Change role" }));
    expect(await screen.findByText(/olly is now viewer/)).toBeTruthy();
    expect(JSON.parse(sent.find((s) => s.url === "/api/v1/users/olly/role")!.body)).toEqual({ role: "viewer" });

    await userEvent.click(screen.getByRole("button", { name: "Reset password of olly" }));
    await userEvent.type(await screen.findByLabelText("Temporary password", { selector: "#dlg-pw" }), "short");
    await userEvent.click(screen.getByRole("button", { name: "Reset password", hidden: false }));
    expect(await screen.findByText(/at least 12 characters/)).toBeTruthy();
    expect(sent.filter((s) => s.url.endsWith("/password"))).toHaveLength(0);
    await userEvent.clear(screen.getByLabelText("Temporary password", { selector: "#dlg-pw" }));
    await userEvent.type(screen.getByLabelText("Temporary password", { selector: "#dlg-pw" }), "another temporary one 2");
    await userEvent.click(screen.getByRole("button", { name: "Reset password", hidden: false }));
    expect(await screen.findByText(/new temporary password/)).toBeTruthy();

    await userEvent.click(screen.getByRole("button", { name: "Disable olly" }));
    await userEvent.click(await screen.findByRole("button", { name: /^Disable$/ }));
    expect(await screen.findByText(/olly is disabled/)).toBeTruthy();
    await userEvent.click(await screen.findByRole("button", { name: "Enable olly" }));
    await userEvent.click(await screen.findByRole("button", { name: /^Enable$/ }));
    expect(await screen.findByText(/olly can sign in again/)).toBeTruthy();
    expect(sent.every((s) => s.csrf === TOKEN("S"))).toBe(true);
    expect(document.body.textContent).not.toContain("another temporary one 2");
  });

  it("is not offered to an operator, who lands on the dashboard instead", async () => {
    me = { username: "olly", role: "operator", must: false };
    render(<Root />);
    expect(await screen.findByRole("link", { name: "Account" })).toBeTruthy();
    expect(screen.queryByRole("link", { name: "Users" })).toBeNull();
    expect(screen.queryByRole("table", { name: "Users of this installation" })).toBeNull();
    expect(screen.getByRole("link", { name: "Account" })).toBeTruthy();
  });
});

describe("Account page", () => {
  beforeEach(() => { location.hash = "#/account"; me = { username: "olly", role: "operator", must: false }; });

  it("checks the form before sending, then changes the password and clears the fields", async () => {
    render(<Root />);
    expect(await screen.findByRole("heading", { level: 1, name: "Account" })).toBeTruthy();
    await userEvent.type(screen.getByLabelText("Current password"), "old passphrase here");
    await userEvent.type(screen.getByLabelText("New password"), "short");
    await userEvent.click(screen.getByRole("button", { name: "Change password" }));
    expect((await screen.findAllByText(/at least 12 characters/i)).length).toBeGreaterThan(0);
    await userEvent.clear(screen.getByLabelText("New password"));
    await userEvent.type(screen.getByLabelText("New password"), "a brand new passphrase 2");
    await userEvent.type(screen.getByLabelText("New password again"), "a different passphrase");
    await userEvent.click(screen.getByRole("button", { name: "Change password" }));
    expect(await screen.findByText(/not the same/)).toBeTruthy();
    expect(sent).toHaveLength(0);
    await userEvent.clear(screen.getByLabelText("New password again"));
    await userEvent.type(screen.getByLabelText("New password again"), "a brand new passphrase 2");
    await userEvent.click(screen.getByRole("button", { name: "Change password" }));
    expect(await screen.findByText(/Password changed/)).toBeTruthy();
    expect(JSON.parse(sent[0].body)).toEqual({ current_password: "old passphrase here", new_password: "a brand new passphrase 2" });
    expect(sent[0].csrf).toBe(TOKEN("S"));
    expect((screen.getByLabelText("Current password") as HTMLInputElement).value).toBe("");
    expect(document.body.textContent).not.toContain("a brand new passphrase 2");
    expect(await axeViolations(document.body)).toEqual([]);
  });

  it("says plainly when the current password is wrong or the attempts are throttled", async () => {
    render(<Root />);
    const fill = async () => {
      await userEvent.clear(screen.getByLabelText("Current password")); await userEvent.type(screen.getByLabelText("Current password"), "old passphrase here");
      await userEvent.clear(screen.getByLabelText("New password")); await userEvent.type(screen.getByLabelText("New password"), "a brand new passphrase 2");
      await userEvent.clear(screen.getByLabelText("New password again")); await userEvent.type(screen.getByLabelText("New password again"), "a brand new passphrase 2");
      await userEvent.click(screen.getByRole("button", { name: "Change password" }));
    };
    await screen.findByRole("heading", { level: 1, name: "Account" });
    pwStatus = 403; await fill();
    expect(await screen.findByText("The current password is not correct.")).toBeTruthy();
    pwStatus = 429; await fill();
    expect(await screen.findByText(/Too many attempts/)).toBeTruthy();
  });
});

describe("a temporary password", () => {
  it("shows only the password change, with no other page in the menu, until it is changed", async () => {
    me = { username: "newbie", role: "viewer", must: true };
    location.hash = "#/vms";
    render(<Root />);
    expect(await screen.findByRole("heading", { level: 1, name: "Choose a new password" })).toBeTruthy();
    expect(screen.queryByRole("link", { name: "Virtual machines" })).toBeNull();
    expect(screen.queryByRole("link", { name: "Dashboard" })).toBeNull();
    expect(screen.getByRole("link", { name: "Account" })).toBeTruthy();
    await userEvent.type(screen.getByLabelText("Current password"), "temporary passphrase 1");
    await userEvent.type(screen.getByLabelText("New password"), "a brand new passphrase 2");
    await userEvent.type(screen.getByLabelText("New password again"), "a brand new passphrase 2");
    await userEvent.click(screen.getByRole("button", { name: "Change password" }));
    await waitFor(() => expect(screen.getByRole("link", { name: "Virtual machines" })).toBeTruthy());
    expect(screen.queryByRole("heading", { name: "Choose a new password" })).toBeNull();
  });
});
