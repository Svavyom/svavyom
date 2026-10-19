// Browser tier, REAL stack (CT-PRODUCT-DELIVERY-003 s3): Chromium -> real API process -> real SQLite. No route mocking.
// Product validation only: the host here is the dev-offline container, so the distribution check is `unknown` and this
// proves nothing about KVM or real-host qualification.
import { expect, request, test, type Page } from "@playwright/test";
import { axe } from "./axe";

const BASE = "http://127.0.0.1:4175";
const PASSWORD = "e2e-only-passphrase-not-a-real-credential";

async function signIn(page: Page, password = PASSWORD) {
  await page.getByLabel(/Username/).fill("admin");
  await page.getByLabel(/Password/).fill(password);
  await page.getByRole("button", { name: "Sign in" }).click();
}

test.describe.configure({ mode: "serial" });

test("anonymous visit shows the sign-in page and no host data", async ({ page }) => {
  await page.goto(BASE);
  await expect(page.getByRole("heading", { level: 1, name: "Sign in" })).toBeVisible();
  await expect(page.getByLabel(/Password/)).toHaveAttribute("type", "password");
  await expect(page.getByText("Processors")).toHaveCount(0);
  const a = await axe(page);
  expect(a.violations).toEqual([]);
  expect(a.incomplete).toEqual([]);
  // Direct API access without a session is refused.
  const res = await page.request.get(`${BASE}/api/v1/hosts/local`);
  expect(res.status()).toBe(401);
});

test("a wrong password shows one generic failure and stays signed out", async ({ page }) => {
  await page.goto(BASE);
  await signIn(page, "definitely the wrong passphrase");
  await expect(page.getByText("The username or password is incorrect.")).toBeVisible();
  await expect(page.getByRole("heading", { level: 1, name: "Dashboard" })).toHaveCount(0);
  const cookies = await page.context().cookies();
  expect(cookies.find((c) => c.name.includes("svavyom_session"))).toBeUndefined();
});

test("sign in, dashboard capacity and readiness, reload keeps the session, sign out restores the anonymous state", async ({ page }) => {
  await page.goto(BASE);
  await signIn(page);
  await expect(page.getByRole("heading", { level: 1, name: "Dashboard" })).toBeVisible();
  await expect(page.getByRole("heading", { level: 2, name: "e2e-host" })).toBeVisible();
  const capacity = page.getByRole("table", { name: "Capacity and software" });
  await expect(capacity.getByRole("row", { name: /Processors/ })).toContainText(/\d+ logical/);
  await expect(capacity.getByRole("row", { name: /Memory/ })).toContainText(/\d+\.\d GiB/);
  await expect(page.getByRole("table", { name: "Virtualization readiness" })).toBeVisible();
  for (const row of ["Hardware virtualization (CPU)", "KVM device", "libvirt installed", "QEMU installed"]) {
    await expect(page.getByRole("row", { name: new RegExp(row.replace(/[()]/g, "\\$&")) })).toBeVisible();
  }
  await expect(page.getByText("matrix conformance only; it is not host qualification")).toBeVisible();
  await expect(page.getByText("Signed in as")).toBeVisible();
  const a = await axe(page);
  expect(a.violations).toEqual([]);
  expect(a.incomplete).toEqual([]);

  // Cookie hygiene as the browser sees it.
  const session = (await page.context().cookies()).find((c) => c.name === "svavyom_session");
  expect(session?.httpOnly).toBe(true);
  expect(session?.sameSite).toBe("Strict");
  expect(await page.evaluate(() => document.cookie)).toBe(""); // HttpOnly: invisible to scripts
  expect(await page.evaluate(() => JSON.stringify(localStorage) + JSON.stringify(sessionStorage))).toBe("{}{}");

  await page.reload();
  await expect(page.getByRole("heading", { level: 1, name: "Dashboard" })).toBeVisible();

  await page.getByRole("button", { name: "Sign out" }).click();
  await expect(page.getByRole("heading", { level: 1, name: "Sign in" })).toBeVisible();
  await expect(page.getByText("Processors")).toHaveCount(0);
  await page.reload();
  await expect(page.getByRole("heading", { level: 1, name: "Sign in" })).toBeVisible();
  expect((await page.request.get(`${BASE}/api/v1/hosts/local`)).status()).toBe(401);
});

test("a session ended on the server returns the browser to sign-in with an explanation", async ({ page, browser }) => {
  await page.goto(BASE);
  await signIn(page);
  await expect(page.getByRole("heading", { level: 1, name: "Dashboard" })).toBeVisible();
  // Another client holding the same session cookie signs it out (server-side revocation, as an idle or absolute timeout
  // would end it). Idle/absolute timers themselves are covered by the Go tests with an injected clock.
  const cookies = await page.context().cookies();
  const other = await request.newContext({ baseURL: BASE });
  await other.storageState();
  const jar = await browser.newContext();
  await jar.addCookies(cookies);
  const status = await jar.request.get(`${BASE}/api/v1/auth/session`);
  const csrf = status.headers()["x-csrf-token"];
  expect((await jar.request.delete(`${BASE}/api/v1/auth/session`, { headers: { "X-CSRF-Token": csrf } })).status()).toBe(200);
  await page.getByRole("button", { name: "Refresh" }).click();
  await expect(page.getByText("Your session has ended. Sign in again to continue.")).toBeVisible();
  await expect(page.getByRole("heading", { level: 1, name: "Sign in" })).toBeVisible();
  const a = await axe(page);
  expect(a.violations).toEqual([]);
  await signIn(page);
  await expect(page.getByRole("heading", { level: 1, name: "Dashboard" })).toBeVisible();
  await jar.close();
  await other.dispose();
});

// ---- VM inventory (read-only) through the real API -> Unix socket -> fixture agent chain ------------------------------
// The agent here is the TEST-ONLY fixture (same protocol as the real agent). Libvirt-backed inventory is covered by the Go
// chain test over libvirt's test driver; real qemu:///system is NOT_RUN (higher-tier qualification).
import { writeFileSync } from "node:fs";

const STATE = "/tmp/svavyom-e2e/state.json";
const setAgent = (mode: "up" | "down", domains: Array<{ name: string; power: string }> = []) =>
  writeFileSync(STATE, JSON.stringify({ mode, domains }));

async function openInventory(page: Page) {
  await page.goto(BASE);
  await signIn(page);
  await expect(page.getByRole("heading", { level: 1, name: "Dashboard" })).toBeVisible();
  await page.getByRole("link", { name: "Virtual machines" }).click();
  await expect(page.getByRole("heading", { level: 1, name: "Virtual machines" })).toBeVisible();
}

test("inventory: empty host shows 'No VMs yet' and no mutation controls", async ({ page }) => {
  setAgent("up", []);
  await openInventory(page);
  await expect(page.getByText("No VMs yet")).toBeVisible();
  const a = await axe(page);
  expect(a.violations).toEqual([]);
  expect(a.incomplete).toEqual([]);
  await expect(page.getByRole("button", { name: /create|start|stop|reboot|force|delete/i })).toHaveCount(0);
});

test("inventory: populated host lists machines with observed power state, then sign out", async ({ page }) => {
  setAgent("up", [{ name: "web-1", power: "running" }, { name: "db-1", power: "shutoff" }, { name: "wk-1", power: "paused" }]);
  await openInventory(page);
  const table = page.getByRole("table", { name: "Virtual machines on this host" });
  await expect(table.getByRole("row", { name: /web-1/ })).toContainText("Running");
  await expect(table.getByRole("row", { name: /db-1/ })).toContainText("Stopped");
  await expect(table.getByRole("row", { name: /wk-1/ })).toContainText("Paused");
  const a = await axe(page);
  expect(a.violations).toEqual([]);
  expect(a.incomplete).toEqual([]);
  // Mutation stays closed at the API too.
  const csrf = (await page.request.get(`${BASE}/api/v1/auth/session`)).headers()["x-csrf-token"];
  expect((await page.request.post(`${BASE}/api/v1/operations`, { headers: { "X-CSRF-Token": csrf }, data: { type: "start", kind: "VM", id: "web-1", idempotency_key: "k1" } })).status()).toBe(401);
  await page.getByRole("button", { name: "Sign out" }).click();
  await expect(page.getByRole("heading", { level: 1, name: "Sign in" })).toBeVisible();
  expect((await page.request.get(`${BASE}/api/v1/vms`)).status()).toBe(401);
});

test("inventory: an unavailable agent is a typed error with retry and recovery", async ({ page }) => {
  setAgent("up", [{ name: "web-1", power: "running" }]);
  await openInventory(page);
  await expect(page.getByRole("row", { name: /web-1/ })).toBeVisible();
  setAgent("down");
  await page.getByRole("button", { name: "Refresh" }).click();
  await expect(page.getByText("Service temporarily unavailable")).toBeVisible();
  await expect(page.getByText(/last updated|Last updated/)).toBeVisible(); // last-known data is marked stale, not passed off as current
  setAgent("up", [{ name: "web-1", power: "running" }, { name: "web-2", power: "running" }]);
  await page.getByRole("button", { name: "Try again" }).click();
  await expect(page.getByRole("row", { name: /web-2/ })).toBeVisible();
  await expect(page.getByText("Service temporarily unavailable")).toHaveCount(0);
});

test("inventory: a session ended on the server returns to sign-in", async ({ page, browser }) => {
  setAgent("up", [{ name: "web-1", power: "running" }]);
  await openInventory(page);
  const jar = await browser.newContext();
  await jar.addCookies(await page.context().cookies());
  const csrf = (await jar.request.get(`${BASE}/api/v1/auth/session`)).headers()["x-csrf-token"];
  expect((await jar.request.delete(`${BASE}/api/v1/auth/session`, { headers: { "X-CSRF-Token": csrf } })).status()).toBe(200);
  await page.getByRole("button", { name: "Refresh" }).click();
  await expect(page.getByText("Your session has ended. Sign in again to continue.")).toBeVisible();
  await jar.close();
});

test("inventory: a host domain Svavyom cannot represent fails the inventory instead of hiding it", async ({ page }) => {
  setAgent("up", [{ name: "web-1", power: "running" }, { name: "bad name!", power: "running" }]);
  await openInventory(page);
  await expect(page.getByText("Something went wrong")).toBeVisible();
  await expect(page.getByText(/cannot represent yet/)).toBeVisible();
  await expect(page.getByRole("table", { name: "Virtual machines on this host" })).toHaveCount(0);
  await expect(page.getByText("No VMs yet")).toHaveCount(0);
  expect(await page.content()).not.toContain("bad name!"); // the rejected name is never shown
  setAgent("up", []);
});
