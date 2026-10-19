// Browser tier, CREATE journey (CT-PRODUCT-DELIVERY-005): Chromium -> real API -> operation worker -> real mutation supervisor ->
// real (simulated-host) helper process -> file-backed simulated host. No route mocking. SIMULATION ONLY: this proves the product
// flow and its failure handling, not libvirt, KVM or a bootable guest.
import { writeFileSync } from "node:fs";
import { expect, test, type Page } from "@playwright/test";
import { axe } from "./axe";

const OPEN = "http://127.0.0.1:4176";
const CLOSED = "http://127.0.0.1:4177";
const PASSWORD = "e2e-only-passphrase-not-a-real-credential";
const KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIyCA34mAg+8tDqqKgTSWK7GI2RLy/Kpy88xCej+HqvJ e2e@test";
const FP = "SHA256:wKNav4+M8aG9WnO7xGvHX1bW1pw3Nrjb9hHhPhPQh24";
const FAULT = "/tmp/svavyom-e2e-create-open/state/sim-fault.json";

test.describe.configure({ mode: "serial" });

async function signIn(page: Page, base: string) {
  await page.goto(base);
  await page.getByLabel(/Username/).fill("admin");
  await page.getByLabel(/Password/).fill(PASSWORD);
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(page.getByRole("heading", { level: 1, name: "Dashboard" })).toBeVisible();
}

async function fillCreate(page: Page, name: string, key = KEY) {
  await page.goto(`${OPEN}/#/create`);
  await expect(page.getByRole("heading", { level: 1, name: "Create VM" })).toBeVisible();
  await page.getByLabel(/^Name/).fill(name);
  await page.getByRole("button", { name: "Continue" }).click();
  await page.getByLabel("SSH public key").fill(key);
  await page.getByRole("button", { name: "Review" }).click();
}

test("closed by default: no create form, no Start, and the API refuses the operation", async ({ page }) => {
  await signIn(page, CLOSED);
  await page.goto(`${CLOSED}/#/create`);
  await expect(page.getByText(/VM creation is not enabled on this installation/)).toBeVisible();
  await expect(page.getByText(/Creating a VM is not available right now/)).toBeVisible();
  await expect(page.getByRole("button", { name: "Review" })).toHaveCount(0);
  const hdr = await page.request.get(`${CLOSED}/api/v1/auth/session`);
  const csrf = hdr.headers()["x-csrf-token"]!;
  const res = await page.request.post(`${CLOSED}/api/v1/operations`, {
    headers: { "X-CSRF-Token": csrf },
    data: { type: "create", kind: "VM", id: "nope", idempotency_key: "k-closed-1", create: { vcpus: 1, memory_mib: 512, image_id: "debian-13", disk_gib: 10, ssh_public_key: KEY } },
  });
  expect(res.ok()).toBe(false);
  expect(res.status()).toBeLessThan(500);
});

test("only a verified image can be chosen; a merely registered one is listed by the API but not offered", async ({ page }) => {
  await signIn(page, OPEN);
  const api = await page.request.get(`${OPEN}/api/v1/images`);
  const items = (await api.json()).items as Array<{ id: string; observed: { qualification: string } }>;
  expect(items.map((i) => `${i.id}:${i.observed.qualification}`).sort()).toEqual(["debian-13:verified", "raw-1:registered"]);
  await page.goto(`${OPEN}/#/create`);
  await expect(page.getByLabel("Image")).toBeVisible();
  const options = await page.getByLabel("Image").locator("option").allTextContents();
  expect(options).toEqual(["Debian 13 (login user debian, compatibility declared, not yet qualified)"]);
  await expect(page.getByText(/No image has been qualified on real hardware yet/)).toBeVisible();
  // Even if a browser tried to name the registered image, the server refuses it.
  const csrf = (await page.request.get(`${OPEN}/api/v1/auth/session`)).headers()["x-csrf-token"]!;
  const res = await page.request.post(`${OPEN}/api/v1/operations`, {
    headers: { "X-CSRF-Token": csrf },
    data: { type: "create", kind: "VM", id: "raw-vm", idempotency_key: "k-raw-1", create: { vcpus: 1, memory_mib: 512, image_id: "raw-1", disk_gib: 10, ssh_public_key: KEY } },
  });
  expect(res.ok()).toBe(false);
});

test("a state-changing request without the CSRF token is refused", async ({ page }) => {
  await signIn(page, OPEN);
  const res = await page.request.post(`${OPEN}/api/v1/operations`, {
    data: { type: "start", kind: "VM", id: "web-1", idempotency_key: "k-csrf-1" },
  });
  expect(res.status()).toBe(403);
});

test("local validation: a private key and a bad name are refused in the page and nothing is sent", async ({ page }) => {
  await signIn(page, OPEN);
  let posts = 0;
  page.on("request", (r) => { if (r.method() === "POST" && r.url().endsWith("/api/v1/operations")) posts++; });
  await page.goto(`${OPEN}/#/create`);
  await page.getByLabel(/^Name/).fill("Bad_Name");
  await page.getByRole("button", { name: "Continue" }).click();
  await expect(page.getByRole("alert").first()).toContainText("There is a problem");
  await expect(page.getByLabel("SSH public key")).toHaveCount(0); // still on the first step
  await page.getByLabel(/^Name/).fill("good-name");
  await page.getByRole("button", { name: "Continue" }).click();
  await page.getByLabel("SSH public key").fill("-----BEGIN OPENSSH PRIVATE KEY-----");
  await page.getByRole("button", { name: "Review" }).click();
  await expect(page.getByRole("alert").first()).toContainText("There is a problem");
  await expect(page.getByText(/Never paste a private key/).first()).toBeVisible();
  await expect(page.getByLabel("SSH public key")).toHaveValue("");
  expect(posts).toBe(0);
  const a = await axe(page);
  expect(a.violations).toEqual([]);
});

test("a weak key that passes the local check is rejected by the server with a typed message", async ({ page }) => {
  await signIn(page, OPEN);
  const weak = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAAgQDVKuFYLWycwHXUVPXFs/TWq77IgGs0ZfmWtTa3P4mHlKuax3or/2+487hE371sr61bES2WPys3dxjAemwO weak";
  await fillCreate(page, "weak-1", weak);
  await page.getByRole("button", { name: "Create VM" }).click();
  await expect(page.getByText(/Some details were not accepted/)).toBeVisible();
});

test("create -> stopped -> start -> running with a connection hint, then sign out", async ({ page }) => {
  await signIn(page, OPEN);
  await page.goto(`${OPEN}/#/vms`);
  await expect(page.getByText(/Development Preview: creating and starting VMs is experimental/)).toBeVisible();
  await fillCreate(page, "web-1");
  await expect(page.getByRole("heading", { level: 2, name: "Review" })).toBeVisible();
  await expect(page.getByText(FP)).toBeVisible();
  await expect(page.getByText(/declared this image compatible.*does not test SSH/)).toBeVisible();
  await expect(page.getByText(/AAAAC3NzaC1lZDI1NTE5/)).toHaveCount(0);
  expect((await axe(page)).violations).toEqual([]);
  // KEY DELIVERY GUARD: the key the person typed is exactly what the browser sends, and the created screen names its fingerprint
  let sent = "";
  page.on("request", (r) => { if (r.method() === "POST" && r.url().endsWith("/api/v1/operations")) sent = r.postData() ?? ""; });
  await page.getByRole("button", { name: "Create VM" }).click();
  await expect(page.getByText("VM created (stopped)")).toBeVisible({ timeout: 30000 });
  expect(JSON.parse(sent).create.ssh_public_key).toBe(KEY);
  await expect(page.getByText(FP)).toBeVisible();
  await page.getByRole("link", { name: "Go to the VM list" }).click();
  await expect(page.getByRole("row", { name: /web-1/ })).toContainText("Stopped");
  await page.getByRole("link", { name: "web-1" }).click(); // the VM's own page
  await expect(page.getByRole("heading", { level: 1, name: "web-1" })).toBeVisible();
  const row = page.locator("main");
  await expect(row).toContainText("Stopped");
  for (const w of ["Stop", "Reboot", "Force off"]) await expect(page.getByRole("button", { name: new RegExp(`^${w}`) })).toHaveCount(0);
  await expect(page.getByRole("button", { name: "Delete web-1" })).toBeVisible();
  const seen: string[] = [];
  page.on("response", async (r) => { if (r.request().method() === "POST") seen.push(`${r.status()} ${r.request().postData()} => ${await r.text().catch(() => "")}`); });
  await page.getByRole("button", { name: "Start web-1" }).click();
  await expect(page.getByText("VM started")).toBeVisible({ timeout: 30000 }).catch(async (e) => {
    throw new Error(`${e.message}\nPAGE: ${await page.locator("main").innerText()}\nPOSTS: ${seen.join(" | ")}`);
  });
  await expect(page.locator("main")).toContainText("Running");
  await expect(page.getByText(/^ssh debian@192\.168\.122\.\d+$/)).toBeVisible();
  await expect(page.getByText(/That does not prove SSH works/)).toBeVisible();
  const a = await axe(page);
  expect(a.violations).toEqual([]);
  expect(a.incomplete).toEqual([]);
  expect(await page.evaluate(() => JSON.stringify(localStorage) + JSON.stringify(sessionStorage) + document.cookie)).toBe("{}{}");
  await page.getByRole("button", { name: "Sign out" }).click();
  await expect(page.getByRole("heading", { level: 1, name: "Sign in" })).toBeVisible();
});

test("a name that already exists fails safely and creates no second VM", async ({ page }) => {
  await signIn(page, OPEN);
  await fillCreate(page, "web-1");
  await page.getByRole("button", { name: "Create VM" }).click();
  await expect(page.getByText(/already exists|Nothing was overwritten/).first()).toBeVisible({ timeout: 30000 });
  await page.goto(`${OPEN}/#/vms`);
  await expect(page.getByRole("row", { name: /web-1/ })).toHaveCount(1);
});

test("helper killed right after the domain is defined: the operation resumes and one VM results", async ({ page }) => {
  await signIn(page, OPEN);
  writeFileSync(FAULT, JSON.stringify({ kill_after: "domain-defined" }));
  await fillCreate(page, "kill-1");
  await page.getByRole("button", { name: "Create VM" }).click();
  await expect(page.getByText("VM created (stopped)")).toBeVisible({ timeout: 60000 });
  await page.goto(`${OPEN}/#/vms`);
  await expect(page.getByRole("row", { name: /kill-1/ })).toHaveCount(1);
  await expect(page.getByRole("row", { name: /kill-1/ })).toContainText("Stopped");
});

test("helper hangs past the supervisor deadline: the host is checked, never blindly retried into a duplicate", async ({ page }) => {
  await signIn(page, OPEN);
  writeFileSync(FAULT, JSON.stringify({ hang_after: "root-volume" }));
  await fillCreate(page, "hang-1");
  await page.getByRole("button", { name: "Create VM" }).click();
  await expect(page.getByText(/VM created \(stopped\)|Failed/)).toBeVisible({ timeout: 90000 });
  await page.goto(`${OPEN}/#/vms`);
  await expect(page.getByRole("row", { name: /hang-1/ })).toHaveCount(1);
});

test("an expired session during the journey returns to sign-in", async ({ page, context }) => {
  await signIn(page, OPEN);
  await fillCreate(page, "gone-1");
  await context.clearCookies();
  await page.getByRole("button", { name: "Create VM" }).click();
  await expect(page.getByRole("heading", { level: 1, name: "Sign in" })).toBeVisible();
  await expect(page.getByText("Your session has ended. Sign in again to continue.")).toBeVisible();
});
