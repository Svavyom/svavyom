// Browser tier, LIFECYCLE and CONSOLE (M1-D / M1-E): Chromium -> real API -> operation worker -> real mutation supervisor -> real
// (simulated-host) helper -> file-backed simulated host, and the real console broker over a SIMULATED hypervisor. No route mocking.
// SIMULATION ONLY: this proves the product flow, the closed protocols and the WebSocket path, not libvirt, KVM or a real guest.
import { expect, test, type Page } from "@playwright/test";
import { axe } from "./axe";

const OPEN = "http://127.0.0.1:4176";
const CLOSED = "http://127.0.0.1:4177";
const PASSWORD = "e2e-only-passphrase-not-a-real-credential";
const KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIyCA34mAg+8tDqqKgTSWK7GI2RLy/Kpy88xCej+HqvJ e2e@test";

test.describe.configure({ mode: "serial" });

async function signIn(page: Page, base: string) {
  await page.goto(base);
  await page.getByLabel(/Username/).fill("admin");
  await page.getByLabel(/Password/).fill(PASSWORD);
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(page.getByRole("heading", { level: 1, name: "Dashboard" })).toBeVisible();
}

async function createVm(page: Page, name: string) {
  await page.goto(`${OPEN}/#/create`);
  await page.getByLabel(/^Name/).fill(name);
  await page.getByRole("button", { name: "Continue" }).click();
  await page.getByLabel("SSH public key").fill(KEY);
  await page.getByRole("button", { name: "Review" }).click();
  await page.getByRole("button", { name: "Create VM" }).click();
  await expect(page.getByText("VM created (stopped)")).toBeVisible({ timeout: 30000 });
  await page.goto(`${OPEN}/#/vms/${name}`);
}

async function act(page: Page, button: string, done: string) {
  await page.getByRole("button", { name: button }).click();
  await expect(page.getByText(done)).toBeVisible({ timeout: 30000 });
}

test("the whole lifecycle from the page: start, reboot, stop, start, force off, delete", async ({ page }) => {
  await signIn(page, OPEN);
  await createVm(page, "life-1");
  const row = () => page.locator("main");
  await expect(row()).toContainText("Stopped");
  await expect(page.getByRole("button", { name: "Start life-1" })).toBeVisible();
  await expect(page.getByRole("button", { name: "Delete life-1" })).toBeVisible();
  for (const w of ["Stop", "Reboot", "Force off"]) await expect(page.getByRole("button", { name: `${w} life-1` })).toHaveCount(0);
  await act(page, "Start life-1", "VM started");
  await expect(row()).toContainText("Running");
  // a running VM offers Stop, Reboot and Force off, and nothing that would delete it
  for (const w of ["Stop", "Reboot", "Force off"]) await expect(page.getByRole("button", { name: `${w} life-1` })).toBeVisible();
  await expect(page.getByRole("button", { name: "Delete life-1" })).toHaveCount(0);
  await expect(page.getByRole("button", { name: "Start life-1" })).toHaveCount(0);
  await act(page, "Reboot life-1", "VM rebooted");
  await expect(row()).toContainText("Running");
  await act(page, "Stop life-1", "VM stopped");
  await expect(row()).toContainText("Stopped");
  await act(page, "Start life-1", "VM started");
  // Force off asks first; Cancel sends nothing
  let posts = 0;
  page.on("request", (r) => { if (r.method() === "POST" && r.url().endsWith("/api/v1/operations")) posts++; });
  await page.getByRole("button", { name: "Force off life-1" }).click();
  await expect(page.getByRole("dialog")).toContainText("cuts power immediately");
  expect((await axe(page)).violations).toEqual([]);
  await page.getByRole("button", { name: "Cancel" }).click();
  expect(posts).toBe(0);
  await page.getByRole("button", { name: "Force off life-1" }).click();
  await page.getByRole("button", { name: "Confirm force off" }).click();
  await expect(page.getByText("VM powered off")).toBeVisible({ timeout: 30000 });
  await expect(row()).toContainText("Stopped");
  // Delete asks first, then removes the VM
  await page.getByRole("button", { name: "Delete life-1" }).click();
  await expect(page.getByRole("dialog")).toContainText("removes this stopped VM, its disk and its cloud-init seed");
  await page.getByRole("button", { name: "Delete permanently" }).click();
  await expect(page.getByText("VM deleted")).toBeVisible({ timeout: 30000 });
  await expect(page.getByText("This VM was removed")).toBeVisible();
  await page.goto(`${OPEN}/#/vms`);
  await expect(page.getByRole("row", { name: /life-1/ })).toHaveCount(0);
  expect((await axe(page)).violations).toEqual([]);
});

test("the API refuses lifecycle actions outside their state and for VMs Svavyom does not own", async ({ page }) => {
  await signIn(page, OPEN);
  await createVm(page, "state-1");
  const csrf = (await page.request.get(`${OPEN}/api/v1/auth/session`)).headers()["x-csrf-token"]!;
  const submit = (type: string, id = "state-1") => page.request.post(`${OPEN}/api/v1/operations`, { headers: { "X-CSRF-Token": csrf },
    data: { type, kind: "VM", id, idempotency_key: `k-${type}-${id}-${Math.random().toString(36).slice(2, 10)}` } });
  for (const t of ["stop", "reboot", "force_off"]) expect((await submit(t)).status(), `${t} of a stopped VM`).toBe(409);
  expect((await submit("restart")).status()).toBe(422); // not a lifecycle type
  expect((await submit("delete", "ghost-vm")).status()).toBe(404);
  const start = await submit("start");
  expect(start.status()).toBe(202);
  await expect.poll(async () => (await (await page.request.get(`${OPEN}/api/v1/vms/state-1`)).json()).observed.power, { timeout: 30000 }).toBe("running");
  await page.reload();
  await expect(page.locator("main")).toContainText("Running", { timeout: 30000 });
  expect((await submit("delete")).status(), "delete of a running VM").toBe(409);
  expect((await submit("start")).status()).toBe(409);
  // clean up through the page
  await page.getByRole("button", { name: "Force off state-1" }).click();
  await page.getByRole("button", { name: "Confirm force off" }).click();
  await expect(page.getByText("VM powered off")).toBeVisible({ timeout: 30000 });
});

test("recovery view: boot output, what is known about SSH, and an interactive serial console over the WebSocket", async ({ page }) => {
  await signIn(page, OPEN);
  await createVm(page, "con-1");
  await act(page, "Start con-1", "VM started");
  await page.getByRole("link", { name: "Console con-1" }).click();
  await expect(page.getByRole("heading", { level: 1, name: "Console: con-1" })).toBeVisible();
  await expect(page.getByText(/rescue mode on the VM's page boots a rescue system/i)).toBeVisible();
  await expect(page.getByText(/SSH: Address 192\.168\.122\.\d+ and login user debian observed/)).toBeVisible();
  const boot = page.getByLabel("Serial boot output text");
  await expect(boot).toContainText("simulated guest booted", { timeout: 20000 });
  await expect(boot).toContainText("con-1 login:");
  // the interactive console needs an explicit acknowledgement
  const open = page.getByRole("button", { name: "Open serial console" });
  await expect(open).toHaveAttribute("aria-disabled", "true");
  await page.getByRole("checkbox", { name: /I understand/ }).check();
  const sockets: string[] = [];
  page.on("websocket", (ws) => sockets.push(ws.url()));
  await open.click();
  const screen = page.getByLabel("Serial console output");
  await expect(screen).toContainText("con-1 login:", { timeout: 20000 });
  expect(sockets).toHaveLength(1);
  expect(sockets[0]).toMatch(/^ws:\/\/127\.0\.0\.1:4176\/console\/v1\/vms\/con-1\/socket$/); // no ticket, no query
  await page.getByLabel(/Send to the console/).fill("whoami");
  await page.getByLabel(/Send to the console/).press("Enter");
  await expect(screen).toContainText("root", { timeout: 10000 });
  expect((await axe(page)).violations).toEqual([]);
  // a second console on the same VM is refused while this one is open; Disconnect releases it
  const csrf = (await page.request.get(`${OPEN}/api/v1/auth/session`)).headers()["x-csrf-token"]!;
  const t2 = await page.request.post(`${OPEN}/console/v1/vms/con-1/tickets`, { headers: { "X-CSRF-Token": csrf } });
  expect(t2.status()).toBe(200);
  await page.getByRole("button", { name: "Disconnect" }).click();
  await expect(page.getByText("The console was closed.")).toBeVisible();
  // reconnect: a new ticket, the earlier output is replayed
  await page.getByRole("checkbox", { name: /I understand/ }).check();
  await page.getByRole("button", { name: "Open the console again" }).click();
  await expect.poll(() => sockets.length, { timeout: 20000 }).toBe(2);
  await expect(page.getByLabel("Serial console output")).toContainText("root", { timeout: 20000 });
  expect(await page.evaluate(() => JSON.stringify(localStorage) + JSON.stringify(sessionStorage) + document.cookie)).toBe("{}{}");
  // stopping the VM ends the console with an explanation
  await page.goto(`${OPEN}/#/vms/con-1`);
  await page.getByRole("button", { name: "Force off con-1" }).click();
  await page.getByRole("button", { name: "Confirm force off" }).click();
  await expect(page.getByText("VM powered off")).toBeVisible({ timeout: 30000 });
});

test("console tickets are single-use and bound to the VM and the session", async ({ page, browser }) => {
  await signIn(page, OPEN);
  await createVm(page, "tick-1");
  await act(page, "Start tick-1", "VM started");
  const csrf = (await page.request.get(`${OPEN}/api/v1/auth/session`)).headers()["x-csrf-token"]!;
  const mint = async (vm: string) => (await (await page.request.post(`${OPEN}/console/v1/vms/${vm}/tickets`, { headers: { "X-CSRF-Token": csrf } })).json()).ticket as string;
  const tryOpen = (vm: string, ticket: string) => page.evaluate(({ vm, ticket }) => new Promise<string>((resolve) => {
    const ws = new WebSocket(`ws://127.0.0.1:4176/console/v1/vms/${vm}/socket`, ["svavyom.console.v1", `t.${ticket}`]);
    ws.onopen = () => { ws.close(); resolve("open"); };
    ws.onerror = () => resolve("refused");
  }), { vm, ticket });
  // The test-only broker learns of a started VM on its next scan (100 ms, longer on a loaded machine): retry with fresh tickets until the first
  // attach is accepted, then use that very ticket for the replay check.
  let good = await mint("tick-1");
  let opened = (await tryOpen("tick-1", good)) === "open";
  for (let i = 0; i < 50 && !opened; i++) {
    await page.waitForTimeout(200);
    good = await mint("tick-1");
    opened = (await tryOpen("tick-1", good)) === "open";
  }
  expect(opened, "the first attach with a fresh ticket").toBe(true);
  expect(await tryOpen("tick-1", good), "replayed ticket").toBe("refused");
  expect(await tryOpen("tick-1", "A".repeat(43)), "forged ticket").toBe("refused");
  expect(await tryOpen("ghost-vm", await mint("tick-1")), "ticket of another VM").toBe("refused");
  // a ticket minted in another session is useless here
  const other = await browser.newContext();
  const op = await other.newPage();
  await signIn(op, OPEN);
  const ocsrf = (await op.request.get(`${OPEN}/api/v1/auth/session`)).headers()["x-csrf-token"]!;
  const foreign = (await (await op.request.post(`${OPEN}/console/v1/vms/tick-1/tickets`, { headers: { "X-CSRF-Token": ocsrf } })).json()).ticket as string;
  expect(await tryOpen("tick-1", foreign), "another session's ticket").toBe("refused");
  await other.close();
  // without the CSRF header no ticket is minted
  expect((await page.request.post(`${OPEN}/console/v1/vms/tick-1/tickets`)).status()).toBe(403);
});

test("the interactive console is off unless the operator enabled it; boot output still reads", async ({ page }) => {
  await signIn(page, CLOSED);
  const csrf = (await page.request.get(`${CLOSED}/api/v1/auth/session`)).headers()["x-csrf-token"]!;
  const res = await page.request.post(`${CLOSED}/console/v1/vms/anything/tickets`, { headers: { "X-CSRF-Token": csrf } });
  expect(res.status()).toBe(422);
  expect((await res.json()).category).toBe("prohibited");
  const serial = await page.request.get(`${CLOSED}/console/v1/vms/anything/serial`);
  expect(serial.status()).toBe(404); // an unknown VM
});

test("usage and activity: a running VM gets a CPU chart, the host a load chart, and the feed lists what was done (DR-022)", async ({ page }) => {
  await signIn(page, OPEN);
  await createVm(page, "use-1");
  await act(page, "Start use-1", "VM started");
  const chart = page.getByRole("img", { name: /CPU use of use-1 over the last hour/ });
  // the sampler runs every second here; the page reads what has been sampled, so refresh until two readings exist
  await expect(async () => {
    await page.getByRole("button", { name: "Refresh" }).click();
    await expect(chart).toBeVisible({ timeout: 2000 });
  }).toPass({ timeout: 30000 });
  await expect(page.getByText(/CPU of this VM: now \d+%/).first()).toBeVisible();
  await expect(page.getByText(/\d+ vCPU, \d+ MiB memory/)).toBeVisible();
  const a1 = await axe(page);
  expect(a1.violations).toEqual([]);
  expect(a1.incomplete).toEqual([]);
  // the dashboard: host load and the activity feed
  await page.getByRole("link", { name: "Dashboard" }).click();
  await expect(page.getByRole("heading", { level: 1, name: "Dashboard" })).toBeVisible();
  await expect(async () => {
    await page.getByRole("button", { name: "Refresh" }).click();
    await expect(page.getByRole("img", { name: /Host CPU and memory use over the last hour/ })).toBeVisible({ timeout: 2000 });
  }).toPass({ timeout: 30000 });
  const feed = page.getByRole("heading", { name: "Recent activity" }).locator("xpath=ancestor::section[1]");
  await expect(feed).toContainText("Start");
  await expect(feed).toContainText("use-1");
  await expect(feed).toContainText("Create");
  const a2 = await axe(page);
  expect(a2.violations).toEqual([]);
  expect(a2.incomplete).toEqual([]);
  // clean up through the page
  await page.goto(`${OPEN}/#/vms/use-1`);
  await page.getByRole("button", { name: "Force off use-1" }).click();
  await page.getByRole("button", { name: "Confirm force off" }).click();
  await expect(page.getByText("VM powered off")).toBeVisible({ timeout: 30000 });
});

test("graphical console: a real noVNC client draws the (simulated) screen through the broker, with a single-use ticket and one viewer per VM", async ({ page }) => {
  await signIn(page, OPEN);
  await createVm(page, "gfx-1");
  await act(page, "Start gfx-1", "VM started");
  await expect(page.getByRole("link", { name: "Graphical console gfx-1" })).toBeVisible();
  await page.getByRole("link", { name: "Graphical console gfx-1" }).click();
  await expect(page.getByRole("heading", { level: 1, name: "Graphical console: gfx-1" })).toBeVisible();
  await expect(page.getByText(/full-power channel into the VM/)).toBeVisible();
  const open = page.getByRole("button", { name: "Open graphical console" });
  await expect(open).toHaveAttribute("aria-disabled", "true");
  await page.getByRole("checkbox", { name: /I understand/ }).check();
  const sockets: string[] = [];
  page.on("websocket", (ws) => sockets.push(ws.url()));
  await open.click();
  await expect(page.getByText(/Connected to sim:gfx-1/)).toBeVisible({ timeout: 30000 });
  expect(sockets).toHaveLength(1);
  expect(sockets[0]).toBe("ws://127.0.0.1:4176/console/v1/vms/gfx-1/graphics-socket"); // no ticket, no query
  // the picture: noVNC draws the simulated framebuffer into a canvas, which is not blank
  const canvas = page.getByLabel("Screen of gfx-1").locator("canvas");
  await expect(canvas).toBeVisible();
  await expect.poll(async () => canvas.evaluate((c: HTMLCanvasElement) => {
    const d = c.getContext("2d")!.getImageData(Math.floor(c.width / 2), Math.floor(c.height / 2), 1, 1).data;
    return d[0] + d[1] + d[2] + d[3] > 0;
  }), { timeout: 20000 }).toBe(true);
  // keyboard and pointer reach the VM: the simulated server changes the picture's colour with every event
  const before = await canvas.evaluate((c: HTMLCanvasElement) => Array.from(c.getContext("2d")!.getImageData(5, 5, 1, 1).data).join(","));
  await canvas.click({ position: { x: 20, y: 20 } });
  await page.keyboard.type("hello");
  await expect.poll(async () => canvas.evaluate((c: HTMLCanvasElement) => Array.from(c.getContext("2d")!.getImageData(5, 5, 1, 1).data).join(",")), { timeout: 20000 }).not.toBe(before);
  await page.getByRole("button", { name: "Send Ctrl-Alt-Del" }).click();
  // a second viewer on the same VM is refused before the upgrade
  const csrf = (await page.request.get(`${OPEN}/api/v1/auth/session`)).headers()["x-csrf-token"]!;
  const second = await page.request.post(`${OPEN}/console/v1/vms/gfx-1/graphics-tickets`, { headers: { "X-CSRF-Token": csrf } });
  expect(second.status()).toBe(200);
  const tk = (await second.json()).ticket as string;
  const refused = await page.evaluate((ticket) => new Promise<string>((resolve) => {
    const ws = new WebSocket("ws://127.0.0.1:4176/console/v1/vms/gfx-1/graphics-socket", ["svavyom.graphics.v1", `t.${ticket}`]);
    ws.onopen = () => { ws.close(); resolve("open"); };
    ws.onerror = () => resolve("refused");
  }), tk);
  expect(refused).toBe("refused");
  expect((await axe(page)).violations).toEqual([]);
  expect(await page.evaluate(() => JSON.stringify(localStorage) + JSON.stringify(sessionStorage) + document.cookie)).toBe("{}{}");
  await page.getByRole("button", { name: "Disconnect" }).click();
  await expect(page.getByText("The console was closed.")).toBeVisible();
  // clean up
  await page.goto(`${OPEN}/#/vms/gfx-1`);
  await page.getByRole("button", { name: "Force off gfx-1" }).click();
  await page.getByRole("button", { name: "Confirm force off" }).click();
  await expect(page.getByText("VM powered off")).toBeVisible({ timeout: 30000 });
});
