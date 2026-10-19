// Browser tier, journeys J1-J10 (M0-E02-S06 AC03): keyboard-only along the catalogue paths, against the test-only
// gallery bundle with route-intercepted PROVISIONAL fixtures. Mock-API journeys are not evidence of real API
// behaviour; M1-E04 stories must pass the same paths against the real API.
import { expect, test, type Page } from "@playwright/test";
import { GALLERY, HOST, VM_RUNNING, apiError, operation, routeApi, vmList } from "./fixtures";
import { axe } from "./axe";

let loads = 0;
async function open(page: Page, hash: string) {
  loads += 1; // a distinct query string forces a fresh document even when only the hash repeats
  await page.goto(`${GALLERY.replace("gallery.html", `gallery.html?load=${loads}`)}${hash}`);
  await expect(page.locator("h1")).toBeFocused();
  // Every keyboard path starts at the top: back to the skip link with Shift+Tab, then into main (review N1).
  const skip = page.getByRole("link", { name: "Skip to main content" });
  for (let i = 0; i < 10 && !(await skip.evaluate((el) => el === document.activeElement)); i++) await page.keyboard.press("Shift+Tab");
  await expect(skip).toBeFocused();
  await page.keyboard.press("Enter");
  await expect(page.locator("main")).toBeFocused();
}

/** Tab until the focused element has this accessible text (bounded), using the keyboard only. */
async function tabTo(page: Page, text: RegExp, max = 25) {
  for (let i = 0; i < max; i++) {
    await page.keyboard.press("Tab");
    const t = await page.evaluate(() => {
      const el = document.activeElement as HTMLElement | null;
      if (!el) return "";
      const label = el.id ? document.querySelector(`label[for="${el.id}"]`)?.textContent : "";
      return `${el.textContent ?? ""} ${el.getAttribute("aria-label") ?? ""} ${label ?? ""}`.trim();
    });
    if (text.test(t)) return;
  }
  throw new Error(`could not reach ${text} with Tab`);
}

async function clean(page: Page, external: string[], csp: string[] = []) {
  const a = await axe(page);
  expect(a.violations).toEqual([]);
  expect(a.incomplete).toEqual([]);
  expect(external).toEqual([]);
  expect(csp).toEqual([]);
}

test("J1 completes keyboard-only along its catalogue path", async ({ page }) => {
  const { external } = await routeApi(page, { "/api/v1/hosts/local": { body: HOST } });
  await open(page, "#/journey/J1");
  await expect(page.getByText(/Qualification: none \(matrix conformance only; not host qualification\)/)).toBeVisible();
  await tabTo(page, /Refresh/);
  await page.keyboard.press("Enter");
  await expect(page.getByText("local-host")).toBeVisible();
  await clean(page, external);
});

test("J2 completes keyboard-only along its catalogue path", async ({ page }) => {
  const { external } = await routeApi(page, { "/api/v1/projects": { status: 401, body: apiError("unauthenticated") } });
  await open(page, "#/journey/J2");
  await expect(page.getByText(/Authentication not configured/)).toBeVisible();
  await tabTo(page, /Back to the journey index/);
  await clean(page, external);
});

test("J3 completes keyboard-only along its catalogue path", async ({ page }) => {
  const { external } = await routeApi(page, { "/api/v1/vms": { body: vmList([VM_RUNNING], ["create"]) } });
  await open(page, "#/journey/J3");
  await tabTo(page, /Pause updates/);
  await page.keyboard.press("Space");
  await tabTo(page, /Refresh/);
  await page.keyboard.press("Enter");
  await tabTo(page, /web-1/);
  await clean(page, external);
});

test("J3 has no automatic refresh and shows a pause control", async ({ page }) => {
  const { calls } = await routeApi(page, { "/api/v1/vms": { body: vmList() } });
  await open(page, "#/journey/J3");
  await expect(page.getByLabel("Pause updates")).toBeVisible();
  await page.waitForTimeout(3000);
  expect(calls.filter((c) => c.path === "/api/v1/vms")).toHaveLength(1);
});

test("J4 completes keyboard-only along its catalogue path", async ({ page }) => {
  const { external, calls } = await routeApi(page, { "/api/v1/operations": { status: 202, body: operation({ id: "op-1" }) } });
  await open(page, "#/journey/J4");
  await tabTo(page, /Continue to review/);
  await page.keyboard.press("Enter");
  const summary = page.getByRole("alert").filter({ hasText: "There is a problem" });
  await expect(summary).toBeFocused();
  await clean(page, []);
  await tabTo(page, /^VM name/);
  await page.keyboard.type("web-1");
  await tabTo(page, /Debian 13/);
  await page.keyboard.press("Space");
  await page.keyboard.press("ArrowDown");
  await expect(page.getByLabel("Ubuntu 24.04")).toBeChecked();
  await tabTo(page, /Continue to review/);
  await page.keyboard.press("Enter");
  await expect(page.getByRole("heading", { name: "Review" })).toBeFocused();
  await tabTo(page, /Create VM/);
  await page.keyboard.press("Enter");
  await expect(page.getByRole("status").filter({ hasText: "Request accepted" })).toBeFocused();
  expect(calls.filter((c) => c.method === "POST")).toHaveLength(1);
  expect((calls[0].body as { idempotency_key: string }).idempotency_key).toMatch(/^[0-9a-f]{32}$/);
  await clean(page, external);
});

test("J4 back from review keeps the entered values", async ({ page }) => {
  await routeApi(page, {});
  await open(page, "#/journey/J4");
  await page.getByLabel(/VM name/).fill("web-2");
  await page.getByLabel("Debian 13").check();
  await page.getByRole("button", { name: "Continue to review" }).press("Enter");
  await page.getByRole("button", { name: "Back" }).press("Enter");
  await expect(page.getByLabel(/VM name/)).toHaveValue("web-2");
  await expect(page.getByLabel("Debian 13")).toBeChecked();
});

test("J5 completes keyboard-only along its catalogue path", async ({ page }) => {
  const { external } = await routeApi(page, { "/api/v1/operations/op-1": { body: operation({ id: "op-1", status: "retryable_failure" }) } });
  await open(page, "#/journey/J5/operations/op-1");
  await expect(page.getByText("Failed, will be retried")).toBeVisible();
  await tabTo(page, /Refresh status/);
  await page.keyboard.press("Enter");
  await clean(page, external);
});

test("J5 reload re-reads the operation and never re-submits", async ({ page }) => {
  let status: "running" | "succeeded" = "running";
  const { calls } = await routeApi(page, { "/api/v1/operations/op-9": () => ({ body: operation({ id: "op-9", status }) }) });
  await open(page, "#/journey/J5/operations/op-9");
  await expect(page.getByText("Running")).toBeVisible();
  status = "succeeded";
  await page.reload();
  await expect(page.getByText("Succeeded")).toBeVisible();
  expect(calls.every((c) => c.method === "GET")).toBe(true);
  expect(calls).toHaveLength(2);
});

test("J6 completes keyboard-only along its catalogue path", async ({ page }) => {
  for (const [category, status, retry] of [["rate_limited", 429, true], ["conflict", 409, false], ["prohibited", 422, false]] as const) {
    const { external } = await routeApi(page, { "/api/v1/vms/vm-x": { status, body: apiError(category) } });
    await open(page, "#/journey/J6");
    await expect(page.getByRole("alert")).toBeVisible();
    await expect(page.getByRole("button", { name: "Try again" })).toHaveCount(retry ? 1 : 0);
    await tabTo(page, /Back to the journey index/);
    await clean(page, external);
    await page.unrouteAll();
  }
});

test("J7 completes keyboard-only along its catalogue path", async ({ page }) => {
  const { external } = await routeApi(page, {
    "/api/v1/vms/vm-a": { body: VM_RUNNING },
    "/api/v1/operations": { status: 202, body: operation({ id: "op-7" }) },
  });
  await open(page, "#/journey/J7?vm=vm-a");
  await tabTo(page, /Delete VM/);
  await page.keyboard.press("Enter");
  await expect(page.getByRole("dialog")).toBeVisible();
  await expect(page.getByText(/This VM is running\. It will be forced off/)).toBeVisible();
  await clean(page, []);
  await tabTo(page, /Name to confirm/);
  await page.keyboard.type("web-1");
  await tabTo(page, /Delete permanently/);
  await page.keyboard.press("Enter");
  await expect(page.getByRole("status").filter({ hasText: "Deletion requested" })).toBeFocused();
  await clean(page, external);
});

test("J8 shows unreachable within the deadline and keeps last-known data", async ({ page }) => {
  let reachable = true;
  const { external, csp } = await routeApi(page, { "/api/v1/hosts/local": () => (reachable ? { body: HOST } : { hang: true }) });
  await open(page, "#/journey/J8");
  await expect(page.getByText("local-host")).toBeVisible();
  reachable = false;
  const started = Date.now();
  await page.getByRole("button", { name: "Refresh" }).press("Enter");
  await expect(page.getByText("Control plane unreachable")).toBeVisible({ timeout: 12000 });
  expect(Date.now() - started).toBeLessThan(11500);
  await expect(page.getByText(/does not stop your VMs, but their current state cannot be confirmed/)).toBeVisible();
  await expect(page.getByText("local-host")).toBeVisible();
  await expect(page.getByText(/may be out of date/)).toBeVisible();
  await tabTo(page, /Retry now/);
  await clean(page, external, csp);
});

test("mutation deadline shows outcome unknown without re-sending", async ({ page }) => {
  const { calls, external, csp } = await routeApi(page, { "/api/v1/vms/vm-a": { body: VM_RUNNING }, "/api/v1/operations": { hang: true } });
  await open(page, "#/journey/J9?vm=vm-a");
  await page.getByRole("button", { name: "Stop" }).press("Enter");
  await expect(page.getByText("The outcome is unknown")).toBeVisible({ timeout: 12000 });
  await page.waitForTimeout(1500);
  expect(calls.filter((c) => c.method === "POST")).toHaveLength(1);
  await clean(page, external, csp);
});

test("J9 completes keyboard-only along its catalogue path", async ({ page }) => {
  const { external, calls } = await routeApi(page, {
    "/api/v1/vms/vm-a": { body: VM_RUNNING },
    "/api/v1/operations": { status: 202, body: operation({ id: "op-9" }) },
  });
  await open(page, "#/journey/J9?vm=vm-a");
  await tabTo(page, /^Stop/);
  await page.keyboard.press("Enter");
  await expect(page.getByText(/Request accepted\. Operation op-9/)).toBeVisible();
  await expect(page.getByText("Observed power: running.")).toBeVisible(); // no optimistic state change
  await tabTo(page, /Force off/);
  await page.keyboard.press("Enter");
  await expect(page.getByRole("dialog")).toBeVisible();
  await tabTo(page, /Confirm force off/);
  await page.keyboard.press("Enter");
  await expect.poll(() => calls.filter((c) => c.method === "POST").map((c) => (c.body as { type: string }).type)).toEqual(["stop", "force_off"]);
  await clean(page, external);
});

test("J10 completes keyboard-only along its catalogue path", async ({ page }) => {
  const { external } = await routeApi(page, { "/api/v1/vms/vm-a": { body: VM_RUNNING } });
  await open(page, "#/journey/J10?vm=vm-a");
  await tabTo(page, /Open console/);
  await page.keyboard.press("Enter");
  await expect(page.getByText(/console is not available in M0/)).toBeVisible();
  await clean(page, external);
});
