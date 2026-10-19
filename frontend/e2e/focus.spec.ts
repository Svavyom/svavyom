// Browser tier: focus rules (M0-E02-S06 AC03, r5 section 5).
import { expect, test } from "@playwright/test";
import { GALLERY, VM_RUNNING, operation, routeApi, vmList } from "./fixtures";

test("dialog contains focus and Escape releases it", async ({ page }) => {
  await routeApi(page, {});
  await page.goto(`${GALLERY}#/state/Dialog/open`);
  const dialog = page.getByRole("dialog");
  await expect(page.getByRole("heading", { name: "Rename VM" })).toBeFocused();
  for (let i = 0; i < 6; i++) {
    await page.keyboard.press("Tab");
    expect(await dialog.evaluate((d) => d.contains(document.activeElement))).toBe(true);
  }
  await page.keyboard.press("Escape");
  await expect(dialog).toHaveCount(0);
  // Reopen from the button: on close, focus returns to that opener.
  const opener = page.getByRole("button", { name: "Open dialog" });
  await opener.focus();
  await page.keyboard.press("Enter");
  await expect(page.getByRole("heading", { name: "Rename VM" })).toBeFocused();
  await page.keyboard.press("Escape");
  await expect(opener).toBeFocused();
});

test("view change moves focus to the new h1", async ({ page }) => {
  await routeApi(page, {});
  await page.goto(`${GALLERY}#/`);
  await page.getByRole("link", { name: "Button: default" }).press("Enter");
  await expect(page.getByRole("heading", { level: 1, name: "Button: default" })).toBeFocused();
  expect(await page.title()).toBe("Button: default - Svavyom");
});

test("focusing and typing never change the context", async ({ page }) => {
  await routeApi(page, {});
  await page.goto(`${GALLERY}#/state/TextField/empty`);
  const url = page.url();
  for (let i = 0; i < 8; i++) await page.keyboard.press("Tab");
  await page.getByLabel(/VM name/).fill("abc");
  await page.goto(`${GALLERY}#/state/Select/default`);
  await page.getByLabel("Image").selectOption("ubuntu-24.04");
  expect(page.url()).toContain("#/state/Select/default");
  expect(url).toContain("#/state/TextField/empty");
  await expect(page.locator("h1")).toHaveText("Select: default");
});

test("skip link appears on focus without hiding content", async ({ page }) => {
  await routeApi(page, {});
  await page.goto(`${GALLERY}#/state/SkipLink/default`);
  // The view-change rule focuses the h1 on load; start keyboard navigation from the top of the document.
  await page.evaluate(() => (document.activeElement as HTMLElement | null)?.blur());
  await page.keyboard.press("Tab");
  const skip = page.getByRole("link", { name: "Skip to main content" });
  await expect(skip).toBeFocused();
  await expect(skip).toBeInViewport();
  await page.keyboard.press("Enter");
  await expect(page.locator("main")).toBeFocused();
});

test("focused elements are not obscured", async ({ page }) => {
  await routeApi(page, { "/api/v1/vms": { body: vmList(Array.from({ length: 30 }, (_, i) => ({ ...VM_RUNNING, id: `vm-${i}`, name: `vm-${i}` }))) } });
  await page.setViewportSize({ width: 1024, height: 500 });
  await page.goto(`${GALLERY}#/journey/J3`);
  await expect(page.getByText("vm-29")).toBeAttached();
  for (let i = 0; i < 40; i++) {
    await page.keyboard.press("Tab");
    const hidden = await page.evaluate(() => {
      const el = document.activeElement as HTMLElement | null;
      if (!el || el === document.body) return false;
      const r = el.getBoundingClientRect();
      const x = Math.min(Math.max(r.left + r.width / 2, 0), innerWidth - 1);
      const y = Math.min(Math.max(r.top + r.height / 2, 0), innerHeight - 1);
      const top = document.elementFromPoint(x, y);
      return !(top && (el.contains(top) || top.contains(el)));
    });
    expect(hidden, `tab ${i}`).toBe(false);
  }
});

test("post destructive focus moves to the status message", async ({ page }) => {
  await routeApi(page, { "/api/v1/vms/vm-a": { body: VM_RUNNING }, "/api/v1/operations": { status: 202, body: operation({ id: "op-1" }) } });
  await page.goto(`${GALLERY}#/journey/J7?vm=vm-a`);
  await page.getByRole("button", { name: "Delete VM" }).click();
  await page.getByLabel(/Name to confirm/).fill("web-1");
  await page.getByRole("button", { name: "Delete permanently" }).click();
  await expect(page.getByRole("status").filter({ hasText: "Deletion requested" })).toBeFocused();
});
