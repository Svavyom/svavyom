// Browser tier: reflow, text resize, text spacing, target size, orientation (M0-E02-S06 AC03, r5 section 8).
import { expect, test, type Page } from "@playwright/test";
import { GALLERY, HOST, PROD, VM_RUNNING, routeApi, vmList } from "./fixtures";
import { STATES } from "./states";

const PAGES = [...STATES.map(([p, s]) => `#/state/${p}/${s}`), "#/journey/J1", "#/journey/J3", "#/journey/J4", "#/journey/J7?vm=vm-a"];
const API = { "/api/v1/hosts/local": { body: HOST }, "/api/v1/vms": { body: vmList() },
  "/api/v1/vms/vm-a": { body: VM_RUNNING } };

async function settled(page: Page) {
  await expect(page.locator("h1")).toHaveCount(1);
  await expect(page.getByText(/^Loading /)).toHaveCount(0); // measure loaded states only (review N2)
}

async function overflow(page: Page) {
  await settled(page);
  return page.evaluate(() => {
    const doc = document.documentElement.scrollWidth > window.innerWidth + 1;
    const clipped = Array.from(document.querySelectorAll<HTMLElement>("button, label, h1, h2, p, a, legend, th, td"))
      .filter((el) => !el.closest(".ds-table-region") && (el.scrollWidth > el.clientWidth + 1) && getComputedStyle(el).overflow !== "visible")
      .map((el) => el.outerHTML.slice(0, 60));
    return { doc, clipped };
  });
}

for (const width of [320, 768, 1024, 1440]) {
  test(`no two-dimensional scrolling at ${width} px`, async ({ page }) => {
    await routeApi(page, API);
    await page.setViewportSize({ width, height: 900 });
    const failures: string[] = [];
    for (const h of PAGES) {
      await page.goto(`${GALLERY}${h}`);
      await expect(page.locator("h1")).toHaveCount(1);
      const o = await overflow(page);
      if (o.doc || o.clipped.length) failures.push(`${h}: ${JSON.stringify(o)}`);
    }
    await page.goto(PROD);
    if ((await overflow(page)).doc) failures.push("production shell");
    expect(failures).toEqual([]);
  });
}

test("reflows without horizontal scrolling at 320 px", async ({ page }) => {
  await routeApi(page, API);
  await page.setViewportSize({ width: 320, height: 640 });
  await page.goto(`${GALLERY}#/state/DataTable/wide`);
  expect((await overflow(page)).doc).toBe(false);
  const region = page.getByRole("region", { name: "Hosts" });
  expect(await region.evaluate((r) => r.scrollWidth > r.clientWidth)).toBe(true); // the table scrolls in its own region
  await region.focus();
  await expect(region).toBeFocused();
});

test("200 percent text resize keeps content usable", async ({ browser }) => {
  const ctx = await browser.newContext({ bypassCSP: true, viewport: { width: 1280, height: 800 } });
  const page = await ctx.newPage();
  await routeApi(page, API);
  const failures: string[] = [];
  for (const h of PAGES) {
    await page.goto(`${GALLERY}${h}`);
    await page.addStyleTag({ content: "html { font-size: 200% !important; }" });
    const o = await overflow(page);
    if (o.doc || o.clipped.length) failures.push(`${h}: ${JSON.stringify(o)}`);
  }
  await ctx.close();
  expect(failures).toEqual([]);
});

test("text spacing overrides cause no clipping", async ({ browser }) => {
  const ctx = await browser.newContext({ bypassCSP: true, viewport: { width: 1024, height: 800 } });
  const page = await ctx.newPage();
  await routeApi(page, API);
  const failures: string[] = [];
  for (const h of PAGES) {
    await page.goto(`${GALLERY}${h}`);
    await page.addStyleTag({ content: "* { line-height: 1.5 !important; letter-spacing: 0.12em !important; word-spacing: 0.16em !important; } p { margin-bottom: 2em !important; }" });
    const o = await overflow(page);
    if (o.doc || o.clipped.length) failures.push(`${h}: ${JSON.stringify(o)}`);
  }
  await ctx.close();
  expect(failures).toEqual([]);
});

test("pointer targets are at least 24 by 24 px", async ({ page }) => {
  await routeApi(page, API);
  const failures: string[] = [];
  for (const h of PAGES) {
    await page.goto(`${GALLERY}${h}`);
    const small = await page.evaluate(() => Array.from(document.querySelectorAll<HTMLElement>("button, input, select, textarea, [role=tab]"))
      .filter((el) => { const r = el.getBoundingClientRect(); return r.width > 0 && (r.width < 24 || r.height < 24); })
      .map((el) => el.outerHTML.slice(0, 60)));
    if (small.length) failures.push(`${h}: ${small.join(" | ")}`);
  }
  expect(failures).toEqual([]);
});

test("content works in portrait and landscape", async ({ page }) => {
  await routeApi(page, API);
  for (const vp of [{ width: 768, height: 1024 }, { width: 1024, height: 768 }]) {
    await page.setViewportSize(vp);
    await page.goto(`${GALLERY}#/journey/J3`);
    await expect(page.getByText("web-1")).toBeVisible();
    expect((await overflow(page)).doc).toBe(false);
  }
});
