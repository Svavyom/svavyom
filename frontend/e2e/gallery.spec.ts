// Browser tier over every manifest state in the test-only gallery bundle (M0-E02-S06 AC03, r5 sections 3, 5).
import { expect, test, type Page } from "@playwright/test";
import { GALLERY, PROD, routeApi } from "./fixtures";
import { axe } from "./axe";
import { STATES } from "./states";

async function openState(page: Page, p: string, s: string) {
  await page.goto(`${GALLERY}#/state/${p}/${s}`);
  await expect(page.locator("h1")).toHaveCount(1);
}

test("axe finds no violations on every manifest state", async ({ page }) => {
  const { external } = await routeApi(page, {});
  const failures: string[] = [];
  for (const [p, s] of STATES) {
    await openState(page, p, s);
    for (const scheme of ["light", "dark"] as const) { // both colour schemes (review N9)
      await page.emulateMedia({ colorScheme: scheme });
      const r = await axe(page);
      for (const v of r.violations) failures.push(`${p}/${s} ${scheme} violation ${v}`);
      for (const v of r.incomplete) failures.push(`${p}/${s} ${scheme} unresolved incomplete ${v}`);
    }
    await page.emulateMedia({ colorScheme: "light" });
  }
  expect(failures).toEqual([]);
  expect(external).toEqual([]);
});

function luminance(rgb: number[]) {
  const c = rgb.map((v) => { const s = v / 255; return s <= 0.03928 ? s / 12.92 : ((s + 0.055) / 1.055) ** 2.4; });
  return 0.2126 * c[0] + 0.7152 * c[1] + 0.0722 * c[2];
}

test("focus indicator is at least 2 px with 3 to 1 contrast on every focusable element", async ({ page }) => {
  await routeApi(page, {});
  const failures: string[] = [];
  for (const [p, s] of STATES) {
    await openState(page, p, s);
    await page.evaluate(() => (document.activeElement as HTMLElement | null)?.blur()); // include skip link and nav
    for (let i = 0; i < 30; i++) {
      await page.keyboard.press("Tab");
      const info = await page.evaluate(() => {
        const el = document.activeElement as HTMLElement | null;
        if (!el || el === document.body) return null;
        const cs = getComputedStyle(el);
        let bgEl: HTMLElement | null = el.parentElement;
        let bg = "rgba(0, 0, 0, 0)";
        while (bgEl && (bg === "rgba(0, 0, 0, 0)" || bg === "transparent")) { bg = getComputedStyle(bgEl).backgroundColor; bgEl = bgEl.parentElement; }
        if (bg === "rgba(0, 0, 0, 0)") bg = getComputedStyle(document.body).backgroundColor;
        return { tag: el.outerHTML.slice(0, 60), style: cs.outlineStyle, width: parseFloat(cs.outlineWidth), color: cs.outlineColor, bg, key: el.outerHTML };
      });
      if (!info) break;
      const parse = (c: string) => (c.match(/[\d.]+/g) ?? []).slice(0, 3).map(Number);
      const [a, b] = [luminance(parse(info.color)), luminance(parse(info.bg))];
      const ratio = (Math.max(a, b) + 0.05) / (Math.min(a, b) + 0.05);
      if (info.style === "none" || info.width < 2 || ratio < 3) failures.push(`${p}/${s}: ${info.tag} outline ${info.style} ${info.width}px ratio ${ratio.toFixed(2)}`);
    }
  }
  expect(failures).toEqual([]);
});

test("no drag-only interactions exist", async ({ page }) => {
  await routeApi(page, {});
  for (const [p, s] of STATES) {
    await openState(page, p, s);
    expect(await page.locator("[draggable=true]").count(), `${p}/${s}`).toBe(0);
  }
});

test("production shell has no axe violations", async ({ page }) => {
  const { external, calls } = await routeApi(page, {}); // the mock refuses every API call: the unreachable state
  await page.goto(PROD);
  await expect(page.getByText("Svavyom could not be reached.")).toBeVisible();
  const r = await axe(page);
  expect(r.violations).toEqual([]);
  expect(r.incomplete).toEqual([]);
  expect(await page.getAttribute("html", "lang")).toBe("en");
  expect(external).toEqual([]);
  expect(calls.map((c) => `${c.method} ${c.path}`)).toEqual(["GET /api/v1/auth/session"]); // nothing else before sign-in
});
