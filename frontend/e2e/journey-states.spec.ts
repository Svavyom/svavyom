// Browser tier: every catalogue state of every journey (M0-E02-S06 AC03 "axe-core reports zero violations and
// no unresolved incomplete in every journey state"; review M1). Scenarios: e2e/journey-states.json, whose
// coverage of the pinned catalogue is checked by tests/unit_ux_catalogue.py.
import fs from "node:fs";
import { expect, test } from "@playwright/test";
import { GALLERY, routeApi } from "./fixtures";
import { axe } from "./axe";

type Action = { press?: string; fill?: [string, string]; check?: string };
type Scenario = { hash: string; api: Record<string, unknown>; actions?: Action[]; expect: string };
const table = JSON.parse(fs.readFileSync(new URL("./journey-states.json", import.meta.url), "utf8")) as { journeys: Record<string, Record<string, Scenario>> };

let loads = 0;
for (const [journey, states] of Object.entries(table.journeys)) {
  for (const [state, sc] of Object.entries(states)) {
    test(`${journey} ${state}: axe-clean, first-party only`, async ({ page }) => {
      const { external, csp } = await routeApi(page, sc.api as never);
      loads += 1;
      await page.goto(`${GALLERY.replace("gallery.html", `gallery.html?s=${loads}`)}${sc.hash}`);
      for (const a of sc.actions ?? []) {
        if (a.fill) await page.getByLabel(new RegExp(`^${a.fill[0]}`)).fill(a.fill[1]);
        if (a.check) await page.getByLabel(a.check).check();
        if (a.press) await page.getByRole("button", { name: new RegExp(`^${a.press}`) }).first().press("Enter");
      }
      await expect(page.getByText(sc.expect, { exact: false }).first()).toBeVisible({ timeout: 15000 });
      const r = await axe(page);
      expect(r.violations).toEqual([]);
      expect(r.incomplete).toEqual([]);
      expect(external).toEqual([]);
      expect(csp).toEqual([]);
    });
  }
}
