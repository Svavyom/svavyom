// Browser tier runs in the no-network dev-offline service: prove DNS and outbound TCP fail (r5 section 10, R2-M1),
// and that the production bundle carries the CSP and loads nothing from other origins.
import { expect, test } from "@playwright/test";
import dns from "node:dns/promises";
import net from "node:net";
import { PROD, routeApi } from "./fixtures";

test("DNS resolution and outbound TCP fail inside dev-offline", async () => {
  await expect(dns.lookup("registry.npmjs.org")).rejects.toThrow();
  const connected = await new Promise<boolean>((resolve) => {
    const s = net.connect({ host: "1.1.1.1", port: 443, timeout: 3000 });
    s.on("connect", () => { s.destroy(); resolve(true); });
    s.on("error", () => resolve(false));
    s.on("timeout", () => { s.destroy(); resolve(false); });
  });
  expect(connected).toBe(false);
});

test("production bundle carries the CSP and requests only first-party files", async ({ page }) => {
  const { external } = await routeApi(page, {});
  const origins = new Set<string>();
  page.on("request", (r) => origins.add(new URL(r.url()).origin));
  await page.goto(PROD);
  const csp = await page.locator('meta[http-equiv="Content-Security-Policy"]').getAttribute("content");
  expect(csp).toContain("default-src 'self'");
  expect([...origins]).toEqual(["http://127.0.0.1:4173"]);
  expect(external).toEqual([]);
});
