// API fixtures for the browser tier: typed values from src/api/fixtures.ts, which the unit tier validates against
// contracts/openapi.yaml (M0-E01-S04, DR-012). Mock-API journeys are not evidence of real API behaviour.
import type { Page, Route } from "@playwright/test";

export { HOST, VM_RUNNING, apiError, operation, vmList } from "../src/api/fixtures";
export const PROD = "http://127.0.0.1:4173";
export const GALLERY = "http://127.0.0.1:4174/gallery.html";


type Reply = { status?: number; body?: unknown; abort?: boolean; hang?: boolean };
/** A reply, a sequence of replies (consumed in order; the last one repeats), or a function. */
export type Api = Record<string, Reply | Reply[] | ((method: string, body: unknown) => Reply)>;
const FIRST_PARTY = new Set(["http://127.0.0.1:4173", "http://127.0.0.1:4174"]);

/** Route every request: first-party static files pass, /api and /healthz come from `api`, anything else is
 *  aborted and recorded (r5 section 9: no request outside the app origin). */
export async function routeApi(page: Page, api: Api) {
  const external: string[] = [];
  const csp: string[] = [];
  const calls: Array<{ path: string; method: string; body: unknown }> = [];
  const seen: Record<string, number> = {};
  // Requests the CSP blocks never reach page.route: record CSP violations too (review N7).
  page.on("console", (m) => { if (m.type() === "error" && /Content Security Policy/i.test(m.text())) csp.push(m.text()); });
  await page.route("**/*", async (route: Route) => {
    const req = route.request();
    const url = new URL(req.url());
    if (!FIRST_PARTY.has(url.origin)) {
      external.push(url.href);
      return route.abort("blockedbyclient");
    }
    if (!url.pathname.startsWith("/api/") && url.pathname !== "/healthz") return route.fallback();
    const body = req.postData() ? JSON.parse(req.postData()!) : null;
    calls.push({ path: url.pathname + url.search, method: req.method(), body });
    const key = api[url.pathname + url.search] !== undefined ? url.pathname + url.search : url.pathname;
    const entry = api[key] ?? api["*"];
    let reply: Reply | undefined;
    if (typeof entry === "function") reply = entry(req.method(), body);
    else if (Array.isArray(entry)) { const n = seen[key] ?? 0; seen[key] = n + 1; reply = entry[Math.min(n, entry.length - 1)]; }
    else reply = entry;
    if (!reply || reply.abort) return route.abort("connectionrefused");
    if (reply.hang) return; // never answered: exercises REQUEST_DEADLINE_MS
    return route.fulfill({ status: reply.status ?? 200, contentType: "application/json", body: JSON.stringify(reply.body ?? {}) });
  });
  return { external, calls, csp };
}
