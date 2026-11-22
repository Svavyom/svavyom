// Browser tier (M0-E02-S06 AC03; DR-010 D4 = A). Runs only in the no-network `dev-offline` service via `make fe-browser`.
// Production bundle (dist/) on :4173, test-only gallery bundle (dist-gallery/) on :4174, both on 127.0.0.1.
// Chromium's sandbox is used when it can start; otherwise FE_NO_SANDBOX=1 is set by e2e/sandbox-probe.mjs and the
// accepted DR-010 D4 risk applies (only first-party loopback content; every other origin aborted; no network).
import { defineConfig, devices } from "@playwright/test";

export default defineConfig({
  testDir: "e2e",
  testMatch: /.*\.spec\.ts/,
  fullyParallel: false,
  workers: 1,
  // N6 of the 2026-11-14 findings plan: three CI runs in a row had a different scenario time out once under load (waiting for text that did not appear in time; the cause under load is not yet known),
  // each passing on a re-run and 80 of 80 times locally. A scenario gets two more attempts; the list reporter names every one that needed them ("flaky"), so the
  // flakes stay visible and countable, and a real regression fails all three attempts. tests/unit_fe_browser_flake.py pins this number.
  retries: 2,
  forbidOnly: true,
  timeout: 60000,
  reporter: [["list"]],
  use: {
    ...devices["Desktop Chrome"],
    viewport: { width: 1280, height: 800 },
    launchOptions: { chromiumSandbox: process.env.FE_NO_SANDBOX !== "1" },
    serviceWorkers: "block",
  },
  webServer: [
    // The real API process serving the production bundle on a throw-away SQLite database (e2e/product-server.sh).
    { command: "sh e2e/product-server.sh", url: "http://127.0.0.1:4175/healthz", reuseExistingServer: false, timeout: 60000 },
    // The create journey: Development Preview switch open (:4176) and closed, the default (:4177). Host = file-backed simulation.
    { command: "sh e2e/product-create-server.sh open", url: "http://127.0.0.1:4176/healthz", reuseExistingServer: false, timeout: 60000 },
    { command: "sh e2e/product-create-server.sh closed", url: "http://127.0.0.1:4177/healthz", reuseExistingServer: false, timeout: 60000 },
    // The storage and recovery journeys (M2): open, plus a real-host-qualified image and a backup store (:4178).
    { command: "sh e2e/product-create-server.sh storage", url: "http://127.0.0.1:4178/healthz", reuseExistingServer: false, timeout: 60000 },
    { command: "npx vite preview --port 4173", url: "http://127.0.0.1:4173/", reuseExistingServer: false, timeout: 60000 },
    { command: "npx vite preview --mode gallery --port 4174", url: "http://127.0.0.1:4174/gallery.html", reuseExistingServer: false, timeout: 60000 },
  ],
});
