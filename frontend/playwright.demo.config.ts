// The product tour video (not a gate): the real API process and the real web console over the SIMULATED host (the same stack as the browser tier),
// recorded by Chromium at 1280x720. Run with `make docker-demo-video`; the recording is written to demo-out/.
import { defineConfig, devices } from "@playwright/test";

export default defineConfig({
  testDir: "demo",
  testMatch: /.*\.demo\.ts/,
  fullyParallel: false,
  workers: 1,
  retries: 0,
  timeout: 300000,
  reporter: [["list"]],
  outputDir: process.env.DEMO_OUT ?? "demo-results",
  use: {
    ...devices["Desktop Chrome"],
    viewport: { width: 1280, height: 720 },
    video: { mode: "on", size: { width: 1280, height: 720 } },
    screenshot: "only-on-failure",
    bypassCSP: true, // only to draw the caption bar and the pointer over the page
    launchOptions: { chromiumSandbox: process.env.FE_NO_SANDBOX !== "1" },
    serviceWorkers: "block",
  },
  webServer: [
    { command: "sh e2e/product-create-server.sh storage", url: "http://127.0.0.1:4178/healthz", reuseExistingServer: false, timeout: 60000 },
  ],
});
