// Decide whether Chromium's sandbox can start under the unchanged dev-offline hardening (DR-010 D4 = A).
import { chromium } from "@playwright/test";
try {
  const b = await chromium.launch({ chromiumSandbox: true });
  await b.close();
  console.log("sandbox=on");
} catch (e) {
  console.log("sandbox=off (ACCEPTED RISK, DR-010 D4 = A: --no-sandbox; first-party loopback content only, no network)");
  process.exitCode = 3;
}
