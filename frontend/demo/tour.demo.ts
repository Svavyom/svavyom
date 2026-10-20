// A silent, captioned tour of the Svavyom control panel (English captions burned into the picture). It drives the real web console against the real
// API process over the SIMULATED host used by the browser tier, so it shows the product's screens and flows, not a real server.
import { expect, test, type Locator, type Page } from "@playwright/test";

const BASE = "http://127.0.0.1:4178";
const PASSWORD = "e2e-only-passphrase-not-a-real-credential";
const KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIyCA34mAg+8tDqqKgTSWK7GI2RLy/Kpy88xCej+HqvJ you@your-laptop";
const VM = "web-demo";

// The caption bar and a visible pointer, re-created after every full page load.
const OVERLAY = `
(() => {
  const mount = () => {
    if (document.getElementById("demo-cap")) return;
    const st = document.createElement("style");
    st.textContent = "#demo-cap{position:fixed;left:240px;right:0;bottom:0;z-index:2147483647;padding:14px 28px;background:rgba(10,18,32,.92);color:#fff;font:600 22px/1.35 system-ui,sans-serif;text-align:center;letter-spacing:.2px;min-height:34px}" +
      "#demo-cap small{display:block;font-weight:400;font-size:16px;opacity:.85;margin-top:2px}" +
      "#demo-ptr{position:fixed;z-index:2147483646;width:22px;height:22px;border-radius:50%;border:3px solid #ffb703;background:rgba(255,183,3,.35);pointer-events:none;transform:translate(-50%,-50%);left:-50px;top:-50px;transition:left .02s,top .02s}";
    document.head.appendChild(st);
    const c = document.createElement("div"); c.id = "demo-cap"; c.setAttribute("aria-hidden", "true");
    c.textContent = sessionStorage.getItem("demo-cap") || ""; document.body.appendChild(c);
    const p = document.createElement("div"); p.id = "demo-ptr"; p.setAttribute("aria-hidden", "true"); document.body.appendChild(p);
    const at = sessionStorage.getItem("demo-ptr"); if (at) { const [x, y] = at.split(","); p.style.left = x + "px"; p.style.top = y + "px"; }
    addEventListener("mousemove", (e) => { p.style.left = e.clientX + "px"; p.style.top = e.clientY + "px"; sessionStorage.setItem("demo-ptr", e.clientX + "," + e.clientY); }, true);
  };
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", mount); else mount();
})();`;

async function cap(page: Page, text: string, sub = "") {
  await page.evaluate(([t, s]) => {
    sessionStorage.setItem("demo-cap", t);
    const c = document.getElementById("demo-cap");
    if (c) { c.textContent = t; if (s) { const m = document.createElement("small"); m.textContent = s; c.appendChild(m); } }
    if (s) sessionStorage.setItem("demo-cap", t);
  }, [text, sub] as [string, string]);
}

const pause = (page: Page, ms: number) => page.waitForTimeout(ms);

async function move(page: Page, target: Locator) {
  await target.scrollIntoViewIfNeeded();
  const b = await target.boundingBox();
  if (!b) return;
  await page.mouse.move(b.x + b.width / 2, b.y + b.height / 2, { steps: 25 });
  await pause(page, 250);
}

async function click(page: Page, target: Locator) {
  await move(page, target);
  await target.click();
}

async function type(page: Page, target: Locator, text: string) {
  await move(page, target);
  await target.click();
  await target.pressSequentially(text, { delay: 55 });
}

test("a silent tour of the Svavyom control panel", async ({ page }) => {
  await page.addInitScript(OVERLAY);

  // 1. Sign in
  await page.goto(BASE);
  await page.mouse.move(640, 360);
  await cap(page, "Svavyom: a free control panel for KVM virtualization servers", "This tour runs on a simulated host, so it shows the real screens without a real server");
  await pause(page, 5500);
  await cap(page, "Sign in with your local account");
  await type(page, page.getByLabel(/Username/), "admin");
  await type(page, page.getByLabel(/Password/), PASSWORD);
  await click(page, page.getByRole("button", { name: "Sign in" }));
  await expect(page.getByRole("heading", { level: 1, name: "Dashboard" })).toBeVisible();

  // 2. Dashboard
  await cap(page, "The dashboard: host health, capacity and usage at a glance");
  await pause(page, 6000);
  await page.mouse.wheel(0, 400);
  await cap(page, "Open alerts and the last nightly boot check show up here too");
  await pause(page, 4000);
  await page.mouse.wheel(0, -400);

  // 3. Create a VM
  await click(page, page.getByRole("navigation", { name: "Primary" }).getByRole("link", { name: "Virtual machines", exact: true }));
  await cap(page, "Virtual machines: every VM on this server, with state, address and usage");
  await pause(page, 4500);
  await page.goto(`${BASE}/#/create`);
  await cap(page, "Create a VM: choose a name and a qualified image");
  await pause(page, 1500);
  await type(page, page.getByLabel(/^Name/), VM);
  await pause(page, 1500);
  await cap(page, "Pick the size: virtual CPUs, memory and disk");
  await pause(page, 3500);
  await click(page, page.getByRole("button", { name: "Continue" }));
  await cap(page, "Paste your public SSH key: the only way to log in, no passwords");
  await type(page, page.getByLabel("SSH public key"), KEY);
  await pause(page, 2500);
  await click(page, page.getByRole("button", { name: "Review" }));
  await cap(page, "Review shows the key's fingerprint and exactly what will be created");
  await pause(page, 5000);
  await click(page, page.getByRole("button", { name: "Create VM" }));
  await expect(page.getByText("VM created (stopped)")).toBeVisible({ timeout: 30000 });
  await cap(page, "The VM is created, stopped, and every step is recorded");
  await pause(page, 3500);

  // 4. Start it and open the consoles
  await page.goto(`${BASE}/#/vms/${VM}`);
  await cap(page, "Each VM has its own actions: start, stop, reboot, snapshot, back up, resize");
  await pause(page, 4000);
  await click(page, page.getByRole("button", { name: `Start ${VM}` }));
  await expect(page.getByText("VM started")).toBeVisible({ timeout: 30000 });
  await cap(page, "Started: it boots in seconds");
  await pause(page, 3500);
  await click(page, page.getByRole("link", { name: `Console ${VM}`, exact: true }));
  await expect(page.getByLabel("Serial boot output text")).toContainText("simulated guest booted", { timeout: 20000 });
  await cap(page, "The console shows boot output, even before the network is up");
  await pause(page, 5500);
  await click(page, page.getByRole("checkbox", { name: /I understand/ }));
  await click(page, page.getByRole("button", { name: "Open serial console" }));
  await expect(page.getByLabel("Serial console output")).toContainText(`${VM} login:`, { timeout: 20000 });
  await cap(page, "An interactive serial console in the browser, one viewer at a time");
  await type(page, page.getByLabel(/Send to the console/), "whoami");
  await page.getByLabel(/Send to the console/).press("Enter");
  await pause(page, 4500);
  await page.goto(`${BASE}/#/vms/${VM}`);
  await click(page, page.getByRole("link", { name: `Graphical console ${VM}` }));
  await cap(page, "A graphical console for installers and desktops (VNC through the server, no open ports on the VM)");
  await pause(page, 3000);
  await click(page, page.getByRole("checkbox", { name: /I understand/ }));
  await click(page, page.getByRole("button", { name: "Open graphical console" }));
  await expect(page.getByText(new RegExp(`Connected to sim:${VM}`))).toBeVisible({ timeout: 30000 });
  await pause(page, 5500);

  // 5. Snapshot and back up
  await page.goto(`${BASE}/#/vms/${VM}`);
  await cap(page, "Protect your work: take a snapshot");
  await pause(page, 1500);
  await click(page, page.getByRole("button", { name: `Stop ${VM}` }));
  await expect(page.getByText("VM stopped")).toBeVisible({ timeout: 30000 });
  await click(page, page.getByRole("button", { name: `Snapshot ${VM}` }));
  await expect(page.getByText("Snapshot taken")).toBeVisible({ timeout: 30000 });
  await pause(page, 3000);

  // 6. Storage, networks, alerts, activity
  await click(page, page.getByRole("navigation", { name: "Primary" }).getByRole("link", { name: "Storage and recovery", exact: true }));
  await cap(page, "Storage and recovery: images, volumes, snapshots and backups, restorable as a new VM");
  await pause(page, 6500);
  await click(page, page.getByRole("navigation", { name: "Primary" }).getByRole("link", { name: "Networks", exact: true }));
  await cap(page, "Networks: private NAT networks you create, and the host's own networks, read-only");
  await pause(page, 6000);
  await page.mouse.wheel(0, 600);
  await cap(page, "Optional: put the server on a bridge so VMs join your real network, with an automatic way back");
  await pause(page, 6000);
  await page.mouse.wheel(0, -600);
  await click(page, page.getByRole("navigation", { name: "Primary" }).getByRole("link", { name: "Alerts", exact: true }));
  await cap(page, "Alerts: low disk space, failed backups, a VM that stopped unexpectedly");
  await pause(page, 5000);
  await click(page, page.getByRole("navigation", { name: "Primary" }).getByRole("link", { name: "Activity", exact: true }));
  await cap(page, "Activity: every action, who did it, and how it ended");
  await pause(page, 6000);

  // 7. Close
  await cap(page, "Svavyom is free software (AGPL-3.0). One server or many, no limits.", "Development Preview: github.com/Svavyom/svavyom");
  await pause(page, 7000);
});
