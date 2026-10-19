// Browser tier, NETWORKS (M3): Chromium -> real API -> operation worker -> real mutation supervisor -> real (simulated-host) helper -> file-backed
// simulated host with managed networks, reservations and compute changes. No route mocking.
// SIMULATION ONLY: this proves the product flow and the closed protocols, not libvirt, a bridge or a DHCP server.
import { expect, test, type Page } from "@playwright/test";
import { axe } from "./axe";

const BASE = "http://127.0.0.1:4178";
const PASSWORD = "e2e-only-passphrase-not-a-real-credential";
const KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIyCA34mAg+8tDqqKgTSWK7GI2RLy/Kpy88xCej+HqvJ e2e@test";

test.describe.configure({ mode: "serial" });

async function signIn(page: Page) {
  await page.goto(BASE);
  await page.getByLabel(/Username/).fill("admin");
  await page.getByLabel(/Password/).fill(PASSWORD);
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(page.getByRole("heading", { level: 1, name: "Dashboard" })).toBeVisible();
}

test("create a managed network, attach a VM, reserve an address, change its size, then tear it all down", async ({ page }) => {
  await signIn(page);
  await page.goto(`${BASE}/#/networks`);
  const table = page.getByRole("region", { name: "Networks on this host" });
  // the pre-existing network is listed, foreign and without actions
  const def = table.getByRole("row", { name: /svavyom-nat/ });
  await expect(def).toContainText("Foreign (read-only)");
  await expect(def.getByRole("button")).toHaveCount(0);
  expect((await axe(page)).violations).toEqual([]);
  // the form refuses a public range locally; an overlapping range is refused by the server
  await page.getByLabel(/^Name/).fill("lab-net");
  await page.getByLabel(/^Subnet/).fill("8.8.8.0/24");
  await page.getByLabel(/^DHCP range start/).fill("8.8.8.10");
  await page.getByLabel(/^DHCP range end/).fill("8.8.8.20");
  await page.getByRole("button", { name: "Create network" }).click();
  await expect(page.getByText(/private \(RFC 1918\)/)).toBeVisible();
  await page.getByLabel(/^Subnet/).fill("192.168.122.0/24");
  await page.getByLabel(/^DHCP range start/).fill("192.168.122.20");
  await page.getByLabel(/^DHCP range end/).fill("192.168.122.30");
  await page.getByRole("button", { name: "Create network" }).click();
  await expect(page.getByText(/no longer in a state this action applies to|conflicts/i)).toBeVisible({ timeout: 30000 });
  await expect(table.getByRole("row", { name: /lab-net/ })).toHaveCount(0);
  // a good one
  await page.getByLabel(/^Subnet/).fill("10.77.0.0/24");
  await page.getByLabel(/^DHCP range start/).fill("10.77.0.10");
  await page.getByLabel(/^DHCP range end/).fill("10.77.0.200");
  await page.getByRole("button", { name: "Create network" }).click();
  await expect(page.getByText("Network created and started")).toBeVisible({ timeout: 30000 });
  const lab = () => table.getByRole("row", { name: /lab-net/ });
  await expect(lab()).toContainText("Svavyom-managed");
  await expect(lab()).toContainText("10.77.0.0/24, gateway 10.77.0.1");
  // a VM on it, with a size profile
  await page.goto(`${BASE}/#/create`);
  await page.getByLabel(/^Name/).fill("net-1");
  await page.getByRole("group", { name: "Size profile" }).getByRole("button").first().click();
  await page.getByRole("button", { name: "Continue" }).click();
  await page.getByLabel("Network").selectOption("lab-net");
  await page.getByLabel("SSH public key").fill(KEY);
  await page.getByRole("button", { name: "Review" }).click();
  await expect(page.getByText("lab-net")).toBeVisible();
  await page.getByRole("button", { name: "Create VM" }).click();
  await expect(page.getByText("VM created (stopped)")).toBeVisible({ timeout: 30000 });
  await page.goto(`${BASE}/#/vms/net-1`);
  const row = () => page.locator("main");
  await expect(row()).toContainText("lab-net");
  // reserve an address while stopped, then start: the guest takes the reserved address
  await page.getByRole("button", { name: "Reserve address for net-1" }).click();
  await expect(page.getByRole("dialog")).toContainText(/nothing is configured inside the guest/i);
  await page.getByLabel(/^IPv4 address/).fill("10.77.0.1");
  await page.getByRole("button", { name: "Reserve the address" }).click();
  await expect(page.getByText(/not a usable|no longer in a state|not accepted|Some details/i)).toBeVisible({ timeout: 30000 });
  await page.getByRole("button", { name: "Reserve address for net-1" }).click();
  await page.getByLabel(/^IPv4 address/).fill("10.77.0.50");
  await page.getByRole("button", { name: "Reserve the address" }).click();
  await expect(page.getByText(/Address reserved/)).toBeVisible({ timeout: 30000 });
  await page.getByRole("button", { name: "Refresh" }).click();
  await expect(row()).toContainText("reserved 10.77.0.50");
  await page.getByRole("button", { name: "Change size of net-1" }).click();
  await page.getByLabel("vCPUs").selectOption({ index: 1 });
  await page.getByRole("button", { name: "Change size", exact: true }).click();
  await expect(page.getByText(/Size changed/)).toBeVisible({ timeout: 30000 });
  await page.getByRole("button", { name: "Start net-1" }).click();
  await expect(page.getByText("VM started")).toBeVisible({ timeout: 30000 });
  await page.getByRole("button", { name: "Refresh" }).click();
  await expect(row()).toContainText("10.77.0.50");
  await expect(page.getByRole("button", { name: "Change size of net-1" })).toHaveCount(0);
  expect((await axe(page)).violations).toEqual([]);
  // the network cannot be stopped or deleted while the VM exists
  await page.goto(`${BASE}/#/networks`);
  await expect(page.getByRole("button", { name: "Stop lab-net" })).toHaveCount(0);
  await expect(page.getByRole("button", { name: "Delete lab-net" })).toHaveCount(0);
  await expect(lab()).toContainText("10.77.0.50");
  // tear down: stop and delete the VM, release is not needed to delete, then delete the network
  await page.goto(`${BASE}/#/vms/net-1`);
  await page.getByRole("button", { name: "Stop net-1" }).click();
  await expect(page.getByText("VM stopped")).toBeVisible({ timeout: 30000 });
  await page.getByRole("button", { name: "Delete net-1" }).click();
  await page.getByRole("button", { name: "Delete permanently" }).click();
  await expect(page.getByText("VM deleted")).toBeVisible({ timeout: 30000 });
  await page.goto(`${BASE}/#/networks`);
  await page.getByRole("button", { name: "Stop lab-net" }).click();
  await page.getByRole("button", { name: "Stop network" }).click();
  await expect(page.getByText("Network stopped")).toBeVisible({ timeout: 30000 });
  await page.getByRole("button", { name: "Delete lab-net" }).click();
  await expect(page.getByRole("dialog")).toContainText("removes this Svavyom-managed network");
  await page.getByRole("button", { name: "Delete network permanently" }).click();
  await expect(page.getByText("Network deleted")).toBeVisible({ timeout: 30000 });
  await expect(lab()).toHaveCount(0);
});
