// Browser tier, STORAGE AND RECOVERY (M2): Chromium -> real API -> operation worker -> real mutation supervisor -> real (simulated-host)
// helper -> file-backed simulated host with real qcow2-header overlays and a real backup store directory. No route mocking.
// SIMULATION ONLY: this proves the product flow and the closed protocols, not libvirt, KVM or a real guest.
import { execFileSync } from "node:child_process";
import { writeFileSync } from "node:fs";
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

async function createVm(page: Page, name: string) {
  await page.goto(`${BASE}/#/create`);
  await page.getByLabel(/^Name/).fill(name);
  await page.getByRole("button", { name: "Continue" }).click();
  await page.getByLabel("SSH public key").fill(KEY);
  await page.getByRole("button", { name: "Review" }).click();
  await page.getByRole("button", { name: "Create VM" }).click();
  await expect(page.getByText("VM created (stopped)")).toBeVisible({ timeout: 30000 });
  await page.goto(`${BASE}/#/vms/${name}`);
}

async function act(page: Page, button: string, done: string | RegExp) {
  await page.getByRole("button", { name: button }).click();
  await expect(page.getByText(done)).toBeVisible({ timeout: 30000 });
}

test("resize, snapshot, backup and delete the snapshot from the VM list and the Storage view", async ({ page }) => {
  await signIn(page);
  await createVm(page, "stor-1");
  const row = () => page.locator("main");
  await expect(row()).toContainText("Stopped");
  const before = Number(/(\d+) GiB/.exec(await row().innerText())![1]);
  for (const w of ["Resize", "Snapshot", "Back up", "Reinstall"]) await expect(page.getByRole("button", { name: `${w} stor-1` })).toBeVisible();
  // a disk can only grow: a smaller number is refused in the dialog and nothing is sent
  let posts = 0;
  page.on("request", (r) => { if (r.method() === "POST" && r.url().endsWith("/api/v1/operations")) posts++; });
  await page.getByRole("button", { name: "Resize stor-1" }).click();
  await expect(page.getByRole("dialog")).toContainText("can only grow");
  await page.getByLabel(/New size in GiB/).fill(String(before));
  await page.getByRole("button", { name: "Grow the disk" }).click();
  await expect(page.getByRole("dialog")).toContainText("larger than the current");
  expect(posts).toBe(0);
  await page.getByLabel(/New size in GiB/).fill(String(before + 10));
  await page.getByRole("button", { name: "Grow the disk" }).click();
  await expect(page.getByText(/Root disk grown/)).toBeVisible({ timeout: 30000 });
  await page.getByRole("button", { name: "Refresh" }).click();
  await expect(row()).toContainText(`${before + 10} GiB`);
  expect((await axe(page)).violations).toEqual([]);
  await act(page, "Snapshot stor-1", "Snapshot taken");
  // with a snapshot the VM no longer offers resize, reinstall or backup
  await page.getByRole("button", { name: "Refresh" }).click();
  await expect(page.getByRole("button", { name: "Snapshot stor-1" })).toBeVisible();
  await expect(page.getByRole("button", { name: "Resize stor-1" })).toHaveCount(0);
  await expect(page.getByRole("button", { name: "Back up stor-1" })).toHaveCount(0);
  await page.getByRole("link", { name: "Storage and recovery" }).first().click();
  await expect(page.getByRole("heading", { level: 1, name: "Storage and recovery" })).toBeVisible();
  await expect(page.getByRole("region", { name: "Snapshots" })).toContainText("stor-1");
  await expect(page.getByRole("region", { name: "Image catalog" })).toContainText("real-host qualified");
  expect((await axe(page)).violations).toEqual([]);
  // delete the snapshot after a confirmation
  await page.getByRole("button", { name: /^Delete snap-/ }).click();
  await expect(page.getByRole("dialog")).toContainText("removes that saved moment");
  await page.getByRole("button", { name: "Delete snapshot" }).click();
  await expect(page.getByText("Snapshot deleted")).toBeVisible({ timeout: 30000 });
  await expect(page.getByRole("region", { name: "Snapshots" })).toHaveCount(0);
});

test("back up, restore as a new VM, reinstall and delete the backup", async ({ page }) => {
  await signIn(page);
  await page.goto(`${BASE}/#/vms/stor-1`);
  await act(page, "Back up stor-1", "Backup complete");
  await page.goto(`${BASE}/#/storage`);
  const backups = page.getByRole("region", { name: "Backups" });
  await expect(backups).toContainText("Complete");
  await expect(page.getByText(/not against losing the host/)).toBeVisible();
  // restore needs a valid name and a public key; a private key is refused and cleared
  await page.getByRole("button", { name: /^Restore bk-/ }).click();
  await page.getByLabel(/Name of the new VM/).fill("stor-2");
  await page.getByLabel(/SSH public key/).fill("-----BEGIN OPENSSH PRIVATE KEY-----");
  await page.getByRole("button", { name: "Restore as a new VM" }).click();
  await expect(page.getByRole("dialog")).toContainText("Never paste a private key");
  await expect(page.getByLabel(/SSH public key/)).toHaveValue("");
  await page.getByLabel(/SSH public key/).fill(KEY);
  await page.getByRole("button", { name: "Restore as a new VM" }).click();
  await expect(page.getByText(/restored as a new VM/)).toBeVisible({ timeout: 30000 });
  await page.goto(`${BASE}/#/vms`);
  await expect(page.getByRole("row", { name: /stor-2/ })).toContainText("Stopped");
  await expect(page.getByRole("row", { name: /stor-1/ })).toBeVisible();
  // reinstall stor-2 from the qualified image: warned, then done; identity and size stay
  const size = /(\d+) GiB/.exec(await page.getByRole("row", { name: /stor-2/ }).innerText())![1];
  await page.goto(`${BASE}/#/vms/stor-2`);
  await page.getByRole("button", { name: "Reinstall stor-2" }).click();
  await expect(page.getByRole("dialog")).toContainText("Everything stored on the current disk is deleted");
  await expect(page.getByLabel("Image")).toContainText("Ubuntu Q (real-host qualified)");
  await page.getByLabel(/SSH public key/).fill(KEY);
  await page.getByRole("button", { name: "Reinstall and erase the disk" }).click();
  await expect(page.getByText("VM reinstalled (stopped)")).toBeVisible({ timeout: 30000 });
  await page.getByRole("button", { name: "Refresh" }).click();
  await expect(page.locator("main")).toContainText(`${size} GiB`);
  // delete the backup, then both VMs
  await page.goto(`${BASE}/#/storage`);
  await page.getByRole("button", { name: /^Delete bk-/ }).click();
  await expect(page.getByRole("dialog")).toContainText("for good");
  await page.getByRole("button", { name: "Delete backup permanently" }).click();
  await expect(page.getByText("Backup deleted")).toBeVisible({ timeout: 30000 });
  await expect(page.getByRole("region", { name: "Backups" })).toHaveCount(0, { timeout: 30000 });
  for (const vm of ["stor-1", "stor-2"]) {
    await page.goto(`${BASE}/#/vms/${vm}`);
    await page.getByRole("button", { name: `Delete ${vm}` }).click();
    await page.getByRole("button", { name: "Delete permanently" }).click();
    await expect(page.getByText("VM deleted")).toBeVisible({ timeout: 30000 });
    await page.goto(`${BASE}/#/vms`);
    await expect(page.getByRole("row", { name: new RegExp(vm) })).toHaveCount(0);
  }
});

test("installation media and rescue mode on a stopped VM: attach, eject, rescue, leave rescue (DR-026)", async ({ page }) => {
  // The host administrator imports the media (root, on the host): the test does the same with the API binary, against this stack's catalog.
  const dir = "/tmp/svavyom-e2e-create-storage";
  const isoFile = (label: string) => {
    const iso = Buffer.alloc(32768 + 2048);
    iso[32768] = 1;
    iso.write("CD001", 32769);
    iso[32768 + 6] = 1;
    iso.write(label, 32768 + 40);
    return iso;
  };
  writeFileSync(`${dir}/src/rescue.iso`, isoFile("rescue-media"), { mode: 0o640 });
  writeFileSync(`${dir}/src/drivers.iso`, isoFile("driver-media"), { mode: 0o640 });
  for (const [id, name, file] of [["rescue-iso", "Rescue ISO", "rescue.iso"], ["drivers-iso", "Driver disc", "drivers.iso"]]) {
    execFileSync(process.env.SVAVYOM_API_BIN!, ["register-image", "--insecure-dev-single-identity", "--catalog-dir", `${dir}/images`, "--id", id, "--display-name", name,
      "--distribution", "Alpine", "--version", "3.20", "--source", `${dir}/src/${file}`, "--min-disk-gib", "2", "--media", "iso"]);
  }
  await signIn(page);
  await createVm(page, "resc-1");
  await expect(page.getByRole("button", { name: "Attach installation media to resc-1" })).toBeVisible();
  await expect(page.getByRole("button", { name: "Start rescue mode for resc-1" })).toBeVisible();
  await expect(page.getByRole("button", { name: "Leave rescue mode of resc-1" })).toHaveCount(0);
  // attach as a tools disc, then eject it
  await page.getByRole("button", { name: "Attach installation media to resc-1" }).click();
  await page.getByLabel("Boot").selectOption("disk");
  await page.getByRole("dialog").getByRole("button", { name: "Attach the media" }).click();
  await expect(page.getByText(/Media attached/)).toBeVisible({ timeout: 30000 });
  await page.getByRole("button", { name: "Refresh" }).click();
  await expect(page.locator("main")).toContainText("rescue-iso");
  await expect(page.getByRole("button", { name: "Start rescue mode for resc-1" })).toHaveCount(0); // media is attached: eject first
  // a second medium (DR-031): no boot choice, the first one is not offered again, each medium has its own eject button
  await page.getByRole("button", { name: "Attach installation media to resc-1" }).click();
  await expect(page.getByLabel("Boot")).toHaveCount(0);
  await expect(page.getByText(/A second medium is only attached/)).toBeVisible();
  expect(await page.getByLabel("Media").locator("option").allTextContents()).toEqual(["Driver disc"]);
  await page.getByRole("dialog").getByRole("button", { name: "Attach the media" }).click();
  await expect(page.getByText(/Media attached/)).toBeVisible({ timeout: 30000 });
  await page.getByRole("button", { name: "Refresh" }).click();
  await expect(page.getByRole("button", { name: "Eject Rescue ISO from resc-1" })).toBeVisible();
  await expect(page.getByRole("button", { name: "Eject Driver disc from resc-1" })).toBeVisible();
  await expect(page.getByRole("button", { name: "Attach installation media to resc-1" })).toHaveCount(0); // two is the most
  expect((await axe(page)).violations).toEqual([]);
  await act(page, "Eject Driver disc from resc-1", /Installation media ejected/);
  await page.getByRole("button", { name: "Refresh" }).click();
  await expect(page.getByRole("button", { name: "Eject Driver disc from resc-1" })).toHaveCount(0);
  await expect(page.getByRole("button", { name: "Attach installation media to resc-1" })).toBeVisible();
  await act(page, "Eject Rescue ISO from resc-1", /Installation media ejected/);
  await page.getByRole("button", { name: "Refresh" }).click();
  await expect(page.getByText("None attached")).toBeVisible();
  // rescue mode: set, seen, left
  await page.getByRole("button", { name: "Start rescue mode for resc-1" }).click();
  await page.getByRole("dialog").getByRole("button", { name: "Start rescue mode" }).click();
  await expect(page.getByText(/Rescue mode set/)).toBeVisible({ timeout: 30000 });
  await page.getByRole("button", { name: "Refresh" }).click();
  await expect(page.getByText(/This VM is in rescue mode/).first()).toBeVisible();
  await expect(page.getByRole("button", { name: "Start rescue mode for resc-1" })).toHaveCount(0);
  await expect(page.getByRole("button", { name: "Reinstall resc-1" })).toHaveCount(0);
  expect((await axe(page)).violations).toEqual([]);
  await act(page, "Leave rescue mode of resc-1", /Left rescue mode/);
  await page.getByRole("button", { name: "Refresh" }).click();
  await expect(page.getByText(/This VM is in rescue mode/)).toHaveCount(0);
  await expect(page.getByRole("button", { name: "Start rescue mode for resc-1" })).toBeVisible();
});
