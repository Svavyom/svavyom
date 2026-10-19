// fe-unit: every request the journey skeletons send is checked against SubmitOperationRequest (M0-E01-S04 AC03).
// J9's `reboot` and `force_off` became submit_operation types with the M1 lifecycle (CT-012); every request must validate.
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { J4Wizard, J7Delete, J9Power } from "./journeys";
import { VM_RUNNING, operation, vmList } from "../api/fixtures";
import { validate } from "../api/validate";

const sent: Array<{ method: string; url: string; body: unknown }> = [];

beforeEach(() => {
  sent.length = 0;
  vi.stubGlobal("fetch", vi.fn(async (url: string, init: RequestInit) => {
    sent.push({ method: init.method ?? "GET", url, body: init.body ? JSON.parse(init.body as string) : null });
    if (init.method === "POST") return new Response(JSON.stringify(operation()), { status: 202 });
    return new Response(JSON.stringify(url.endsWith("/vms") ? vmList() : VM_RUNNING), { status: 200 });
  }));
});
afterEach(() => { cleanup(); vi.unstubAllGlobals(); });

const posts = () => sent.filter((c) => c.method === "POST");

describe("journey requests against SubmitOperationRequest", () => {
  it("J4 create sends a conformant body to the declared path", async () => {
    render(<J4Wizard />);
    await userEvent.type(screen.getByLabelText(/VM name/), "web-1");
    await userEvent.click(screen.getByLabelText("Debian 13"));
    await userEvent.click(screen.getByRole("button", { name: "Continue to review" }));
    await userEvent.click(screen.getByRole("button", { name: /Create VM/ }));
    await vi.waitFor(() => expect(posts()).toHaveLength(1));
    expect(posts()[0].url).toBe("/api/v1/operations");
    expect(validate("SubmitOperationRequest", posts()[0].body)).toEqual({ ok: true });
  });

  it("J7 delete sends a conformant body", async () => {
    render(<J7Delete id="vm-a" />);
    await userEvent.click(await screen.findByRole("button", { name: "Delete VM" }));
    await userEvent.type(screen.getByLabelText(/Name to confirm/), "web-1");
    await userEvent.click(screen.getByRole("button", { name: "Delete permanently" }));
    await vi.waitFor(() => expect(posts()).toHaveLength(1));
    expect(validate("SubmitOperationRequest", posts()[0].body)).toEqual({ ok: true });
    expect((posts()[0].body as { type: string }).type).toBe("delete");
  });

  it("J9 start, stop, reboot and force_off are all conformant submit_operation types", async () => {
    render(<J9Power id="vm-a" />);
    for (const name of ["Start", "Stop", "Reboot"]) {
      await userEvent.click(await screen.findByRole("button", { name }));
      await vi.waitFor(() => expect(screen.getByRole("button", { name }).getAttribute("aria-disabled")).not.toBe("true"));
    }
    await userEvent.click(screen.getByRole("button", { name: "Force off" }));
    await userEvent.click(await screen.findByRole("button", { name: "Confirm force off" }));
    await vi.waitFor(() => expect(posts()).toHaveLength(4));
    const verdicts = posts().map((c) => [(c.body as { type: string }).type, validate("SubmitOperationRequest", c.body)] as const);
    expect(verdicts).toEqual([
      ["start", { ok: true }], ["stop", { ok: true }],
      ["reboot", { ok: true }],
      ["force_off", { ok: true }],
    ]);
  });
});
