// fe-unit: the System page: the version, each service with its state, and what to do when one does not answer.
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen, within } from "@testing-library/react";
import { Root } from "./Root";
import { HOST, apiError } from "../api/fixtures";
import { forgetCsrf } from "../api/session";
import { axeViolations } from "../test-axe";
import type { Host } from "../api/schema";

const TOKEN = (c: string) => c.repeat(43);
const IN = { authenticated: true, username: "admin", expires_at: "2026-10-09T08:30:00Z", role: "admin", must_change_password: false };
const respond = (status: number, body: unknown, csrf?: string) => new Response(JSON.stringify(body), { status, headers: csrf ? { "X-CSRF-Token": csrf } : {} });
const withServices = (services: Host["observed"]["services"], version = "0.1.0-preview.16"): Host => ({ ...HOST, observed: { ...HOST.observed, agent_version: version, services } });

let host: Host;
beforeEach(() => {
  forgetCsrf();
  host = HOST;
  location.hash = "#/system";
  vi.stubGlobal("fetch", vi.fn(async (url: string) => {
    if (url === "/api/v1/auth/session") return respond(200, IN, TOKEN("S"));
    if (url === "/api/v1/hosts/local") return respond(200, host);
    return respond(404, apiError("not_found"));
  }));
});
afterEach(() => { cleanup(); vi.unstubAllGlobals(); });

describe("System page", () => {
  it("shows the version, every service and says all is well when each one that is on answers", async () => {
    host = withServices([{ id: "api", state: "ok" }, { id: "agent", state: "ok" }, { id: "mutation", state: "ok" }, { id: "console", state: "not_enabled" }, { id: "offsite", state: "not_enabled" }]);
    render(<Root />);
    expect(await screen.findByRole("heading", { level: 1, name: "System" })).toBeTruthy();
    expect(await screen.findByText("0.1.0-preview.16")).toBeTruthy();
    const table = screen.getByRole("table", { name: "Services Svavyom depends on" });
    for (const n of ["Web console and API", "Host agent", "Mutation service", "Console broker", "Off-host backup service"]) expect(within(table).getByText(n)).toBeTruthy();
    expect(within(table).getAllByText("Answering")).toHaveLength(3);
    expect(within(table).getAllByText("Turned off")).toHaveLength(2);
    expect(screen.getByText("Every service that is turned on is answering.")).toBeTruthy();
    expect(await axeViolations(document.body)).toEqual([]);
  });

  it("names the service that does not answer and the exact commands to run on the host", async () => {
    host = withServices([{ id: "api", state: "ok" }, { id: "agent", state: "ok" }, { id: "mutation", state: "unreachable" }, { id: "console", state: "ok" }, { id: "offsite", state: "not_enabled" }]);
    render(<Root />);
    expect(await screen.findByText(/Mutation service is not answering/)).toBeTruthy();
    expect(screen.getByText(/journalctl -u svavyom-mutation -n 100 --no-pager/)).toBeTruthy();
    expect(screen.getByText(/sudo systemctl restart svavyom-mutation/)).toBeTruthy();
    expect(screen.getByText(/sudo svavyom-ctl rollback/)).toBeTruthy();
    expect(await axeViolations(document.body)).toEqual([]);
  });

  it("says plainly that a development build has no release version", async () => {
    host = withServices([{ id: "api", state: "ok" }], "dev");
    render(<Root />);
    expect(await screen.findByText(/dev \(a development build/)).toBeTruthy();
  });

  it("is reachable from the navigation", async () => {
    location.hash = "";
    render(<Root />);
    expect(await screen.findByRole("link", { name: "System" })).toBeTruthy();
  });
});
