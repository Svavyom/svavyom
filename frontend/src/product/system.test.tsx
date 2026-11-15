// fe-unit: the System page: the version, each service with its state, and what to do when one does not answer.
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen, within } from "@testing-library/react";
import { Root } from "./Root";
import { HOST, apiError } from "../api/fixtures";
import { validate } from "../api/validate";
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

describe("Certificate (DR-034)", () => {
  const cert = (over: Partial<NonNullable<Host["observed"]["certificate"]>> = {}): NonNullable<Host["observed"]["certificate"]> => ({
    names: ["console.example.org"], issuer: "Let's Encrypt R10", not_before: "2026-11-01T00:00:00Z", not_after: "2027-01-30T00:00:00Z", days_left: 60, source: "lets_encrypt",
    renews_from: "2026-12-30T00:00:00Z", managed: true, last_attempt: "2026-11-01T00:00:00Z", last_result: "ok", last_detail: null, ...over });
  const withCert = (c: Host["observed"]["certificate"]): Host => ({ ...HOST, observed: { ...HOST.observed, certificate: c } });

  it("the fixtures with a certificate are valid against the schema", () => {
    expect(validate("Host", withCert(cert()))).toEqual({ ok: true });
    expect(validate("Host", withCert(null))).toEqual({ ok: true });
    expect(validate("Host", withCert({ ...cert(), source: "made_up" } as never)).ok).toBe(false);
  });

  it("says a proxy ends TLS when there is no certificate", async () => {
    host = withCert(null);
    render(<Root />);
    expect(await screen.findByText(/a proxy in front of it does/)).toBeTruthy();
  });

  it("shows a managed Let's Encrypt certificate with its renewal and the commands to switch back", async () => {
    host = withCert(cert());
    render(<Root />);
    const table = await screen.findByRole("table", { name: "The certificate in use" });
    expect(within(table).getByText("console.example.org")).toBeTruthy();
    expect(within(table).getByText("Let's Encrypt")).toBeTruthy();
    expect(within(table).getByText(/2026-11-01 to 2027-01-30 \(60 days left\)/)).toBeTruthy();
    expect(within(table).getByText(/Automatic, from 2026-12-30/)).toBeTruthy();
    expect(screen.getByText(/svavyom-ctl tls use-self-signed/)).toBeTruthy();
    expect(screen.queryByText(/expires in/)).toBeNull();
    expect(await axeViolations(document.body)).toEqual([]);
  });

  it("a self-signed certificate says browsers warn and gives the staging and production commands", async () => {
    host = withCert(cert({ source: "self_signed", managed: false, issuer: "x", last_attempt: null, last_result: null }));
    render(<Root />);
    expect(await screen.findByText(/Browsers warn about a self-signed certificate/)).toBeTruthy();
    expect(screen.getByText(/acme-issue --name YOUR.NAME.EXAMPLE .* --staging/)).toBeTruthy();
    expect(screen.getByText(/Not renewed: replace it before it expires/)).toBeTruthy();
    expect(screen.getByText(/Cloudflare/)).toBeTruthy();
    expect(await axeViolations(document.body)).toEqual([]);
  });

  it("warns as the certificate nears expiry and when it is a staging one", async () => {
    host = withCert(cert({ days_left: 10 }));
    const { unmount } = render(<Root />);
    expect(await screen.findByText(/expires in 10 days/)).toBeTruthy();
    unmount();
    cleanup();
    host = withCert(cert({ days_left: 2 }));
    render(<Root />);
    expect(await screen.findByText(/expires in 2 days\. Browsers will refuse it/)).toBeTruthy();
    cleanup();
    host = withCert(cert({ source: "lets_encrypt_staging" }));
    render(<Root />);
    expect(await screen.findByText(/staging certificate: browsers do not trust it/)).toBeTruthy();
  });

  it("explains a failed attempt in words keyed by the closed code, never by a message from the host", async () => {
    host = withCert(cert({ last_result: "validation_failed", last_detail: "ignored <script>alert(1)</script>" }));
    render(<Root />);
    expect(await screen.findByText(/The last attempt failed \(validation_failed\)\. Let's Encrypt could not validate the name/)).toBeTruthy();
    expect(document.body.textContent).not.toContain("alert(1)");
  });
});

