// fe-unit: fixture conformance (M0-E01-S04 AC03). Every positive fixture validates against contracts/openapi.yaml
// (through the generated schemas); every negative fixture fails with its named keyword and path. The journey
// scenarios used by the browser tier and the typed builders used by the unit tests are checked the same way.
import { describe, expect, it } from "vitest";
import fixtures from "./fixtures.json";
import journeyStates from "../../e2e/journey-states.json";
import errorsContract from "../../../contracts/interfaces/errors.json";
import { CORRELATION_ID, HOST, VM_RUNNING, apiError, operation, vm, vmList } from "./fixtures";
import { ERROR_CATEGORIES, ROUTES, SCHEMAS, type SchemaName } from "./schema";
import { validate } from "./validate";

const names = Object.keys(SCHEMAS) as SchemaName[];
const FIXTURE_KEYS = ["name", "schema", "value", "reason", "path"];

describe("fixture catalogue", () => {
  it("has no provisional marker and only known schemas", () => {
    expect(JSON.stringify(fixtures)).not.toMatch(/provisional/i);
    expect(JSON.stringify(journeyStates)).not.toMatch(/provisional/i);
    for (const f of [...fixtures.positive, ...fixtures.negative]) {
      expect(names, f.name).toContain(f.schema);
      expect(Object.keys(f).every((k) => FIXTURE_KEYS.includes(k)), f.name).toBe(true);
    }
    expect(new Set([...fixtures.positive, ...fixtures.negative].map((f) => f.name)).size).toBe(fixtures.positive.length + fixtures.negative.length);
  });

  it("covers every schema with a positive fixture and every resource, the envelope and the request with a negative one", () => {
    const positive = new Set(fixtures.positive.map((f) => f.schema));
    for (const n of names) expect(positive.has(n), `positive fixture for ${n}`).toBe(true);
    const negative = new Set(fixtures.negative.map((f) => f.schema));
    for (const n of names.filter((x) => !x.endsWith("List") || x === "VMList")) expect(negative.has(n), `negative fixture for ${n}`).toBe(true);
  });
});

describe("positive fixtures validate", () => {
  for (const f of fixtures.positive) it(f.name, () => expect(validate(f.schema as SchemaName, f.value)).toEqual({ ok: true }));
});

describe("negative fixtures fail with their named reason", () => {
  for (const f of fixtures.negative) {
    it(f.name, () => expect(validate(f.schema as SchemaName, f.value)).toEqual({ ok: false, reason: f.reason, path: f.path }));
  }
});

describe("derived mutations of every positive object fixture", () => {
  const objects = fixtures.positive.filter((f) => typeof f.value === "object" && f.value !== null && !Array.isArray(f.value));
  it("an unknown key is rejected with additionalProperties", () => {
    for (const f of objects) {
      const r = validate(f.schema as SchemaName, { ...(f.value as object), message: "x" });
      expect(r, f.name).toEqual({ ok: false, reason: "additionalProperties", path: "$.message" });
    }
  });
  it("each required key is needed", () => {
    for (const f of objects) {
      const schema = SCHEMAS[f.schema as SchemaName] as unknown as { required?: string[] };
      for (const key of schema.required ?? []) {
        const { [key]: _dropped, ...rest } = f.value as Record<string, unknown>;
        expect(validate(f.schema as SchemaName, rest), `${f.name} without ${key}`).toEqual({ ok: false, reason: "required", path: `$.${key}` });
      }
    }
  });
  it("every string property rejects a value one past its maxLength", () => {
    for (const f of objects) {
      const props = (SCHEMAS[f.schema as SchemaName] as unknown as { properties: Record<string, { type?: unknown; maxLength?: number; enum?: unknown; const?: unknown }> }).properties;
      for (const [key, p] of Object.entries(props)) {
        if (typeof p.maxLength !== "number" || p.enum || p.const !== undefined) continue;
        const r = validate(f.schema as SchemaName, { ...(f.value as object), [key]: "a".repeat(p.maxLength + 1) });
        expect(r.ok, `${f.name}.${key}`).toBe(false);
      }
    }
  });
});

describe("typed builders are schema-conformant", () => {
  it("resources and lists", () => {
    expect(validate("Host", HOST)).toEqual({ ok: true });
    expect(validate("VM", VM_RUNNING)).toEqual({ ok: true });
    expect(validate("VM", vm({ allowed_actions: [] }))).toEqual({ ok: true });
    expect(validate("VMList", vmList())).toEqual({ ok: true });
    expect(validate("VMList", vmList([], ["create"]))).toEqual({ ok: true });
    expect(validate("Operation", operation())).toEqual({ ok: true });
    for (const status of ["pending", "running", "succeeded", "failed", "retryable_failure", "cancelled"] as const) {
      expect(validate("Operation", operation({ status })), status).toEqual({ ok: true });
    }
  });
  it("every error category has a conformant envelope with the right retryable constant", () => {
    for (const c of ERROR_CATEGORIES) expect(validate("ApiError", apiError(c)), c).toEqual({ ok: true });
    expect(apiError("rate_limited").correlation_id).toBe(CORRELATION_ID);
  });
});

// ---- route -> schema mapping for the browser-tier journey scenarios ----------------------------------------------
function matchRoutes(path: string) {
  const parts = path.split("?")[0].split("/");
  return ROUTES.filter((r) => {
    const t = r.path.split("/");
    return t.length === parts.length && t.every((seg, i) => seg === parts[i] || (seg.startsWith("{") && parts[i] !== ""));
  });
}

type Reply = { status?: number; body?: unknown; abort?: boolean; hang?: boolean };
type Scenario = { api: Record<string, Reply | Reply[]> };

describe("route table", () => {
  it("declares only the DR-015 routes as implemented", () => {
    expect(ROUTES.filter((r) => r.implemented).map((r) => `${r.method} ${r.path}`).sort()).toEqual([
      "DELETE /api/v1/auth/session", "GET /api/v1/auth/session", "GET /api/v1/backups", "GET /api/v1/backups/{id}", "GET /api/v1/events", "GET /api/v1/events/{id}", "GET /api/v1/hosts", "GET /api/v1/hosts/{id}", "GET /api/v1/images", "GET /api/v1/images/{id}", "GET /api/v1/operations", "GET /api/v1/operations/{id}", "GET /api/v1/virtual-networks", "GET /api/v1/virtual-networks/{id}", "GET /api/v1/vms", "GET /api/v1/vms/{id}", "GET /api/v1/volumes", "GET /api/v1/volumes/{id}", "GET /healthz",
      "POST /api/v1/auth/session", "POST /api/v1/operations"]);
    expect(ROUTES).toHaveLength(26);
  });
  it("lists only browser-api error statuses", () => {
    const allowed = new Set([400, 401, 403, 404, 409, 422, 429, 500, 503]);
    for (const r of ROUTES) for (const s of r.error_statuses) expect(allowed.has(s), `${r.method} ${r.path} ${s}`).toBe(true);
  });
});

describe("journey scenarios used by the browser tier", () => {
  const replies: Array<{ where: string; path: string; reply: Reply }> = [];
  for (const [journey, states] of Object.entries(journeyStates.journeys)) {
    for (const [state, sc] of Object.entries(states as unknown as Record<string, Scenario>)) {
      for (const [path, entry] of Object.entries(sc.api)) {
        for (const reply of Array.isArray(entry) ? entry : [entry]) replies.push({ where: `${journey} ${state} ${path}`, path, reply });
      }
    }
  }
  it("has replies to check", () => expect(replies.length).toBeGreaterThan(60));
  it("every reply body validates against the schema of its declared route and status", () => {
    let checked = 0;
    for (const { where, path, reply } of replies) {
      if (reply.body === undefined) continue;
      const status = reply.status ?? 200;
      if (where.startsWith("J6 ")) {
        // J6 renders one error state per browser-api category. No single route returns every category, so the GET it
        // uses is only a stand-in trigger: check the body against ApiError and the status against errors.json.
        const category = (reply.body as { category?: keyof typeof errorsContract.categories }).category;
        expect(validate("ApiError", reply.body), where).toEqual({ ok: true });
        expect(errorsContract.categories[category!].http_status, where).toBe(status);
        checked += 1;
        continue;
      }
      const routes = matchRoutes(path);
      expect(routes.length, `${where}: path is not declared in contracts/openapi.yaml`).toBeGreaterThan(0);
      const success = routes.filter((r) => r.success.status === status);
      const error = routes.filter((r) => (r.error_statuses as readonly number[]).includes(status));
      expect(success.length + error.length, `${where}: status ${status} is not declared for this path`).toBeGreaterThan(0);
      const verdicts = [
        ...success.map((r) => validate(r.success.schema as SchemaName, reply.body)),
        ...error.map(() => validate("ApiError", reply.body)),
      ];
      expect(verdicts.some((v) => v.ok), `${where}: ${JSON.stringify(verdicts)}`).toBe(true);
      checked += 1;
    }
    expect(checked).toBeGreaterThan(60);
  });
});
