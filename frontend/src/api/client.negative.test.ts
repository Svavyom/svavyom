// fe-negative: malformed and hostile API responses become typed states; nothing is logged or stored (AC02).
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { MAX_BODY_BYTES, decodeError, mutate, read } from "./client";
import { BOUNDARY_CATEGORIES } from "./errors";
import { CORRELATION_ID, apiError } from "./fixtures";

const respond = (body: string, status = 200) => vi.fn(async () => new Response(body, { status })) as unknown as typeof fetch;
const decodeAnything = (v: unknown) => (v && typeof v === "object" ? (v as object) : null);
let spies: ReturnType<typeof vi.spyOn>[] = [];

beforeEach(() => {
  spies = (["log", "info", "warn", "error", "debug"] as const).map((m) => vi.spyOn(console, m).mockImplementation(() => undefined));
  localStorage.clear();
  sessionStorage.clear();
});
afterEach(() => {
  for (const s of spies) expect(s).not.toHaveBeenCalled();
  expect(localStorage.length + sessionStorage.length).toBe(0);
  expect(document.cookie).toBe("");
});

describe("client negative cases", () => {
  it("hostile bodies become internal", async () => {
    for (const body of ["<html><script>alert(1)</script></html>", "{", "null", "[]", '"text"', '{"__proto__":{"x":1}}']) {
      const r = await read("/api/v1/vms", () => null, respond(body));
      expect(r, body).toEqual({ kind: "error", category: "internal", correlationId: null });
    }
  });

  it("unknown and out-of-boundary categories become internal", async () => {
    for (const category of ["teapot", "timeout", "host_error", "", 42, null]) {
      expect(decodeError({ ...apiError("forbidden"), category }).category, String(category)).toBe("internal");
    }
    for (const category of BOUNDARY_CATEGORIES) {
      expect(decodeError(apiError(category)), category).toEqual({ category, correlationId: CORRELATION_ID });
    }
  });

  it("an envelope that is not exactly the ApiError schema becomes internal with no id", async () => {
    const good = apiError("forbidden");
    const bad: unknown[] = [
      { category: "forbidden" }, // no correlation id, no retryable (the S06 provisional shape)
      { category: "forbidden", correlation_id: CORRELATION_ID }, // retryable missing
      { ...good, message: "secret path /etc/x" }, // free text is not part of the envelope
      { ...good, correlation_id: "<script>" },
      { ...good, correlation_id: "short" },
      { ...good, retryable: true }, // retryable is fixed per category
      { ...apiError("rate_limited"), retryable: false },
      { ...good, field_errors: [{ field: "name", code: "required", extra: 1 }] },
      { ...good, field_errors: [{ field: "name", code: "teapot" }] },
      JSON.parse('{"category":"forbidden","retryable":false,"correlation_id":"0123456789abcdef","__proto__":{"x":1}}'),
      [], null, "text", 7,
    ];
    for (const body of bad) expect(decodeError(body), JSON.stringify(body)).toEqual({ category: "internal", correlationId: null });
    expect(decodeError({ ...good, field_errors: [{ field: "name", code: "required" }] }).category).toBe("forbidden");
  });

  it("oversized bodies become internal", async () => {
    const r = await read("/api/v1/vms", decodeAnything, respond("x".repeat(MAX_BODY_BYTES + 1)));
    expect(r).toEqual({ kind: "error", category: "internal", correlationId: null });
  });

  it("absolute, protocol-relative and traversal urls are refused", async () => {
    for (const p of ["https://evil.example/x", "//evil.example/x", "/api/../../etc", "api/v1", "/api/v1/vms?x=<s>"]) {
      await expect(read(p, decodeAnything, respond("{}")), p).rejects.toThrow(/same-origin/);
    }
  });

  it("network errors on a mutation are outcome_unknown and are not retried", async () => {
    const f = vi.fn(async () => { throw new TypeError("network"); }) as unknown as typeof fetch;
    expect(await mutate("/api/v1/operations", { type: "delete" }, "k", decodeAnything, f)).toEqual({ kind: "outcome_unknown" });
    expect(f).toHaveBeenCalledTimes(1);
  });

  it("redirects are refused", async () => {
    const f = vi.fn(async (_u: RequestInfo | URL, init?: RequestInit) => {
      expect(init?.redirect).toBe("error");
      throw new TypeError("redirect");
    }) as unknown as typeof fetch;
    expect(await read("/healthz", decodeAnything, f)).toEqual({ kind: "unreachable" });
  });
});
