// fe-negative: hostile and malformed values never validate and never throw (M0-E01-S04 AC02).
import { describe, expect, it } from "vitest";
import { apiError, vm } from "./fixtures";
import { validate } from "./validate";

describe("validate hostile input", () => {
  it("rejects non-objects for object schemas", () => {
    for (const v of [null, undefined, 1, "x", true, [], [vm()], () => 1, Symbol("s")]) {
      expect(validate("VM", v).ok, String(typeof v)).toBe(false);
      expect(validate("ApiError", v).ok).toBe(false);
    }
  });

  it("rejects own __proto__, constructor and prototype keys", () => {
    const polluted = JSON.parse('{"__proto__":{"admin":true},"category":"forbidden","retryable":false,"correlation_id":"0123456789abcdef"}');
    expect(validate("ApiError", polluted)).toEqual({ ok: false, reason: "additionalProperties", path: "$.__proto__" });
    expect(validate("ApiError", { ...apiError("forbidden"), constructor: 1 }).ok).toBe(false);
    expect(({} as Record<string, unknown>).admin).toBeUndefined();
  });

  it("does not trust inherited properties", () => {
    const inherited = Object.create({ category: "forbidden", retryable: false, correlation_id: "0123456789abcdef" });
    expect(validate("ApiError", inherited)).toEqual({ ok: false, reason: "required", path: "$.category" });
  });

  it("rejects wrong types for every scalar", () => {
    const base = vm();
    for (const [key, bad] of [["id", 1], ["name", null], ["generation", "1"], ["generation", NaN], ["generation", Infinity], ["allowed_actions", "start"], ["desired", []]] as const) {
      expect(validate("VM", { ...base, [key]: bad }).ok, `${key}=${String(bad)}`).toBe(false);
    }
  });

  it("rejects numbers beyond the safe integer range and non-finite values", () => {
    expect(validate("VM", vm({ generation: Number.MAX_SAFE_INTEGER + 2 })).ok).toBe(false);
    expect(validate("VM", vm({ generation: Number.NaN })).ok).toBe(false);
  });

  it("is not tricked by a regex special value", () => {
    expect(validate("VM", vm({ id: "a".repeat(63) + "\n" })).ok).toBe(false);
    expect(validate("VM", vm({ id: "vm-1\u0000" })).ok).toBe(false);
    expect(validate("VM", vm({ id: "vm‮-1" })).ok).toBe(false);
  });

  it("handles a deeply nested value without throwing", () => {
    let deep: unknown = {};
    for (let i = 0; i < 5000; i++) deep = { a: deep };
    expect(validate("VM", deep).ok).toBe(false);
    expect(validate("VMList", { items: [deep], allowed_actions: [], next_cursor: null }).ok).toBe(false);
  });

  it("rejects a value whose getters throw", () => {
    const trap = new Proxy({}, { ownKeys() { throw new Error("boom"); }, getOwnPropertyDescriptor() { throw new Error("boom"); } });
    expect(validate("VM", trap)).toMatchObject({ ok: false });
  });

  it("fails closed on an unknown schema name", () => {
    expect(validate("Nope" as never, {})).toEqual({ ok: false, reason: "schema", path: "$" });
  });

  it("rejects oversized collections and arrays", () => {
    const items = Array.from({ length: 201 }, (_, i) => vm({ id: `vm-${i}` }));
    expect(validate("VMList", { items, allowed_actions: [], next_cursor: null })).toEqual({ ok: false, reason: "maxItems", path: "$.items" });
  });
});
