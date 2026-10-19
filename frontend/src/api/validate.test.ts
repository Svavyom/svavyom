// fe-unit: the strict validator itself (M0-E01-S04). Fixture conformance is in conformance.test.ts; hostile and
// edge inputs are in validate.negative.test.ts.
import { describe, expect, it } from "vitest";
import { apiError, operation, vm } from "./fixtures";
import { validate } from "./validate";

describe("validate", () => {
  it("accepts conformant values", () => {
    expect(validate("VM", vm())).toEqual({ ok: true });
    expect(validate("Operation", operation({ error_category: "timeout" }))).toEqual({ ok: true });
    expect(validate("ApiError", apiError("unavailable"))).toEqual({ ok: true });
  });

  it("reports the failing keyword and a path", () => {
    expect(validate("VM", vm({ name: "" }))).toEqual({ ok: false, reason: "minLength", path: "$.name" });
    expect(validate("VMList", { items: [vm({ id: "x y" })], allowed_actions: [], next_cursor: null })).toEqual({ ok: false, reason: "pattern", path: "$.items[0].id" });
  });

  it("date-time accepts offsets and fractions and rejects impossible dates", () => {
    const at = (s: string) => validate("VM", { ...vm(), observed: { power: "running", last_seen_at: s, managed: false, ip_address: null, login_user: null, disk_gib: null, snapshots: [], network: null, vcpus: null, memory_mib: null, iso: null, usage: { state: "unavailable", cpu_percent: null, memory_used_mib: null, disk_kib_s: null, net_kib_s: null, history: [] }, backup: { next_run_at: null, last_run: null }, graphical_console: "absent", rescue: false } }).ok;
    expect(at("2026-10-08T10:00:00Z")).toBe(true);
    expect(at("2026-10-08T10:00:00.5+05:30")).toBe(true);
    expect(at("2028-02-29T00:00:00Z")).toBe(true);
    for (const bad of ["2026-10-08", "2026-10-08 10:00:00Z", "2026-13-01T00:00:00Z", "2026-02-29T00:00:00Z", "2026-10-08T25:00:00Z", "2026-10-08T10:00:00"]) {
      expect(at(bad), bad).toBe(false);
    }
  });

  it("measures length in code points", () => {
    expect(validate("VM", vm({ name: "😀".repeat(63) })).ok).toBe(true);
    expect(validate("VM", vm({ name: "😀".repeat(64) })).ok).toBe(false);
  });
});
