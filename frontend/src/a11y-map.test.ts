// fe-unit: the SC map covers every WCAG 2.2 A/AA criterion, required criteria are verified, and every named test
// exists (r5 section 3; R3-N1). No conformance claim is made in M0.
import { describe, expect, it } from "vitest";
import map from "../a11y-map.json";
import wcag from "../wcag22-a-aa.json";

const sources = { ...import.meta.glob("./**/*.test.{ts,tsx}", { query: "?raw", import: "default", eager: true }),
  ...import.meta.glob("../e2e/*.spec.ts", { query: "?raw", import: "default", eager: true }) } as Record<string, string>;
const REQUIRED = ["1.3.1", "1.3.5", "1.4.1", "1.4.3", "1.4.4", "1.4.10", "1.4.11", "1.4.12", "1.4.13", "2.1.1", "2.1.2", "2.2.2",
  "2.4.1", "2.4.2", "2.4.3", "2.4.6", "2.4.7", "2.4.11", "2.5.3", "2.5.7", "2.5.8", "3.2.1", "3.2.2", "3.3.1", "3.3.2", "3.3.3",
  "3.3.4", "3.3.7", "4.1.2", "4.1.3"];
type Entry = { status: string; tests?: string[]; axe_rules?: string[]; owner?: string; reason?: string };
const criteria = map.criteria as Record<string, Entry>;

function testExists(ref: string): boolean {
  const [file, title] = ref.split("::");
  const key = Object.keys(sources).find((k) => k.endsWith(file.replace(/^src\//, "").replace(/^e2e\//, "e2e/")));
  if (!key) return false;
  const esc = title.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  return new RegExp(`\\b(?:it|test)\\(\\s*["'\`]${esc}["'\`]`).test(sources[key]);
}

describe("accessibility map", () => {
  it("map covers every WCAG 2.2 A and AA criterion", () => {
    expect(wcag.criteria).toHaveLength(55);
    expect(Object.keys(criteria).sort()).toEqual(wcag.criteria.map((c) => c.id).sort());
    expect(map.conformance_claim).toMatch(/^none in M0/);
  });

  it("every entry is verified with tests, owned, or justified", () => {
    for (const [id, e] of Object.entries(criteria)) {
      if (e.status === "verified") expect((e.tests ?? []).length + (e.axe_rules ?? []).length, id).toBeGreaterThan(0);
      else if (e.status === "not_verified_in_M0") expect(e.owner, id).toMatch(/^M[0-9]-E[0-9]{2}-S[0-9]{2}$/);
      else expect([e.status, (e.reason ?? "").length > 5], id).toEqual(["not_applicable", true]);
    }
  });

  it("required criteria are verified", () => {
    for (const id of REQUIRED) expect(criteria[id]?.status, id).toBe("verified");
    expect(criteria["3.3.8"].status).toBe("not_verified_in_M0");
  });

  it("referenced tests exist", () => {
    for (const [id, e] of Object.entries(criteria)) for (const t of e.tests ?? []) expect(testExists(t), `${id}: ${t}`).toBe(true);
  });
});
