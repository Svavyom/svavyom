import AxeBuilder from "@axe-core/playwright";
import type { Page } from "@playwright/test";

export const WCAG_TAGS = ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22a", "wcag22aa"];

/** Browser tier: zero violations AND no unresolved `incomplete` results (r5 section 3). */
export async function axe(page: Page) {
  const r = await new AxeBuilder({ page }).withTags(WCAG_TAGS).analyze();
  return {
    violations: r.violations.map((v) => `${v.id}: ${v.nodes.map((n) => n.target.join(" ")).join(", ")}`),
    incomplete: r.incomplete.map((v) => `${v.id}: ${v.nodes.map((n) => n.target.join(" ")).join(", ")}`),
  };
}
