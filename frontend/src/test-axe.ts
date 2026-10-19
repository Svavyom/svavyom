// axe-core in jsdom (unit tier). jsdom has no layout, so colour-contrast and other layout rules come back as
// `incomplete` here; r5 section 3 defers those to the browser tier, which runs the same states in Chromium.
import axe from "axe-core";

export const WCAG_TAGS = ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22a", "wcag22aa"];

export async function axeViolations(root: Element): Promise<string[]> {
  const res = await axe.run(root, { runOnly: { type: "tag", values: WCAG_TAGS }, resultTypes: ["violations"] });
  return res.violations.map((v) => `${v.id}: ${v.nodes.map((n) => n.target.join(" ")).join(", ")}`);
}
