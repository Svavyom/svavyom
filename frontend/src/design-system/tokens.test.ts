import { describe, expect, it } from "vitest";
import css from "./design-system.css?raw";
import { colors, contrast, contrastPairs, type Scheme } from "./tokens";

const kebab = (t: string) => t.replace(/[A-Z]/g, (c) => "-" + c.toLowerCase());

function cssVars(block: string): Record<string, string> {
  const out: Record<string, string> = {};
  for (const m of block.matchAll(/--([a-z-]+):\s*(#[0-9a-f]{6})/gi)) out[m[1]] = m[2].toLowerCase();
  return out;
}

describe("design tokens", () => {
  it("every token pair meets its contrast threshold", () => {
    for (const scheme of Object.keys(colors) as Scheme[]) {
      for (const [fg, bg, min] of contrastPairs) {
        expect(contrast(colors[scheme][fg], colors[scheme][bg]), `${scheme} ${fg} on ${bg}`).toBeGreaterThanOrEqual(min);
      }
    }
  });

  it("css variables equal the tokens in light, system-dark and chosen-dark", () => {
    const light = cssVars(css.split("@media (prefers-color-scheme: dark)")[0]);
    const system = cssVars(css.split("@media (prefers-color-scheme: dark)")[1].split(':root[data-theme="dark"]')[0]);
    const chosen = cssVars(css.split(':root[data-theme="dark"]')[1]);
    for (const token of Object.keys(colors.light)) {
      const name = kebab(token);
      expect(light[name], `light --${name}`).toBe(colors.light[token as keyof typeof colors.light]);
      expect(system[name], `system dark --${name}`).toBe(colors.dark[token as keyof typeof colors.dark]);
      expect(chosen[name], `chosen dark --${name}`).toBe(colors.dark[token as keyof typeof colors.dark]);
    }
  });

  it("an operator who chose Light keeps light colours under a dark system setting", () => {
    expect(css).toMatch(/@media \(prefers-color-scheme: dark\) \{\s*:root:not\(\[data-theme="light"\]\)/);
  });

  it("uses bundled fonts with a system fallback, rem type and no remote assets", () => {
    expect(css).not.toMatch(/@import|url\(|@font-face|https?:/);
    expect(css).toMatch(/--font: "Manrope", system-ui/);
    expect(css).toMatch(/prefers-reduced-motion/);
  });
});
