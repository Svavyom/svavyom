import fs from "node:fs";
const manifest = JSON.parse(fs.readFileSync(new URL("../src/design-system/states.json", import.meta.url), "utf8"));
export const STATES: Array<[string, string]> = Object.entries(manifest.primitives as Record<string, string[]>)
  .flatMap(([p, ss]) => ss.map((s) => [p, s] as [string, string]));
