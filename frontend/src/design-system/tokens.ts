// Design tokens (M0-E02-S06 r5 section 2). The same values are declared as CSS custom properties in
// design-system.css; a unit test checks both agree and that every pairing meets its contrast threshold.
export const colors = {
  light: {
    bg: "#eef1f6", surface: "#ffffff", text: "#162033", textMuted: "#4a5a73", border: "#66758c", line: "#dde3ec",
    primary: "#1a67d2", onPrimary: "#ffffff", primarySoft: "#e3eefc", danger: "#b3261e", onDanger: "#ffffff",
    focus: "#1a67d2", success: "#0f7a43", warning: "#8a5200", link: "#1a67d2",
    okSoft: "#dff4e8", warnSoft: "#fdf0d6", badSoft: "#fbe3e6", off: "#4a5a73", offSoft: "#e3e8f0",
    sideBg: "#0f1a2e", sideText: "#b8c4da", sideActive: "#1d2d4a", onSide: "#ffffff",
  },
  dark: {
    bg: "#0b1322", surface: "#121d31", text: "#e6ecf7", textMuted: "#a3b1c8", border: "#7d8da8", line: "#243453",
    primary: "#5aa2ff", onPrimary: "#06142b", primarySoft: "#1b2f52", danger: "#ff8f9b", onDanger: "#3a0a08",
    focus: "#5aa2ff", success: "#43d08a", warning: "#f0b24a", link: "#5aa2ff",
    okSoft: "#12372a", warnSoft: "#3b2d10", badSoft: "#401a21", off: "#a3b1c8", offSoft: "#1e2c47",
    sideBg: "#08101e", sideText: "#aebdd6", sideActive: "#16253f", onSide: "#ffffff",
  },
} as const;

export type Scheme = keyof typeof colors;
export type ColorToken = keyof typeof colors.light;

/** Pairs that must meet a contrast ratio: [foreground, background, minimum]. 4.5 text, 3 UI/focus/large. */
export const contrastPairs: ReadonlyArray<readonly [ColorToken, ColorToken, number]> = [
  ["text", "bg", 4.5], ["text", "surface", 4.5], ["textMuted", "bg", 4.5], ["textMuted", "surface", 4.5],
  ["onPrimary", "primary", 4.5], ["onDanger", "danger", 4.5], ["link", "bg", 4.5], ["link", "surface", 4.5],
  ["success", "bg", 4.5], ["warning", "bg", 4.5], ["danger", "bg", 4.5], ["success", "surface", 4.5], ["warning", "surface", 4.5], ["danger", "surface", 4.5],
  ["success", "okSoft", 4.5], ["warning", "warnSoft", 4.5], ["danger", "badSoft", 4.5], ["off", "offSoft", 4.5],
  ["primary", "primarySoft", 4.5], ["text", "primarySoft", 4.5],
  ["sideText", "sideBg", 4.5], ["sideText", "sideActive", 4.5], ["onSide", "sideActive", 4.5], ["onSide", "sideBg", 4.5],
  ["border", "bg", 3], ["border", "surface", 3], ["focus", "bg", 3], ["focus", "surface", 3], ["primary", "bg", 3], ["primary", "surface", 3],
];

export const space = { xs: "0.25rem", sm: "0.5rem", md: "1rem", lg: "1.5rem", xl: "2rem" } as const;
export const typeScale = { sm: "0.875rem", base: "1rem", lg: "1.25rem", xl: "1.5rem", xxl: "2rem" } as const;
export const radius = "0.625rem";
export const focusRing = { width: "2px", offset: "2px" } as const;
/** Layout widths (CSS px). 320 px is the reflow test width, not a breakpoint. */
export const layoutWidths = [768, 1024, 1440] as const;
export const minTargetPx = 24;
/** Loading indicators appear only after this delay (no flash); the text status is always present. */
export const loadingIndicatorDelayMs = 300;

function channel(c: number): number {
  const s = c / 255;
  return s <= 0.03928 ? s / 12.92 : Math.pow((s + 0.055) / 1.055, 2.4);
}

export function luminance(hex: string): number {
  const m = /^#([0-9a-f]{2})([0-9a-f]{2})([0-9a-f]{2})$/i.exec(hex);
  if (!m) throw new Error("bad colour " + hex);
  const [r, g, b] = [m[1], m[2], m[3]].map((h) => channel(parseInt(h, 16)));
  return 0.2126 * r + 0.7152 * g + 0.0722 * b;
}

/** WCAG 2.x contrast ratio. */
export function contrast(a: string, b: string): number {
  const [hi, lo] = [luminance(a), luminance(b)].sort((x, y) => y - x);
  return (hi + 0.05) / (lo + 0.05);
}
