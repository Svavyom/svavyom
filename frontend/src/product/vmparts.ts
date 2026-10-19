import type { VM } from "../api/schema";

/** A rate sampled in KiB per second, in the unit a person reads (KiB/s below 1 MiB/s). */
export const formatRate = (kib: number): string => (kib >= 1024 ? `${(kib / 1024).toFixed(1)} MiB/s` : `${kib} KiB/s`);

export const POWER_LABEL: Record<VM["observed"]["power"], string> = {
  running: "Running", stopped: "Stopped", paused: "Paused", crashed: "Crashed", unknown: "Unknown",
};

export const POWER_TONE: Record<VM["observed"]["power"], "ok" | "warn" | "bad" | "neutral"> = {
  running: "ok", stopped: "neutral", paused: "warn", crashed: "bad", unknown: "warn",
};
