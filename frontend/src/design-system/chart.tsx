// Usage chart (DR-022): a small time-series line chart drawn as inline SVG with no library. Colours come from the theme classes in the
// stylesheet (never an inline style), every value carries a text equivalent, and a series with no points says so instead of drawing a line.
import type { ReactNode } from "react";

export interface ChartPoint { at: string; value: number }
export interface ChartSeries { id: "cpu" | "mem"; label: string; points: ReadonlyArray<ChartPoint> }

const W = 640, H = 140, LEFT = 0, RIGHT = 0, TOP = 3, BOTTOM = 3;

function pathFor(points: ReadonlyArray<ChartPoint>, t0: number, t1: number): { line: string; area: string; last: [number, number] } | null {
  if (points.length === 0) return null;
  const span = Math.max(1, t1 - t0);
  const xy = points.map((p) => {
    const x = LEFT + ((Date.parse(p.at) - t0) / span) * (W - LEFT - RIGHT);
    const y = TOP + (1 - Math.min(100, Math.max(0, p.value)) / 100) * (H - TOP - BOTTOM);
    return [Math.round(x * 10) / 10, Math.round(y * 10) / 10] as [number, number];
  });
  const line = xy.map(([x, y], i) => `${i === 0 ? "M" : "L"}${x} ${y}`).join(" ");
  const base = H - BOTTOM;
  return { line, area: `${line} L${xy[xy.length - 1]![0]} ${base} L${xy[0]![0]} ${base} Z`, last: xy[xy.length - 1]! };
}

export function summarize(points: ReadonlyArray<ChartPoint>): { now: number; avg: number; peak: number } | null {
  if (points.length === 0) return null;
  const vals = points.map((p) => p.value);
  return { now: vals[vals.length - 1]!, avg: Math.round(vals.reduce((a, b) => a + b, 0) / vals.length), peak: Math.max(...vals) };
}

function clock(ms: number): string {
  const d = new Date(ms);
  return `${String(d.getUTCHours()).padStart(2, "0")}:${String(d.getUTCMinutes()).padStart(2, "0")}`;
}

/** A percentage chart (0-100) over the span of the given series. `label` names the chart; the text under it carries the same numbers. */
export function UsageChart({ label, series, empty }: { label: string; series: ReadonlyArray<ChartSeries>; empty: ReactNode }) {
  const all = series.flatMap((s) => s.points.map((p) => Date.parse(p.at)));
  if (all.length === 0) return <p className="ds-chart-empty">{empty}</p>;
  const t0 = Math.min(...all), t1 = Math.max(...all);
  const paths = series.map((s) => ({ s, p: pathFor(s.points, t0, t1) }));
  const text = series.map((s) => {
    const m = summarize(s.points);
    return m ? `${s.label}: now ${m.now}%, average ${m.avg}%, peak ${m.peak}%` : `${s.label}: no samples`;
  }).join(". ");
  const mid = Math.round((t0 + t1) / 2);
  return (
    <figure className="ds-chart-figure">
      <ul className="ds-legend" aria-label="Legend">
        {series.map((s) => <li key={s.id} className={s.id === "mem" ? "mem" : ""}>{s.label}</li>)}
      </ul>
      <div className="ds-chart-grid-layout">
        <div className="ds-chart-y" aria-hidden="true"><span>100%</span><span>50%</span><span>0%</span></div>
        <svg className="ds-chart" viewBox={`0 0 ${W} ${H}`} role="img" aria-label={`${label}. ${text}.`} preserveAspectRatio="none">
          {[0, 50, 100].map((g) => {
            const y = TOP + (1 - g / 100) * (H - TOP - BOTTOM);
            return <line key={g} className="ds-chart-grid" x1={LEFT} x2={W - RIGHT} y1={y} y2={y} vectorEffect="non-scaling-stroke" />;
          })}
          {paths.map(({ s, p }) => p ? (
            <g key={s.id}>
              <path className={`ds-chart-fill ds-chart-fill--${s.id}`} d={p.area} />
              <path className={`ds-chart-line ds-chart-line--${s.id}`} d={p.line} vectorEffect="non-scaling-stroke" />
            </g>
          ) : null)}
        </svg>
        <div className="ds-chart-x-spacer" aria-hidden="true" />
        <div className="ds-chart-x" aria-hidden="true"><span>{clock(t0)}</span><span>{clock(mid)}</span><span>{clock(t1)}</span></div>
      </div>
      <figcaption className="ds-chart-caption">{text}. Times are UTC.</figcaption>
    </figure>
  );
}
