import type { Alert } from "./alerts";

export type LatencyStats = {
  count: number;
  p50: number | null;
  p95: number | null;
  max: number | null;
};

function percentile(sorted: number[], p: number): number | null {
  if (!sorted.length) return null;
  const idx = Math.min(
    sorted.length - 1,
    Math.max(0, Math.ceil((p / 100) * sorted.length) - 1),
  );
  return sorted[idx] ?? null;
}

/** Detection latency distribution from alert.latency_ms. */
export function latencyStats(alerts: Alert[]): LatencyStats {
  const values = alerts
    .map((a) => a.latency_ms)
    .filter((v): v is number => typeof v === "number" && Number.isFinite(v) && v >= 0)
    .sort((a, b) => a - b);
  if (!values.length) {
    return { count: 0, p50: null, p95: null, max: null };
  }
  return {
    count: values.length,
    p50: percentile(values, 50),
    p95: percentile(values, 95),
    max: values[values.length - 1] ?? null,
  };
}

export function formatMs(ms: number | null): string {
  if (ms == null) return "—";
  if (ms < 10) return `${ms.toFixed(1)} ms`;
  return `${Math.round(ms)} ms`;
}
