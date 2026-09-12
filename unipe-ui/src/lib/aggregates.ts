import type { Alert } from "./alerts";
import { THREAT_CLASSES } from "./alerts";

export type TimelineBucket = {
  start: number;
  label: string;
  high: number;
  medium: number;
  low: number;
  total: number;
};

export type ClassCount = {
  threat_class: string;
  count: number;
};

export type DestCount = {
  dst_ip: string;
  count: number;
};

export function buildTimeline(
  alerts: Alert[],
  bucketSecs = 60,
  buckets = 12,
): TimelineBucket[] {
  if (!alerts.length) {
    const now = Date.now() / 1000;
    return Array.from({ length: buckets }, (_, i) => {
      const start = now - (buckets - i) * bucketSecs;
      return { start, label: "", high: 0, medium: 0, low: 0, total: 0 };
    });
  }
  let newest = alerts[0]!.timestamp;
  for (const a of alerts) {
    if (a.timestamp > newest) newest = a.timestamp;
  }
  const end = Math.ceil(newest / bucketSecs) * bucketSecs;
  const start0 = end - buckets * bucketSecs;
  const highs = new Array<number>(buckets).fill(0);
  const mediums = new Array<number>(buckets).fill(0);
  const lows = new Array<number>(buckets).fill(0);

  for (const a of alerts) {
    if (a.timestamp < start0 || a.timestamp >= end) continue;
    const idx = Math.min(
      buckets - 1,
      Math.max(0, Math.floor((a.timestamp - start0) / bucketSecs)),
    );
    if (a.severity === "high") highs[idx]! += 1;
    else if (a.severity === "medium") mediums[idx]! += 1;
    else lows[idx]! += 1;
  }

  const out: TimelineBucket[] = [];
  for (let i = 0; i < buckets; i++) {
    const start = start0 + i * bucketSecs;
    const high = highs[i]!;
    const medium = mediums[i]!;
    const low = lows[i]!;
    const d = new Date(start * 1000);
    out.push({
      start,
      label: d.toLocaleTimeString([], {
        hour: "2-digit",
        minute: "2-digit",
        hour12: false,
      }),
      high,
      medium,
      low,
      total: high + medium + low,
    });
  }
  return out;
}

export function buildClassMix(alerts: Alert[]): ClassCount[] {
  const counts = new Map<string, number>();
  for (const c of THREAT_CLASSES) counts.set(c, 0);
  for (const a of alerts) {
    counts.set(a.threat_class, (counts.get(a.threat_class) ?? 0) + 1);
  }
  return [...counts.entries()]
    .map(([threat_class, count]) => ({ threat_class, count }))
    .filter((row) => row.count > 0)
    .sort((a, b) => b.count - a.count);
}

export function buildTopDestinations(alerts: Alert[], limit = 6): DestCount[] {
  const counts = new Map<string, number>();
  for (const a of alerts) {
    const ip = a.dst_ip || "(aggregate)";
    if (!ip) continue;
    counts.set(ip, (counts.get(ip) ?? 0) + 1);
  }
  return [...counts.entries()]
    .map(([dst_ip, count]) => ({ dst_ip, count }))
    .sort((a, b) => b.count - a.count)
    .slice(0, limit);
}

export function parseJsonl(text: string): Alert[] {
  const alerts: Alert[] = [];
  for (const line of text.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    try {
      const row = JSON.parse(trimmed) as Alert;
      if (row && typeof row === "object" && row.threat_class && row.message) {
        alerts.push(row);
      }
    } catch {
      // skip bad lines
    }
  }
  return alerts;
}
