import type { Alert } from "./alerts";

/** Fallback coverage notes when an alert predates engine `coverage` field. */
export function coverageForAlert(
  alert: Alert | null | undefined,
  status: Record<string, unknown> | null,
): string[] {
  if (alert?.coverage?.length) return alert.coverage;

  const notes: string[] = [
    "Passive monitoring only: the sensor cannot query hosts, complete handshakes, decrypt payloads, block traffic, or send mitigation.",
    "Application payload content is not available; only flow counters and handshake metadata are inspected.",
  ];

  const tap = (status?.tap as Record<string, unknown> | undefined) || {};
  if (tap.one_directional) {
    const msg = String(tap.message || "").trim();
    if (msg) notes.push(msg);
    notes.push(
      "Observed outbound/inbound ratio is based only on traffic visible to the sensor; reverse traffic is not available on this tap.",
    );
  }

  if (status?.coverage_degraded) {
    notes.push(
      "Sensor coverage is degraded — do not interpret silence as clean traffic.",
    );
  }
  const dropped = Number(status?.flows_dropped_cap ?? 0);
  if (dropped > 0) {
    notes.push(
      `Scoring backlog dropped ${dropped} flows this process (per-tick cap); absence of an alert is not assurance the network is safe.`,
    );
  }

  if (alert?.threat_class === "data_exfiltration") {
    notes.push(
      "Outbound/inbound byte ratios reflect only flows the sensor observed; missing reverse traffic can hide or invent asymmetry.",
    );
  }

  return notes;
}

export type HealthView = {
  mode: string;
  flowsIn: number;
  flowsScored: number;
  flowsDropped: number;
  flowsPerSec: number;
  capacityPerSec: number;
  worstBatchMs: number;
  alerts: number;
  /** file-replay only: total alerts in the loaded capture */
  replayTotal: number;
  coverageDegraded: boolean;
  tapOneWay: boolean;
  tapMessage: string;
  helloComplete: number;
  hellos: number;
  ja3: number;
  ja3s: number;
  blindSpots: string[];
  /** file-replay: high/medium/low counts among revealed alerts */
  sevHigh: number;
  sevMed: number;
  sevLow: number;
};

export function healthFromStatus(
  status: Record<string, unknown> | null,
  opts: {
    replayActive: boolean;
    engineReplay: boolean;
    live: boolean;
  },
): HealthView {
  const hs = (status?.handshakes as Record<string, unknown> | undefined) || {};
  const vis = (status?.visibility as Record<string, unknown> | undefined) || {};
  const blind = Array.isArray(vis.blind_spots)
    ? vis.blind_spots.map(String).filter((n) => !/one.?way|one-directional|directional/i.test(n))
    : [];
  const mode = opts.replayActive
    ? "file replay"
    : opts.engineReplay || status?.replay
      ? "engine replay"
      : opts.live
        ? "live"
        : "offline";
  return {
    mode,
    flowsIn: Number(status?.flows_in ?? 0),
    flowsScored: Number(status?.flows_scored ?? 0),
    flowsDropped: Number(status?.flows_dropped_cap ?? 0),
    flowsPerSec: Number(status?.flows_per_sec ?? 0),
    capacityPerSec: Number(status?.capacity_flows_per_sec ?? 0),
    worstBatchMs: Number(status?.worst_batch_ms ?? 0),
    alerts: Number(status?.alerts ?? 0),
    replayTotal: 0,
    coverageDegraded: Boolean(status?.coverage_degraded),
    // kept for schema compat; UI no longer surfaces one-way tap copy
    tapOneWay: false,
    tapMessage: "",
    helloComplete: Number(hs.complete ?? 0),
    hellos: Number(hs.hellos ?? 0),
    ja3: Number(hs.ja3 ?? 0),
    ja3s: Number(hs.ja3s ?? 0),
    blindSpots: blind,
    sevHigh: 0,
    sevMed: 0,
    sevLow: 0,
  };
}

/** Sensor panel view while scrubbing a loaded alerts JSONL (no live exporter metrics). */
export function healthFromFileReplay(
  revealed: { severity: string }[],
  totalInFile: number,
): HealthView {
  let sevHigh = 0;
  let sevMed = 0;
  let sevLow = 0;
  for (const a of revealed) {
    if (a.severity === "high") sevHigh += 1;
    else if (a.severity === "medium") sevMed += 1;
    else sevLow += 1;
  }
  return {
    mode: "file replay",
    flowsIn: 0,
    flowsScored: 0,
    flowsDropped: 0,
    flowsPerSec: 0,
    capacityPerSec: 0,
    worstBatchMs: 0,
    alerts: revealed.length,
    replayTotal: totalInFile,
    coverageDegraded: false,
    tapOneWay: false,
    tapMessage: "",
    helloComplete: 0,
    hellos: 0,
    ja3: 0,
    ja3s: 0,
    blindSpots: [],
    sevHigh,
    sevMed,
    sevLow,
  };
}
