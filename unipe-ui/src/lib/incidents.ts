import type { Alert } from "./alerts";
import { SEVERITY_ORDER, rowKey, shortClass } from "./alerts";

/** Correlated alert group — same victim within a time window. */
export type Incident = {
  id: string;
  victim: string;
  severity: string;
  subtypes: string[];
  threat_classes: string[];
  alert_count: number;
  start: number;
  end: number;
  duration_s: number;
  peak_confidence: number;
  peak_packet_rate: number | null;
  sample_message: string;
  alerts: Alert[];
};

const WINDOW_S = 300; // fold alerts to same victim within 5 minutes

function victimOf(a: Alert): string {
  if (a.dst_ip) return a.dst_ip;
  if (a.src_ip) return `src:${a.src_ip}`;
  return "(aggregate)";
}

function packetRate(a: Alert): number | null {
  const v = a.evidence?.packet_rate;
  return typeof v === "number" && Number.isFinite(v) ? v : null;
}

/** Group alerts into incidents by engine incident_id when present, else victim+time. */
export function buildIncidents(alerts: Alert[], windowSecs = WINDOW_S): Incident[] {
  const sorted = [...alerts].sort((a, b) => a.timestamp - b.timestamp);
  const open: Incident[] = [];
  const byVictim = new Map<string, Incident>();
  const byEngineId = new Map<string, Incident>();

  for (const alert of sorted) {
    const engineId = alert.incident_id?.trim();
    let hit: Incident | undefined;
    if (engineId) {
      hit = byEngineId.get(engineId);
    }
    const victim = victimOf(alert);
    if (!hit) {
      hit = byVictim.get(victim);
      if (!hit || alert.timestamp - hit.end > windowSecs) {
        hit = {
          id: engineId || `inc-${victim}-${alert.timestamp}`,
          victim,
          severity: alert.severity,
          subtypes: [],
          threat_classes: [],
          alert_count: 0,
          start: alert.timestamp,
          end: alert.timestamp,
          duration_s: 0,
          peak_confidence: 0,
          peak_packet_rate: null,
          sample_message: alert.message,
          alerts: [],
        };
        open.push(hit);
        byVictim.set(victim, hit);
      }
      if (engineId) byEngineId.set(engineId, hit);
    }
    hit.alerts.push(alert);
    hit.alert_count += 1;
    hit.end = Math.max(hit.end, alert.timestamp);
    hit.start = Math.min(hit.start, alert.timestamp);
    hit.duration_s = Math.max(0, hit.end - hit.start);
    if (!hit.subtypes.includes(alert.subtype)) hit.subtypes.push(alert.subtype);
    if (!hit.threat_classes.includes(alert.threat_class)) {
      hit.threat_classes.push(alert.threat_class);
    }
    if ((SEVERITY_ORDER[alert.severity] ?? 0) >= (SEVERITY_ORDER[hit.severity] ?? 0)) {
      hit.severity = alert.severity;
    }
    hit.peak_confidence = Math.max(hit.peak_confidence, alert.confidence);
    const pps = packetRate(alert);
    if (pps != null) {
      hit.peak_packet_rate =
        hit.peak_packet_rate == null ? pps : Math.max(hit.peak_packet_rate, pps);
    }
    if (alert.confidence >= hit.peak_confidence) {
      hit.sample_message = alert.message;
    }
  }

  return open.sort((a, b) => {
    const sev =
      (SEVERITY_ORDER[b.severity] ?? 0) - (SEVERITY_ORDER[a.severity] ?? 0);
    if (sev !== 0) return sev;
    return b.end - a.end;
  });
}

function csvEscape(value: string | number | null | undefined): string {
  const s = value == null ? "" : String(value);
  if (/[",\n\r]/.test(s)) return `"${s.replace(/"/g, '""')}"`;
  return s;
}

/** Incident report CSV for judges / handoff. */
export function incidentsToCsv(incidents: Incident[]): string {
  const header = [
    "incident_id",
    "severity",
    "victim",
    "threat_classes",
    "subtypes",
    "alert_count",
    "start_unix",
    "end_unix",
    "start_iso",
    "end_iso",
    "duration_s",
    "peak_confidence",
    "peak_packet_rate",
    "sample_message",
  ];
  const rows = incidents.map((inc) =>
    [
      inc.id,
      inc.severity,
      inc.victim,
      inc.threat_classes.map(shortClass).join("|"),
      inc.subtypes.join("|"),
      inc.alert_count,
      inc.start.toFixed(3),
      inc.end.toFixed(3),
      new Date(inc.start * 1000).toISOString(),
      new Date(inc.end * 1000).toISOString(),
      Math.round(inc.duration_s),
      inc.peak_confidence.toFixed(3),
      inc.peak_packet_rate != null ? Math.round(inc.peak_packet_rate) : "",
      inc.sample_message,
    ]
      .map(csvEscape)
      .join(","),
  );
  return [header.join(","), ...rows].join("\n") + "\n";
}

/** Flat alert CSV (one row per alert, with incident id). */
export function alertsToCsv(alerts: Alert[], incidents: Incident[]): string {
  const byKey = new Map<string, string>();
  for (const inc of incidents) {
    for (const a of inc.alerts) byKey.set(rowKey(a), inc.id);
  }
  const header = [
    "incident_id",
    "timestamp_iso",
    "severity",
    "threat_class",
    "subtype",
    "confidence",
    "src_ip",
    "src_port",
    "dst_ip",
    "dst_port",
    "protocol",
    "latency_ms",
    "message",
    "flow_id",
  ];
  const rows = alerts.map((a) =>
    [
      byKey.get(rowKey(a)) ?? "",
      new Date(a.timestamp * 1000).toISOString(),
      a.severity,
      a.threat_class,
      a.subtype,
      a.confidence.toFixed(3),
      a.src_ip,
      a.src_port || "",
      a.dst_ip,
      a.dst_port || "",
      a.protocol || "",
      a.latency_ms ?? "",
      a.message,
      a.flow_id,
    ]
      .map(csvEscape)
      .join(","),
  );
  return [header.join(","), ...rows].join("\n") + "\n";
}

export function suppressionsToCsv(
  rules: { id: string; kind: string; value: string; reason: string; created_at: number }[],
): string {
  const header = ["id", "kind", "value", "reason", "created_iso"];
  const rows = rules.map((r) =>
    [
      r.id,
      r.kind,
      r.value,
      r.reason,
      new Date(r.created_at * 1000).toISOString(),
    ]
      .map(csvEscape)
      .join(","),
  );
  return [header.join(","), ...rows].join("\n") + "\n";
}

export function downloadText(filename: string, body: string, mime: string) {
  const blob = new Blob([body], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}
