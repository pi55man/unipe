export type Severity = "low" | "medium" | "high";

export type ThreatClass =
  | "volumetric_ddos"
  | "ip_spoofing"
  | "c2_beaconing"
  | "dns_abuse"
  | "encrypted_anomaly"
  | "recon_scanning"
  | "data_exfiltration";

export type Alert = {
  schema_version: number;
  timestamp: number;
  detected_at: number;
  flow_id: string;
  threat_class: ThreatClass | string;
  subtype: string;
  severity: Severity | string;
  confidence: number;
  src_ip: string;
  src_port: number;
  dst_ip: string;
  dst_port: number;
  protocol: number;
  message: string;
  evidence: Record<string, unknown>;
  latency_ms?: number;
  /** aggregation / correlation (engine-added, optional for older logs) */
  incident_id?: string;
  occurrence_count?: number;
  incident_first_seen?: number;
  incident_last_seen?: number;
  contributing_subtypes?: string[];
  contributing_classes?: string[];
  escalation_reasons?: string[];
  related_incident_ids?: string[];
  correlation_hypothesis?: string;
  coverage?: string[];
};

export const THREAT_CLASSES: ThreatClass[] = [
  "volumetric_ddos",
  "ip_spoofing",
  "c2_beaconing",
  "dns_abuse",
  "encrypted_anomaly",
  "recon_scanning",
  "data_exfiltration",
];

export const SEVERITY_ORDER: Record<string, number> = {
  low: 0,
  medium: 1,
  high: 2,
};

export function threatColorVar(threatClass: string): string {
  switch (threatClass) {
    case "volumetric_ddos":
      return "var(--threat-volumetric)";
    case "ip_spoofing":
      return "var(--threat-spoofing)";
    case "c2_beaconing":
      return "var(--threat-beaconing)";
    case "dns_abuse":
      return "var(--threat-dns)";
    case "encrypted_anomaly":
    case "encrypted_malware": // legacy jsonl
      return "var(--threat-encrypted)";
    case "recon_scanning":
      return "var(--threat-scanning)";
    case "data_exfiltration":
      return "var(--threat-exfil)";
    default:
      return "var(--muted)";
  }
}

export function severityColorVar(severity: string): string {
  switch (severity) {
    case "high":
      return "var(--sev-high)";
    case "medium":
      return "var(--sev-med)";
    default:
      return "var(--sev-low)";
  }
}

export function sortAlerts(alerts: Alert[]): Alert[] {
  return [...alerts].sort((a, b) => {
    const sev =
      (SEVERITY_ORDER[b.severity] ?? 0) - (SEVERITY_ORDER[a.severity] ?? 0);
    if (sev !== 0) return sev;
    return b.confidence - a.confidence;
  });
}

export function formatTime(ts: number): string {
  const d = new Date(ts * 1000);
  return d.toLocaleTimeString([], {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
  });
}

export function shortClass(threatClass: string): string {
  return threatClass.replace(/_/g, " ");
}

export function rowKey(a: Alert, index?: number): string {
  // prefer stable engine fields; avoid hashing the full message on hot paths
  if (a.incident_id && a.detected_at != null) {
    return [
      a.incident_id,
      a.subtype,
      String(a.detected_at),
      String(a.occurrence_count ?? 1),
      index == null ? "" : String(index),
    ].join("|");
  }
  return [
    a.flow_id,
    a.subtype,
    String(a.timestamp),
    String(a.detected_at ?? ""),
    String(a.confidence),
    index == null ? "" : String(index),
  ].join("|");
}

/** Drop exact duplicate alert rows while preserving order. */
export function dedupeAlerts(alerts: Alert[]): Alert[] {
  const seen = new Set<string>();
  const out: Alert[] = [];
  for (let i = 0; i < alerts.length; i++) {
    const a = alerts[i]!;
    const k = rowKey(a);
    if (seen.has(k)) continue;
    seen.add(k);
    out.push(a);
  }
  return out;
}

/** Stable DOM id from a row key (pipes/spaces are invalid in HTML ids). */
export function alertDomId(key: string): string {
  return `alert-${key.replace(/[^a-zA-Z0-9_-]/g, "_")}`;
}
