import type { Alert } from "./alerts";

export type EntityAlertRef = {
  timestamp: number;
  threat_class: string;
  subtype: string;
  severity: string;
  confidence: number;
  message: string;
  incident_id?: string;
  peer_ip?: string;
};

export type EntityPartner = {
  first_seen: number;
  last_seen: number;
  count: number;
};

export type EntityDossier = {
  ip: string;
  first_seen: number;
  last_seen: number;
  threat_classes: string[];
  severity: string;
  priority: string;
  partners: Record<string, EntityPartner>;
  ports: Record<string, number>;
  domains: Record<string, number>;
  alerts: EntityAlertRef[];
  alert_count: number;
  flow_observations: number;
};

export type EntitiesFile = {
  schema_version: number;
  updated_at: number;
  entity_count: number;
  entities: Record<string, EntityDossier>;
};

export function parseEntities(raw: unknown): Record<string, EntityDossier> {
  if (!raw || typeof raw !== "object") return {};
  const ents = (raw as EntitiesFile).entities;
  if (!ents || typeof ents !== "object") return {};
  const out: Record<string, EntityDossier> = {};
  for (const [ip, ent] of Object.entries(ents)) {
    if (!ent || typeof ent !== "object") continue;
    out[ip] = {
      ip,
      first_seen: Number(ent.first_seen) || 0,
      last_seen: Number(ent.last_seen) || 0,
      threat_classes: Array.isArray(ent.threat_classes)
        ? ent.threat_classes.map(String)
        : [],
      severity: String(ent.severity || "low"),
      priority: String(ent.priority || "low"),
      partners: (ent.partners as Record<string, EntityPartner>) || {},
      ports: (ent.ports as Record<string, number>) || {},
      domains: (ent.domains as Record<string, number>) || {},
      alerts: Array.isArray(ent.alerts) ? (ent.alerts as EntityAlertRef[]) : [],
      alert_count: Number(ent.alert_count) || 0,
      flow_observations: Number(ent.flow_observations) || 0,
    };
  }
  return out;
}

export function topPartners(
  ent: EntityDossier,
  n = 8,
): { ip: string; count: number; last_seen: number }[] {
  return Object.entries(ent.partners)
    .map(([ip, p]) => ({
      ip,
      count: Number(p.count) || 0,
      last_seen: Number(p.last_seen) || 0,
    }))
    .sort((a, b) => b.count - a.count || b.last_seen - a.last_seen)
    .slice(0, n);
}

function bumpPriority(severity: string, alertCount: number, threatN: number): string {
  const rank = severity === "high" ? 2 : severity === "medium" ? 1 : 0;
  if (rank >= 2 && (alertCount >= 2 || threatN >= 2)) return "critical";
  if (rank >= 2 || (rank >= 1 && alertCount >= 3)) return "high";
  if (rank >= 1 || alertCount >= 1) return "medium";
  return "low";
}

/** Build dossiers from the in-memory alert list when the engine file is absent. */
export function dossiersFromAlerts(
  alerts: Alert[],
): Record<string, EntityDossier> {
  const out: Record<string, EntityDossier> = {};

  const touch = (ip: string, ts: number): EntityDossier => {
    let ent = out[ip];
    if (!ent) {
      ent = {
        ip,
        first_seen: ts,
        last_seen: ts,
        threat_classes: [],
        severity: "low",
        priority: "low",
        partners: {},
        ports: {},
        domains: {},
        alerts: [],
        alert_count: 0,
        flow_observations: 0,
      };
      out[ip] = ent;
    }
    ent.first_seen = Math.min(ent.first_seen || ts, ts);
    ent.last_seen = Math.max(ent.last_seen || ts, ts);
    return ent;
  };

  for (const a of alerts) {
    const ts = Number(a.timestamp) || 0;
    const src = (a.src_ip || "").trim();
    const dst = (a.dst_ip || "").trim();
    const ips = [src, dst].filter(
      (ip) => ip && ip !== "*" && ip !== "0.0.0.0",
    );

    for (const ip of ips) {
      const ent = touch(ip, ts);
      const peer = ip === src ? dst : src;
      if (peer && peer !== "*" && peer !== ip) {
        const slot = ent.partners[peer] || {
          first_seen: ts,
          last_seen: ts,
          count: 0,
        };
        slot.last_seen = Math.max(slot.last_seen, ts);
        slot.count += 1;
        ent.partners[peer] = slot;
      }
      if (a.dst_port) {
        const key = `${a.protocol || 0}/${a.dst_port}`;
        ent.ports[key] = (ent.ports[key] || 0) + 1;
      }
      const qname = a.evidence?.qname;
      if (typeof qname === "string" && qname) {
        ent.domains[qname.toLowerCase()] = ts;
      }
      if (a.threat_class && !ent.threat_classes.includes(a.threat_class)) {
        ent.threat_classes.push(a.threat_class);
      }
      const sev = a.severity || "low";
      const order = { low: 0, medium: 1, high: 2 } as Record<string, number>;
      if ((order[sev] ?? 0) >= (order[ent.severity] ?? 0)) ent.severity = sev;
      ent.alerts.push({
        timestamp: ts,
        threat_class: a.threat_class,
        subtype: a.subtype,
        severity: sev,
        confidence: a.confidence,
        message: a.message,
        incident_id: a.incident_id,
        peer_ip: peer && peer !== "*" ? peer : "",
      });
      if (ent.alerts.length > 40) ent.alerts = ent.alerts.slice(-40);
      ent.alert_count += 1;
      ent.priority = bumpPriority(
        ent.severity,
        ent.alert_count,
        ent.threat_classes.length,
      );
    }
  }
  return out;
}

/** Build a single IP dossier from alerts (avoids scanning every IP on each render). */
export function dossierForIp(
  ip: string,
  alerts: Alert[],
): EntityDossier | null {
  if (!ip) return null;
  const all = dossiersFromAlerts(
    alerts.filter((a) => a.src_ip === ip || a.dst_ip === ip),
  );
  return all[ip] ?? null;
}
