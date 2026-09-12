"use client";

import type { Alert } from "@/lib/alerts";
import {
  formatTime,
  severityColorVar,
  shortClass,
  threatColorVar,
} from "@/lib/alerts";
import { formatEvidence } from "@/lib/evidence";
import type { Incident } from "@/lib/incidents";
import { thresholdBreadcrumbs } from "@/lib/thresholds";
import { memo } from "react";

type Props = {
  alert: Alert | null;
  incident?: Incident | null;
  pinned?: boolean;
  onSelectIp?: (ip: string) => void;
};

function Meter({
  label,
  value,
  max = 1,
  display,
}: {
  label: string;
  value: number;
  max?: number;
  display?: string;
}) {
  const pct = Math.max(0, Math.min(100, (value / max) * 100));
  return (
    <div className="space-y-1">
      <div className="flex justify-between font-mono text-xs text-muted">
        <span>{label}</span>
        <span>{display ?? value.toFixed(3)}</span>
      </div>
      <div className="h-1.5 bg-line">
        <div className="h-full bg-foreground/60" style={{ width: `${pct}%` }} />
      </div>
    </div>
  );
}

function IpLink({
  ip,
  port,
  onSelectIp,
}: {
  ip: string;
  port?: number;
  onSelectIp?: (ip: string) => void;
}) {
  if (!ip || ip === "*") {
    return (
      <span>
        *{port ? `:${port}` : ""}
      </span>
    );
  }
  if (!onSelectIp) {
    return (
      <span>
        {ip}
        {port ? `:${port}` : ""}
      </span>
    );
  }
  return (
    <button
      type="button"
      onClick={() => onSelectIp(ip)}
      className="text-left text-accent underline-offset-2 hover:underline"
      title={`open entity dossier for ${ip}`}
    >
      {ip}
      {port ? `:${port}` : ""}
    </button>
  );
}

function EvidenceExtras({ alert }: { alert: Alert }) {
  const e = alert.evidence;
  if (alert.subtype === "periodic_beacon") {
    const jitter = Number(e.jitter_ratio ?? 0);
    const mean = Number(e.mean_interval_s ?? 0);
    return (
      <div className="mt-5 space-y-3 border-t border-line pt-4">
        <p className="text-sm font-medium text-foreground">beacon shape</p>
        <div className="grid grid-cols-3 gap-3 font-mono text-base">
          <div>
            <p className="text-xs text-muted">interval</p>
            <p>{mean.toFixed(1)}s</p>
          </div>
          <div>
            <p className="text-xs text-muted">jitter</p>
            <p>{(jitter * 100).toFixed(0)}%</p>
          </div>
          <div>
            <p className="text-xs text-muted">windows</p>
            <p>{String(e.interval_count ?? "—")}</p>
          </div>
        </div>
        <Meter
          label="regularity (1 − jitter)"
          value={1 - jitter}
          display={`${((1 - jitter) * 100).toFixed(0)}%`}
        />
      </div>
    );
  }
  if (alert.subtype === "dga_domain") {
    return (
      <div className="mt-5 space-y-3 border-t border-line pt-4">
        <p className="text-sm font-medium text-foreground">name stats</p>
        <Meter
          label="DGA model score"
          value={Number(e.dns_ml_probability ?? 0)}
          display={`${(Number(e.dns_ml_probability ?? 0) * 100).toFixed(0)}%`}
        />
        <Meter
          label="letter-pair familiarity"
          value={Number(e.bigram_familiarity ?? 0)}
          display={`${(Number(e.bigram_familiarity ?? 0) * 100).toFixed(0)}%`}
        />
        <Meter
          label="name entropy"
          value={Number(e.normalized_entropy ?? 0)}
        />
      </div>
    );
  }
  if (alert.subtype === "dns_tunnel") {
    return (
      <div className="mt-5 grid grid-cols-2 gap-3 border-t border-line pt-4 font-mono">
        <div>
          <p className="text-xs text-muted">query name length</p>
          <p className="text-3xl tabular-nums">{String(e.qname_len ?? "—")}</p>
        </div>
        <div>
          <p className="text-xs text-muted">DNS labels</p>
          <p className="text-3xl tabular-nums">{String(e.label_count ?? "—")}</p>
        </div>
      </div>
    );
  }
  if (
    alert.subtype === "syn_flood" ||
    alert.subtype === "udp_flood" ||
    alert.subtype === "icmp_flood" ||
    alert.subtype === "fan_in_flood"
  ) {
    return (
      <div className="mt-5 grid grid-cols-2 gap-3 border-t border-line pt-4 font-mono">
        <div>
          <p className="text-xs text-muted">distinct sources</p>
          <p className="text-3xl tabular-nums">
            {String(e.unique_sources ?? "—")}
          </p>
        </div>
        <div>
          <p className="text-xs text-muted">packet rate</p>
          <p className="text-3xl tabular-nums">
            {e.packet_rate != null
              ? `${Number(e.packet_rate).toFixed(0)}/s`
              : "—"}
          </p>
        </div>
      </div>
    );
  }
  return null;
}

export const AlertDetail = memo(function AlertDetail({
  alert,
  incident = null,
  pinned = false,
  onSelectIp,
}: Props) {
  if (incident && !alert) {
    return (
      <section
        className="flex min-h-0 flex-[0.45] flex-col bg-panel"
        aria-label="incident evidence"
      >
        <div className="shrink-0 border-b border-line px-5 py-3.5">
          <div className="flex items-center gap-2">
            <span
              className="font-mono text-xs uppercase tracking-wide"
              style={{ color: severityColorVar(incident.severity) }}
            >
              {incident.severity}
            </span>
            <span className="text-sm text-foreground">incident</span>
            <span className="ml-auto font-mono text-xs text-muted">
              {incident.alert_count} alerts
            </span>
          </div>
          <p className="mt-2 font-mono text-xs text-muted">
            <IpLink
              ip={incident.victim.startsWith("src:") ? incident.victim.slice(4) : incident.victim}
              onSelectIp={onSelectIp}
            />
          </p>
        </div>
        <div className="min-h-0 flex-1 overflow-y-auto px-5 py-5">
          <p className="text-base leading-7 text-foreground">
            {incident.sample_message}
          </p>
          <div className="mt-5 grid grid-cols-2 gap-x-5 gap-y-3 border-t border-line pt-4 font-mono text-xs">
            <div>
              <span className="text-muted">start</span>
              <p className="text-sm text-foreground">{formatTime(incident.start)}</p>
            </div>
            <div>
              <span className="text-muted">end</span>
              <p className="text-sm text-foreground">{formatTime(incident.end)}</p>
            </div>
            <div>
              <span className="text-muted">duration</span>
              <p className="text-sm text-foreground">{Math.round(incident.duration_s)}s</p>
            </div>
            <div>
              <span className="text-muted">peak confidence</span>
              <p className="text-sm text-foreground">
                {(incident.peak_confidence * 100).toFixed(0)}%
              </p>
            </div>
            <div>
              <span className="text-muted">peak packet rate</span>
              <p className="text-sm text-foreground">
                {incident.peak_packet_rate != null
                  ? `${Math.round(incident.peak_packet_rate)} pps`
                  : "—"}
              </p>
            </div>
            <div>
              <span className="text-muted">classes</span>
              <p className="text-sm text-foreground">
                {incident.threat_classes.map(shortClass).join(", ")}
              </p>
            </div>
          </div>
          <div className="mt-5 border-t border-line pt-4">
            <p className="mb-3 text-sm font-medium text-foreground">
              correlated subtypes
            </p>
            <ul className="space-y-1 font-mono text-xs text-muted">
              {incident.subtypes.map((s) => (
                <li key={s}>{s}</li>
              ))}
            </ul>
          </div>
          <div className="mt-5 border-t border-line pt-4">
            <p className="mb-3 text-sm font-medium text-foreground">
              member alerts
            </p>
            <ul className="space-y-2">
              {incident.alerts.map((a, i) => (
                <li
                  key={`${a.incident_id || ""}|${a.flow_id}|${a.subtype}|${a.timestamp}|${a.detected_at}|${i}`}
                  className="text-sm"
                >
                  <span
                    className="font-mono text-xs uppercase"
                    style={{ color: severityColorVar(a.severity) }}
                  >
                    {a.severity}
                  </span>{" "}
                  <span className="font-mono text-xs text-muted">{a.subtype}</span>
                  <p className="truncate text-muted">{a.message}</p>
                </li>
              ))}
            </ul>
          </div>
        </div>
      </section>
    );
  }

  if (!alert) {
    return (
      <section
        className="flex min-h-0 flex-[0.45] flex-col bg-panel"
        aria-label="evidence"
      >
        <div className="border-b border-line px-5 py-3.5">
          <p className="text-sm font-medium text-foreground">evidence</p>
        </div>
        <p className="px-5 py-10 font-mono text-sm text-muted">
          select an alert to inspect evidence
        </p>
      </section>
    );
  }

  const rows = formatEvidence(alert.evidence);

  return (
    <section
      className="flex min-h-0 flex-[0.45] flex-col bg-panel"
      aria-label="alert evidence"
    >
      <div className="shrink-0 border-b border-line px-5 py-3.5">
        <div className="flex items-center gap-2">
          {pinned ? (
            <span className="font-mono text-[10px] text-accent" title="pinned">
              ◆
            </span>
          ) : null}
          <span
            className="font-mono text-xs uppercase tracking-wide"
            style={{ color: severityColorVar(alert.severity) }}
          >
            {alert.severity}
          </span>
          <span
            className="h-2 w-2 rounded-full"
            style={{ background: threatColorVar(alert.threat_class) }}
            aria-hidden
          />
          <span className="text-sm text-foreground">
            {shortClass(alert.threat_class)} / {alert.subtype}
          </span>
          <span className="ml-auto font-mono text-xs text-muted">
            conf {(alert.confidence * 100).toFixed(0)}%
          </span>
        </div>
        <p className="mt-2 font-mono text-xs break-all text-muted">
          {alert.flow_id}
        </p>
      </div>

      <div className="min-h-0 flex-1 overflow-y-auto px-5 py-5">
        <p className="text-base leading-7 text-foreground">{alert.message}</p>

        {(() => {
          const crumbs = thresholdBreadcrumbs(alert);
          if (!crumbs.length) return null;
          return (
            <ul className="mt-3 space-y-1 border-l-2 border-accent/40 pl-3">
              {crumbs.map((c) => (
                <li key={`${c.label}:${c.text}`} className="font-mono text-[11px] text-muted">
                  <span className="text-foreground/70">{c.label}</span>
                  {" · "}
                  {c.text}
                </li>
              ))}
            </ul>
          );
        })()}

        {(alert.incident_id || alert.occurrence_count) && (
          <div className="mt-4 border border-line bg-background-wash/30 px-3 py-2 font-mono text-[11px] text-muted">
            <p>
              incident{" "}
              <span className="text-foreground">{alert.incident_id || "—"}</span>
              {alert.occurrence_count != null ? (
                <>
                  {" "}
                  · seen{" "}
                  <span className="text-foreground">{alert.occurrence_count}×</span>
                </>
              ) : null}
            </p>
            {alert.incident_first_seen != null ? (
              <p className="mt-0.5">
                first {formatTime(alert.incident_first_seen)}
                {alert.incident_last_seen != null
                  ? ` · last ${formatTime(alert.incident_last_seen)}`
                  : ""}
              </p>
            ) : null}
            {alert.escalation_reasons?.length ? (
              <p className="mt-0.5">
                change{" "}
                <span className="text-foreground">
                  {alert.escalation_reasons.join(", ")}
                </span>
              </p>
            ) : null}
            {alert.contributing_subtypes?.length ? (
              <p className="mt-0.5">
                contributing{" "}
                <span className="text-foreground">
                  {alert.contributing_subtypes.join(", ")}
                </span>
              </p>
            ) : null}
            {alert.correlation_hypothesis ? (
              <p className="mt-1 leading-4 text-sev-med">
                {alert.correlation_hypothesis}
              </p>
            ) : null}
          </div>
        )}

        <div className="mt-5 grid grid-cols-2 gap-x-5 gap-y-3 border-t border-line pt-4 font-mono text-xs">
          <div>
            <span className="text-muted">time</span>
            <p className="text-sm text-foreground">{formatTime(alert.timestamp)}</p>
          </div>
          <div>
            <span className="text-muted">detect latency</span>
            <p className="text-sm text-foreground">
              {alert.latency_ms != null ? `${alert.latency_ms} ms` : "—"}
            </p>
          </div>
          <div>
            <span className="text-muted">source</span>
            <p className="text-sm text-foreground">
              <IpLink
                ip={alert.src_ip || "*"}
                port={alert.src_port || undefined}
                onSelectIp={onSelectIp}
              />
            </p>
          </div>
          <div>
            <span className="text-muted">destination</span>
            <p className="text-sm text-foreground">
              <IpLink
                ip={alert.dst_ip || "*"}
                port={alert.dst_port || undefined}
                onSelectIp={onSelectIp}
              />
            </p>
          </div>
          <div>
            <span className="text-muted">protocol</span>
            <p className="text-sm text-foreground">{alert.protocol || "*"}</p>
          </div>
        </div>

        <EvidenceExtras alert={alert} />

        <div className="mt-5 border-t border-line pt-4">
          <p className="mb-3 text-sm font-medium text-foreground">evidence</p>
          {rows.length === 0 ? (
            <p className="font-mono text-xs text-muted">no structured evidence</p>
          ) : (
            <dl className="space-y-2.5">
              {rows.map((row) => (
                <div
                  key={row.key}
                  className="grid grid-cols-[minmax(0,11rem)_1fr] gap-3 text-sm"
                >
                  <dt className="text-foreground">{row.label}</dt>
                  <dd className="break-all font-mono text-foreground">
                    {row.value}
                  </dd>
                </div>
              ))}
            </dl>
          )}
        </div>
      </div>
    </section>
  );
});
