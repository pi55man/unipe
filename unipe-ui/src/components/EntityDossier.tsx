"use client";

import { memo } from "react";
import { formatTime, shortClass, severityColorVar } from "@/lib/alerts";
import { topPartners, type EntityDossier } from "@/lib/entities";

type Props = {
  entity: EntityDossier | null;
  ip: string;
  onSelectIp?: (ip: string) => void;
  onClose: () => void;
};

function EntityDossierPanelInner({ entity, ip, onSelectIp, onClose }: Props) {
  const partners = entity ? topPartners(entity, 10) : [];
  const ports = entity
    ? Object.entries(entity.ports)
        .sort((a, b) => b[1] - a[1])
        .slice(0, 8)
    : [];
  const domains = entity
    ? Object.entries(entity.domains)
        .sort((a, b) => Number(b[1]) - Number(a[1]))
        .slice(0, 8)
    : [];
  const history = entity
    ? [...entity.alerts].reverse().slice(0, 15)
    : [];

  return (
    <section
      className="flex min-h-0 flex-[0.45] flex-col bg-panel"
      aria-label="entity dossier"
    >
      <div className="shrink-0 border-b border-line px-5 py-3.5">
        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={onClose}
            className="font-mono text-[11px] text-muted underline-offset-2 hover:underline"
          >
            ← alert
          </button>
          <span className="font-mono text-xs text-muted">entity</span>
          <span className="font-mono text-sm text-accent">{ip}</span>
          {entity ? (
            <span
              className="ml-auto font-mono text-[10px] uppercase"
              style={{ color: severityColorVar(entity.severity) }}
            >
              {entity.priority}
            </span>
          ) : null}
        </div>
      </div>

      {!entity ? (
        <p className="px-5 py-10 font-mono text-sm text-muted">
          no profile for this address in the current session
        </p>
      ) : (
        <div className="min-h-0 flex-1 overflow-y-auto px-5 py-4">
          <dl className="grid grid-cols-2 gap-3 font-mono text-xs">
            <div>
              <dt className="text-muted">first seen</dt>
              <dd className="text-sm text-foreground">
                {formatTime(entity.first_seen)}
              </dd>
            </div>
            <div>
              <dt className="text-muted">last seen</dt>
              <dd className="text-sm text-foreground">
                {formatTime(entity.last_seen)}
              </dd>
            </div>
            <div>
              <dt className="text-muted">alerts</dt>
              <dd className="text-sm text-foreground">{entity.alert_count}</dd>
            </div>
            <div>
              <dt className="text-muted">severity</dt>
              <dd
                className="text-sm"
                style={{ color: severityColorVar(entity.severity) }}
              >
                {entity.severity}
              </dd>
            </div>
          </dl>

          {entity.threat_classes.length ? (
            <p className="mt-4 font-mono text-[11px] text-muted">
              classes{" "}
              <span className="text-foreground">
                {entity.threat_classes.map(shortClass).join(", ")}
              </span>
            </p>
          ) : null}

          <div className="mt-5 border-t border-line pt-4">
            <p className="mb-2 text-sm font-medium text-foreground">partners</p>
            {partners.length ? (
              <ul className="space-y-1 font-mono text-[11px]">
                {partners.map((p) => (
                  <li key={p.ip} className="flex justify-between gap-2">
                    <button
                      type="button"
                      className="truncate text-accent underline-offset-2 hover:underline"
                      onClick={() => onSelectIp?.(p.ip)}
                    >
                      {p.ip}
                    </button>
                    <span className="shrink-0 text-muted">×{p.count}</span>
                  </li>
                ))}
              </ul>
            ) : (
              <p className="font-mono text-[11px] text-muted">none</p>
            )}
          </div>

          <div className="mt-5 border-t border-line pt-4">
            <p className="mb-2 text-sm font-medium text-foreground">
              ports / domains
            </p>
            <div className="grid grid-cols-2 gap-4 font-mono text-[11px] text-muted">
              <ul className="space-y-0.5">
                {ports.map(([k, n]) => (
                  <li key={k}>
                    {k} <span className="text-foreground">×{n}</span>
                  </li>
                ))}
                {!ports.length ? <li>no ports</li> : null}
              </ul>
              <ul className="space-y-0.5">
                {domains.map(([d]) => (
                  <li key={d} className="truncate" title={d}>
                    {d}
                  </li>
                ))}
                {!domains.length ? <li>no domains</li> : null}
              </ul>
            </div>
          </div>

          <div className="mt-5 border-t border-line pt-4">
            <p className="mb-2 text-sm font-medium text-foreground">
              related activity
            </p>
            <ul className="space-y-2">
              {history.map((a, i) => (
                <li
                  key={`${a.timestamp}-${a.subtype}-${i}`}
                  className="font-mono text-[11px]"
                >
                  <div className="flex gap-2 text-muted">
                    <span>{formatTime(a.timestamp)}</span>
                    <span style={{ color: severityColorVar(a.severity) }}>
                      {a.severity}
                    </span>
                    <span>{a.subtype}</span>
                  </div>
                  <p className="truncate text-foreground/80">{a.message}</p>
                </li>
              ))}
              {!history.length ? (
                <li className="font-mono text-[11px] text-muted">none</li>
              ) : null}
            </ul>
          </div>
        </div>
      )}
    </section>
  );
}

export const EntityDossierPanel = memo(EntityDossierPanelInner);
