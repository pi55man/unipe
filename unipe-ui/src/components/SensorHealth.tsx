"use client";

import { memo } from "react";
import type { HealthView } from "@/lib/coverage";

type Props = {
  health: HealthView;
};

function SensorHealthPanelInner({ health }: Props) {
  const fileReplay = health.mode === "file replay";
  const scoredRatio =
    health.flowsIn > 0
      ? Math.min(1, health.flowsScored / health.flowsIn)
      : 1;
  const warn =
    !fileReplay &&
    (health.coverageDegraded ||
      health.flowsDropped > 0 ||
      scoredRatio < 0.95);

  const rows: { label: string; value: string; warn?: boolean }[] = fileReplay
    ? [
        { label: "mode", value: "file replay" },
        {
          label: "alerts revealed",
          value: `${health.alerts} / ${health.replayTotal}`,
        },
        {
          label: "severity mix",
          value: `${health.sevHigh}h · ${health.sevMed}m · ${health.sevLow}l`,
        },
        {
          label: "progress",
          value:
            health.replayTotal > 0
              ? `${Math.round((100 * health.alerts) / health.replayTotal)}%`
              : "—",
        },
      ]
    : [
        { label: "mode", value: health.mode },
        { label: "flows in", value: String(health.flowsIn) },
        { label: "flows scored", value: String(health.flowsScored) },
        {
          label: "drop / score-cap",
          value: String(health.flowsDropped),
          warn: health.flowsDropped > 0,
        },
        {
          label: "observed rate",
          value: `~${Math.round(health.flowsPerSec)}/s`,
        },
        {
          label: "capacity",
          value: `~${Math.round(health.capacityPerSec)}/s`,
        },
        {
          label: "processing lag",
          value: `${health.worstBatchMs.toFixed(1)} ms`,
        },
        { label: "alerts emitted", value: String(health.alerts) },
        {
          label: "tls handshakes",
          value: `${health.helloComplete}/${health.hellos} complete · ja3 ${health.ja3} · ja3s ${health.ja3s}`,
        },
        {
          label: "coverage",
          value: health.coverageDegraded ? "degraded" : "ok",
          warn: health.coverageDegraded,
        },
      ];

  return (
    <div
      className={`min-h-0 flex-1 overflow-y-auto px-4 py-3 ${
        warn ? "bg-sev-high/5" : ""
      }`}
      aria-label="sensor health"
    >
      <div className="grid grid-cols-2 gap-x-8 gap-y-2 sm:grid-cols-3 lg:grid-cols-4">
        {rows.map((row) => (
          <div key={row.label} className="font-mono text-[11px]">
            <p className="text-muted">{row.label}</p>
            <p className={row.warn ? "text-sev-med" : "text-foreground"}>
              {row.value}
            </p>
          </div>
        ))}
      </div>
    </div>
  );
}

export const SensorHealthPanel = memo(SensorHealthPanelInner);
/** @deprecated strip form removed — use SensorHealthPanel in the bottom tab */
export const SensorHealth = SensorHealthPanel;
