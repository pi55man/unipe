"use client";

import { memo, useMemo, useState, useSyncExternalStore } from "react";

import type { Alert } from "@/lib/alerts";
import { shortClass, threatColorVar } from "@/lib/alerts";
import {
  buildClassMix,
  buildTimeline,
  buildTopDestinations,
  type TimelineBucket,
} from "@/lib/aggregates";
import {
  getHealthView,
  subscribeHealthView,
} from "@/lib/healthStore";
import { SensorHealthPanel } from "@/components/SensorHealth";

type BottomTab = "context" | "sensor";

type Props = {
  alerts: Alert[];
  classFilter: string;
  destFilter: string;
  onClassFilter: (threatClass: string) => void;
  onDestFilter: (dstIp: string) => void;
};

const TimelineBar = memo(function TimelineBar({
  bucket,
  maxBucket,
}: {
  bucket: TimelineBucket;
  maxBucket: number;
}) {
  const heightPct = (bucket.total / maxBucket) * 100;

  return (
    <div
      className="group relative flex min-w-0 flex-1 flex-col items-center gap-1"
      title={
        bucket.total
          ? `${bucket.label}: ${bucket.total} (${bucket.high}h ${bucket.medium}m ${bucket.low}l)`
          : bucket.label
      }
    >
      <div
        className="flex w-full flex-col justify-end"
        style={{ height: "6.25rem" }}
      >
        <div
          className="flex w-full flex-col justify-end rounded-sm"
          style={{
            height: `${heightPct}%`,
            minHeight: bucket.total ? 4 : 0,
          }}
        >
          <div
            className="w-full bg-sev-high"
            style={{
              height: `${bucket.total ? (bucket.high / bucket.total) * 100 : 0}%`,
            }}
          />
          <div
            className="w-full bg-sev-med"
            style={{
              height: `${bucket.total ? (bucket.medium / bucket.total) * 100 : 0}%`,
            }}
          />
          <div
            className="w-full bg-sev-low"
            style={{
              height: `${bucket.total ? (bucket.low / bucket.total) * 100 : 0}%`,
            }}
          />
        </div>
      </div>
      <span className="truncate font-mono text-[10px] text-muted group-hover:text-foreground">
        {bucket.label.slice(-5)}
      </span>
      {bucket.total > 0 ? (
        <div className="pointer-events-none absolute bottom-[calc(100%-0.25rem)] z-10 hidden w-max -translate-y-1 rounded border border-line bg-panel px-2 py-1.5 font-mono text-[10px] shadow-sm group-hover:block">
          <p className="text-foreground">{bucket.label}</p>
          <p className="mt-0.5 text-muted">{bucket.total} alerts</p>
          <p className="mt-1 flex gap-2">
            <span style={{ color: "var(--sev-high)" }}>{bucket.high}h</span>
            <span style={{ color: "var(--sev-med)" }}>{bucket.medium}m</span>
            <span style={{ color: "var(--sev-low)" }}>{bucket.low}l</span>
          </p>
        </div>
      ) : null}
    </div>
  );
});

function ContextCharts({
  alerts,
  classFilter,
  destFilter,
  onClassFilter,
  onDestFilter,
}: Omit<Props, "health">) {
  const timeline = useMemo(() => buildTimeline(alerts, 60, 12), [alerts]);
  const mix = useMemo(() => buildClassMix(alerts), [alerts]);
  const tops = useMemo(() => buildTopDestinations(alerts, 6), [alerts]);
  const maxBucket = Math.max(1, ...timeline.map((b) => b.total));
  const maxClass = Math.max(1, ...mix.map((c) => c.count));
  const maxDest = Math.max(1, ...tops.map((d) => d.count));

  return (
    <div className="grid min-h-0 flex-1 grid-cols-3 gap-0">
      <div className="border-r border-line px-4 py-3">
        <p className="mb-2 text-xs font-medium text-foreground">
          alert timeline
        </p>
        <div className="flex h-[8.5rem] items-end gap-1.5">
          {timeline.map((b) => (
            <TimelineBar key={b.start} bucket={b} maxBucket={maxBucket} />
          ))}
        </div>
      </div>

      <div className="border-r border-line px-4 py-3">
        <div className="mb-2 flex items-center justify-between gap-2">
          <p className="text-xs font-medium text-foreground">threat-class mix</p>
          {classFilter !== "all" ? (
            <button
              type="button"
              onClick={() => onClassFilter("all")}
              className="font-mono text-[10px] text-accent underline-offset-2 hover:underline"
            >
              clear
            </button>
          ) : (
            <span className="font-mono text-[10px] text-muted">
              click to filter
            </span>
          )}
        </div>
        <ul
          className="space-y-1.5 overflow-y-auto"
          style={{ maxHeight: "8.5rem" }}
        >
          {mix.map((row) => {
            const active = classFilter === row.threat_class;
            return (
              <li key={row.threat_class}>
                <button
                  type="button"
                  onClick={() =>
                    onClassFilter(active ? "all" : row.threat_class)
                  }
                  aria-pressed={active}
                  className={`flex w-full items-center gap-2 rounded-sm px-1.5 py-1 text-left transition-colors ${
                    active
                      ? "bg-accent-soft ring-1 ring-accent/40"
                      : "hover:bg-background-wash"
                  }`}
                >
                  <span
                    className="h-2 w-2 shrink-0 rounded-full"
                    style={{ background: threatColorVar(row.threat_class) }}
                  />
                  <span
                    className={`w-32 shrink-0 truncate font-mono text-[11px] ${
                      active ? "text-foreground" : "text-muted"
                    }`}
                  >
                    {shortClass(row.threat_class)}
                  </span>
                  <span className="h-1.5 min-w-0 flex-1 bg-line">
                    <span
                      className="block h-full"
                      style={{
                        width: `${(row.count / maxClass) * 100}%`,
                        background: threatColorVar(row.threat_class),
                      }}
                    />
                  </span>
                  <span className="w-5 font-mono text-[11px] text-muted">
                    {row.count}
                  </span>
                </button>
              </li>
            );
          })}
        </ul>
      </div>

      <div className="px-4 py-3">
        <div className="mb-2 flex items-center justify-between gap-2">
          <p className="text-xs font-medium text-foreground">top destinations</p>
          {destFilter ? (
            <button
              type="button"
              onClick={() => onDestFilter(destFilter)}
              className="font-mono text-[10px] text-accent underline-offset-2 hover:underline"
            >
              clear
            </button>
          ) : (
            <span className="font-mono text-[10px] text-muted">
              click to filter
            </span>
          )}
        </div>
        <ul
          className="space-y-1.5 overflow-y-auto"
          style={{ maxHeight: "8.5rem" }}
        >
          {tops.map((row) => {
            const active = destFilter === row.dst_ip;
            return (
              <li key={row.dst_ip}>
                <button
                  type="button"
                  onClick={() => onDestFilter(row.dst_ip)}
                  aria-pressed={active}
                  className={`flex w-full items-center gap-2 rounded-sm px-1.5 py-1 text-left transition-colors ${
                    active
                      ? "bg-accent-soft ring-1 ring-accent/40"
                      : "hover:bg-background-wash"
                  }`}
                >
                  <span
                    className={`w-40 shrink-0 truncate font-mono text-[11px] ${
                      active ? "text-foreground" : "text-muted"
                    }`}
                  >
                    {row.dst_ip}
                  </span>
                  <span className="h-1.5 min-w-0 flex-1 bg-line">
                    <span
                      className="block h-full bg-foreground/50"
                      style={{ width: `${(row.count / maxDest) * 100}%` }}
                    />
                  </span>
                  <span className="w-5 font-mono text-[11px] text-muted">
                    {row.count}
                  </span>
                </button>
              </li>
            );
          })}
        </ul>
      </div>
    </div>
  );
}

const ContextChartsMemo = memo(ContextCharts);

function SensorTabDot() {
  const health = useSyncExternalStore(
    subscribeHealthView,
    getHealthView,
    getHealthView,
  );
  const warn =
    health.coverageDegraded ||
    health.flowsDropped > 0;
  if (!warn) return null;
  return (
    <span className="ml-1.5 text-sev-med" title="coverage warning">
      ·
    </span>
  );
}

function SensorHealthFromStore() {
  const health = useSyncExternalStore(
    subscribeHealthView,
    getHealthView,
    getHealthView,
  );
  return <SensorHealthPanel health={health} />;
}

function ContextStripInner({
  alerts,
  classFilter,
  destFilter,
  onClassFilter,
  onDestFilter,
}: Props) {
  const [tab, setTab] = useState<BottomTab>("context");

  return (
    <footer className="flex h-52 shrink-0 flex-col border-t border-line bg-panel">
      <div
        className="flex shrink-0 items-center gap-1 border-b border-line px-3"
        role="tablist"
        aria-label="bottom panel"
      >
        <button
          type="button"
          role="tab"
          aria-selected={tab === "context"}
          onClick={() => setTab("context")}
          className={`px-3 py-1.5 font-mono text-[11px] ${
            tab === "context"
              ? "border-b-2 border-accent text-foreground"
              : "text-muted hover:text-foreground"
          }`}
        >
          context
        </button>
        <button
          type="button"
          role="tab"
          aria-selected={tab === "sensor"}
          onClick={() => setTab("sensor")}
          className={`px-3 py-1.5 font-mono text-[11px] ${
            tab === "sensor"
              ? "border-b-2 border-accent text-foreground"
              : "text-muted hover:text-foreground"
          }`}
        >
          sensor
          <SensorTabDot />
        </button>
      </div>

      {tab === "context" ? (
        <ContextChartsMemo
          alerts={alerts}
          classFilter={classFilter}
          destFilter={destFilter}
          onClassFilter={onClassFilter}
          onDestFilter={onDestFilter}
        />
      ) : (
        <SensorHealthFromStore />
      )}
    </footer>
  );
}

export const ContextStrip = memo(ContextStripInner);
