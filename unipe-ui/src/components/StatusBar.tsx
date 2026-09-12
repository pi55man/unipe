"use client";

import { memo } from "react";
import { useTheme } from "@/lib/theme";
import type { ReplayMode } from "@/components/ReplayBar";
import { formatMs, type LatencyStats } from "@/lib/latency";

type PipeState = "up" | "idle" | "stale";

type Props = {
  exporter: PipeState;
  engine: PipeState;
  ui: PipeState;
  mode: ReplayMode;
  paused: boolean;
  sourceLabel: string;
  engineReplay: boolean;
  latency: LatencyStats;
  onLoadFile: (file: File) => void;
  onResumeLive?: () => void;
  onTogglePause: () => void;
};

function Dot({ state, label }: { state: PipeState; label: string }) {
  const color =
    state === "up"
      ? "bg-accent"
      : state === "stale"
        ? "bg-sev-high"
        : "bg-muted/40";
  return (
    <span className="inline-flex items-center gap-1.5 font-mono text-[11px] text-muted">
      <span className={`h-1.5 w-1.5 rounded-full ${color}`} aria-hidden />
      {label}
    </span>
  );
}

function modeLabel(mode: ReplayMode, paused: boolean, engineReplay: boolean): string {
  if (mode === "replay") return "file replay";
  if (engineReplay) return "engine replay";
  if (mode === "live") return paused ? "paused" : "live";
  if (mode === "mock") return "mock";
  return "offline";
}

function StatusBarInner({
  exporter,
  engine,
  ui,
  mode,
  paused,
  sourceLabel,
  engineReplay,
  latency,
  onLoadFile,
  onResumeLive,
  onTogglePause,
}: Props) {
  const { theme, toggle } = useTheme();
  const label = modeLabel(mode, paused, engineReplay);
  const liveish = mode === "live" || engineReplay;

  return (
    <div className="flex h-10 shrink-0 items-center gap-4 border-t border-line bg-panel px-4">
      <div className="flex min-w-0 flex-wrap items-center gap-3">
        <Dot state={exporter} label="exporter" />
        <Dot state={engine} label="engine" />
        <Dot state={ui} label="ui" />
        <span
          className={`font-mono text-[11px] ${
            mode === "replay" || engineReplay
              ? "text-accent"
              : mode === "live"
                ? "text-accent"
                : "text-muted"
          }`}
        >
          {label}
        </span>
        {mode === "live" ? (
          <button
            type="button"
            onClick={onTogglePause}
            className="font-mono text-[11px] text-muted underline-offset-2 hover:text-foreground hover:underline"
            title={paused ? "resume live polling" : "pause live polling"}
          >
            {paused ? "resume" : "pause"}
          </button>
        ) : null}
        {onResumeLive ? (
          <button
            type="button"
            onClick={onResumeLive}
            className="font-mono text-[11px] text-accent underline-offset-2 hover:underline"
          >
            resume live
          </button>
        ) : null}
        <span
          className="inline-flex items-center gap-2 border-l border-line pl-3 font-mono text-[11px] text-muted"
          title="Time from flow batch receipt to alert emit inside the engine"
          aria-label="detection latency"
        >
          <span className="text-foreground/70">latency</span>
          {latency.count === 0 ? (
            <span>—</span>
          ) : (
            <>
              <span>
                p50{" "}
                <span className="text-foreground">{formatMs(latency.p50)}</span>
              </span>
              <span>
                p95{" "}
                <span className="text-foreground">{formatMs(latency.p95)}</span>
              </span>
              <span>
                max{" "}
                <span className="text-foreground">{formatMs(latency.max)}</span>
              </span>
            </>
          )}
        </span>
      </div>

      <div className="ml-auto flex min-w-0 items-center gap-3">
        <button
          type="button"
          onClick={toggle}
          className="shrink-0 border border-line px-2 py-0.5 font-mono text-[11px] text-foreground hover:border-accent"
          aria-label="toggle dark mode"
          title="toggle dark mode"
        >
          {theme === "dark" ? "light" : "dark"}
        </button>
        <p
          className="min-w-0 max-w-[20rem] truncate font-mono text-[11px] text-muted"
          title={sourceLabel}
        >
          {sourceLabel}
        </p>
        <label
          className="shrink-0 cursor-pointer font-mono text-[11px] text-accent underline-offset-2 hover:underline"
          title="Load an alerts JSONL to scrub/replay offline"
        >
          {liveish ? "replay jsonl" : "load jsonl"}
          <input
            type="file"
            accept=".jsonl,.json,text/plain"
            className="hidden"
            onChange={(e) => {
              const file = e.target.files?.[0];
              if (file) onLoadFile(file);
              e.target.value = "";
            }}
          />
        </label>
      </div>
    </div>
  );
}

export const StatusBar = memo(StatusBarInner);
