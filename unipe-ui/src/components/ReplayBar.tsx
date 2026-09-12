"use client";

import { memo } from "react";
import { formatTime } from "@/lib/alerts";

export type ReplayMode = "live" | "replay" | "offline" | "mock";

type Props = {
  mode: ReplayMode;
  playing: boolean;
  speed: number;
  cursor: number;
  tMin: number;
  tMax: number;
  shown: number;
  total: number;
  onPlayPause: () => void;
  onSpeed: (speed: number) => void;
  onSeek: (t: number) => void;
  onSkipEnd: () => void;
  onRestart: () => void;
};

function ReplayBarInner({
  mode,
  playing,
  speed,
  cursor,
  tMin,
  tMax,
  shown,
  total,
  onPlayPause,
  onSpeed,
  onSeek,
  onSkipEnd,
  onRestart,
}: Props) {
  if (mode !== "replay") return null;
  const span = Math.max(tMax - tMin, 0.001);
  const pct = ((cursor - tMin) / span) * 100;

  return (
    <div
      className="flex h-10 shrink-0 items-center gap-3 border-b border-line bg-panel px-4"
      aria-label="replay controls"
    >
      <span className="shrink-0 rounded-sm bg-accent-soft px-2 py-0.5 font-mono text-[11px] text-accent">
        replay
      </span>
      <button
        type="button"
        onClick={onPlayPause}
        className="font-mono text-[11px] text-foreground underline-offset-2 hover:underline"
      >
        {playing ? "pause" : "play"}
      </button>
      <button
        type="button"
        onClick={onRestart}
        className="font-mono text-[11px] text-muted underline-offset-2 hover:underline"
      >
        restart
      </button>
      <button
        type="button"
        onClick={onSkipEnd}
        className="font-mono text-[11px] text-muted underline-offset-2 hover:underline"
      >
        end
      </button>
      <div className="flex items-center gap-1">
        {[1, 2, 4].map((s) => (
          <button
            key={s}
            type="button"
            onClick={() => onSpeed(s)}
            className={`px-1.5 py-0.5 font-mono text-[10px] ${
              speed === s
                ? "bg-accent-soft text-foreground"
                : "text-muted hover:text-foreground"
            }`}
          >
            {s}×
          </button>
        ))}
      </div>
      <input
        type="range"
        min={tMin}
        max={tMax}
        step={Math.max(span / 500, 0.01)}
        value={cursor}
        onChange={(e) => onSeek(Number(e.target.value))}
        className="min-w-0 flex-1 accent-[var(--accent)]"
        aria-label="replay scrubber"
      />
      <span className="shrink-0 font-mono text-[11px] text-muted">
        {formatTime(cursor)} · {shown}/{total}
      </span>
      <span className="sr-only">{Math.round(pct)}% through capture</span>
    </div>
  );
}

export const ReplayBar = memo(ReplayBarInner);
