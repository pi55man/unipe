"use client";

import { memo, useSyncExternalStore } from "react";
import {
  getFlowsPerSec,
  subscribeFlowsPerSec,
} from "@/lib/flowRateStore";

type Props = {
  alertCount: number;
  onResetAlerts: () => void;
};

function TopBarInner({ alertCount, onResetAlerts }: Props) {
  const flowsPerSec = useSyncExternalStore(
    subscribeFlowsPerSec,
    getFlowsPerSec,
    getFlowsPerSec,
  );

  return (
    <header className="flex h-14 shrink-0 items-center gap-5 border-b border-line bg-panel px-6">
      <p className="font-mono text-base tracking-wide text-accent">unipe</p>

      <div className="ml-auto flex min-w-0 items-center gap-5">
        <p className="shrink-0 font-mono text-xs text-muted">
          <span className="text-foreground">~{Math.round(flowsPerSec)}</span>{" "}
          flows/s
        </p>
        <p className="shrink-0 font-mono text-xs text-muted">
          <span className="text-foreground">{alertCount}</span> alerts
        </p>
        <button
          type="button"
          onClick={onResetAlerts}
          className="shrink-0 font-mono text-[11px] text-muted underline-offset-2 hover:text-sev-high hover:underline"
          title="clear alerts and reset the session flows/s counter"
        >
          reset
        </button>
      </div>
    </header>
  );
}

export const TopBar = memo(TopBarInner);
