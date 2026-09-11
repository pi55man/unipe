"""turn the ebpf map's cumulative counters into per-window deltas.

the exporter re-sends every live flow on every tick, so a flow that stopped an
hour ago still shows up with its old totals. scoring those totals directly both
re-alerts on stale traffic and drags aggregate rates down. here we keep the
previous totals per flow and hand the detectors only what arrived since the
last tick, which is what makes the pipeline streaming rather than batch.
"""

from __future__ import annotations

from typing import Any

from unipe_ai.alerts import flow_id_of
from unipe_ai.util import to_float

# counters that accumulate in the ebpf map and therefore need differencing
COUNTER_FIELDS = ("packets", "bytes", "syn_count", "ack_count", "fin_count", "rst_count")


class FlowWindow:
    def __init__(self, idle_evict_secs: float = 120.0, min_window_ms: float = 1.0) -> None:
        self.idle_evict_secs = idle_evict_secs
        self.min_window_ms = min_window_ms
        self._seen: dict[str, dict[str, float]] = {}
        self._last_tick: float | None = None

    def deltas(self, batch: list[dict[str, Any]], now: float) -> list[dict[str, Any]]:
        """return one flow dict per flow that moved traffic in this window."""
        elapsed_ms = 0.0
        if self._last_tick is not None:
            elapsed_ms = max((now - self._last_tick) * 1000.0, self.min_window_ms)
        self._last_tick = now

        out: list[dict[str, Any]] = []
        for flow in batch:
            key = flow_id_of(flow)
            totals = {field: to_float(flow.get(field)) for field in COUNTER_FIELDS}
            previous = self._seen.get(key)
            self._seen[key] = {**totals, "last_seen": now}

            if previous is None:
                # first sighting: the totals cover the flow's whole life so far
                delta = totals
                base_ms = max(to_float(flow.get("duration_ms")), elapsed_ms, self.min_window_ms)
            elif totals["packets"] < previous["packets"]:
                # the lru map recycled this 5-tuple, so treat it as brand new
                delta = totals
                base_ms = max(elapsed_ms, self.min_window_ms)
            else:
                delta = {f: max(totals[f] - previous[f], 0.0) for f in COUNTER_FIELDS}
                base_ms = max(elapsed_ms, self.min_window_ms)

            if delta["packets"] <= 0:
                continue

            windowed = dict(flow)
            windowed.update(delta)
            windowed["is_new_flow"] = previous is None
            windowed["duration_ms"] = base_ms
            windowed["window_ms"] = elapsed_ms
            windowed["total_packets"] = totals["packets"]
            windowed["total_bytes"] = totals["bytes"]
            windowed["total_duration_ms"] = to_float(flow.get("duration_ms"))
            out.append(windowed)

        self._evict(now)
        return out

    def _evict(self, now: float) -> None:
        cutoff = now - self.idle_evict_secs
        stale = [key for key, state in self._seen.items() if state["last_seen"] < cutoff]
        for key in stale:
            del self._seen[key]
