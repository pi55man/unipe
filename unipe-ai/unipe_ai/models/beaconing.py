"""botnet C2 beaconing: flows that wake up on a metronome.

a beacon is boring by design, so instead of volume we look at how regular the
gaps between activity are. this detector has to remember previous windows, so
it keeps state between calls unlike the other ones.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from unipe_ai.alerts import C2_BEACONING, make_alert, make_flow_id
from unipe_ai.util import clamp, mean, stdev, to_float, to_int


@dataclass(frozen=True)
class BeaconingConfig:
    # need this many gaps before periodicity means anything
    min_intervals: int = 4
    # stddev / mean of the gaps. real beacons sit well under 0.2 even with jitter
    max_jitter_ratio: float = 0.20
    min_interval_s: float = 1.0
    max_interval_s: float = 3600.0
    # beacons carry little data; bulk transfers are not C2 check-ins
    max_avg_bytes_per_window: float = 8192.0
    # how many activity times to remember per peer
    history: int = 24
    # don't re-raise the same beacon every window
    alert_cooldown_s: float = 300.0
    # forget peers that went quiet
    idle_evict_s: float = 7200.0


class BeaconTracker:
    """remembers when each (src, dst, dst_port) pair last moved traffic."""

    def __init__(self, cfg: BeaconingConfig | None = None) -> None:
        self.cfg = cfg or BeaconingConfig()
        self._times: dict[tuple[str, str, int, int], list[float]] = {}
        self._bytes: dict[tuple[str, str, int, int], list[float]] = {}
        self._last_alert: dict[tuple[str, str, int, int], float] = {}

    def update(self, features: list[dict[str, Any]], now: float) -> list[dict[str, Any]]:
        # several 5-tuples can share a peer in one window, so total them up first
        # and record a single activity time per peer
        active: dict[tuple[str, str, int, int], float] = {}
        for feat in features:
            if to_float(feat.get("packets")) <= 0:
                continue
            key = _key(feat)
            active[key] = active.get(key, 0.0) + to_float(feat.get("bytes"))

        for key, window_bytes in active.items():
            times = self._times.setdefault(key, [])
            sizes = self._bytes.setdefault(key, [])
            times.append(now)
            sizes.append(window_bytes)
            del times[: -self.cfg.history]
            del sizes[: -self.cfg.history]

        # only peers that moved traffic this window can have a new interval
        alerts = [a for a in (self._check(key, now) for key in active) if a]
        self._evict(now)
        return alerts

    def _check(self, key: tuple[str, str, int, int], now: float) -> dict[str, Any] | None:
        cfg = self.cfg
        times = self._times[key]
        if len(times) < cfg.min_intervals + 1:
            return None

        gaps = [b - a for a, b in zip(times, times[1:]) if b > a]
        if len(gaps) < cfg.min_intervals:
            return None

        avg_gap = mean(gaps)
        if not cfg.min_interval_s <= avg_gap <= cfg.max_interval_s:
            return None

        jitter = stdev(gaps) / avg_gap if avg_gap > 0 else 1.0
        if jitter > cfg.max_jitter_ratio:
            return None

        avg_bytes = mean(self._bytes[key])
        if avg_bytes > cfg.max_avg_bytes_per_window:
            return None

        last = self._last_alert.get(key, 0.0)
        if now - last < cfg.alert_cooldown_s:
            return None
        self._last_alert[key] = now

        src_ip, dst_ip, dst_port, protocol = key
        # a perfectly flat interval is the strongest signal, so invert the jitter
        confidence = clamp(
            0.5 + 0.45 * (1.0 - jitter / max(cfg.max_jitter_ratio, 1e-6)),
            0.5,
            0.95,
        )
        return make_alert(
            threat_class=C2_BEACONING,
            subtype="periodic_beacon",
            severity="high" if jitter <= cfg.max_jitter_ratio / 2 else "medium",
            confidence=confidence,
            flow_id=make_flow_id(protocol, src_ip, "*", dst_ip, dst_port),
            timestamp=times[-1],
            src_ip=src_ip,
            dst_ip=dst_ip,
            dst_port=dst_port,
            protocol=protocol,
            message=(
                f"periodic beacon {src_ip} -> {dst_ip}:{dst_port} every "
                f"{avg_gap:.1f}s (jitter {jitter:.0%}, {len(gaps)} intervals)"
            ),
            evidence={
                "mean_interval_s": round(avg_gap, 3),
                "interval_stdev_s": round(stdev(gaps), 3),
                "jitter_ratio": round(jitter, 4),
                "interval_count": len(gaps),
                "avg_bytes_per_window": round(avg_bytes, 1),
            },
        )

    def _evict(self, now: float) -> None:
        cutoff = now - self.cfg.idle_evict_s
        stale = [key for key, times in self._times.items() if times[-1] < cutoff]
        for key in stale:
            del self._times[key]
            del self._bytes[key]
            self._last_alert.pop(key, None)


def _key(feat: dict[str, Any]) -> tuple[str, str, int, int]:
    # source port is deliberately excluded: a beacon opens a new one every time
    return (
        str(feat.get("src_ip", "")),
        str(feat.get("dst_ip", "")),
        to_int(feat.get("dst_port")),
        to_int(feat.get("protocol")),
    )
