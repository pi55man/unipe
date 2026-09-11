"""botnet C2 beaconing: flows that wake up on a metronome.

a beacon is boring by design, so instead of volume we look at how regular the
gaps between activity are. this detector has to remember previous windows, so
it keeps state between calls unlike the other ones.
"""

from __future__ import annotations

from dataclasses import dataclass
from itertools import pairwise
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
    max_bytes_per_window: float = 8192.0
    # how many activity times to remember per peer
    history: int = 24
    # don't re-raise the same beacon every window
    alert_cooldown_s: float = 300.0
    # forget peers that went quiet
    idle_evict_s: float = 7200.0
    # C2 lives outside the monitored network
    external_only: bool = True


class BeaconTracker:
    """remembers when each (src, dst, dst_port) pair last moved traffic."""

    def __init__(self, cfg: BeaconingConfig | None = None) -> None:
        self.cfg = cfg or BeaconingConfig()
        self._times: dict[tuple[str, str, int, int], list[float]] = {}
        self._bytes: dict[tuple[str, str, int, int], list[float]] = {}
        self._packets: dict[tuple[str, str, int, int], list[float]] = {}
        self._last_alert: dict[tuple[str, str, int, int], float] = {}

    def update(self, features: list[dict[str, Any]], now: float) -> list[dict[str, Any]]:
        # several 5-tuples can share a peer in one window, so total them up first
        # and record a single activity time per peer
        active: dict[tuple[str, str, int, int], list[float]] = {}
        for feat in features:
            packets = to_float(feat.get("packets"))
            if packets <= 0 or not self._is_candidate(feat):
                continue
            key = _key(feat)
            totals = active.setdefault(key, [0.0, 0.0])
            totals[0] += to_float(feat.get("bytes"))
            totals[1] += packets

        for key, (window_bytes, window_packets) in active.items():
            times = self._times.setdefault(key, [])
            sizes = self._bytes.setdefault(key, [])
            counts = self._packets.setdefault(key, [])
            times.append(now)
            sizes.append(window_bytes)
            counts.append(window_packets)
            del times[: -self.cfg.history]
            del sizes[: -self.cfg.history]
            del counts[: -self.cfg.history]

        # only peers that moved traffic this window can have a new interval
        alerts = [a for a in (self._check(key, now) for key in active) if a]
        self._evict(now)
        return alerts

    def _is_candidate(self, feat: dict[str, Any]) -> bool:
        if not self.cfg.external_only:
            return True
        # whichever endpoint is the far side has to be out on the internet
        remote_is_dst = to_int(feat.get("dst_port")) <= to_int(feat.get("src_port"))
        key = "dst_is_public_unicast" if remote_is_dst else "src_is_public_unicast"
        return bool(feat.get(key))

    def _check(self, key: tuple[str, str, int, int], now: float) -> dict[str, Any] | None:
        cfg = self.cfg
        times = self._times[key]
        if len(times) < cfg.min_intervals + 1:
            return None

        gaps = [b - a for a, b in pairwise(times) if b > a]
        if len(gaps) < cfg.min_intervals:
            return None

        avg_gap = mean(gaps)
        if not cfg.min_interval_s <= avg_gap <= cfg.max_interval_s:
            return None

        jitter = stdev(gaps) / avg_gap if avg_gap > 0 else 1.0
        if jitter > cfg.max_jitter_ratio:
            return None

        # Gate on the *busiest* window, not the average. A beacon is small every
        # single time; a browser keepalive is small only because the page it
        # belongs to already finished loading. One heavy window says this
        # conversation carries real traffic and is not a beacon.
        avg_bytes = mean(self._bytes[key])
        if max(self._bytes[key]) > cfg.max_bytes_per_window:
            return None

        last = self._last_alert.get(key, 0.0)
        if now - last < cfg.alert_cooldown_s:
            return None
        self._last_alert[key] = now

        local_ip, remote_ip, service_port, protocol = key
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
            flow_id=make_flow_id(protocol, local_ip, "*", remote_ip, service_port),
            timestamp=times[-1],
            src_ip=local_ip,
            dst_ip=remote_ip,
            dst_port=service_port,
            protocol=protocol,
            message=(
                f"periodic beacon {local_ip} -> {remote_ip}:{service_port} every "
                f"{avg_gap:.1f}s (jitter {jitter:.0%}, {len(gaps)} intervals)"
            ),
            evidence={
                "mean_interval_s": round(avg_gap, 3),
                "interval_stdev_s": round(stdev(gaps), 3),
                "jitter_ratio": round(jitter, 4),
                "interval_count": len(gaps),
                "avg_bytes_per_window": round(avg_bytes, 1),
                "peak_bytes_per_window": round(max(self._bytes[key]), 1),
                # packet-size shape: small uniform payloads back up the timing
                "avg_packets_per_window": round(mean(self._packets[key]), 2),
                "avg_packet_size": round(avg_bytes / max(mean(self._packets[key]), 1.0), 1),
            },
        )

    def _evict(self, now: float) -> None:
        cutoff = now - self.cfg.idle_evict_s
        stale = [key for key, times in self._times.items() if times[-1] < cutoff]
        for key in stale:
            del self._times[key]
            del self._bytes[key]
            del self._packets[key]
            self._last_alert.pop(key, None)


def _key(feat: dict[str, Any]) -> tuple[str, str, int, int]:
    """One key per conversation, whichever direction of it the tap carries.

    Both halves arrive as separate 5-tuples. Keying on them separately
    double-counts a mirrored link, and keying on the outbound half alone goes
    blind on a tap that only sees one direction, which is what XDP gives us.
    Folding both onto the same key handles all three cases.

    The service is the lower port, since clients draw high ephemeral ones, and
    the ephemeral port itself is excluded because a beacon picks a new one
    every time it calls home.
    """
    src_ip = str(feat.get("src_ip", ""))
    dst_ip = str(feat.get("dst_ip", ""))
    src_port = to_int(feat.get("src_port"))
    dst_port = to_int(feat.get("dst_port"))
    if dst_port <= src_port:
        local, remote, service = src_ip, dst_ip, dst_port
    else:
        local, remote, service = dst_ip, src_ip, src_port
    return (local, remote, service, to_int(feat.get("protocol")))
