"""botnet C2 beaconing: flows that wake up on a metronome.

a beacon is boring by design, so instead of volume we look at how regular the
gaps between activity are. this detector has to remember previous windows, so
it keeps state between calls unlike the other ones.

bitTorrent and other P2P clients wake *many* peers on the same schedule, which
looks like a row of beacons if you score each peer alone. that swarm pattern is
filtered before anything is raised.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from itertools import pairwise
from typing import Any

from unipe_ai.alerts import C2_BEACONING, make_alert, make_flow_id
from unipe_ai.util import clamp, mean, stdev, to_float, to_int

# classic bitTorrent / DHT / tracker client ports — not C2
_P2P_PORTS = frozenset(range(6881, 6990)) | {6771, 6969, 51413}
# browsers and CDNs keepalive on these; need a longer, tighter metronome
# 8080/8443 stay on the normal threshold — implants love those ports
_WEB_PORTS = frozenset({80, 443, 853})


@dataclass(frozen=True)
class BeaconingConfig:
    # need this many gaps before periodicity means anything
    min_intervals: int = 5
    # stddev / mean of the gaps. real beacons sit well under 0.2 even with jitter
    max_jitter_ratio: float = 0.15
    # https keepalives are common; demand a cleaner signal there
    web_min_intervals: int = 8
    web_max_jitter_ratio: float = 0.08
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
    # same host, several peers, same period → P2P / sync, not a lone C2 implant
    swarm_min_peers: int = 3
    swarm_interval_slack: float = 0.25
    # skip well-known P2P service ports entirely
    ignore_p2p_ports: bool = True


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
        # [bytes, packets, activity_time] — time from flow timestamp, not wall clock
        active: dict[tuple[str, str, int, int], list[float]] = {}
        for feat in features:
            packets = to_float(feat.get("packets"))
            if packets <= 0 or not self._is_candidate(feat):
                continue
            key = _key(feat)
            if self.cfg.ignore_p2p_ports and key[2] in _P2P_PORTS:
                continue
            raw_ts = feat.get("timestamp")
            if raw_ts is None:
                activity_t = now
            else:
                activity_t = to_float(raw_ts)
                if activity_t <= 0:
                    activity_t = now
            totals = active.setdefault(key, [0.0, 0.0, 0.0])
            totals[0] += to_float(feat.get("bytes"))
            totals[1] += packets
            if activity_t > totals[2]:
                totals[2] = activity_t

        for key, (window_bytes, window_packets, activity_t) in active.items():
            times = self._times.setdefault(key, [])
            sizes = self._bytes.setdefault(key, [])
            counts = self._packets.setdefault(key, [])
            times.append(activity_t)
            sizes.append(window_bytes)
            counts.append(window_packets)
            del times[: -self.cfg.history]
            del sizes[: -self.cfg.history]
            del counts[: -self.cfg.history]

        # score first, then drop anything that looks like a P2P swarm wake-up
        candidates = []
        for key in active:
            stats = self._evaluate(key)
            if stats is not None:
                candidates.append((key, stats))
        candidates = _drop_swarms(candidates, self.cfg)

        alerts: list[dict[str, Any]] = []
        for key, stats in candidates:
            alert = self._alert_from_stats(key, stats, now)
            if alert is not None:
                alerts.append(alert)
        self._evict(now)
        return alerts

    def _is_candidate(self, feat: dict[str, Any]) -> bool:
        if not self.cfg.external_only:
            return True
        # whichever endpoint is the far side has to be out on the internet
        remote_is_dst = to_int(feat.get("dst_port")) <= to_int(feat.get("src_port"))
        key = "dst_is_public_unicast" if remote_is_dst else "src_is_public_unicast"
        return bool(feat.get(key))

    def _thresholds(self, service_port: int) -> tuple[int, float]:
        if service_port in _WEB_PORTS:
            return self.cfg.web_min_intervals, self.cfg.web_max_jitter_ratio
        return self.cfg.min_intervals, self.cfg.max_jitter_ratio

    def _evaluate(self, key: tuple[str, str, int, int]) -> dict[str, float] | None:
        cfg = self.cfg
        _local, _remote, service_port, _proto = key
        min_intervals, max_jitter = self._thresholds(service_port)

        times = self._times[key]
        if len(times) < min_intervals + 1:
            return None

        gaps = [b - a for a, b in pairwise(times) if b > a]
        if len(gaps) < min_intervals:
            return None

        avg_gap = mean(gaps)
        if not cfg.min_interval_s <= avg_gap <= cfg.max_interval_s:
            return None

        jitter = stdev(gaps) / avg_gap if avg_gap > 0 else 1.0
        if jitter > max_jitter:
            return None

        # Gate on the *busiest* window, not the average. A beacon is small every
        # single time; a browser keepalive is small only because the page it
        # belongs to already finished loading. One heavy window means this
        # conversation carries real traffic and is not a beacon.
        avg_bytes = mean(self._bytes[key])
        peak = max(self._bytes[key])
        if peak > cfg.max_bytes_per_window:
            return None

        return {
            "avg_gap": avg_gap,
            "jitter": jitter,
            "gap_count": float(len(gaps)),
            "avg_bytes": avg_bytes,
            "peak_bytes": peak,
            "max_jitter": max_jitter,
        }

    def _alert_from_stats(
        self,
        key: tuple[str, str, int, int],
        stats: dict[str, float],
        now: float,
    ) -> dict[str, Any] | None:
        last = self._last_alert.get(key, 0.0)
        if now - last < self.cfg.alert_cooldown_s:
            return None
        self._last_alert[key] = now

        local_ip, remote_ip, service_port, protocol = key
        jitter = stats["jitter"]
        max_jitter = stats["max_jitter"]
        avg_gap = stats["avg_gap"]
        avg_bytes = stats["avg_bytes"]
        # a perfectly flat interval is the strongest signal, so invert the jitter
        confidence = clamp(
            0.5 + 0.45 * (1.0 - jitter / max(max_jitter, 1e-6)),
            0.5,
            0.95,
        )
        return make_alert(
            threat_class=C2_BEACONING,
            subtype="periodic_beacon",
            severity="high" if jitter <= max_jitter / 2 else "medium",
            confidence=confidence,
            flow_id=make_flow_id(protocol, local_ip, "*", remote_ip, service_port),
            timestamp=self._times[key][-1],
            src_ip=local_ip,
            dst_ip=remote_ip,
            dst_port=service_port,
            protocol=protocol,
            message=(
                f"periodic beacon {local_ip} -> {remote_ip}:{service_port} every "
                f"{avg_gap:.1f}s (jitter {jitter:.0%}, {int(stats['gap_count'])} intervals)"
            ),
            evidence={
                "mean_interval_s": round(avg_gap, 3),
                "interval_stdev_s": round(stdev(
                    [b - a for a, b in pairwise(self._times[key]) if b > a]
                ), 3),
                "jitter_ratio": round(jitter, 4),
                "interval_count": int(stats["gap_count"]),
                "avg_bytes_per_window": round(avg_bytes, 1),
                "peak_bytes_per_window": round(stats["peak_bytes"], 1),
                "avg_packets_per_window": round(mean(self._packets[key]), 2),
                "avg_packet_size": round(
                    avg_bytes / max(mean(self._packets[key]), 1.0), 1
                ),
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


def _drop_swarms(
    candidates: list[tuple[tuple[str, str, int, int], dict[str, float]]],
    cfg: BeaconingConfig,
) -> list[tuple[tuple[str, str, int, int], dict[str, float]]]:
    """drop peers that share a host and a period — that is P2P, not C2."""
    if cfg.swarm_min_peers < 2 or len(candidates) < cfg.swarm_min_peers:
        return candidates

    by_local: dict[str, list[tuple[tuple[str, str, int, int], dict[str, float]]]] = (
        defaultdict(list)
    )
    for item in candidates:
        by_local[item[0][0]].append(item)

    kept: list[tuple[tuple[str, str, int, int], dict[str, float]]] = []
    for items in by_local.values():
        if len(items) < cfg.swarm_min_peers:
            kept.extend(items)
            continue
        gaps = sorted(s["avg_gap"] for _, s in items)
        median = gaps[len(gaps) // 2]
        if median <= 0:
            kept.extend(items)
            continue
        clustered = {
            k
            for k, s in items
            if abs(s["avg_gap"] - median) / median <= cfg.swarm_interval_slack
        }
        if len(clustered) >= cfg.swarm_min_peers:
            kept.extend((k, s) for k, s in items if k not in clustered)
        else:
            kept.extend(items)
    return kept


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
