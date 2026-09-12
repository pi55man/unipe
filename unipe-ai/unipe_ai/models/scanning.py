"""reconnaissance and port scanning: one source touching far too many things.

vertical scan  = one source, one target, many ports
horizontal scan = one source, one port, many targets
both look the same in the counters: lots of tiny flows that never establish.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from typing import Any

from unipe_ai.alerts import (
    RECON_SCANNING,
    make_alert,
    make_flow_id,
    newest_timestamp,
    ratio_confidence,
)
from unipe_ai.util import mean, to_float, to_int


@dataclass(frozen=True)
class ScanningConfig:
    min_ports_per_dst: int = 20
    min_dsts_per_port: int = 20
    # probes are tiny; a real session moves more than this
    max_avg_packets: float = 5.0
    # for TCP we also expect handshakes that never complete
    min_syn_only_fraction: float = 0.7
    # On a receive-only host NIC, return traffic lands on many ephemeral local
    # ports and looks like a vertical scan. Real scanners hit service ports.
    max_scan_dst_port: int = 10000


def detect_scanning(
    features: list[dict[str, Any]],
    cfg: ScanningConfig | None = None,
) -> list[dict[str, Any]]:
    cfg = cfg or ScanningConfig()
    probes = [f for f in features if f.get("is_tcp") or f.get("is_udp")]
    if not probes:
        return []
    return _vertical_alerts(probes, cfg) + _horizontal_alerts(probes, cfg)


def _vertical_alerts(
    probes: list[dict[str, Any]],
    cfg: ScanningConfig,
) -> list[dict[str, Any]]:
    groups: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for feat in probes:
        groups[(str(feat.get("src_ip", "")), str(feat.get("dst_ip", "")))].append(feat)

    alerts: list[dict[str, Any]] = []
    for (src, dst), flows in groups.items():
        ports = {to_int(f.get("dst_port")) for f in flows if to_int(f.get("dst_port")) > 0}
        # only count ports a real scanner would care about
        scan_ports = {p for p in ports if p <= cfg.max_scan_dst_port}
        if len(scan_ports) < cfg.min_ports_per_dst or not _looks_like_probing(flows, cfg):
            continue
        alerts.append(
            make_alert(
                threat_class=RECON_SCANNING,
                subtype="vertical_port_scan",
                severity="medium",
                confidence=ratio_confidence(len(scan_ports), cfg.min_ports_per_dst, ceiling=5.0),
                flow_id=make_flow_id(to_int(flows[0].get("protocol")), src, "*", dst, "*"),
                timestamp=newest_timestamp(flows),
                src_ip=src,
                dst_ip=dst,
                protocol=to_int(flows[0].get("protocol")),
                message=f"port scan: {src} probed {len(scan_ports)} ports on {dst}",
                evidence={
                    "unique_ports": len(scan_ports),
                    "ephemeral_ports_ignored": len(ports) - len(scan_ports),
                    "flow_count": len(flows),
                    "avg_packets": round(mean(to_float(f.get("packets")) for f in flows), 2),
                    "syn_only_fraction": round(_syn_only_fraction(flows), 3),
                    "port_sample": sorted(scan_ports)[:10],
                },
            )
        )
    return alerts


def _horizontal_alerts(
    probes: list[dict[str, Any]],
    cfg: ScanningConfig,
) -> list[dict[str, Any]]:
    groups: dict[tuple[str, int], list[dict[str, Any]]] = defaultdict(list)
    for feat in probes:
        port = to_int(feat.get("dst_port"))
        if port > cfg.max_scan_dst_port:
            continue
        groups[(str(feat.get("src_ip", "")), port)].append(feat)

    alerts: list[dict[str, Any]] = []
    for (src, port), flows in groups.items():
        hosts = {str(f.get("dst_ip", "")) for f in flows}
        if len(hosts) < cfg.min_dsts_per_port or not _looks_like_probing(flows, cfg):
            continue
        alerts.append(
            make_alert(
                threat_class=RECON_SCANNING,
                subtype="horizontal_sweep",
                severity="medium",
                confidence=ratio_confidence(len(hosts), cfg.min_dsts_per_port, ceiling=5.0),
                flow_id=make_flow_id(to_int(flows[0].get("protocol")), src, "*", "*", port),
                timestamp=newest_timestamp(flows),
                src_ip=src,
                dst_port=port,
                protocol=to_int(flows[0].get("protocol")),
                message=f"host sweep: {src} probed port {port} on {len(hosts)} hosts",
                evidence={
                    "unique_hosts": len(hosts),
                    "dst_port": port,
                    "flow_count": len(flows),
                    "avg_packets": round(mean(to_float(f.get("packets")) for f in flows), 2),
                    "syn_only_fraction": round(_syn_only_fraction(flows), 3),
                    "host_sample": sorted(hosts)[:10],
                },
            )
        )
    return alerts


def _looks_like_probing(flows: list[dict[str, Any]], cfg: ScanningConfig) -> bool:
    if mean(to_float(f.get("packets")) for f in flows) > cfg.max_avg_packets:
        return False
    tcp = [f for f in flows if f.get("is_tcp")]
    # UDP scans have no handshake to be half-open, so size alone has to do
    if not tcp:
        return True
    return _syn_only_fraction(tcp) >= cfg.min_syn_only_fraction


def _syn_only_fraction(flows: list[dict[str, Any]]) -> float:
    if not flows:
        return 0.0
    return sum(1 for f in flows if f.get("is_syn_only")) / len(flows)
