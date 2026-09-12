from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from typing import Any

from unipe_ai.alerts import (
    VOLUMETRIC_DDOS,
    alert_from_flow,
    make_alert,
    make_flow_id,
    newest_timestamp,
    ratio_confidence,
)
from unipe_ai.util import to_float


@dataclass(frozen=True)
class VolumetricConfig:
    # Destination fan-in / aggregate volume
    min_unique_sources: int = 30
    dst_packet_rate: float = 5_000.0
    dst_byte_rate: float = 2_000_000.0
    # Per-flow extremes (ignored for very short / tiny flows — see below)
    flow_packet_rate: float = 5_000.0
    flow_byte_rate: float = 2_000_000.0
    flow_min_duration_ms: float = 500.0
    flow_min_packets: float = 100.0
    # SYN flood heuristics (unidirectional)
    syn_flood_min_flows: int = 20
    syn_flood_min_syn_ratio: float = 5.0
    syn_only_fraction: float = 0.7
    # Protocol floods
    udp_flood_min_flows: int = 25
    udp_flood_packet_rate: float = 5_000.0
    # Classic --rand-source: many 1-packet UDP 5-tuples, not necessarily high pps
    # after duration is diluted by older map entries.
    udp_flood_max_avg_packets: float = 3.0
    icmp_flood_min_flows: int = 25
    icmp_flood_packet_rate: float = 1_000.0
    # Off by default: on a laptop/Wi-Fi tap, ingress dest is your RFC1918 address,
    # so the generic fan-in alert is mostly noise there. The specific protocol
    # flood signatures below always run, LAN destination or not.
    alert_lan_destinations: bool = False


def detect_volumetric(
    features: list[dict[str, Any]],
    cfg: VolumetricConfig | None = None,
) -> list[dict[str, Any]]:
    """Detect volumetric DDoS patterns from a unidirectional flow batch."""
    cfg = cfg or VolumetricConfig()
    alerts: list[dict[str, Any]] = []

    by_dst: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for feat in features:
        dst = str(feat.get("dst_ip", ""))
        if dst:
            by_dst[dst].append(feat)

    for dst, flows in by_dst.items():
        alerts.extend(_dst_alerts(dst, flows, cfg))

    for feat in features:
        alerts.extend(_flow_alerts(feat, cfg))

    return alerts


def _dst_alerts(
    dst: str,
    flows: list[dict[str, Any]],
    cfg: VolumetricConfig,
) -> list[dict[str, Any]]:
    alerts: list[dict[str, Any]] = []
    sources = {str(f.get("src_ip", "")) for f in flows if f.get("src_ip")}
    total_packets = sum(to_float(f.get("packets")) for f in flows)
    total_bytes = sum(to_float(f.get("bytes")) for f in flows)
    # Sum each flow's own rate. Dividing shared totals by the longest member
    # duration let one stale long-lived flow hide an active flood.
    packet_rate = sum(to_float(f.get("packet_rate")) for f in flows)
    byte_rate = sum(to_float(f.get("byte_rate")) for f in flows)
    stamp = newest_timestamp(flows)

    tcp_flows = [f for f in flows if f.get("is_tcp")]
    udp_flows = [f for f in flows if f.get("is_udp") and not f.get("is_benign_udp")]
    icmp_flows = [f for f in flows if f.get("is_icmp")]
    udp_packets = sum(to_float(f.get("packets")) for f in udp_flows)
    udp_rate = sum(to_float(f.get("packet_rate")) for f in udp_flows)
    udp_sources = {str(f.get("src_ip", "")) for f in udp_flows if f.get("src_ip")}

    lan_victim = bool(flows) and all(
        f.get("dst_is_private")
        or f.get("dst_is_multicast")
        or f.get("dst_is_loopback")
        for f in flows
    )
    # Only the generic fan-in alert is muted for LAN/loopback destinations.
    # SYN/UDP/ICMP flood signatures are specific enough to trust anywhere.
    mute_generic = lan_victim and not cfg.alert_lan_destinations

    syn_total = sum(to_float(f.get("syn_count")) for f in tcp_flows)
    ack_total = sum(to_float(f.get("ack_count")) for f in tcp_flows)
    syn_only = sum(1 for f in tcp_flows if f.get("is_syn_only"))
    syn_only_frac = syn_only / max(len(tcp_flows), 1)

    # Prefer specific protocol floods; fan-in is the catch-all when none apply.
    specific = False

    syn_ratio = syn_total / max(ack_total, 1.0)
    if (
        len(tcp_flows) >= cfg.syn_flood_min_flows
        and syn_ratio >= cfg.syn_flood_min_syn_ratio
        and syn_only_frac >= cfg.syn_only_fraction
    ):
        specific = True
        severity = "high" if len(sources) >= cfg.min_unique_sources else "medium"
        alerts.append(
            _dst_alert(
                subtype="syn_flood",
                severity=severity,
                confidence=ratio_confidence(syn_ratio, cfg.syn_flood_min_syn_ratio),
                dst_ip=dst,
                protocol=6,
                timestamp=stamp,
                message=f"SYN flood toward {dst}: syn/ack={syn_ratio:.1f}, "
                f"syn-only flows={syn_only}/{len(tcp_flows)}",
                evidence={
                    "unique_sources": len(sources),
                    "tcp_flows": len(tcp_flows),
                    "syn_count": syn_total,
                    "ack_count": ack_total,
                    "syn_only_fraction": syn_only_frac,
                    "packet_rate": packet_rate,
                },
            )
        )

    avg_udp_packets = udp_packets / max(len(udp_flows), 1)
    spoofed_udp = (
        len(udp_flows) >= cfg.udp_flood_min_flows
        and len(udp_sources) >= cfg.min_unique_sources
        and avg_udp_packets <= cfg.udp_flood_max_avg_packets
    )
    high_rate_udp = (
        len(udp_flows) >= cfg.udp_flood_min_flows
        and len(udp_sources) >= cfg.min_unique_sources
        and udp_rate >= cfg.udp_flood_packet_rate
    )
    # On a laptop NIC, BitTorrent/P2P toward your RFC1918 address is high-pps
    # with real sessions — only trust the classic 1-packet spoofed signature
    # there. High-rate floods still fire toward public victims.
    if mute_generic:
        high_rate_udp = False
    if spoofed_udp or high_rate_udp:
        specific = True
        alerts.append(
            _dst_alert(
                subtype="udp_flood",
                severity="high",
                confidence=max(
                    ratio_confidence(udp_rate, cfg.udp_flood_packet_rate),
                    ratio_confidence(len(udp_sources), cfg.min_unique_sources),
                ),
                dst_ip=dst,
                protocol=17,
                timestamp=stamp,
                message=f"UDP flood toward {dst}: {len(udp_flows)} UDP flows, "
                f"{len(udp_sources)} sources, {udp_rate:.0f} pps",
                evidence={
                    "unique_sources": len(udp_sources),
                    "udp_flows": len(udp_flows),
                    "packet_rate": udp_rate,
                    "avg_packets": avg_udp_packets,
                    "spoofed_short_flows": spoofed_udp,
                    "byte_rate": byte_rate,
                },
            )
        )

    icmp_rate = sum(to_float(f.get("packet_rate")) for f in icmp_flows)
    if len(icmp_flows) >= cfg.icmp_flood_min_flows and icmp_rate >= cfg.icmp_flood_packet_rate:
        specific = True
        alerts.append(
            _dst_alert(
                subtype="icmp_flood",
                severity="high",
                confidence=ratio_confidence(icmp_rate, cfg.icmp_flood_packet_rate),
                dst_ip=dst,
                protocol=1,
                timestamp=stamp,
                message=f"ICMP flood toward {dst}: {icmp_rate:.0f} pps across "
                f"{len(icmp_flows)} flows",
                evidence={
                    "unique_sources": len(sources),
                    "icmp_flows": len(icmp_flows),
                    "packet_rate": icmp_rate,
                },
            )
        )

    fan_in = len(sources) >= cfg.min_unique_sources and (
        packet_rate >= cfg.dst_packet_rate or byte_rate >= cfg.dst_byte_rate
    )
    if fan_in and not mute_generic and not specific:
        alerts.append(
            _dst_alert(
                subtype="fan_in_flood",
                severity="high",
                confidence=max(
                    ratio_confidence(packet_rate, cfg.dst_packet_rate),
                    ratio_confidence(byte_rate, cfg.dst_byte_rate),
                ),
                dst_ip=dst,
                timestamp=stamp,
                message=f"volumetric fan-in toward {dst}: {len(sources)} sources, "
                f"{packet_rate:.0f} pps / {byte_rate:.0f} Bps",
                evidence={
                    "unique_sources": len(sources),
                    "flow_count": len(flows),
                    "packet_rate": packet_rate,
                    "byte_rate": byte_rate,
                    "packets": total_packets,
                    "bytes": total_bytes,
                },
            )
        )

    return alerts


def _flow_alerts(feat: dict[str, Any], cfg: VolumetricConfig) -> list[dict[str, Any]]:
    alerts: list[dict[str, Any]] = []
    duration_ms = to_float(feat.get("duration_ms"))
    packets = to_float(feat.get("packets"))
    # Tiny duration (often floored to 1ms) makes 2 packets look like 2000 pps.
    if duration_ms < cfg.flow_min_duration_ms or packets < cfg.flow_min_packets:
        return alerts

    packet_rate = to_float(feat.get("packet_rate"))
    byte_rate = to_float(feat.get("byte_rate"))
    if packet_rate < cfg.flow_packet_rate and byte_rate < cfg.flow_byte_rate:
        return alerts

    subtype = "high_rate_flow"
    if feat.get("is_udp"):
        subtype = "udp_high_rate_flow"
    elif feat.get("is_icmp"):
        subtype = "icmp_high_rate_flow"
    elif feat.get("is_tcp") and feat.get("is_syn_only"):
        subtype = "syn_high_rate_flow"

    alerts.append(
        alert_from_flow(
            feat,
            threat_class=VOLUMETRIC_DDOS,
            subtype=subtype,
            severity="medium",
            confidence=max(
                ratio_confidence(packet_rate, cfg.flow_packet_rate),
                ratio_confidence(byte_rate, cfg.flow_byte_rate),
            ),
            message=(
                f"high-rate flow {to_float(feat.get('src_port')):.0f}->"
                f"{to_float(feat.get('dst_port')):.0f} "
                f"proto={feat.get('protocol')}: {packet_rate:.0f} pps / {byte_rate:.0f} Bps"
            ),
            evidence={
                "packet_rate": packet_rate,
                "byte_rate": byte_rate,
                "packets": feat.get("packets"),
                "bytes": feat.get("bytes"),
                "duration_ms": feat.get("duration_ms"),
                "protocol": feat.get("protocol"),
            },
        )
    )
    return alerts


def _dst_alert(
    *,
    subtype: str,
    severity: str,
    confidence: float,
    message: str,
    evidence: dict[str, Any],
    dst_ip: str,
    timestamp: float,
    protocol: Any = "*",
) -> dict[str, Any]:
    """aggregate alert: the flow id wildcards everything except the victim."""
    return make_alert(
        threat_class=VOLUMETRIC_DDOS,
        subtype=subtype,
        severity=severity,
        confidence=confidence,
        message=message,
        evidence=evidence,
        flow_id=make_flow_id(protocol, "*", "*", dst_ip, "*"),
        timestamp=timestamp,
        dst_ip=dst_ip,
        protocol=protocol if isinstance(protocol, int) else 0,
    )
