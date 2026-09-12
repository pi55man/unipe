from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from typing import Any

from unipe_ai.alerts import (
    IP_SPOOFING,
    alert_from_flow,
    make_alert,
    make_flow_id,
    newest_timestamp,
    ratio_confidence,
)
from unipe_ai.util import to_float, to_int


@dataclass(frozen=True)
class SpoofingConfig:
    ttl_variance_min_values: int = 3
    ttl_min_families: int = 3
    spoofed_syn_min_sources: int = 20
    spoofed_syn_min_flows: int = 20
    spoofed_syn_only_fraction: float = 0.8
    # Off by default: on a LAN/laptop tap, private→public is normal browsing/NAT.
    # Enable only on upstream/edge spans where RFC1918 sources should not appear.
    alert_private_to_public: bool = False


def detect_spoofing(
    features: list[dict[str, Any]],
    cfg: SpoofingConfig | None = None,
) -> list[dict[str, Any]]:
    """Detect IP spoofing indicators on unidirectional traffic."""
    cfg = cfg or SpoofingConfig()
    alerts: list[dict[str, Any]] = []

    for feat in features:
        alerts.extend(_per_flow_spoof_alerts(feat, cfg))

    alerts.extend(_ttl_inconsistency_alerts(features, cfg))
    alerts.extend(_spoofed_syn_storm_alerts(features, cfg))
    alerts.extend(_martian_source_storm_alerts(features, cfg))
    return alerts


def _per_flow_spoof_alerts(feat: dict[str, Any], cfg: SpoofingConfig) -> list[dict[str, Any]]:
    alerts: list[dict[str, Any]] = []
    src = str(feat.get("src_ip", ""))
    dst = str(feat.get("dst_ip", ""))

    if feat.get("is_land") and not feat.get("src_is_loopback"):
        alerts.append(
            alert_from_flow(
                feat,
                threat_class=IP_SPOOFING,
                subtype="land_attack",
                severity="high",
                confidence=0.9,
                message=f"land attack pattern: src==dst ({src})",
                evidence={"src_ip": src, "dst_ip": dst, "protocol": feat.get("protocol")},
            )
        )

    if feat.get("src_is_martian"):
        return alerts  # handled in aggregate; per-flow martians drown flood logs

    # Private→public is only meaningful on edge/ISP taps, not home Wi‑Fi clients.
    if (
        cfg.alert_private_to_public
        and feat.get("src_is_private")
        and feat.get("dst_is_public_unicast")
    ):
        alerts.append(
            alert_from_flow(
                feat,
                threat_class=IP_SPOOFING,
                subtype="private_to_public",
                severity="medium",
                confidence=0.6,
                message=f"RFC1918/link-local source {src} toward public {dst}",
                evidence={"src_ip": src, "dst_ip": dst, "ttl": feat.get("ttl")},
            )
        )

    # Observed TTLs are decremented in flight (64→57 is normal). Only flag TTL 0.
    if feat.get("ttl_suspicious"):
        alerts.append(
            alert_from_flow(
                feat,
                threat_class=IP_SPOOFING,
                subtype="ttl_anomaly",
                severity="low",
                confidence=0.55,
                message=f"invalid TTL {feat.get('ttl')} from {src}",
                evidence={"ttl": feat.get("ttl"), "protocol": feat.get("protocol")},
            )
        )

    return alerts


_INITIAL_TTLS = (255, 128, 64, 32)


def _ttl_family(ttl: int) -> int | None:
    """Map an observed TTL to a common OS initial TTL, or None if it doesn't fit."""
    for initial in _INITIAL_TTLS:
        hops = initial - ttl
        if 0 <= hops <= 40:
            return initial
    return None


def _ttl_inconsistency_alerts(
    features: list[dict[str, Any]],
    cfg: SpoofingConfig,
) -> list[dict[str, Any]]:
    """Alert only when one claimed source spans many initial-TTL families.

    Hop-decremented values (64→44) and anycast mixing 64-origin with 255-origin
    (GitHub, CDNs) are normal. Spoofed packets scatter across 32/64/128/255.
    """
    ttl_by_src: dict[str, set[int]] = defaultdict(set)
    samples: dict[str, list[dict[str, Any]]] = defaultdict(list)

    for feat in features:
        src = str(feat.get("src_ip", ""))
        if not src or feat.get("src_is_martian"):
            continue
        ttl = to_int(feat.get("ttl"))
        if ttl <= 0:
            continue
        ttl_by_src[src].add(ttl)
        samples[src].append(feat)

    alerts: list[dict[str, Any]] = []
    for src, ttls in ttl_by_src.items():
        if len(ttls) < cfg.ttl_variance_min_values:
            continue
        families = {fam for t in ttls if (fam := _ttl_family(t)) is not None}
        # unmapped TTLs (None) must not inflate the family count
        family_count = len(families)
        if family_count < cfg.ttl_min_families:
            continue
        dsts = {str(f.get("dst_ip", "")) for f in samples[src]}
        alerts.append(
            make_alert(
                threat_class=IP_SPOOFING,
                subtype="ttl_inconsistency",
                severity="high",
                confidence=ratio_confidence(family_count, cfg.ttl_min_families, ceiling=1.4),
                flow_id=make_flow_id("*", src, "*", "*", "*"),
                timestamp=newest_timestamp(samples[src]),
                src_ip=src,
                message=(
                    f"source {src} observed with {len(ttls)} distinct TTLs "
                    f"{sorted(ttls)} across {family_count} initial-TTL families"
                ),
                evidence={
                    "ttls": sorted(ttls),
                    "families": sorted(families),
                    "unmapped": sorted(t for t in ttls if _ttl_family(t) is None),
                    "flow_count": len(samples[src]),
                    "dst_count": len(dsts),
                },
            )
        )
    return alerts


def _spoofed_syn_storm_alerts(
    features: list[dict[str, Any]],
    cfg: SpoofingConfig,
) -> list[dict[str, Any]]:
    """Many unique sources, SYN-only, no ACKs: classic spoofed SYN flood signature."""
    by_dst: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for feat in features:
        if feat.get("is_tcp"):
            dst = str(feat.get("dst_ip", ""))
            if dst:
                by_dst[dst].append(feat)

    alerts: list[dict[str, Any]] = []
    for dst, flows in by_dst.items():
        if len(flows) < cfg.spoofed_syn_min_flows:
            continue
        sources = {str(f.get("src_ip", "")) for f in flows if f.get("src_ip")}
        syn_only = sum(1 for f in flows if f.get("is_syn_only"))
        syn_only_frac = syn_only / max(len(flows), 1)
        ack_total = sum(to_float(f.get("ack_count")) for f in flows)
        if (
            len(sources) >= cfg.spoofed_syn_min_sources
            and syn_only_frac >= cfg.spoofed_syn_only_fraction
            and ack_total == 0
        ):
            alerts.append(
                make_alert(
                    threat_class=IP_SPOOFING,
                    subtype="spoofed_syn_storm",
                    severity="high",
                    confidence=ratio_confidence(len(sources), cfg.spoofed_syn_min_sources),
                    flow_id=make_flow_id(6, "*", "*", dst, "*"),
                    timestamp=newest_timestamp(flows),
                    dst_ip=dst,
                    protocol=6,
                    message=(
                        f"likely spoofed SYN storm toward {dst}: "
                        f"{len(sources)} sources, {syn_only_frac:.0%} SYN-only, 0 ACKs"
                    ),
                    evidence={
                        "unique_sources": len(sources),
                        "tcp_flows": len(flows),
                        "syn_only_fraction": syn_only_frac,
                        "ack_count": ack_total,
                    },
                )
            )
    return alerts


# DHCP / broadcast placeholders — noisy on every LAN, not useful as spoofing
_DHCP_NOISE_SRCS = frozenset({"0.0.0.0", "255.255.255.255"})


def _martian_source_storm_alerts(
    features: list[dict[str, Any]],
    cfg: SpoofingConfig,
) -> list[dict[str, Any]]:
    """One alert per destination instead of one per forged packet."""
    by_dst: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for feat in features:
        if not feat.get("src_is_martian"):
            continue
        if feat.get("src_is_loopback") or feat.get("dst_is_loopback"):
            continue
        src = str(feat.get("src_ip", ""))
        if src in _DHCP_NOISE_SRCS:
            continue
        dst = str(feat.get("dst_ip", ""))
        by_dst[dst].append(feat)

    alerts: list[dict[str, Any]] = []
    for dst, flows in by_dst.items():
        sources = {str(f.get("src_ip", "")) for f in flows if f.get("src_ip")}
        sample = flows[0]
        is_storm = len(sources) >= 10
        alerts.append(
            make_alert(
                threat_class=IP_SPOOFING,
                subtype="martian_source_storm" if is_storm else "martian_source",
                severity="high",
                confidence=0.9 if is_storm else 0.75,
                flow_id=make_flow_id("*", "*" if is_storm else sample.get("src_ip", ""),
                                     "*", dst, "*"),
                timestamp=newest_timestamp(flows),
                src_ip="" if is_storm else str(sample.get("src_ip", "")),
                dst_ip=dst,
                message=(
                    f"{len(sources)} martian/bogon sources toward {dst}"
                    if is_storm
                    else f"martian/bogon source address {sample.get('src_ip')}"
                ),
                evidence={
                    "unique_sources": len(sources),
                    "flow_count": len(flows),
                    "ttl": sample.get("ttl"),
                    "protocol": sample.get("protocol"),
                },
            )
        )
    return alerts
