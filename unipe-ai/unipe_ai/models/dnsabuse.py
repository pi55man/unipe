"""DGA domains and DNS tunnelling, from query names only.

two different shapes we care about:
  - DGA: one short random-looking label, e.g. kq7bxz1mvhqp.com
  - tunnelling: very long names with many stuffed labels under one parent
    domain, often asking for TXT/NULL records
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from typing import Any

from unipe_ai.alerts import (
    DNS_ABUSE,
    alert_from_flow,
    make_alert,
    make_flow_id,
    newest_timestamp,
    ratio_confidence,
)
from unipe_ai.util import clamp, to_float

# labels that are normal to see but look random to an entropy test
_COMMON_TLDS = {"com", "net", "org", "io", "dev", "co", "in", "uk", "de", "app", "arpa"}


@dataclass(frozen=True)
class DnsConfig:
    # DGA: entropy is bits per character; english words sit near 3.0
    dga_min_entropy: float = 3.6
    dga_min_label_len: int = 10
    dga_max_label_len: int = 32
    # tunnelling: rfc1035 allows 253 chars and tunnels use most of them, but the
    # exporter only samples 64 payload bytes, so ~52 chars is all we can ever see
    tunnel_min_qname_len: int = 45
    tunnel_min_label_count: int = 4
    tunnel_min_entropy: float = 3.2
    # a tunnel keeps hammering one parent domain with fresh subdomains
    tunnel_min_subdomains: int = 15
    # anything above this is an oversized query even without a tunnel signature
    max_reasonable_qname_len: int = 50


def detect_dns_abuse(
    features: list[dict[str, Any]],
    cfg: DnsConfig | None = None,
) -> list[dict[str, Any]]:
    cfg = cfg or DnsConfig()
    queries = [f for f in features if f.get("dns_parsed") and f.get("dns_qname")]
    if not queries:
        return []

    alerts: list[dict[str, Any]] = []
    for feat in queries:
        alerts.extend(_query_alerts(feat, cfg))
    alerts.extend(_parent_domain_alerts(queries, cfg))
    return alerts


def _query_alerts(feat: dict[str, Any], cfg: DnsConfig) -> list[dict[str, Any]]:
    alerts: list[dict[str, Any]] = []
    qname = str(feat.get("dns_qname", ""))
    qname_len = int(to_float(feat.get("dns_qname_len")))
    entropy = to_float(feat.get("dns_entropy"))
    label_count = int(to_float(feat.get("dns_label_count")))
    max_label = int(to_float(feat.get("dns_max_label_len")))
    qtype_name = str(feat.get("dns_qtype_name", ""))

    longest = _longest_label(qname)
    looks_random = (
        cfg.dga_min_label_len <= len(longest) <= cfg.dga_max_label_len
        and entropy >= cfg.dga_min_entropy
        and longest not in _COMMON_TLDS
    )
    if looks_random and qname_len < cfg.tunnel_min_qname_len:
        alerts.append(
            alert_from_flow(
                feat,
                threat_class=DNS_ABUSE,
                subtype="dga_domain",
                severity="medium",
                confidence=ratio_confidence(entropy, cfg.dga_min_entropy, ceiling=1.3),
                message=f"DGA-like query name {qname} (entropy {entropy:.2f} bits/char)",
                evidence={
                    "qname": qname,
                    "entropy": round(entropy, 3),
                    "longest_label": longest,
                    "label_count": label_count,
                    "digit_ratio": round(to_float(feat.get("dns_digit_ratio")), 3),
                },
            )
        )

    # a truncated sample means the name ran past our 64-byte window, which is
    # already longer than anything a browser asks for
    long_name = qname_len >= cfg.tunnel_min_qname_len or bool(feat.get("dns_sample_truncated"))
    is_tunnel = (
        long_name
        and label_count >= cfg.tunnel_min_label_count
        and entropy >= cfg.tunnel_min_entropy
    )
    long_odd_record = qtype_name in {"TXT", "NULL"} and qname_len >= cfg.tunnel_min_qname_len
    if is_tunnel or long_odd_record:
        alerts.append(
            alert_from_flow(
                feat,
                threat_class=DNS_ABUSE,
                subtype="dns_tunnel",
                severity="high",
                confidence=ratio_confidence(qname_len, cfg.tunnel_min_qname_len, ceiling=2.5),
                message=(
                    f"DNS tunnelling pattern: {qname_len}-char name in {label_count} labels"
                    + (f", {qtype_name} record" if qtype_name else "")
                ),
                evidence={
                    "qname": qname,
                    "qname_len": qname_len,
                    "label_count": label_count,
                    "max_label_len": max_label,
                    "entropy": round(entropy, 3),
                    "qtype": feat.get("dns_qtype"),
                    "qtype_name": qtype_name,
                },
            )
        )
        return alerts

    if qname_len >= cfg.max_reasonable_qname_len:
        alerts.append(
            alert_from_flow(
                feat,
                threat_class=DNS_ABUSE,
                subtype="oversized_query",
                severity="low",
                confidence=0.55,
                message=f"unusually long DNS query name ({qname_len} chars)",
                evidence={"qname": qname, "qname_len": qname_len},
            )
        )
    return alerts


def _parent_domain_alerts(
    queries: list[dict[str, Any]],
    cfg: DnsConfig,
) -> list[dict[str, Any]]:
    """one parent domain answering hundreds of unique subdomains is a tunnel."""
    by_parent: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for feat in queries:
        parent = _parent_domain(str(feat.get("dns_qname", "")))
        if parent:
            by_parent[parent].append(feat)

    alerts: list[dict[str, Any]] = []
    for parent, flows in by_parent.items():
        subdomains = {str(f.get("dns_qname", "")) for f in flows}
        if len(subdomains) < cfg.tunnel_min_subdomains:
            continue
        entropy = max(to_float(f.get("dns_entropy")) for f in flows)
        servers = {str(f.get("dst_ip", "")) for f in flows if f.get("dst_ip")}
        resolver = min(servers) if servers else ""
        alerts.append(
            make_alert(
                threat_class=DNS_ABUSE,
                subtype="dns_tunnel_volume",
                severity="high",
                confidence=clamp(
                    ratio_confidence(len(subdomains), cfg.tunnel_min_subdomains, ceiling=4.0),
                    0.5,
                    0.95,
                ),
                flow_id=make_flow_id(17, "*", "*", resolver or "*", 53),
                timestamp=newest_timestamp(flows),
                dst_ip=resolver,
                dst_port=53,
                protocol=17,
                message=(
                    f"{len(subdomains)} unique subdomains under {parent} in one window"
                ),
                evidence={
                    "parent_domain": parent,
                    "unique_subdomains": len(subdomains),
                    "query_count": len(flows),
                    "max_entropy": round(entropy, 3),
                    "resolvers": sorted(servers),
                    "sample": sorted(subdomains)[:5],
                },
            )
        )
    return alerts


def _longest_label(qname: str) -> str:
    labels = [label for label in qname.split(".") if label]
    if not labels:
        return ""
    return max(labels, key=len)


def _parent_domain(qname: str) -> str:
    labels = [label for label in qname.split(".") if label]
    if len(labels) < 3:
        return ""
    return ".".join(labels[-2:])
