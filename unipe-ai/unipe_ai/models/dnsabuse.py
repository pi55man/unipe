"""DGA domains and DNS tunnelling, from query names only.

two different shapes we care about:
  - DGA: one short random-looking label, e.g. kq7bxz1mvhqp.com
  - tunnelling: very long names with many stuffed labels under one parent
    domain, often asking for TXT/NULL records

DGA scoring prefers the trained logistic in artifacts/dns_model.json (published
algorithm families + benign names). the old 3-of-4 signal vote stays as the
fallback when that artifact is missing.
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
from unipe_ai.features.dns_stats import (
    bigram_familiarity,
    longest_label,
    normalized_entropy,
    parent_domain,
    vowel_ratio,
)
from unipe_ai.models.dns_ml import dns_probability
from unipe_ai.models.ml import LogisticModel
from unipe_ai.util import clamp, digit_ratio, to_float


@dataclass(frozen=True)
class DnsConfig:
    # trained model threshold; rules below are the no-model fallback
    dga_model_threshold: float = 0.55
    dga_min_signals: int = 3
    dga_max_bigram_familiarity: float = 0.35
    dga_min_normalized_entropy: float = 0.90
    dga_max_vowel_ratio: float = 0.25
    dga_min_digit_ratio: float = 0.15
    # fewer letters than this and the pronounceability signals mean nothing
    dga_min_letters: int = 6
    dga_min_label_len: int = 10
    dga_max_label_len: int = 40
    # CDNs mint random hostnames by design, so entropy there means nothing
    dga_ignore_parents: tuple[str, ...] = (
        "cloudfront.net",
        "akamaiedge.net",
        "akamai.net",
        "akadns.net",
        "azureedge.net",
        "trafficmanager.net",
        "amazonaws.com",
        "googleusercontent.com",
        "1e100.net",
        "fastly-edge.com",
        "fbcdn.net",
        "windowsupdate.com",
        "github.com",
        "githubusercontent.com",
        "microsoft.com",
        "office.com",
        "google.com",
        "gstatic.com",
        "cloudflare.com",
        # firefox / mozilla CDNs — long product labels, not DGA
        "mozilla.net",
        "mozilla.org",
        "mozilla.com",
        "mozgcp.net",
        "mozaws.net",
    )
    # tunnelling: rfc1035 allows 253 chars and tunnels use most of them
    tunnel_min_qname_len: int = 60
    tunnel_min_label_count: int = 4
    tunnel_min_entropy: float = 3.2
    # a tunnel keeps hammering one parent domain with fresh subdomains
    tunnel_min_subdomains: int = 15
    # anything above this is an oversized query even without a tunnel signature
    max_reasonable_qname_len: int = 100


def detect_dns_abuse(
    features: list[dict[str, Any]],
    cfg: DnsConfig | None = None,
    model: LogisticModel | None = None,
) -> list[dict[str, Any]]:
    cfg = cfg or DnsConfig()
    queries = [f for f in features if f.get("dns_parsed") and f.get("dns_qname")]
    if not queries:
        return []

    alerts: list[dict[str, Any]] = []
    for feat in queries:
        alerts.extend(_query_alerts(feat, cfg, model))
    alerts.extend(_parent_domain_alerts(queries, cfg))
    return alerts


def _query_alerts(
    feat: dict[str, Any],
    cfg: DnsConfig,
    model: LogisticModel | None,
) -> list[dict[str, Any]]:
    alerts: list[dict[str, Any]] = []
    qname = str(feat.get("dns_qname", ""))
    qname_len = int(to_float(feat.get("dns_qname_len")))
    entropy = to_float(feat.get("dns_entropy"))
    label_count = int(to_float(feat.get("dns_label_count")))
    max_label = int(to_float(feat.get("dns_max_label_len")))
    qtype_name = str(feat.get("dns_qtype_name", ""))

    longest = longest_label(qname)
    signals = _dga_signals(longest, cfg)
    matched = sum(signals.values())
    model_p = dns_probability(model, qname)
    allowlisted = parent_domain(qname) in cfg.dga_ignore_parents
    in_length = cfg.dga_min_label_len <= len(longest) <= cfg.dga_max_label_len
    not_tunnel_shaped = qname_len < cfg.tunnel_min_qname_len
    # all-digit ids are not DGA; the model is also trained on them as benign,
    # but this gate keeps a bad weight from flipping them
    enough_letters = sum(1 for c in longest if c.isalpha()) >= cfg.dga_min_letters

    if model_p is not None:
        is_dga = (
            model_p >= cfg.dga_model_threshold
            and in_length
            and enough_letters
            and not allowlisted
            and not_tunnel_shaped
        )
        confidence = clamp(0.5 + 0.45 * model_p, 0.5, 0.95)
        how = f"dns-model p={model_p:.2f}"
    else:
        is_dga = (
            matched >= cfg.dga_min_signals
            and in_length
            and not allowlisted
            and not_tunnel_shaped
        )
        confidence = clamp(0.45 + 0.125 * matched, 0.5, 0.95)
        how = f"{matched} of {len(signals)} randomness signals"

    if is_dga:
        evidence = {
            "qname": qname,
            "longest_label": longest,
            "signals": sorted(name for name, hit in signals.items() if hit),
            "bigram_familiarity": round(bigram_familiarity(longest), 3),
            "normalized_entropy": round(normalized_entropy(longest), 3),
            "vowel_ratio": round(vowel_ratio(longest), 3),
            "digit_ratio": round(digit_ratio(longest), 3),
            "entropy_bits_per_char": round(entropy, 3),
            "label_count": label_count,
        }
        if model_p is not None:
            evidence["dns_ml_probability"] = round(model_p, 3)
        alerts.append(
            alert_from_flow(
                feat,
                threat_class=DNS_ABUSE,
                subtype="dga_domain",
                severity="medium",
                confidence=confidence,
                message=f"DGA-like query name {qname}: {how} on '{longest}'",
                evidence=evidence,
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
        parent = parent_domain(str(feat.get("dns_qname", "")))
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


def _dga_signals(label: str, cfg: DnsConfig) -> dict[str, bool]:
    """which independent randomness signals this label trips.

    kept as explainability evidence and as the fallback when no model is loaded.
    """
    letters = sum(1 for c in label if c.isalpha())
    judgeable = letters >= cfg.dga_min_letters
    return {
        "improbable_letter_pairs": judgeable
        and bigram_familiarity(label) < cfg.dga_max_bigram_familiarity,
        "near_max_entropy": normalized_entropy(label) >= cfg.dga_min_normalized_entropy,
        "too_few_vowels": judgeable and vowel_ratio(label) < cfg.dga_max_vowel_ratio,
        "digit_heavy": digit_ratio(label) >= cfg.dga_min_digit_ratio,
    }