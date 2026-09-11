"""DGA domains and DNS tunnelling, from query names only.

two different shapes we care about:
  - DGA: one short random-looking label, e.g. kq7bxz1mvhqp.com
  - tunnelling: very long names with many stuffed labels under one parent
    domain, often asking for TXT/NULL records
"""

from __future__ import annotations

import math
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
from unipe_ai.util import clamp, digit_ratio, shannon_entropy, to_float

# The ~150 most common english letter pairs. Words and brand names are built
# out of these; DGA output mostly is not. This is the n-gram half of the
# "entropy/n-gram analysis" the DGA check needs, and it does the heavy lifting:
# raw entropy alone cannot work on short labels, because a 12-character string
# can never score above log2(12) = 3.58 bits/char no matter how random it is.
_BIGRAM_LINES = (
    "th he in er an re on at en nd ti es or te of ed is it al ar st to nt ng se",
    "ha as ou io le ve co me de hi ri ro ic ne ea ra ce li ch ll be ma si om ur",
    "ca el ta la ns di fo ho pe ec pr no ct us ac ot il tr ly nc et ut ss so rs",
    "un lo wa ge ie wh ee wi em ad ol rt po we na ul ni ts mo ow pa im mi ai sh",
    "ir su id os iv ia am fi ci vi pl ig tu ev ld ry mp fe bl ab gh ty op wo sa",
    "ay ex ke fr oo av ag if ap gr od bo sp rd do uc bu ei ov by rm ep tt oc fa",
    "ef cu rn sc gi da yo cr cl du ga qu ue ff ba ey ls va um pp ua up lu go ht",
    "ru ug ds lt pi rc rr eg au ck ew mu br bi pt ak pu ui rg ib tl ny ki rk ys",
)
COMMON_BIGRAMS = frozenset(pair for line in _BIGRAM_LINES for pair in line.split())

_VOWELS = frozenset("aeiou")


@dataclass(frozen=True)
class DnsConfig:
    # DGA: a label has to trip several independent randomness signals
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
    signals = _dga_signals(longest, cfg)
    matched = sum(signals.values())
    if (
        matched >= cfg.dga_min_signals
        and cfg.dga_min_label_len <= len(longest) <= cfg.dga_max_label_len
        and _parent_domain(qname) not in cfg.dga_ignore_parents
        and qname_len < cfg.tunnel_min_qname_len
    ):
        alerts.append(
            alert_from_flow(
                feat,
                threat_class=DNS_ABUSE,
                subtype="dga_domain",
                severity="medium",
                confidence=clamp(0.45 + 0.125 * matched, 0.5, 0.95),
                message=(
                    f"DGA-like query name {qname}: {matched} of "
                    f"{len(signals)} randomness signals on '{longest}'"
                ),
                evidence={
                    "qname": qname,
                    "longest_label": longest,
                    "signals": sorted(name for name, hit in signals.items() if hit),
                    "bigram_familiarity": round(_bigram_familiarity(longest), 3),
                    "normalized_entropy": round(_normalized_entropy(longest), 3),
                    "vowel_ratio": round(_vowel_ratio(longest), 3),
                    "digit_ratio": round(digit_ratio(longest), 3),
                    "entropy_bits_per_char": round(entropy, 3),
                    "label_count": label_count,
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


def _dga_signals(label: str, cfg: DnsConfig) -> dict[str, bool]:
    """Which independent randomness signals this label trips.

    One signal on its own is meaningless: plenty of real hostnames are short on
    vowels or carry digits. Several at once is what a generated name looks like.

    The two letter-based signals only count when there are enough letters to
    judge. An all-digit label scores zero on both of them for the trivial
    reason that it has no letters at all, and that is not evidence of anything
    -- numeric ids like a Discord snowflake would otherwise look like DGA.
    """
    letters = sum(1 for c in label if c.isalpha())
    judgeable = letters >= cfg.dga_min_letters
    return {
        "improbable_letter_pairs": judgeable
        and _bigram_familiarity(label) < cfg.dga_max_bigram_familiarity,
        "near_max_entropy": _normalized_entropy(label) >= cfg.dga_min_normalized_entropy,
        "too_few_vowels": judgeable and _vowel_ratio(label) < cfg.dga_max_vowel_ratio,
        "digit_heavy": digit_ratio(label) >= cfg.dga_min_digit_ratio,
    }


def _bigram_familiarity(label: str) -> float:
    """Fraction of the label's letter pairs that occur in ordinary words."""
    pairs = [label[i : i + 2] for i in range(len(label) - 1)]
    pairs = [p for p in pairs if p.isalpha()]
    if not pairs:
        return 0.0
    return sum(1 for p in pairs if p.lower() in COMMON_BIGRAMS) / len(pairs)


def _normalized_entropy(label: str) -> float:
    """Entropy as a fraction of the most a string this long could carry."""
    if len(label) < 2:
        return 0.0
    ceiling = math.log2(len(label))
    return shannon_entropy(label) / ceiling if ceiling > 0 else 0.0


def _vowel_ratio(label: str) -> float:
    letters = [c for c in label.lower() if c.isalpha()]
    if not letters:
        return 0.0
    return sum(1 for c in letters if c in _VOWELS) / len(letters)


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
