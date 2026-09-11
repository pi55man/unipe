"""data exfiltration: far more going out than came in.

the tap is unidirectional, but each direction of a conversation arrives as its
own 5-tuple, so we can still pair a flow with its reverse and compare volumes.
if the reverse direction was never observed we stay quiet by default, since on
an asymmetric span that absence means nothing.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from unipe_ai.alerts import DATA_EXFILTRATION, alert_from_flow, ratio_confidence
from unipe_ai.util import to_float, to_int


@dataclass(frozen=True)
class ExfiltrationConfig:
    min_outbound_bytes: float = 5_000_000.0
    min_ratio: float = 10.0
    min_duration_ms: float = 1_000.0
    # only care about data leaving the protected network
    require_internal_source: bool = True
    # an unseen reverse direction is normal on a one-way span, so don't guess
    require_reverse_flow: bool = True


def detect_exfiltration(
    features: list[dict[str, Any]],
    cfg: ExfiltrationConfig | None = None,
) -> list[dict[str, Any]]:
    cfg = cfg or ExfiltrationConfig()
    by_tuple = {_tuple_key(f): f for f in features}

    alerts: list[dict[str, Any]] = []
    for feat in features:
        alert = _flow_alert(feat, by_tuple, cfg)
        if alert:
            alerts.append(alert)
    return alerts


def _flow_alert(
    feat: dict[str, Any],
    by_tuple: dict[tuple[Any, ...], dict[str, Any]],
    cfg: ExfiltrationConfig,
) -> dict[str, Any] | None:
    if cfg.require_internal_source and not feat.get("src_is_private"):
        return None
    if not feat.get("dst_is_public_unicast"):
        return None

    outbound = to_float(feat.get("total_bytes"), to_float(feat.get("bytes")))
    if outbound < cfg.min_outbound_bytes:
        return None

    duration_ms = to_float(feat.get("total_duration_ms"), to_float(feat.get("duration_ms")))
    if duration_ms < cfg.min_duration_ms:
        return None

    reverse = by_tuple.get(_reverse_key(feat))
    if reverse is None and cfg.require_reverse_flow:
        return None

    inbound = 0.0
    if reverse is not None:
        inbound = to_float(reverse.get("total_bytes"), to_float(reverse.get("bytes")))

    ratio = outbound / max(inbound, 1.0)
    if ratio < cfg.min_ratio:
        return None

    return alert_from_flow(
        feat,
        threat_class=DATA_EXFILTRATION,
        subtype="asymmetric_outbound_volume",
        severity="high",
        confidence=max(
            ratio_confidence(ratio, cfg.min_ratio),
            ratio_confidence(outbound, cfg.min_outbound_bytes),
        ),
        message=(
            f"{outbound / 1e6:.1f} MB out vs {inbound / 1e6:.1f} MB in "
            f"({ratio:.0f}x) from {feat.get('src_ip')} to {feat.get('dst_ip')}"
        ),
        evidence={
            "outbound_bytes": outbound,
            "inbound_bytes": inbound,
            "out_in_ratio": round(ratio, 2),
            "duration_ms": duration_ms,
            "reverse_flow_seen": reverse is not None,
            "dst_port": to_int(feat.get("dst_port")),
        },
    )


def _tuple_key(feat: dict[str, Any]) -> tuple[Any, ...]:
    return (
        to_int(feat.get("protocol")),
        str(feat.get("src_ip", "")),
        to_int(feat.get("src_port")),
        str(feat.get("dst_ip", "")),
        to_int(feat.get("dst_port")),
    )


def _reverse_key(feat: dict[str, Any]) -> tuple[Any, ...]:
    return (
        to_int(feat.get("protocol")),
        str(feat.get("dst_ip", "")),
        to_int(feat.get("dst_port")),
        str(feat.get("src_ip", "")),
        to_int(feat.get("src_port")),
    )
