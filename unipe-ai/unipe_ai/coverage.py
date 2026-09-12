"""honest coverage / blind-spot notes for passive unidirectional monitoring.

never invent sensor capabilities. every note must be derivable from tap state,
alert evidence, or measured health counters.
"""

from __future__ import annotations

from typing import Any

ALWAYS = (
    "Passive monitoring only: the sensor cannot query hosts, complete "
    "handshakes, decrypt payloads, block traffic, or send mitigation."
)

NO_PAYLOAD = (
    "Application payload content is not available; only flow counters and "
    "handshake metadata (DNS/TLS/QUIC samples) are inspected."
)


def coverage_notes(
    alert: dict[str, Any] | None = None,
    *,
    tap: dict[str, Any] | None = None,
    health: dict[str, Any] | None = None,
) -> list[str]:
    notes: list[str] = [ALWAYS, NO_PAYLOAD]
    tap = tap or {}
    health = health or {}
    alert = alert or {}

    if tap.get("one_directional"):
        msg = str(tap.get("message") or "").strip()
        if msg:
            notes.append(msg)
        else:
            notes.append(
                "Tap appears one-directional: observed direction mix is based "
                "only on traffic visible to this sensor."
            )
        notes.append(
            "Observed outbound/inbound ratio is based only on traffic visible "
            "to the sensor; reverse traffic is not available on this tap."
        )
    else:
        total = int(tap.get("to_server") or 0) + int(tap.get("to_client") or 0)
        if total < 200:
            notes.append(
                "Tap direction not yet classified (insufficient new-flow samples); "
                "treat direction-dependent detections cautiously."
            )

    subtype = str(alert.get("subtype") or "")
    threat = str(alert.get("threat_class") or "")
    evidence = alert.get("evidence") if isinstance(alert.get("evidence"), dict) else {}

    if threat == "data_exfiltration" or subtype == "asymmetric_outbound_volume":
        if not evidence.get("reverse_flow_seen"):
            notes.append(
                "Exfiltration asymmetry requires a visible reverse flow; "
                "without it this class stays quiet or incomplete on this tap."
            )
        notes.append(
            "Outbound/inbound byte ratios reflect only flows the sensor observed; "
            "missing reverse traffic can hide or invent asymmetry."
        )

    if threat == "encrypted_anomaly":
        notes.append(
            "TLS/QUIC judgments use handshake metadata only — no decryption. "
            "Truncated ClientHellos yield no JA3."
        )
        if tap.get("one_directional"):
            to_client = int(tap.get("to_client") or 0)
            to_server = int(tap.get("to_server") or 0)
            if to_client > to_server:
                notes.append(
                    "Reply-heavy tap: ClientHello/JA3 (client→server) is likely "
                    "invisible; JA3S may still appear."
                )

    if threat == "dns_abuse":
        notes.append(
            "DNS findings require the query or response bytes to cross this "
            "sensor; the opposite direction may be invisible on a one-way tap."
        )

    if threat == "recon_scanning":
        notes.append(
            "Scan detection needs the probe direction on-wire; outbound scans "
            "are missed on a reply-only host NIC."
        )

    dropped = int(health.get("flows_dropped_cap") or 0)
    if dropped > 0:
        notes.append(
            f"Scoring backlog dropped {dropped} flows this process (per-tick cap); "
            "absence of an alert is not assurance the network is safe."
        )

    if health.get("coverage_degraded"):
        notes.append(
            "Sensor coverage is degraded — do not interpret silence as clean traffic."
        )

    # stable unique order
    seen: set[str] = set()
    out: list[str] = []
    for n in notes:
        if n not in seen:
            seen.add(n)
            out.append(n)
    return out


def visibility_block(tap: dict[str, Any], health: dict[str, Any]) -> dict[str, Any]:
    one_way = bool(tap.get("one_directional"))
    return {
        "passive_only": True,
        "payload_content": False,
        "decryption": False,
        "host_queries": False,
        "mitigation": False,
        "reverse_traffic_assumed": not one_way,
        "one_directional_tap": one_way,
        "tap_message": str(tap.get("message") or ""),
        "blind_spots": coverage_notes(tap=tap, health=health),
    }
