"""malware signals inside TLS/QUIC sessions, metadata only.

nothing is decrypted here. we work from the cleartext handshake header, the
port the session runs on, and the packet size / timing shape of the flow.

limitation worth knowing: the ebpf side samples 64 payload bytes, which stops
inside the ClientHello random. that is enough for the record and handshake
versions but not for the cipher and extension lists a real JA3/JA4 needs, so
what we emit is a prefix fingerprint. raising the sample size is the single
change needed to upgrade this to full JA3.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from unipe_ai.alerts import ENCRYPTED_MALWARE, alert_from_flow, ratio_confidence
from unipe_ai.util import to_float, to_int

# ssl3.0, tls1.0, tls1.1 - deprecated, and a common malware tell
LEGACY_TLS_VERSIONS = {0x0300: "SSL 3.0", 0x0301: "TLS 1.0", 0x0302: "TLS 1.1"}
EXPECTED_TLS_PORTS = {443, 465, 563, 636, 853, 993, 995, 8443, 9443}
EXPECTED_QUIC_PORTS = {443, 80, 8443}


@dataclass(frozen=True)
class EncryptedConfig:
    # C2 over TLS keeps packets small and the session long
    c2_max_avg_packet_size: float = 300.0
    c2_min_duration_ms: float = 30_000.0
    c2_max_packets: float = 400.0
    c2_min_packets: float = 8.0
    alert_nonstandard_port: bool = True


def detect_encrypted(
    features: list[dict[str, Any]],
    cfg: EncryptedConfig | None = None,
) -> list[dict[str, Any]]:
    cfg = cfg or EncryptedConfig()
    alerts: list[dict[str, Any]] = []
    for feat in features:
        alerts.extend(_tls_alerts(feat, cfg))
        alerts.extend(_quic_alerts(feat, cfg))
        alerts.extend(_shape_alerts(feat, cfg))
    return alerts


def _tls_alerts(feat: dict[str, Any], cfg: EncryptedConfig) -> list[dict[str, Any]]:
    if not feat.get("tls_is_client_hello"):
        return []

    alerts: list[dict[str, Any]] = []
    dst_port = to_int(feat.get("dst_port"))
    client_version = to_int(feat.get("tls_client_version"))
    fingerprint = str(feat.get("tls_prefix_fingerprint", ""))

    if client_version in LEGACY_TLS_VERSIONS:
        name = LEGACY_TLS_VERSIONS[client_version]
        alerts.append(
            alert_from_flow(
                feat,
                threat_class=ENCRYPTED_MALWARE,
                subtype="legacy_tls_version",
                severity="medium",
                confidence=0.7,
                message=f"client offered deprecated {name} to {feat.get('dst_ip')}:{dst_port}",
                evidence={
                    "tls_client_version": hex(client_version),
                    "tls_version_name": name,
                    "tls_prefix_fingerprint": fingerprint,
                },
            )
        )

    if cfg.alert_nonstandard_port and dst_port not in EXPECTED_TLS_PORTS:
        alerts.append(
            alert_from_flow(
                feat,
                threat_class=ENCRYPTED_MALWARE,
                subtype="tls_on_nonstandard_port",
                severity="low",
                confidence=0.55,
                message=f"TLS handshake on unexpected port {dst_port}",
                evidence={
                    "dst_port": dst_port,
                    "tls_client_version": hex(client_version),
                    "tls_prefix_fingerprint": fingerprint,
                },
            )
        )
    return alerts


def _quic_alerts(feat: dict[str, Any], cfg: EncryptedConfig) -> list[dict[str, Any]]:
    if not feat.get("quic_is_initial"):
        return []
    dst_port = to_int(feat.get("dst_port"))
    if not cfg.alert_nonstandard_port or dst_port in EXPECTED_QUIC_PORTS:
        return []
    return [
        alert_from_flow(
            feat,
            threat_class=ENCRYPTED_MALWARE,
            subtype="quic_on_nonstandard_port",
            severity="low",
            confidence=0.55,
            message=f"QUIC initial packet on unexpected port {dst_port}",
            evidence={
                "dst_port": dst_port,
                "quic_version": hex(to_int(feat.get("quic_version"))),
            },
        )
    ]


def _shape_alerts(feat: dict[str, Any], cfg: EncryptedConfig) -> list[dict[str, Any]]:
    """long-lived encrypted session that only ever trickles tiny packets."""
    if not (feat.get("tls_is_handshake") or feat.get("quic_is_long_header")):
        return []

    duration_ms = to_float(feat.get("total_duration_ms"), to_float(feat.get("duration_ms")))
    packets = to_float(feat.get("total_packets"), to_float(feat.get("packets")))
    avg_size = to_float(feat.get("avg_packet_size"))
    if duration_ms < cfg.c2_min_duration_ms:
        return []
    if not cfg.c2_min_packets <= packets <= cfg.c2_max_packets:
        return []
    if avg_size > cfg.c2_max_avg_packet_size:
        return []

    return [
        alert_from_flow(
            feat,
            threat_class=ENCRYPTED_MALWARE,
            subtype="encrypted_low_volume_session",
            severity="medium",
            confidence=ratio_confidence(
                cfg.c2_max_avg_packet_size / max(avg_size, 1.0), 1.0, ceiling=4.0
            ),
            message=(
                f"encrypted session held {duration_ms / 1000:.0f}s with only {packets:.0f} "
                f"packets averaging {avg_size:.0f} bytes"
            ),
            evidence={
                "duration_ms": duration_ms,
                "packets": packets,
                "avg_packet_size": round(avg_size, 1),
                "tls_prefix_fingerprint": feat.get("tls_prefix_fingerprint", ""),
            },
        )
    ]
