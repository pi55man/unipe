"""encrypted-session anomalies from TLS/QUIC handshake metadata only.

nothing is decrypted here, and nothing could be: the exporter only samples the
cleartext handshake, which is the negotiation that happens before any key
exists. from it we get a JA3 fingerprint of the client, a JA3S of the server,
the offered version, and the SNI. the rest comes from the packet-size and
timing shape of the session.

heuristics here are anomalies (odd ports, legacy versions, missing SNI) — not
proof of malware. the only high-confidence "known bad" signal is a JA3 hash
that sits on an explicit blocklist.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from unipe_ai.alerts import ENCRYPTED_ANOMALY, alert_from_flow
from unipe_ai.util import to_int

# ssl3.0, tls1.0, tls1.1 - deprecated; uncommon on modern clients
LEGACY_TLS_VERSIONS = {0x0300: "SSL 3.0", 0x0301: "TLS 1.0", 0x0302: "TLS 1.1"}
EXPECTED_TLS_PORTS = {443, 465, 563, 636, 853, 993, 995, 8443, 9443}
EXPECTED_QUIC_PORTS = {443, 80, 8443}


@dataclass(frozen=True)
class EncryptedConfig:
    alert_nonstandard_port: bool = True
    # a client that skips SNI is usually talking to a raw IP, which is normal
    # for infrastructure and abnormal for anything user-facing
    alert_missing_sni: bool = True
    # JA3 md5 hashes of known-bad clients. empty by default; fill it from a
    # public feed such as abuse.ch SSLBL, or from your own malware sandbox.
    ja3_blocklist: tuple[str, ...] = ()


def detect_encrypted(
    features: list[dict[str, Any]],
    cfg: EncryptedConfig | None = None,
) -> list[dict[str, Any]]:
    cfg = cfg or EncryptedConfig()
    alerts: list[dict[str, Any]] = []
    for feat in features:
        alerts.extend(_tls_alerts(feat, cfg))
        alerts.extend(_quic_alerts(feat, cfg))
    return alerts


def _on_known_service_port(feat: dict[str, Any], expected: set[int]) -> bool:
    """True if either end is a normal port for this protocol.

    Both directions of a session are separate flows here, so the server->client
    direction has the service port as its *source*. Looking only at dst_port
    flags every reply as running on a weird port.
    """
    return (
        to_int(feat.get("dst_port")) in expected or to_int(feat.get("src_port")) in expected
    )


def _tls_alerts(feat: dict[str, Any], cfg: EncryptedConfig) -> list[dict[str, Any]]:
    if not feat.get("tls_is_client_hello"):
        return []
    # loopback TLS is local tooling, not C2
    if feat.get("src_is_loopback") or feat.get("dst_is_loopback"):
        return []

    alerts: list[dict[str, Any]] = []
    dst_port = to_int(feat.get("dst_port"))
    client_version = to_int(feat.get("tls_client_version"))
    ja3_hash = str(feat.get("tls_ja3_hash", ""))
    sni = str(feat.get("tls_sni", ""))
    # every TLS alert carries the fingerprint so alerts can be pivoted on it
    common = {
        "tls_ja3_hash": ja3_hash,
        "tls_ja3": feat.get("tls_ja3", ""),
        "tls_sni": sni,
        "tls_client_version": hex(client_version),
        "tls_sample_complete": bool(feat.get("tls_sample_complete")),
    }

    if ja3_hash and ja3_hash in cfg.ja3_blocklist:
        alerts.append(
            alert_from_flow(
                feat,
                threat_class=ENCRYPTED_ANOMALY,
                subtype="known_bad_ja3",
                severity="high",
                confidence=0.95,
                message=f"client JA3 {ja3_hash} is on the blocklist",
                evidence=dict(common, alpn=list(feat.get("tls_alpn", ()))),
            )
        )

    if client_version in LEGACY_TLS_VERSIONS:
        name = LEGACY_TLS_VERSIONS[client_version]
        alerts.append(
            alert_from_flow(
                feat,
                threat_class=ENCRYPTED_ANOMALY,
                subtype="legacy_tls_version",
                severity="medium",
                confidence=0.7,
                message=f"client offered deprecated {name} to {feat.get('dst_ip')}:{dst_port}",
                evidence=dict(common, tls_version_name=name),
            )
        )

    if cfg.alert_nonstandard_port and not _on_known_service_port(feat, EXPECTED_TLS_PORTS):
        alerts.append(
            alert_from_flow(
                feat,
                threat_class=ENCRYPTED_ANOMALY,
                subtype="tls_on_nonstandard_port",
                severity="low",
                confidence=0.55,
                message=f"TLS handshake on unexpected port {dst_port}",
                evidence=dict(common, dst_port=dst_port),
            )
        )

    if cfg.alert_missing_sni and not sni and feat.get("dst_is_public_unicast"):
        alerts.append(
            alert_from_flow(
                feat,
                threat_class=ENCRYPTED_ANOMALY,
                subtype="tls_without_sni",
                severity="medium",
                confidence=0.6,
                message=f"TLS handshake to public {feat.get('dst_ip')} carried no SNI",
                evidence=dict(common, ciphers=len(feat.get("tls_ciphers", ()))),
            )
        )
    return alerts


def _quic_alerts(feat: dict[str, Any], cfg: EncryptedConfig) -> list[dict[str, Any]]:
    if not feat.get("quic_is_initial"):
        return []
    dst_port = to_int(feat.get("dst_port"))
    if not cfg.alert_nonstandard_port or _on_known_service_port(feat, EXPECTED_QUIC_PORTS):
        return []
    return [
        alert_from_flow(
            feat,
            threat_class=ENCRYPTED_ANOMALY,
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


# There used to be an "encrypted_low_volume_session" rule here: long-lived TLS
# session, few packets, small average size. It fired on every idle browser
# keepalive, because shape on its own does not distinguish C2 from a connection
# sitting open doing nothing. What actually separates them is *regularity*, so
# packet-size shape now feeds the beaconing detector as evidence instead of
# raising an alert by itself.
