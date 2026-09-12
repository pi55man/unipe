"""the one alert record shape every detector emits.

keeping this in a single place means the jsonl log and any future ui only ever
have to know about one schema.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any, TextIO

from unipe_ai.util import clamp, to_float, to_int

SCHEMA_VERSION = 1

# threat classes, one per detector family
VOLUMETRIC_DDOS = "volumetric_ddos"
IP_SPOOFING = "ip_spoofing"
C2_BEACONING = "c2_beaconing"
DNS_ABUSE = "dns_abuse"
ENCRYPTED_ANOMALY = "encrypted_anomaly"
RECON_SCANNING = "recon_scanning"
DATA_EXFILTRATION = "data_exfiltration"

SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2}


def make_flow_id(
    protocol: Any = "*",
    src_ip: Any = "*",
    src_port: Any = "*",
    dst_ip: Any = "*",
    dst_port: Any = "*",
) -> str:
    """5-tuple string. aggregate alerts use '*' for the parts they span."""
    return f"{protocol}/{src_ip}:{src_port}->{dst_ip}:{dst_port}"


def flow_id_of(flow: dict[str, Any]) -> str:
    return make_flow_id(
        to_int(flow.get("protocol")),
        flow.get("src_ip", ""),
        to_int(flow.get("src_port")),
        flow.get("dst_ip", ""),
        to_int(flow.get("dst_port")),
    )


def ratio_confidence(value: float, threshold: float, ceiling: float = 3.0) -> float:
    """0.5 right at the threshold, rising toward 0.95 at ceiling x threshold."""
    if threshold <= 0:
        return 0.5
    over = value / threshold
    if over <= 1.0:
        return 0.5
    span = max(ceiling - 1.0, 0.001)
    return clamp(0.5 + 0.45 * min((over - 1.0) / span, 1.0), 0.5, 0.95)


def make_alert(
    *,
    threat_class: str,
    subtype: str,
    severity: str,
    confidence: float,
    message: str,
    evidence: dict[str, Any],
    flow_id: str,
    timestamp: float | None = None,
    src_ip: str = "",
    dst_ip: str = "",
    src_port: Any = 0,
    dst_port: Any = 0,
    protocol: Any = 0,
) -> dict[str, Any]:
    now = time.time()
    return {
        "schema_version": SCHEMA_VERSION,
        # when the traffic happened (unix seconds, from the exporter)
        "timestamp": to_float(timestamp, now),
        # when we raised the alert, so latency is measurable
        "detected_at": now,
        "flow_id": flow_id,
        "threat_class": threat_class,
        "subtype": subtype,
        "severity": severity,
        "confidence": round(clamp(to_float(confidence, 0.5), 0.0, 1.0), 3),
        "src_ip": src_ip,
        "src_port": to_int(src_port),
        "dst_ip": dst_ip,
        "dst_port": to_int(dst_port),
        "protocol": to_int(protocol),
        "message": message,
        "evidence": evidence,
    }


def alert_from_flow(
    feat: dict[str, Any],
    *,
    threat_class: str,
    subtype: str,
    severity: str,
    confidence: float,
    message: str,
    evidence: dict[str, Any],
) -> dict[str, Any]:
    """convenience wrapper when an alert is about one concrete flow."""
    return make_alert(
        threat_class=threat_class,
        subtype=subtype,
        severity=severity,
        confidence=confidence,
        message=message,
        evidence=evidence,
        flow_id=flow_id_of(feat),
        timestamp=feat.get("timestamp"),
        src_ip=str(feat.get("src_ip", "")),
        dst_ip=str(feat.get("dst_ip", "")),
        src_port=feat.get("src_port"),
        dst_port=feat.get("dst_port"),
        protocol=feat.get("protocol"),
    )


def newest_timestamp(features: list[dict[str, Any]]) -> float:
    stamps = [to_float(f.get("timestamp")) for f in features]
    stamps = [s for s in stamps if s > 0]
    return max(stamps) if stamps else time.time()


class AlertSink:
    """writes alerts as json lines so a separate frontend can tail the file."""

    def __init__(self, path: Path | None = None) -> None:
        self.path = path
        self._fh: TextIO | None = None
        if path is not None:
            path.parent.mkdir(parents=True, exist_ok=True)
            self._fh = path.open("a", encoding="utf-8")

    def write(self, alert: dict[str, Any]) -> None:
        if self._fh is None:
            return
        self._fh.write(json.dumps(alert, separators=(",", ":")) + "\n")
        self._fh.flush()

    def close(self) -> None:
        if self._fh is not None:
            self._fh.close()
            self._fh = None
