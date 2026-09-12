"""bounded persistent entity dossiers for passive monitoring.

profiles survive engine restart via a json file next to alerts/status.
retention is hard-capped so the monitor enclave cannot grow without bound.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from unipe_ai.alerts import SEVERITY_ORDER

MAX_ENTITIES = 2000
MAX_PARTNERS = 24
MAX_PORTS = 16
MAX_DOMAINS = 16
MAX_ALERT_REFS = 40
FLUSH_EVERY_S = 2.0

_SKIP_IPS = {"", "*", "0.0.0.0", "255.255.255.255"}


def _valid_ip(ip: Any) -> str | None:
    s = str(ip or "").strip()
    if not s or s in _SKIP_IPS:
        return None
    return s


def _sev_rank(sev: str) -> int:
    return SEVERITY_ORDER.get(sev, 0)


def _priority(severity: str, alert_count: int, threat_n: int) -> str:
    """coarse analyst priority from what we have passively observed."""
    rank = _sev_rank(severity)
    if rank >= 2 and (alert_count >= 2 or threat_n >= 2):
        return "critical"
    if rank >= 2 or (rank >= 1 and alert_count >= 3):
        return "high"
    if rank >= 1 or alert_count >= 1:
        return "medium"
    return "low"


class EntityStore:
    """in-memory dossiers flushed to disk; keyed by IP string."""

    def __init__(self, path: Path | None = None) -> None:
        self.path = path
        self._entities: dict[str, dict[str, Any]] = {}
        self._dirty = False
        self._last_flush = 0.0
        if path is not None:
            path.parent.mkdir(parents=True, exist_ok=True)
            self.load()

    def load(self) -> None:
        if self.path is None or not self.path.is_file():
            return
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return
        ents = data.get("entities") if isinstance(data, dict) else None
        if not isinstance(ents, dict):
            return
        self._entities = {k: v for k, v in ents.items() if isinstance(v, dict)}
        self._trim()

    def flush(self, force: bool = False) -> None:
        if self.path is None:
            return
        now = time.time()
        if not force and not self._dirty:
            return
        if not force and now - self._last_flush < FLUSH_EVERY_S:
            return
        self._trim()
        body = {
            "schema_version": 1,
            "updated_at": now,
            "entity_count": len(self._entities),
            "entities": self._entities,
        }
        tmp = self.path.with_suffix(self.path.suffix + ".tmp")
        tmp.write_text(json.dumps(body, separators=(",", ":")) + "\n", encoding="utf-8")
        tmp.replace(self.path)
        self._dirty = False
        self._last_flush = now

    def get(self, ip: str) -> dict[str, Any] | None:
        return self._entities.get(ip)

    def all(self) -> dict[str, dict[str, Any]]:
        return self._entities

    def observe_flows(self, features: list[dict[str, Any]], now: float | None = None) -> None:
        now = time.time() if now is None else now
        for feat in features:
            src = _valid_ip(feat.get("src_ip"))
            dst = _valid_ip(feat.get("dst_ip"))
            if src:
                self._touch(src, now)
                if dst:
                    self._add_partner(src, dst, now)
                self._add_port(src, feat, role="src")
                domain = self._domain_of(feat)
                if domain:
                    self._add_domain(src, domain, now)
            if dst:
                self._touch(dst, now)
                if src:
                    self._add_partner(dst, src, now)
                self._add_port(dst, feat, role="dst")
                domain = self._domain_of(feat)
                if domain:
                    self._add_domain(dst, domain, now)
        self._dirty = True

    def note_alert(self, alert: dict[str, Any]) -> None:
        ts = float(alert.get("timestamp") or alert.get("detected_at") or time.time())
        for ip in (_valid_ip(alert.get("src_ip")), _valid_ip(alert.get("dst_ip"))):
            if not ip:
                continue
            ent = self._touch(ip, ts)
            tc = str(alert.get("threat_class") or "")
            if tc and tc not in ent["threat_classes"]:
                ent["threat_classes"].append(tc)
                if len(ent["threat_classes"]) > 12:
                    ent["threat_classes"] = ent["threat_classes"][-12:]
            sev = str(alert.get("severity") or "low")
            if _sev_rank(sev) >= _sev_rank(ent["severity"]):
                ent["severity"] = sev
            peer = None
            if ip == alert.get("src_ip"):
                peer = _valid_ip(alert.get("dst_ip"))
            else:
                peer = _valid_ip(alert.get("src_ip"))
            if peer:
                self._add_partner(ip, peer, ts)
            ref = {
                "timestamp": ts,
                "threat_class": tc,
                "subtype": str(alert.get("subtype") or ""),
                "severity": sev,
                "confidence": float(alert.get("confidence") or 0),
                "message": str(alert.get("message") or "")[:240],
                "incident_id": str(alert.get("incident_id") or ""),
                "peer_ip": peer or "",
            }
            alerts = ent["alerts"]
            alerts.append(ref)
            if len(alerts) > MAX_ALERT_REFS:
                ent["alerts"] = alerts[-MAX_ALERT_REFS:]
            ent["alert_count"] = int(ent.get("alert_count") or 0) + 1
            ent["priority"] = _priority(
                ent["severity"],
                int(ent["alert_count"]),
                len(ent["threat_classes"]),
            )
        self._dirty = True

    def _touch(self, ip: str, now: float) -> dict[str, Any]:
        ent = self._entities.get(ip)
        if ent is None:
            ent = {
                "ip": ip,
                "first_seen": now,
                "last_seen": now,
                "threat_classes": [],
                "severity": "low",
                "priority": "low",
                "partners": {},
                "ports": {},
                "domains": {},
                "alerts": [],
                "alert_count": 0,
                "flow_observations": 0,
            }
            self._entities[ip] = ent
            self._trim()
        ent["last_seen"] = max(float(ent.get("last_seen") or 0), now)
        if not ent.get("first_seen"):
            ent["first_seen"] = now
        ent["flow_observations"] = int(ent.get("flow_observations") or 0) + 1
        return ent

    def _add_partner(self, ip: str, peer: str, now: float) -> None:
        ent = self._entities[ip]
        partners: dict[str, Any] = ent.setdefault("partners", {})
        slot = partners.get(peer)
        if slot is None:
            partners[peer] = {"first_seen": now, "last_seen": now, "count": 1}
        else:
            slot["last_seen"] = now
            slot["count"] = int(slot.get("count") or 0) + 1
        if len(partners) > MAX_PARTNERS:
            # drop oldest by last_seen
            ordered = sorted(partners.items(), key=lambda kv: float(kv[1].get("last_seen") or 0))
            for dead, _ in ordered[: len(partners) - MAX_PARTNERS]:
                partners.pop(dead, None)

    def _add_port(self, ip: str, feat: dict[str, Any], *, role: str) -> None:
        ent = self._entities[ip]
        ports: dict[str, Any] = ent.setdefault("ports", {})
        proto = int(feat.get("protocol") or 0)
        port = int(feat.get("dst_port") if role == "src" else feat.get("dst_port") or 0)
        if role == "dst":
            port = int(feat.get("dst_port") or 0)
        else:
            # as a source, the remote service port is usually dst_port
            port = int(feat.get("dst_port") or 0)
        if port <= 0 and proto not in {1}:
            return
        key = f"{proto}/{port}"
        ports[key] = int(ports.get(key) or 0) + 1
        if len(ports) > MAX_PORTS:
            ordered = sorted(ports.items(), key=lambda kv: kv[1])
            for dead, _ in ordered[: len(ports) - MAX_PORTS]:
                ports.pop(dead, None)

    def _add_domain(self, ip: str, domain: str, now: float) -> None:
        ent = self._entities[ip]
        domains: dict[str, Any] = ent.setdefault("domains", {})
        domains[domain] = now
        if len(domains) > MAX_DOMAINS:
            ordered = sorted(domains.items(), key=lambda kv: float(kv[1] or 0))
            for dead, _ in ordered[: len(domains) - MAX_DOMAINS]:
                domains.pop(dead, None)

    @staticmethod
    def _domain_of(feat: dict[str, Any]) -> str | None:
        for key in ("dns_qname", "tls_sni"):
            val = feat.get(key)
            if isinstance(val, str) and val.strip():
                return val.strip().lower()[:253]
        return None

    def _trim(self) -> None:
        if len(self._entities) <= MAX_ENTITIES:
            return
        ordered = sorted(
            self._entities.items(),
            key=lambda kv: float(kv[1].get("last_seen") or 0),
        )
        drop = len(self._entities) - MAX_ENTITIES
        for ip, _ in ordered[:drop]:
            self._entities.pop(ip, None)
