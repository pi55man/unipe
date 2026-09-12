"""alert aggregation + soft multi-stage correlation.

stops identical ongoing detections from flooding the jsonl while still
escalating when something meaningful changes. correlation across threat
classes is probabilistic — never presented as proof of a kill chain.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from unipe_ai.alerts import SEVERITY_ORDER

# soft kill-chain adjacency (lower = earlier). gaps are ok; order is a hint.
_CHAIN_RANK = {
    "recon_scanning": 1,
    "dns_abuse": 2,
    "c2_beaconing": 3,
    "encrypted_anomaly": 4,
    "data_exfiltration": 5,
    "volumetric_ddos": 0,
    "ip_spoofing": 0,
}

FLOOD_SUBTYPES = {"udp_flood", "syn_flood", "fan_in_flood", "icmp_flood"}
_RATE_FLOW_SUBTYPES = {
    "high_rate_flow",
    "udp_high_rate_flow",
    "icmp_high_rate_flow",
    "syn_high_rate_flow",
}

# reopen / escalate window for the same ongoing event
DEFAULT_WINDOW_S = 300.0
# don't re-emit the same event without a meaningful change inside this quiet period
DEFAULT_QUIET_S = 60.0
MAX_OPEN = 512
MAX_RELATED = 8
PPS_STEP_RATIO = 2.0  # behavioral change: packet rate roughly doubles


def _sev(sev: str) -> int:
    return SEVERITY_ORDER.get(sev, 0)


def _entity_of(alert: dict[str, Any]) -> str:
    """primary entity for aggregation — prefer victim/destination."""
    dst = str(alert.get("dst_ip") or "").strip()
    src = str(alert.get("src_ip") or "").strip()
    if dst and dst not in {"*", "0.0.0.0"}:
        return dst
    if src and src not in {"*", "0.0.0.0"}:
        return f"src:{src}"
    return str(alert.get("flow_id") or "unknown")


def _agg_key(alert: dict[str, Any]) -> tuple[Any, ...]:
    subtype = alert.get("subtype", "")
    if subtype in FLOOD_SUBTYPES or subtype in _RATE_FLOW_SUBTYPES:
        return ("dst", subtype, alert.get("dst_ip", ""))
    if subtype in {"vertical_port_scan", "horizontal_sweep"}:
        return (
            "scan",
            subtype,
            alert.get("src_ip", ""),
            alert.get("dst_ip", ""),
            alert.get("dst_port", 0),
        )
    return ("flow", alert.get("threat_class"), subtype, alert.get("flow_id", ""))


def _packet_rate(alert: dict[str, Any]) -> float | None:
    v = alert.get("evidence", {}).get("packet_rate")
    try:
        f = float(v)
    except (TypeError, ValueError):
        return None
    return f if f >= 0 else None


class IncidentAggregator:
    """fold repeats; emit on first sight or meaningful escalation."""

    def __init__(
        self,
        path: Path | None = None,
        *,
        window_s: float = DEFAULT_WINDOW_S,
        quiet_s: float = DEFAULT_QUIET_S,
    ) -> None:
        self.path = path
        self.window_s = max(window_s, 1.0)
        self.quiet_s = max(quiet_s, 0.0)
        self._open: dict[str, dict[str, Any]] = {}  # incident_id -> state
        self._by_key: dict[tuple[Any, ...], str] = {}
        self._by_entity: dict[str, list[str]] = {}
        self._seq = 0
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
        if not isinstance(data, dict):
            return
        self._seq = int(data.get("seq") or 0)
        opens = data.get("open") or {}
        if isinstance(opens, dict):
            self._open = {k: v for k, v in opens.items() if isinstance(v, dict)}
        self._by_key.clear()
        self._by_entity.clear()
        for iid, state in self._open.items():
            key = tuple(state.get("agg_key") or ())
            if key:
                self._by_key[key] = iid
            ent = str(state.get("entity") or "")
            if ent:
                self._by_entity.setdefault(ent, []).append(iid)

    def flush(self) -> None:
        if self.path is None:
            return
        body = {
            "schema_version": 1,
            "updated_at": time.time(),
            "seq": self._seq,
            "open": self._open,
        }
        tmp = self.path.with_suffix(self.path.suffix + ".tmp")
        tmp.write_text(json.dumps(body, separators=(",", ":")) + "\n", encoding="utf-8")
        tmp.replace(self.path)

    def process(
        self, alerts: list[dict[str, Any]], now: float | None = None
    ) -> list[dict[str, Any]]:
        now = time.time() if now is None else now
        self._expire(now)
        emitted: list[dict[str, Any]] = []
        for alert in alerts:
            out = self._handle(alert, now)
            if out is not None:
                emitted.append(out)
        if self.path is not None:
            self.flush()
        return emitted

    def _expire(self, now: float) -> None:
        dead = [
            iid
            for iid, st in self._open.items()
            if now - float(st.get("last_seen") or 0) > self.window_s
        ]
        for iid in dead:
            self._drop(iid)
        if len(self._open) > MAX_OPEN:
            oldest = sorted(
                self._open.items(),
                key=lambda kv: float(kv[1].get("last_seen") or 0),
            )
            for iid, _ in oldest[: len(self._open) - MAX_OPEN]:
                self._drop(iid)

    def _drop(self, iid: str) -> None:
        st = self._open.pop(iid, None)
        if not st:
            return
        key = tuple(st.get("agg_key") or ())
        if self._by_key.get(key) == iid:
            self._by_key.pop(key, None)
        ent = str(st.get("entity") or "")
        ids = self._by_entity.get(ent) or []
        if iid in ids:
            ids = [x for x in ids if x != iid]
            if ids:
                self._by_entity[ent] = ids
            else:
                self._by_entity.pop(ent, None)

    def _handle(self, alert: dict[str, Any], now: float) -> dict[str, Any] | None:
        key = _agg_key(alert)
        entity = _entity_of(alert)
        # traffic timestamps can be lab/synthetic and far from wall clock; expiry
        # and quiet windows must follow the engine's `now`.
        traffic_ts = float(alert.get("timestamp") or now)
        iid = self._by_key.get(key)
        state = self._open.get(iid) if iid else None

        if state is None or now - float(state.get("last_seen") or 0) > self.window_s:
            return self._open_new(alert, key, entity, traffic_ts, now)

        reasons = self._escalation_reasons(state, alert)
        state["occurrence_count"] = int(state.get("occurrence_count") or 1) + 1
        state["last_seen"] = now
        state["traffic_last_seen"] = max(
            float(state.get("traffic_last_seen") or 0), traffic_ts
        )
        self._merge_state(state, alert)

        # soft-correlate other open events on this entity
        related, hypothesis = self._correlate(entity, state, alert)

        quiet_ok = now - float(state.get("last_emitted") or 0) >= self.quiet_s
        if not reasons and not quiet_ok:
            # still refresh correlation hooks on the stored state
            state["related_incident_ids"] = related
            if hypothesis:
                state["correlation_hypothesis"] = hypothesis
            return None
        if not reasons and quiet_ok:
            # periodic heartbeat after quiet — treat as continuation update
            reasons = ["continuation"]

        state["last_emitted"] = now
        state["escalation_reasons"] = reasons
        state["related_incident_ids"] = related
        if hypothesis:
            state["correlation_hypothesis"] = hypothesis
        return self._enrich(alert, state, reasons, related, hypothesis)

    def _open_new(
        self,
        alert: dict[str, Any],
        key: tuple[Any, ...],
        entity: str,
        traffic_ts: float,
        now: float,
    ) -> dict[str, Any]:
        self._seq += 1
        iid = f"inc-{self._seq}-{entity}"
        pps = _packet_rate(alert)
        state = {
            "id": iid,
            "entity": entity,
            "agg_key": list(key),
            "first_seen": traffic_ts,
            "last_seen": now,
            "traffic_last_seen": traffic_ts,
            "last_emitted": now,
            "occurrence_count": 1,
            "severity": alert.get("severity") or "low",
            "confidence": float(alert.get("confidence") or 0),
            "subtypes": [str(alert.get("subtype") or "")],
            "threat_classes": [str(alert.get("threat_class") or "")],
            "partners": [],
            "peak_packet_rate": pps,
            "escalation_reasons": ["new"],
            "related_incident_ids": [],
            "correlation_hypothesis": "",
        }
        self._merge_partners(state, alert)
        related, hypothesis = self._correlate(entity, state, alert)
        state["related_incident_ids"] = related
        state["correlation_hypothesis"] = hypothesis
        self._open[iid] = state
        self._by_key[key] = iid
        self._by_entity.setdefault(entity, []).append(iid)
        # also index src entity for correlation lookup
        src = str(alert.get("src_ip") or "")
        if src and f"src:{src}" != entity and src not in {"*", ""}:
            self._by_entity.setdefault(src, []).append(iid)
        return self._enrich(alert, state, ["new"], related, hypothesis)

    def _merge_state(self, state: dict[str, Any], alert: dict[str, Any]) -> None:
        subtype = str(alert.get("subtype") or "")
        tc = str(alert.get("threat_class") or "")
        if subtype and subtype not in state["subtypes"]:
            state["subtypes"].append(subtype)
        if tc and tc not in state["threat_classes"]:
            state["threat_classes"].append(tc)
        if _sev(str(alert.get("severity") or "")) >= _sev(str(state.get("severity") or "")):
            state["severity"] = alert.get("severity") or state["severity"]
        state["confidence"] = max(
            float(state.get("confidence") or 0),
            float(alert.get("confidence") or 0),
        )
        pps = _packet_rate(alert)
        if pps is not None:
            prev = state.get("peak_packet_rate")
            if prev is None or pps > float(prev):
                state["peak_packet_rate"] = pps
        self._merge_partners(state, alert)

    def _merge_partners(self, state: dict[str, Any], alert: dict[str, Any]) -> None:
        partners: list[str] = list(state.get("partners") or [])
        for ip in (alert.get("src_ip"), alert.get("dst_ip")):
            s = str(ip or "").strip()
            if not s or s in {"*", "0.0.0.0"}:
                continue
            if s == state.get("entity"):
                continue
            if s.startswith("src:"):
                continue
            if s not in partners:
                partners.append(s)
        state["partners"] = partners[-32:]

    def _escalation_reasons(
        self, state: dict[str, Any], alert: dict[str, Any]
    ) -> list[str]:
        reasons: list[str] = []
        subtype = str(alert.get("subtype") or "")
        if subtype and subtype not in (state.get("subtypes") or []):
            reasons.append("new_detector")
        if _sev(str(alert.get("severity") or "")) > _sev(str(state.get("severity") or "")):
            reasons.append("severity_increase")
        # spoofed floods naturally grow unique sources every tick — that is not
        # an escalation by itself. only non-flood events treat new peers as news.
        floodish = subtype in FLOOD_SUBTYPES or subtype in _RATE_FLOW_SUBTYPES
        if not floodish:
            before = set(state.get("partners") or [])
            for ip in (alert.get("src_ip"), alert.get("dst_ip")):
                s = str(ip or "").strip()
                if not s or s in {"*", "0.0.0.0", state.get("entity")}:
                    continue
                if s not in before:
                    if s == alert.get("dst_ip"):
                        reasons.append("new_destination")
                    else:
                        reasons.append("additional_host")
        pps = _packet_rate(alert)
        peak = state.get("peak_packet_rate")
        if pps is not None and peak is not None and float(peak) > 0:
            if pps >= float(peak) * PPS_STEP_RATIO:
                reasons.append("behavioral_change")
        # dedupe while preserving order
        seen: set[str] = set()
        out: list[str] = []
        for r in reasons:
            if r not in seen:
                seen.add(r)
                out.append(r)
        return out

    def _correlate(
        self,
        entity: str,
        state: dict[str, Any],
        alert: dict[str, Any],
    ) -> tuple[list[str], str]:
        """link other open incidents on the same entity if chain-adjacent."""
        related: list[str] = []
        classes = set(state.get("threat_classes") or [])
        classes.add(str(alert.get("threat_class") or ""))
        candidates = list(self._by_entity.get(entity) or [])
        # also check bare src if entity is a dst
        src = str(alert.get("src_ip") or "")
        if src:
            candidates.extend(self._by_entity.get(src) or [])
            candidates.extend(self._by_entity.get(f"src:{src}") or [])
        for oid in candidates:
            if oid == state.get("id"):
                continue
            other = self._open.get(oid)
            if not other:
                continue
            other_classes = set(other.get("threat_classes") or [])
            if not other_classes:
                continue
            if self._chain_adjacent(classes, other_classes):
                related.append(oid)
            if len(related) >= MAX_RELATED:
                break
        hypothesis = ""
        if related:
            ordered = sorted(
                {c for c in classes if c in _CHAIN_RANK},
                key=lambda c: _CHAIN_RANK.get(c, 99),
            )
            if len(ordered) >= 2:
                hypothesis = (
                    "Possible multi-stage activity involving "
                    + " → ".join(ordered)
                    + " on the same entity (probabilistic correlation only; "
                    "not proof of a single campaign)."
                )
            else:
                hypothesis = (
                    "Related detections share an entity within the correlation "
                    "window (probabilistic; not proof of a single campaign)."
                )
        return related, hypothesis

    @staticmethod
    def _chain_adjacent(a: set[str], b: set[str]) -> bool:
        ranks_a = [_CHAIN_RANK[c] for c in a if c in _CHAIN_RANK and _CHAIN_RANK[c] > 0]
        ranks_b = [_CHAIN_RANK[c] for c in b if c in _CHAIN_RANK and _CHAIN_RANK[c] > 0]
        if not ranks_a or not ranks_b:
            # volumetric/spoof next to anything on same entity still soft-links
            return bool(a & b) or bool(a) and bool(b)
        for ra in ranks_a:
            for rb in ranks_b:
                if abs(ra - rb) <= 2 and ra != rb:
                    return True
                if ra == rb and a != b:
                    return True
        return False

    def _enrich(
        self,
        alert: dict[str, Any],
        state: dict[str, Any],
        reasons: list[str],
        related: list[str],
        hypothesis: str,
    ) -> dict[str, Any]:
        out = dict(alert)
        out["incident_id"] = state["id"]
        out["occurrence_count"] = int(state.get("occurrence_count") or 1)
        out["incident_first_seen"] = float(state.get("first_seen") or 0)
        out["incident_last_seen"] = float(
            state.get("traffic_last_seen") or state.get("last_seen") or 0
        )
        out["contributing_subtypes"] = list(state.get("subtypes") or [])
        out["contributing_classes"] = list(state.get("threat_classes") or [])
        out["escalation_reasons"] = list(reasons)
        out["related_incident_ids"] = list(related)
        if hypothesis:
            out["correlation_hypothesis"] = hypothesis
        # keep evidence self-describing for UIs that only read evidence
        ev = dict(out.get("evidence") or {})
        ev["occurrence_count"] = out["occurrence_count"]
        ev["incident_id"] = out["incident_id"]
        if reasons:
            ev["escalation_reasons"] = list(reasons)
        if hypothesis:
            ev["correlation_hypothesis"] = hypothesis
        out["evidence"] = ev
        return out
