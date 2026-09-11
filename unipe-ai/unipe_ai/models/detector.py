from __future__ import annotations

import time
from dataclasses import fields, is_dataclass
from pathlib import Path
from typing import Any

from unipe_ai.alerts import SEVERITY_ORDER
from unipe_ai.models.beaconing import BeaconingConfig, BeaconTracker
from unipe_ai.models.dnsabuse import DnsConfig, detect_dns_abuse
from unipe_ai.models.encrypted import EncryptedConfig, detect_encrypted
from unipe_ai.models.exfiltration import ExfiltrationConfig, detect_exfiltration
from unipe_ai.models.ml import DEFAULT_MODEL_PATH, LogisticModel
from unipe_ai.models.scanning import ScanningConfig, detect_scanning
from unipe_ai.models.spoofing import SpoofingConfig, detect_spoofing
from unipe_ai.models.volumetric import VolumetricConfig, detect_volumetric
from unipe_ai.util import clamp

_DEFAULT_CONFIG = Path(__file__).resolve().parents[2] / "configs" / "default.toml"

# how much of the final confidence comes from the trained model vs the rule
_MODEL_WEIGHT = 0.4

FLOOD_SUBTYPES = {"udp_flood", "syn_flood", "fan_in_flood", "icmp_flood"}
SPOOF_NOISE_SUBTYPES = {"martian_source", "martian_source_storm", "land_attack"}


class Detector:
    """Unidirectional IDS detector covering every threat class in the brief."""

    def __init__(self, config_path: Path | None = None, model_path: Path | None = None) -> None:
        configs = _load_configs(config_path or _DEFAULT_CONFIG)
        self.volumetric_cfg: VolumetricConfig = configs["volumetric"]
        self.spoofing_cfg: SpoofingConfig = configs["spoofing"]
        self.beaconing_cfg: BeaconingConfig = configs["beaconing"]
        self.dns_cfg: DnsConfig = configs["dns"]
        self.encrypted_cfg: EncryptedConfig = configs["encrypted"]
        self.scanning_cfg: ScanningConfig = configs["scanning"]
        self.exfiltration_cfg: ExfiltrationConfig = configs["exfiltration"]
        self.beacons = BeaconTracker(self.beaconing_cfg)
        self.model = LogisticModel.load(model_path or DEFAULT_MODEL_PATH)

    def score(self, features: list[dict[str, Any]], now: float | None = None) -> list[dict[str, Any]]:
        if not features:
            return []
        now = time.time() if now is None else now

        volumetric = detect_volumetric(features, self.volumetric_cfg)
        spoofing = _drop_flood_noise(detect_spoofing(features, self.spoofing_cfg), volumetric)

        alerts = (
            volumetric
            + spoofing
            + self.beacons.update(features, now)
            + detect_dns_abuse(features, self.dns_cfg)
            + detect_encrypted(features, self.encrypted_cfg)
            + detect_scanning(features, self.scanning_cfg)
            + detect_exfiltration(features, self.exfiltration_cfg)
        )
        alerts = _dedupe(alerts)
        self._apply_model(alerts, features)
        alerts.sort(
            key=lambda a: (SEVERITY_ORDER.get(a["severity"], 0), a["confidence"]),
            reverse=True,
        )
        return alerts

    def _apply_model(self, alerts: list[dict[str, Any]], features: list[dict[str, Any]]) -> None:
        """blend the rule's own confidence with the trained model's opinion."""
        if self.model is None or not alerts:
            return

        by_flow_id = {}
        by_dst: dict[str, float] = {}
        for feat in features:
            probability = self.model.probability(feat)
            by_flow_id[feat.get("flow_id")] = probability
            dst = str(feat.get("dst_ip", ""))
            by_dst[dst] = max(by_dst.get(dst, 0.0), probability)

        for alert in alerts:
            probability = by_flow_id.get(alert["flow_id"])
            if probability is None:
                # aggregate alerts wildcard the tuple, so fall back to the victim
                probability = by_dst.get(alert["dst_ip"])
            if probability is None:
                continue
            blended = (1 - _MODEL_WEIGHT) * alert["confidence"] + _MODEL_WEIGHT * probability
            alert["confidence"] = round(clamp(blended, 0.0, 1.0), 3)
            alert["evidence"]["ml_probability"] = round(probability, 3)


def _drop_flood_noise(
    spoofing: list[dict[str, Any]],
    volumetric: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """a flood already reported per destination doesn't need per-packet spoof spam."""
    flood_dsts = {a["dst_ip"] for a in volumetric if a["subtype"] in FLOOD_SUBTYPES}
    return [
        a
        for a in spoofing
        if not (
            a["subtype"] in SPOOF_NOISE_SUBTYPES
            and (a["dst_ip"] in flood_dsts or a["src_ip"] == "127.0.0.1")
        )
    ]


def _dedupe(alerts: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[tuple[Any, ...]] = set()
    out: list[dict[str, Any]] = []
    for alert in alerts:
        key = (alert["threat_class"], alert["subtype"], alert["flow_id"])
        if key in seen:
            continue
        seen.add(key)
        out.append(alert)
    return out


_CONFIG_SECTIONS: dict[str, Any] = {
    "volumetric": VolumetricConfig,
    "spoofing": SpoofingConfig,
    "beaconing": BeaconingConfig,
    "dns": DnsConfig,
    "encrypted": EncryptedConfig,
    "scanning": ScanningConfig,
    "exfiltration": ExfiltrationConfig,
}


def _load_configs(path: Path) -> dict[str, Any]:
    data = _parse_toml(path.read_text(encoding="utf-8")) if path.is_file() else {}
    return {
        name: _build(cls, data.get(name, {})) for name, cls in _CONFIG_SECTIONS.items()
    }


def _build(cls: Any, values: dict[str, Any]) -> Any:
    """fill a config dataclass from toml, casting to whatever the default is."""
    if not is_dataclass(cls):
        raise TypeError(f"{cls} is not a config dataclass")
    defaults = cls()
    supplied = {}
    for field in fields(cls):
        if field.name not in values:
            continue
        caster = type(getattr(defaults, field.name))
        try:
            supplied[field.name] = caster(values[field.name])
        except (TypeError, ValueError):
            continue
    return cls(**supplied)


def _parse_toml(text: str) -> dict[str, dict[str, Any]]:
    try:
        import tomllib

        loaded = tomllib.loads(text)
        return {k: v for k, v in loaded.items() if isinstance(v, dict)}
    except (ImportError, ValueError):
        # ValueError covers TOMLDecodeError, so a malformed file still loads
        return _parse_simple_toml(text)


def _parse_simple_toml(text: str) -> dict[str, dict[str, Any]]:
    """fallback for a malformed file or a python without tomllib."""
    sections: dict[str, dict[str, Any]] = {}
    current: str | None = None
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("[") and line.endswith("]"):
            current = line[1:-1].strip()
            sections.setdefault(current, {})
            continue
        if current is None or "=" not in line:
            continue
        key, value = [p.strip() for p in line.split("=", 1)]
        sections[current][key] = _coerce(value)
    return sections


def _coerce(value: str) -> Any:
    value = value.split("#", 1)[0].strip().strip('"').strip("'")
    if value.lower() in {"true", "false"}:
        return value.lower() == "true"
    try:
        if "." in value:
            return float(value)
        return int(value)
    except ValueError:
        return value
