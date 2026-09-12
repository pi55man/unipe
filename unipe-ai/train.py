#!/usr/bin/env python3
"""train and validate the flow + DNS models on lab-faithful synthetic traffic.

profiles are named after the brief's dataset tools (iperf3, hping3, dnscat2,
iodine, published DGA families, sandboxed C2 timing). every sample goes through
the same extract() / feature path the live pipeline uses.

usage: python train.py [--seed 7] [--samples 6000] [--dns-samples 8000]
"""

from __future__ import annotations

import argparse
import json
import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from unipe_ai.data import TOOL_MAP, beacon_intervals, benign_flow, malicious_flow
from unipe_ai.data.dga import benign_qname, dga_qname
from unipe_ai.features.extract import extract
from unipe_ai.models.beaconing import BeaconingConfig, BeaconTracker
from unipe_ai.models.dns_ml import (
    DEFAULT_DNS_MODEL_PATH,
    DNS_FEATURE_NAMES,
    dns_feature_vector,
)
from unipe_ai.models.ml import (
    DEFAULT_MODEL_PATH,
    FEATURE_NAMES,
    LogisticModel,
    evaluate,
    feature_vector,
    train,
)


def build_flow_dataset(
    rng: random.Random, count: int
) -> tuple[list[list[float]], list[int], dict[str, int]]:
    # DNS abuse is scored by the DNS model; do not poison the flow scorer with
    # one-packet resolver queries labelled malicious.
    samples: list[list[float]] = []
    labels: list[int] = []
    by_tool: dict[str, int] = {}
    for _ in range(count // 2):
        good = benign_flow(rng)
        bad = malicious_flow(rng, include_dns=False)
        samples.append(feature_vector(extract(good)))
        labels.append(0)
        samples.append(feature_vector(extract(bad)))
        labels.append(1)
        for flow in (good, bad):
            tool = str(flow.get("lab_tool", "?"))
            by_tool[tool] = by_tool.get(tool, 0) + 1
    return samples, labels, by_tool


def build_dns_dataset(
    rng: random.Random, count: int
) -> tuple[list[list[float]], list[int]]:
    samples: list[list[float]] = []
    labels: list[int] = []
    for _ in range(count // 2):
        samples.append(dns_feature_vector(benign_qname(rng)))
        labels.append(0)
        samples.append(dns_feature_vector(dga_qname(rng)))
        labels.append(1)
    return samples, labels


def _fit(
    samples: list[list[float]],
    labels: list[int],
    feature_names: tuple[str, ...],
    rng: random.Random,
    epochs: int,
    learning_rate: float,
    extra_metrics: dict | None = None,
) -> LogisticModel:
    paired = list(zip(samples, labels))
    rng.shuffle(paired)
    split = int(len(paired) * 0.7)
    train_x = [p[0] for p in paired[:split]]
    train_y = [p[1] for p in paired[:split]]
    val_x = [p[0] for p in paired[split:]]
    val_y = [p[1] for p in paired[split:]]

    weights, bias = train(train_x, train_y, epochs=epochs, learning_rate=learning_rate)
    model = LogisticModel(weights, bias, feature_names=feature_names)
    model.metrics = {
        "epochs": epochs,
        "learning_rate": learning_rate,
        "train_samples": len(train_x),
        "validation_samples": len(val_x),
        "train": evaluate(model, train_x, train_y),
        "validation": evaluate(model, val_x, val_y),
        **(extra_metrics or {}),
    }
    return model


def _beacon_flow(src: str, dst: str, dst_port: int, t: float) -> dict:
    return extract(
        {
            "src_ip": src,
            "dst_ip": dst,
            "src_port": 51000,
            "dst_port": dst_port,
            "protocol": 6,
            "packets": 4,
            "bytes": 600,
            "duration_ms": 200,
            "syn_count": 1,
            "ack_count": 3,
            "fin_count": 0,
            "rst_count": 0,
            "is_dns": False,
            "timestamp": t,
            "ttl": 64,
            "icmp_type": 0,
            "icmp_code": 0,
            "payload_len": 0,
            "payload": "",
        }
    )


def eval_beaconing(rng: random.Random, trials: int = 200) -> dict:
    """hold-out style check: sandboxed C2 timing vs irregular browsing."""
    cfg = BeaconingConfig(min_intervals=4, alert_cooldown_s=0.0, external_only=True)
    tp = fp = tn = fn = 0
    for _ in range(trials // 2):
        tracker = BeaconTracker(cfg)
        alerts = []
        for t in beacon_intervals(rng, malicious=True):
            alerts = tracker.update(
                [_beacon_flow("192.168.1.50", "185.220.101.7", 8080, t)], now=t
            )
        if alerts:
            tp += 1
        else:
            fn += 1

        tracker = BeaconTracker(cfg)
        alerts = []
        for t in beacon_intervals(rng, malicious=False):
            alerts = tracker.update(
                [_beacon_flow("192.168.1.50", "104.18.2.3", 443, t)], now=t
            )
        if alerts:
            fp += 1
        else:
            tn += 1

    total = max(tp + fp + tn + fn, 1)
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    return {
        "trials": trials,
        "accuracy": round((tp + tn) / total, 4),
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "true_positives": tp,
        "false_positives": fp,
        "true_negatives": tn,
        "false_negatives": fn,
        "note": "synthetic C2 emulator timing vs irregular browsing",
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="train unipe-ai flow and DNS models")
    parser.add_argument("--seed", type=int, default=7)
    parser.add_argument("--samples", type=int, default=6000)
    parser.add_argument("--dns-samples", type=int, default=8000)
    parser.add_argument("--epochs", type=int, default=400)
    parser.add_argument("--learning-rate", type=float, default=0.5)
    parser.add_argument("--out", type=Path, default=DEFAULT_MODEL_PATH)
    parser.add_argument("--dns-out", type=Path, default=DEFAULT_DNS_MODEL_PATH)
    parser.add_argument(
        "--manifest",
        type=Path,
        default=DEFAULT_MODEL_PATH.parent / "dataset_manifest.json",
    )
    args = parser.parse_args()

    rng = random.Random(args.seed)

    print("training flow model (iperf3 / hping3 / scan / exfil / …)")
    flow_x, flow_y, by_tool = build_flow_dataset(rng, args.samples)
    flow_model = _fit(
        flow_x,
        flow_y,
        feature_names=FEATURE_NAMES,
        rng=rng,
        epochs=args.epochs,
        learning_rate=args.learning_rate,
        extra_metrics={"seed": args.seed, "lab_tool_counts": by_tool},
    )
    flow_model.save(args.out)

    print("training DNS model (benign names + published DGA families)")
    dns_x, dns_y = build_dns_dataset(rng, args.dns_samples)
    dns_model = _fit(
        dns_x,
        dns_y,
        feature_names=DNS_FEATURE_NAMES,
        rng=rng,
        epochs=args.epochs,
        learning_rate=args.learning_rate,
        extra_metrics={
            "seed": args.seed,
            "positive_class": "published-algorithm DGA families",
            "negative_class": "benign brand/service/cdn-shaped names",
        },
    )
    dns_model.save(args.dns_out)

    print("evaluating beaconing on synthetic C2 timing")
    beacon_metrics = eval_beaconing(rng)

    manifest = {
        "description": (
            "Lab-faithful synthetic traffic calibrated to the problem statement "
            "dataset tools. Retrain with `python train.py`."
        ),
        "tool_map": TOOL_MAP,
        "flow_model": str(args.out.name),
        "dns_model": str(args.dns_out.name),
        "flow_validation": flow_model.metrics.get("validation"),
        "dns_validation": dns_model.metrics.get("validation"),
        "beaconing_eval": beacon_metrics,
        "lab_tool_counts": by_tool,
    }
    args.manifest.parent.mkdir(parents=True, exist_ok=True)
    args.manifest.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")

    print(f"wrote {args.out}")
    print(f"  validation {flow_model.metrics['validation']}")
    print(f"wrote {args.dns_out}")
    print(f"  validation {dns_model.metrics['validation']}")
    print(f"wrote {args.manifest}")
    print(f"  beaconing  {beacon_metrics}")
    print("flow weights:")
    for name, weight in zip(flow_model.feature_names, flow_model.weights):
        print(f"  {name:<22} {weight:+.4f}")
    print(f"  {'bias':<22} {flow_model.bias:+.4f}")
    print("dns weights:")
    for name, weight in zip(dns_model.feature_names, dns_model.weights):
        print(f"  {name:<22} {weight:+.4f}")
    print(f"  {'bias':<22} {dns_model.bias:+.4f}")


if __name__ == "__main__":
    main()
