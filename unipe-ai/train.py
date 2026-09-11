#!/usr/bin/env python3
"""train and validate the flow-scoring model.

there is no public capture that matches a one-way tap of *our* exporter's
fields, so the training set is generated here from the traffic profiles the
detectors care about. every sample goes through the same extract() the live
pipeline uses, which keeps training and inference honest.

usage: python train.py [--seed 7] [--samples 6000]
"""

from __future__ import annotations

import argparse
import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from unipe_ai.features.extract import extract
from unipe_ai.models.ml import (
    DEFAULT_MODEL_PATH,
    LogisticModel,
    evaluate,
    feature_vector,
    train,
)


def benign_flow(rng: random.Random) -> dict:
    """ordinary browsing, streaming, dns lookups and lan chatter."""
    kind = rng.choice(["web", "stream", "dns", "lan", "idle"])
    if kind == "web":
        packets = rng.randint(10, 400)
        return _flow(
            protocol=6,
            src_ip=f"192.168.1.{rng.randint(2, 200)}",
            dst_ip=f"104.18.{rng.randint(0, 255)}.{rng.randint(1, 254)}",
            dst_port=443,
            packets=packets,
            bytes=packets * rng.randint(200, 1400),
            duration_ms=rng.randint(500, 60_000),
            syn_count=1,
            ack_count=max(packets - 1, 1),
        )
    if kind == "stream":
        packets = rng.randint(2_000, 40_000)
        return _flow(
            protocol=6,
            src_ip=f"142.250.{rng.randint(0, 255)}.{rng.randint(1, 254)}",
            dst_ip=f"192.168.1.{rng.randint(2, 200)}",
            src_port=443,
            packets=packets,
            bytes=packets * rng.randint(1000, 1500),
            duration_ms=rng.randint(30_000, 600_000),
            syn_count=1,
            ack_count=packets,
        )
    if kind == "dns":
        return _flow(
            protocol=17,
            src_ip=f"192.168.1.{rng.randint(2, 200)}",
            dst_ip="192.168.1.1",
            dst_port=53,
            packets=rng.randint(1, 4),
            bytes=rng.randint(60, 300),
            duration_ms=rng.randint(1, 200),
        )
    if kind == "lan":
        return _flow(
            protocol=17,
            src_ip=f"192.168.1.{rng.randint(2, 200)}",
            dst_ip="224.0.0.251",
            src_port=5353,
            dst_port=5353,
            packets=rng.randint(1, 20),
            bytes=rng.randint(80, 2000),
            duration_ms=rng.randint(100, 30_000),
            ttl=255,
        )
    return _flow(
        protocol=6,
        src_ip=f"192.168.1.{rng.randint(2, 200)}",
        dst_ip=f"93.184.{rng.randint(0, 255)}.{rng.randint(1, 254)}",
        dst_port=443,
        packets=rng.randint(2, 8),
        bytes=rng.randint(150, 900),
        duration_ms=rng.randint(1, 400),
        syn_count=1,
        ack_count=rng.randint(1, 6),
    )


def malicious_flow(rng: random.Random) -> dict:
    """one sample per threat family the pipeline is asked to catch."""
    kind = rng.choice(["syn_flood", "udp_flood", "icmp_flood", "scan", "exfil", "spoofed"])
    if kind == "syn_flood":
        packets = rng.randint(500, 20_000)
        return _flow(
            protocol=6,
            src_ip=f"203.0.113.{rng.randint(1, 254)}",
            dst_ip="198.51.100.10",
            dst_port=80,
            packets=packets,
            bytes=packets * 60,
            duration_ms=rng.randint(1000, 5000),
            syn_count=packets,
            ack_count=0,
        )
    if kind == "udp_flood":
        packets = rng.randint(1, 3)
        return _flow(
            protocol=17,
            src_ip=f"{rng.randint(1, 223)}.{rng.randint(0, 255)}."
            f"{rng.randint(0, 255)}.{rng.randint(1, 254)}",
            dst_ip="198.51.100.10",
            dst_port=rng.randint(1, 65535),
            packets=packets,
            bytes=packets * rng.randint(28, 1400),
            duration_ms=rng.randint(1, 50),
        )
    if kind == "icmp_flood":
        packets = rng.randint(300, 10_000)
        return _flow(
            protocol=1,
            src_ip=f"203.0.113.{rng.randint(1, 254)}",
            dst_ip="198.51.100.10",
            packets=packets,
            bytes=packets * 84,
            duration_ms=rng.randint(500, 4000),
        )
    if kind == "scan":
        return _flow(
            protocol=6,
            src_ip="203.0.113.77",
            dst_ip=f"198.51.100.{rng.randint(1, 254)}",
            dst_port=rng.randint(1, 65535),
            packets=1,
            bytes=60,
            duration_ms=rng.randint(1, 20),
            syn_count=1,
            ack_count=0,
        )
    if kind == "exfil":
        packets = rng.randint(20_000, 200_000)
        return _flow(
            protocol=6,
            src_ip=f"192.168.1.{rng.randint(2, 200)}",
            dst_ip=f"185.220.{rng.randint(0, 255)}.{rng.randint(1, 254)}",
            dst_port=rng.choice([443, 22, 8080]),
            packets=packets,
            bytes=packets * 1400,
            duration_ms=rng.randint(60_000, 900_000),
            syn_count=1,
            ack_count=packets,
        )
    return _flow(
        protocol=17,
        src_ip=rng.choice(["0.0.0.0", "169.254.3.9", "224.1.2.3", "255.255.255.255"]),
        dst_ip="198.51.100.10",
        dst_port=rng.randint(1, 65535),
        packets=rng.randint(1, 5),
        bytes=rng.randint(28, 500),
        duration_ms=rng.randint(1, 100),
    )


def _flow(**overrides) -> dict:
    base = {
        "src_ip": "192.168.1.10",
        "dst_ip": "8.8.8.8",
        "src_port": 40000,
        "dst_port": 443,
        "protocol": 6,
        "packets": 1,
        "bytes": 100,
        "duration_ms": 100,
        "syn_count": 0,
        "ack_count": 0,
        "fin_count": 0,
        "rst_count": 0,
        "is_dns": False,
        "timestamp": 0.0,
        "ttl": 64,
        "icmp_type": 0,
        "icmp_code": 0,
        "payload_len": 0,
        "payload": "",
    }
    base.update(overrides)
    return base


def build_dataset(rng: random.Random, count: int) -> tuple[list[list[float]], list[int]]:
    samples: list[list[float]] = []
    labels: list[int] = []
    for _ in range(count // 2):
        samples.append(feature_vector(extract(benign_flow(rng))))
        labels.append(0)
        samples.append(feature_vector(extract(malicious_flow(rng))))
        labels.append(1)
    return samples, labels


def main() -> None:
    parser = argparse.ArgumentParser(description="train the unipe-ai flow scoring model")
    parser.add_argument("--seed", type=int, default=7)
    parser.add_argument("--samples", type=int, default=6000)
    parser.add_argument("--epochs", type=int, default=400)
    parser.add_argument("--learning-rate", type=float, default=0.5)
    parser.add_argument("--out", type=Path, default=DEFAULT_MODEL_PATH)
    args = parser.parse_args()

    rng = random.Random(args.seed)
    samples, labels = build_dataset(rng, args.samples)

    # shuffle before splitting so the two classes land in both halves
    paired = list(zip(samples, labels))
    rng.shuffle(paired)
    split = int(len(paired) * 0.7)
    train_x = [p[0] for p in paired[:split]]
    train_y = [p[1] for p in paired[:split]]
    val_x = [p[0] for p in paired[split:]]
    val_y = [p[1] for p in paired[split:]]

    weights, bias = train(
        train_x, train_y, epochs=args.epochs, learning_rate=args.learning_rate
    )
    model = LogisticModel(weights, bias)
    train_metrics = evaluate(model, train_x, train_y)
    val_metrics = evaluate(model, val_x, val_y)
    model.metrics = {
        "seed": args.seed,
        "epochs": args.epochs,
        "learning_rate": args.learning_rate,
        "train_samples": len(train_x),
        "validation_samples": len(val_x),
        "train": train_metrics,
        "validation": val_metrics,
    }
    model.save(args.out)

    print(f"wrote {args.out}")
    print(f"train      {train_metrics}")
    print(f"validation {val_metrics}")
    print("weights:")
    for name, weight in zip(model.feature_names, model.weights):
        print(f"  {name:<22} {weight:+.4f}")
    print(f"  {'bias':<22} {model.bias:+.4f}")


if __name__ == "__main__":
    main()
