#!/usr/bin/env python3
"""measure how many flows/sec the pipeline sustains, and how fast it alerts.

this is what backs the throughput number in the README. it drives the real
window -> extract -> detect path, only the socket is replaced by a generator.

usage: python bench.py [--batches 60] [--flows-per-batch 2000]
"""

from __future__ import annotations

import argparse
import random
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from unipe_ai.features.extract import extract
from unipe_ai.features.window import FlowWindow
from unipe_ai.models.detector import Detector


def make_batch(rng: random.Random, size: int, tick: int) -> list[dict]:
    """mostly background traffic with a syn flood and a port scan mixed in."""
    batch = []
    for i in range(size):
        roll = rng.random()
        if roll < 0.10:
            flow = _flow(
                src_ip=f"203.0.113.{i % 254 + 1}",
                dst_ip="198.51.100.10",
                dst_port=80,
                protocol=6,
                packets=200 * (tick + 1),
                bytes=12_000 * (tick + 1),
                syn_count=200 * (tick + 1),
                ack_count=0,
                duration_ms=1000 * (tick + 1),
            )
        elif roll < 0.15:
            flow = _flow(
                src_ip="203.0.113.77",
                dst_ip="198.51.100.20",
                dst_port=i % 65535 + 1,
                protocol=6,
                packets=1,
                bytes=60,
                syn_count=1,
                ack_count=0,
                duration_ms=5,
            )
        else:
            flow = _flow(
                src_ip=f"192.168.{i % 255}.{i % 254 + 1}",
                dst_ip=f"104.18.{i % 255}.{(i * 7) % 254 + 1}",
                dst_port=443,
                protocol=6,
                packets=40 * (tick + 1),
                bytes=45_000 * (tick + 1),
                syn_count=1,
                ack_count=40 * (tick + 1),
                duration_ms=2000 * (tick + 1),
            )
        flow["src_port"] = 1024 + (i % 60000)
        batch.append(flow)
    return batch


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
        "timestamp": time.time(),
        "ttl": 64,
        "icmp_type": 0,
        "icmp_code": 0,
        "payload_len": 0,
        "payload": "",
    }
    base.update(overrides)
    return base


def main() -> None:
    parser = argparse.ArgumentParser(description="benchmark the unipe-ai pipeline")
    parser.add_argument("--batches", type=int, default=60)
    parser.add_argument("--flows-per-batch", type=int, default=2000)
    parser.add_argument("--seed", type=int, default=11)
    args = parser.parse_args()

    rng = random.Random(args.seed)
    detector = Detector()
    window = FlowWindow()

    batches = [make_batch(rng, args.flows_per_batch, tick) for tick in range(args.batches)]

    scored = 0
    alerts = 0
    worst_ms = 0.0
    started = time.perf_counter()
    for batch in batches:
        batch_start = time.perf_counter()
        now = time.time()
        flows = window.deltas(batch, now=now)
        features = [extract(flow) for flow in flows]
        found = detector.score(features, now=now)
        scored += len(flows)
        alerts += len(found)
        worst_ms = max(worst_ms, (time.perf_counter() - batch_start) * 1000.0)
    elapsed = time.perf_counter() - started

    total_in = args.batches * args.flows_per_batch
    print(f"batches           {args.batches}")
    print(f"flows received    {total_in}")
    print(f"flows scored      {scored}   (idle flows are skipped by the window)")
    print(f"alerts raised     {alerts}")
    print(f"wall time         {elapsed:.2f} s")
    print(f"ingest throughput {total_in / elapsed:,.0f} flows/sec")
    print(f"scoring rate      {scored / elapsed:,.0f} flows/sec")
    print(f"worst batch       {worst_ms:.1f} ms")
    if detector.model is None:
        print("note: no trained model loaded, run train.py first")


if __name__ == "__main__":
    main()
