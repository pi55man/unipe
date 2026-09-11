from __future__ import annotations

import argparse
import logging
import time
from pathlib import Path
from typing import Any

from unipe_ai.alerts import AlertSink
from unipe_ai.features.extract import extract
from unipe_ai.features.window import FlowWindow
from unipe_ai.ingest.replay import ReplaySource
from unipe_ai.ingest.uds import FlowSocket
from unipe_ai.models.detector import Detector

DEFAULT_SOCKET = "/tmp/unipe.sock"
LOG = logging.getLogger("unipe_ai")


def main(argv: list[str] | None = None) -> None:
    args = _parse_args(argv)
    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s"
    )

    source: Any
    if args.replay is not None:
        source = ReplaySource(args.replay, tick_secs=args.replay_tick)
        LOG.info("replaying %s", args.replay)
    else:
        source = FlowSocket(args.socket)
        LOG.info("connecting to %s", args.socket)

    detector = Detector(config_path=args.config)
    if detector.model is None:
        LOG.warning("no trained model found; confidence comes from rules only")
    window = FlowWindow()
    sink = AlertSink(args.alerts_out)
    stats = Throughput(args.stats_every)

    source.connect()
    try:
        for batch in source.batches():
            received_at = time.time()
            # only the traffic that arrived since the last tick gets scored
            flows = window.deltas(batch, now=received_at)
            features = [extract(flow) for flow in flows]
            alerts = detector.score(features, now=received_at)

            for alert in alerts:
                alert["latency_ms"] = round((time.time() - received_at) * 1000.0, 3)
                sink.write(alert)
                LOG.warning(
                    "[%s/%s] sev=%s conf=%.2f %s",
                    alert["threat_class"],
                    alert["subtype"],
                    alert["severity"],
                    alert["confidence"],
                    alert["message"],
                )

            stats.add(len(batch), len(flows), len(alerts), time.time() - received_at)
            stats.maybe_log()
    except KeyboardInterrupt:
        LOG.info("stopping")
    finally:
        stats.log()
        sink.close()
        source.close()


class Throughput:
    """running totals so the prototype can state the rate it was tested at."""

    def __init__(self, every_secs: float = 10.0) -> None:
        self.every_secs = every_secs
        self.started = time.time()
        self.last_log = self.started
        self.batches = 0
        self.flows_in = 0
        self.flows_scored = 0
        self.alerts = 0
        self.busy_secs = 0.0
        self.max_batch_secs = 0.0

    def add(self, received: int, scored: int, alerts: int, elapsed: float) -> None:
        self.batches += 1
        self.flows_in += received
        self.flows_scored += scored
        self.alerts += alerts
        self.busy_secs += elapsed
        self.max_batch_secs = max(self.max_batch_secs, elapsed)

    def maybe_log(self) -> None:
        if self.every_secs > 0 and time.time() - self.last_log >= self.every_secs:
            self.log()
            self.last_log = time.time()

    def log(self) -> None:
        wall = max(time.time() - self.started, 1e-9)
        # capacity is what the pipeline could sustain if it never waited on input
        capacity = self.flows_scored / self.busy_secs if self.busy_secs > 0 else 0.0
        LOG.info(
            "throughput: %d batches, %d flows in, %d scored, %d alerts | "
            "%.0f flows/s observed, %.0f flows/s capacity, worst batch %.1f ms",
            self.batches,
            self.flows_in,
            self.flows_scored,
            self.alerts,
            self.flows_in / wall,
            capacity,
            self.max_batch_secs * 1000.0,
        )


def _parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Consume unipe flow batches over UDS")
    parser.add_argument(
        "--socket",
        type=Path,
        default=Path(DEFAULT_SOCKET),
        help="Unix socket published by unipe (default: /tmp/unipe.sock)",
    )
    parser.add_argument(
        "--replay",
        type=Path,
        help="replay a JSONL capture instead of reading the live socket",
    )
    parser.add_argument(
        "--replay-tick",
        type=float,
        default=0.0,
        help="seconds to sleep between replayed batches (default: as fast as possible)",
    )
    parser.add_argument("--config", type=Path, help="detector config TOML")
    parser.add_argument(
        "--alerts-out",
        type=Path,
        help="append alerts as JSON lines to this file",
    )
    parser.add_argument(
        "--stats-every",
        type=float,
        default=10.0,
        help="seconds between throughput lines (0 disables)",
    )
    return parser.parse_args(argv)
