from __future__ import annotations

import argparse
import logging
import time
from pathlib import Path
from typing import Any

from unipe_ai.alerts import AlertSink
from unipe_ai.coverage import coverage_notes, visibility_block
from unipe_ai.entities import EntityStore
from unipe_ai.features.extract import extract
from unipe_ai.features.window import FlowWindow
from unipe_ai.ingest.replay import ReplaySource
from unipe_ai.ingest.uds import FlowSocket
from unipe_ai.models.detector import Detector
from unipe_ai.status import StatusSink

DEFAULT_SOCKET = "/tmp/unipe.sock"
DEFAULT_ALERTS = Path("/tmp/unipe/alerts.jsonl")
DEFAULT_STATUS = Path("/tmp/unipe/status.json")
DEFAULT_ENTITIES = Path("/tmp/unipe/entities.json")
DEFAULT_INCIDENTS = Path("/tmp/unipe/incidents.json")
# under a spoofed flood the eBPF map fills with unique 5-tuples; scoring every
# new flow each tick melts the python process. keep a hard ceiling.
MAX_SCORE_PER_TICK = 12_000
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

    detector = Detector(
        config_path=args.config,
        incidents_path=args.incidents_out,
    )
    if detector.model is None:
        LOG.warning("no trained flow model found; confidence comes from rules only")
    if detector.dns_model is None:
        LOG.warning("no trained DNS model found; DGA falls back to the signal vote")
    window = FlowWindow()
    sink = AlertSink(args.alerts_out)
    status = StatusSink(args.status_out)
    entities = EntityStore(args.entities_out)
    stats = Throughput(args.stats_every)
    direction = TapDirection()

    LOG.info("alerts -> %s", args.alerts_out)
    LOG.info("status -> %s", args.status_out)
    LOG.info("entities -> %s", args.entities_out)
    LOG.info("incidents -> %s", args.incidents_out)

    source.connect()
    try:
        # FlowSocket.batches() reconnects after disconnect; ReplaySource ends once.
        for batch in source.batches():
            received_at = time.time()
            # only the traffic that arrived since the last tick gets scored
            flows = window.deltas(batch, now=received_at)
            dropped = 0
            if len(flows) > MAX_SCORE_PER_TICK:
                dropped = len(flows) - MAX_SCORE_PER_TICK
                LOG.warning(
                    "scoring capped %d -> %d flows this tick (flood backlog)",
                    len(flows),
                    MAX_SCORE_PER_TICK,
                )
                flows.sort(
                    key=lambda f: float(f.get("packets") or 0),
                    reverse=True,
                )
                flows = flows[:MAX_SCORE_PER_TICK]
            features = [extract(flow) for flow in flows]
            entities.observe_flows(features, now=received_at)
            alerts = detector.score(features, now=received_at)

            tap_snap = direction.snapshot()
            health_partial = {
                "flows_dropped_cap": stats.flows_dropped_cap + dropped,
                "coverage_degraded": bool(
                    stats.flows_dropped_cap + dropped > 0
                    or tap_snap.get("one_directional")
                ),
            }
            for alert in alerts:
                alert["latency_ms"] = round((time.time() - received_at) * 1000.0, 3)
                alert["coverage"] = coverage_notes(
                    alert, tap=tap_snap, health=health_partial
                )
                entities.note_alert(alert)
                sink.write(alert)
                LOG.warning(
                    "[%s/%s] sev=%s conf=%.2f %s",
                    alert["threat_class"],
                    alert["subtype"],
                    alert["severity"],
                    alert["confidence"],
                    alert["message"],
                )

            stats.add(
                len(batch),
                len(flows),
                len(alerts),
                time.time() - received_at,
                dropped=dropped,
            )
            stats.note_handshakes(features)
            direction.note(features)
            direction.maybe_warn()
            stats.maybe_log()
            entities.flush()
            status.write(
                stats.snapshot(
                    tap=direction.snapshot(),
                    socket=str(args.socket),
                    alerts_path=str(args.alerts_out),
                    entities_path=str(args.entities_out),
                    incidents_path=str(args.incidents_out),
                    replay=args.replay is not None,
                )
            )
    except KeyboardInterrupt:
        LOG.info("stopping")
    finally:
        stats.log()
        entities.flush(force=True)
        status.write(
            stats.snapshot(
                tap=direction.snapshot(),
                socket=str(args.socket),
                alerts_path=str(args.alerts_out),
                entities_path=str(args.entities_out),
                incidents_path=str(args.incidents_out),
                replay=args.replay is not None,
                stopping=True,
            )
        )
        sink.close()
        source.close()


class TapDirection:
    """Warn once if the tap only ever carries one side of a conversation.

    XDP is a receive-path hook, so pointing it at a host's own NIC shows the
    replies coming back but never the requests that provoked them. Several
    detectors then go quiet for a structural reason rather than because the
    traffic was clean, which is worth saying out loud. A mirrored link or SPAN
    feed does not have this problem: both directions arrive as ingress there.

    Direction is read off the ports rather than the addresses, so this works on
    an edge span where both endpoints are public.
    """

    # enough flows that a quiet start does not trigger the warning
    min_samples = 200
    # below this share, one direction is effectively absent rather than rare
    min_minority_share = 0.05

    def __init__(self) -> None:
        self.to_server = 0
        self.to_client = 0
        self.warned = False
        self.message = ""

    def note(self, features: list[dict]) -> None:
        for feat in features:
            # count conversations, not the windows they span
            if not feat.get("is_new_flow"):
                continue
            src_port = int(feat.get("src_port") or 0)
            dst_port = int(feat.get("dst_port") or 0)
            # equal ports means icmp or a peer-to-peer protocol like mdns,
            # neither of which says anything about direction
            if src_port == dst_port:
                continue
            if dst_port < src_port:
                self.to_server += 1
            else:
                self.to_client += 1

    def maybe_warn(self) -> None:
        snap = self.snapshot()
        if self.warned or not snap["one_directional"]:
            return
        if snap["total"] < self.min_samples:
            return
        self.warned = True
        self.message = snap["message"]
        LOG.warning("%s", self.message)

    def snapshot(self) -> dict[str, Any]:
        total = self.to_server + self.to_client
        one_directional = False
        message = ""
        if total >= self.min_samples:
            minority = min(self.to_server, self.to_client) / total
            if minority < self.min_minority_share:
                one_directional = True
                inbound_only = self.to_client > self.to_server
                side = "replies inbound" if inbound_only else "requests outbound"
                detail = (
                    "JA3 needs the ClientHello and exfiltration needs outbound volume, "
                    "so neither can be detected from here"
                    if inbound_only
                    else "JA3S and inbound scan detection are unavailable from here"
                )
                message = (
                    f"tap looks one-directional: {max(self.to_server, self.to_client)} "
                    f"of {total} flows are {side}. {detail}"
                )
                self.message = message
        return {
            "one_directional": one_directional,
            "message": message or self.message,
            "to_server": self.to_server,
            "to_client": self.to_client,
            "total": total,
        }


class Throughput:
    """running totals so the prototype can state the rate it was tested at."""

    def __init__(self, every_secs: float = 10.0) -> None:
        self.every_secs = every_secs
        self.started = time.time()
        self.last_log = self.started
        self.batches = 0
        self.flows_in = 0
        self.flows_scored = 0
        self.flows_dropped_cap = 0
        self.alerts = 0
        self.busy_secs = 0.0
        self.max_batch_secs = 0.0
        # handshake sampling health, counted once per flow so long-lived
        # sessions reappearing every window don't inflate the numbers
        self.hellos = 0
        self.hellos_complete = 0
        self.ja3 = 0
        self.ja3s = 0

    def note_handshakes(self, features: list[dict]) -> None:
        for feat in features:
            if not feat.get("is_new_flow"):
                continue
            if not (feat.get("tls_is_client_hello") or feat.get("tls_is_server_hello")):
                continue
            self.hellos += 1
            self.hellos_complete += bool(feat.get("tls_sample_complete"))
            self.ja3 += bool(feat.get("tls_ja3_hash"))
            self.ja3s += bool(feat.get("tls_ja3s_hash"))

    def add(
        self,
        received: int,
        scored: int,
        alerts: int,
        elapsed: float,
        *,
        dropped: int = 0,
    ) -> None:
        self.batches += 1
        self.flows_in += received
        self.flows_scored += scored
        self.flows_dropped_cap += max(dropped, 0)
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
            "%.0f flows/s observed, %.0f flows/s capacity, worst batch %.1f ms"
            "%s",
            self.batches,
            self.flows_in,
            self.flows_scored,
            self.alerts,
            self.flows_in / wall,
            capacity,
            self.max_batch_secs * 1000.0,
            (
                f", {self.flows_dropped_cap} dropped by score cap"
                if self.flows_dropped_cap
                else ""
            ),
        )
        LOG.info(
            "handshakes: %d hellos sampled, %d complete, %d ja3, %d ja3s",
            self.hellos,
            self.hellos_complete,
            self.ja3,
            self.ja3s,
        )

    def snapshot(
        self,
        *,
        tap: dict[str, Any],
        socket: str,
        alerts_path: str,
        entities_path: str = "",
        incidents_path: str = "",
        replay: bool = False,
        stopping: bool = False,
    ) -> dict[str, Any]:
        wall = max(time.time() - self.started, 1e-9)
        coverage_degraded = bool(
            self.flows_dropped_cap > 0 or tap.get("one_directional")
        )
        health = {
            "flows_dropped_cap": self.flows_dropped_cap,
            "score_cap_per_tick": MAX_SCORE_PER_TICK,
            "coverage_degraded": coverage_degraded,
            "processing_lag_ms": round(self.max_batch_secs * 1000.0, 2),
        }
        return {
            "running": not stopping,
            "replay": replay,
            "socket": socket,
            "alerts_path": alerts_path,
            "entities_path": entities_path,
            "incidents_path": incidents_path,
            "batches": self.batches,
            "flows_in": self.flows_in,
            "flows_scored": self.flows_scored,
            "flows_dropped_cap": self.flows_dropped_cap,
            "score_cap_per_tick": MAX_SCORE_PER_TICK,
            "alerts": self.alerts,
            "flows_per_sec": round(self.flows_in / wall, 2),
            "capacity_flows_per_sec": round(
                self.flows_scored / self.busy_secs if self.busy_secs > 0 else 0.0,
                2,
            ),
            "worst_batch_ms": round(self.max_batch_secs * 1000.0, 2),
            "coverage_degraded": coverage_degraded,
            "handshakes": {
                "hellos": self.hellos,
                "complete": self.hellos_complete,
                "ja3": self.ja3,
                "ja3s": self.ja3s,
            },
            "tap": tap,
            "visibility": visibility_block(tap, health),
        }


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
        default=DEFAULT_ALERTS,
        help=f"append alerts as JSON lines (default: {DEFAULT_ALERTS})",
    )
    parser.add_argument(
        "--status-out",
        type=Path,
        default=DEFAULT_STATUS,
        help=f"write live status json for the desktop ui (default: {DEFAULT_STATUS})",
    )
    parser.add_argument(
        "--entities-out",
        type=Path,
        default=DEFAULT_ENTITIES,
        help=f"persistent entity dossiers (default: {DEFAULT_ENTITIES})",
    )
    parser.add_argument(
        "--incidents-out",
        type=Path,
        default=DEFAULT_INCIDENTS,
        help=f"persistent open-incident state (default: {DEFAULT_INCIDENTS})",
    )
    parser.add_argument(
        "--stats-every",
        type=float,
        default=10.0,
        help="seconds between throughput lines (0 disables)",
    )
    return parser.parse_args(argv)
