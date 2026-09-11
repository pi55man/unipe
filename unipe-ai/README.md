# unipe-ai

Detection engine for a one-way tap. It consumes flow records that the `unipe`
eBPF/XDP exporter publishes over a Unix socket, scores them, and emits alerts.

Nothing in here ever writes back toward the monitored network: the socket is
opened read-only, no detector performs a lookup, probe, or handshake, and the
only output is an alert record.

## Running it

```shell
# live, against the exporter
sudo cargo run --release -p unipe -- --iface eth0 --interval-ms 250
python3 run.py --alerts-out alerts.jsonl

# replay a recorded capture, no root needed
python3 run.py --replay capture.jsonl --alerts-out alerts.jsonl

# retrain the scoring model, then measure throughput
python3 train.py
python3 bench.py
```

A replay file is one JSON array of flows per line, i.e. one exporter tick per
line. Alerts are appended to `--alerts-out` as JSON lines, which is what a
separate frontend is expected to read.

## Pipeline

```
XDP  ->  flow map  ->  UDS  ->  window  ->  extract  ->  detectors  ->  alerts
                                (deltas)   (features)   (rules + model)  (jsonl)
```

**Window.** The eBPF map holds cumulative counters and the exporter re-sends
every live flow on every tick, so a flow that went quiet an hour ago still
arrives with its old totals. `features/window.py` remembers the previous totals
per 5-tuple and passes on only what moved since the last tick. Idle flows are
dropped entirely. This is what makes the pipeline incremental instead of a
repeated whole-map rescan, and it also stops stale flows from dragging down
aggregate rates.

**Extract.** `features/extract.py` derives rates, ratios, protocol flags and
address classifications, then calls `features/payload.py` to pull metadata out
of the 64-byte payload sample.

**Detect.** Seven detector modules, each owning one threat class, plus a
trained model that adjusts the confidence of whatever the rules found.

## Threat classes

| Class | Module | Signal |
| --- | --- | --- |
| `volumetric_ddos` | `models/volumetric.py` | fan-in rate per victim, SYN/UDP/ICMP flood signatures, per-flow rate extremes |
| `ip_spoofing` | `models/spoofing.py` | martian sources, TTL spread across initial-TTL families, SYN storms with zero ACKs, LAND |
| `c2_beaconing` | `models/beaconing.py` | stddev/mean of the gaps between activity per (src, dst, port) |
| `dns_abuse` | `models/dnsabuse.py` | query-name entropy and label length (DGA), long stuffed names, TXT/NULL records, subdomain volume per parent (tunnelling) |
| `encrypted_malware` | `models/encrypted.py` | TLS/QUIC handshake metadata, deprecated versions, handshakes on odd ports, low-volume long-lived sessions |
| `recon_scanning` | `models/scanning.py` | port fan-out per target, host fan-out per port, with probe-sized flows |
| `data_exfiltration` | `models/exfiltration.py` | outbound/inbound byte ratio, pairing each flow with its reverse 5-tuple |

## Features engineered

From the flow counters: packet rate, byte rate, average packet size, SYN/ACK
and ACK/SYN ratios, total TCP flag count, protocol flags, SYN-only flag, flow
duration, cumulative vs per-window totals.

From the addresses: martian/bogon, loopback, private, multicast, public unicast,
LAND (src == dst), and a TTL-to-initial-TTL-family mapping.

From the 64-byte payload sample, metadata only:

- **DNS** — query name, name length, label count, longest label, Shannon
  entropy, digit ratio, record type.
- **TLS** — record type and version, ClientHello flag, client version, and a
  prefix fingerprint.
- **QUIC** — long-header flag, version, Initial-packet flag.

### Known limitation: JA3/JA4

The exporter samples 64 payload bytes. A ClientHello puts a 32-byte random at
offset 11, so the sample ends before the cipher-suite and extension lists that
a real JA3 or JA4 hash is built from. What `parse_tls` produces is a *prefix*
fingerprint over the record and client versions, and it is named that way on
purpose rather than being passed off as JA3.

Raising `FlowRecord.payload` in `unipe-common` to roughly 320 bytes is the one
change needed to compute a real JA3, but that overflows the 512-byte eBPF stack
when the record is built, so it needs a per-CPU scratch map first. Until then,
requirement (d) is served by the TLS/QUIC handshake metadata above plus the
packet-size and timing shape of the session.

## The model

`models/ml.py` is a logistic regression over ten features, written out by hand
with no third-party packages. It is deliberately linear and small: it trains in
about a second and every weight can be read and argued with.

The rules decide *what* a threat is and supply the evidence; the model decides
*how much to believe it*. Final confidence is

```
confidence = 0.6 * rule_confidence + 0.4 * model_probability
```

and the model's probability is recorded in `evidence.ml_probability` so a
reviewer can see both halves. If `artifacts/flow_model.json` is missing the
engine logs a warning and runs on rule confidence alone.

Rule confidence itself comes from `ratio_confidence`: 0.5 at the threshold,
rising toward 0.95 at three times the threshold.

### Training and validation

There is no public capture that matches a one-way tap of this exporter's exact
field set, so `train.py` generates a labelled set from the traffic profiles the
detectors target — benign (browsing, streaming, DNS, mDNS, short idle sessions)
against malicious (SYN flood, UDP flood, ICMP flood, port scan, bulk exfil,
spoofed sources). Every sample goes through the same `extract()` the live
pipeline uses, so training and inference cannot drift apart.

6000 samples, shuffled, split 70/30 into train and validation. Batch gradient
descent on log-loss, 400 epochs, learning rate 0.5, L2 0.001.

Held-out validation (seed 7):

| metric | train | validation |
| --- | --- | --- |
| accuracy | 0.914 | 0.912 |
| precision | 0.967 | 0.979 |
| recall | 0.857 | 0.846 |
| F1 | 0.909 | 0.907 |

Train and validation scores sitting on top of each other is the point: a linear
model on ten features is not able to memorise the set. The bias toward
precision over recall is intentional — the rules are what catch threats, and a
model that cried wolf would only inflate confidence on false positives.

Retrain with `python3 train.py`. Metrics are stored inside the model file.

## Throughput

`bench.py` drives the real window → extract → detect path with synthetic
batches. On one core of the development machine (Python 3.14, 60 batches of
2000 flows):

```
flows received    120000
flows scored      115903
wall time         7.17 s
ingest throughput 16,739 flows/sec
scoring rate      16,168 flows/sec
worst batch       182.0 ms
```

**Detection latency** is bounded by the exporter tick plus the scoring time for
one batch. At the default `--interval-ms 250` that is roughly 250 ms + 15 ms for
a typical batch, and every alert carries a measured `latency_ms`.

Reproduce with `python3 bench.py --batches 60 --flows-per-batch 2000`.

## Alert schema

Every detector emits the same record, built by `alerts.py`:

```json
{
  "schema_version": 1,
  "timestamp": 1789131320.884,
  "detected_at": 1789131321.005,
  "flow_id": "6/*:*->198.51.100.10:*",
  "threat_class": "volumetric_ddos",
  "subtype": "syn_flood",
  "severity": "high",
  "confidence": 0.952,
  "src_ip": "",
  "src_port": 0,
  "dst_ip": "198.51.100.10",
  "dst_port": 0,
  "protocol": 6,
  "message": "SYN flood toward 198.51.100.10: syn/ack=6000.0, syn-only flows=30/30",
  "evidence": {
    "unique_sources": 30,
    "tcp_flows": 30,
    "syn_count": 6000.0,
    "ack_count": 0.0,
    "syn_only_fraction": 1.0,
    "packet_rate": 6000.0,
    "ml_probability": 0.955
  },
  "latency_ms": 15.217
}
```

`timestamp` is when the traffic happened, `detected_at` is when the alert was
raised. `flow_id` is `protocol/src:port->dst:port`; aggregate alerts wildcard
the parts they span, so a flood against one victim reads
`6/*:*->198.51.100.10:*`. `severity` is `low`, `medium`, or `high`; alerts come
out sorted by severity then confidence. `evidence` always holds the features
that triggered the rule.

## Configuration

`configs/default.toml` has one section per detector, and every key maps to a
field on that detector's config dataclass. Two knobs matter on a laptop tap:

- `volumetric.alert_lan_destinations` — when false, mutes only the *generic*
  fan-in alert for RFC1918/multicast destinations. The SYN, UDP and ICMP flood
  signatures always run, LAN victim or not.
- `spoofing.alert_private_to_public` — leave false on a client-side tap where
  private→public is just ordinary NAT. Turn it on for edge/ISP spans.

## Tests

```shell
python3 -m pytest tests/
```
