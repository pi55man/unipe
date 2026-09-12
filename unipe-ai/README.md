# unipe-ai

Detection engine for a one-way tap. It consumes flow records that the `unipe`
eBPF/XDP exporter publishes over a Unix socket, scores them, and emits alerts.

Nothing in here ever writes back toward the monitored network: the socket is
opened read-only, no detector performs a lookup, probe, or handshake, and the
only output is an alert record.

## Running it

```shell
# live against the exporter; alerts/status default under /tmp/unipe/ for the ui
sudo ./target/release/unipe --iface eth0 --interval-ms 250
python3 run.py

# replay a recorded capture, no root needed
python3 run.py --replay capture.jsonl --replay-tick 0.25

# retrain the scoring model, then measure throughput
python3 train.py
python3 bench.py
```

A replay file is one JSON array of flows per line, i.e. one exporter tick per
line. By default alerts append to `/tmp/unipe/alerts.jsonl` and a live
`/tmp/unipe/status.json` is written for the Tauri desktop console.

## Pipeline

```
XDP  ->  flow map      ->  UDS  ->  window  ->  extract  ->  detectors  ->  alerts
     ->  handshake map            (deltas)   (features)   (rules + model)  (jsonl)
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
| `c2_beaconing` | `models/beaconing.py` | stddev/mean of the gaps between activity per conversation, both directions folded onto one key |
| `dns_abuse` | `models/dnsabuse.py` | trained DNS logistic on label stats (DGA); long stuffed names / TXT / subdomain volume (tunnelling) |
| `encrypted_anomaly` | `models/encrypted.py` | JA3/JA3S fingerprints, blocklisted JA3 (known-bad), deprecated TLS versions, handshakes on odd ports, missing SNI to a public IP |
| `recon_scanning` | `models/scanning.py` | port fan-out per target, host fan-out per port, with probe-sized flows |
| `data_exfiltration` | `models/exfiltration.py` | outbound/inbound byte ratio, pairing each flow with its reverse 5-tuple |

## Features engineered

From the flow counters: packet rate, byte rate, average packet size, SYN/ACK
and ACK/SYN ratios, total TCP flag count, protocol flags, SYN-only flag, flow
duration, cumulative vs per-window totals.

From the addresses: martian/bogon, loopback, private, multicast, public unicast,
LAND (src == dst), and a TTL-to-initial-TTL-family mapping.

From the handshake sample, metadata only:

- **DNS** — query name, name length, label count, longest label, Shannon
  entropy, digit ratio, record type.
- **TLS** — record and handshake versions, cipher list, extension list,
  supported groups, EC point formats, SNI, ALPN, and the **JA3** hash for a
  ClientHello or the **JA3S** hash for a ServerHello.
- **QUIC** — long-header flag, version, Initial-packet flag.

### How the handshake sample stays metadata-only

The XDP program never copies application data. Before sampling anything it
checks that the bytes are one of:

- a DNS message (port 53), or
- a TLS handshake record (first byte `0x16`), or
- a QUIC Initial packet, identified by its long-header bit, the mandatory
  fixed bit and packet type 0 — deliberately not gated on port, since QUIC on
  an unexpected port is precisely what is worth catching.

Anything else — an HTTP body, a file transfer, TLS application data — is
counted but never copied. A TLS handshake is cleartext by definition: it is the
negotiation that happens *before* a key exists, so there is nothing here that
could be decrypted even in principle.

Samples live in their own `HANDSHAKES` map rather than inside `FlowRecord`,
because most flows never have one. That keeps `FlowRecord` at 56 bytes across
10240 entries while the 2 KB samples occupy only 2048 entries.

### The per-CPU scratch map

A `HandshakeSample` is ~2 KB and the eBPF stack is 512 bytes, so the sample
cannot be built as a local. `unipe-ebpf` declares a one-slot `PerCpuArray`,
fills it, and copies it into `HANDSHAKES`. XDP runs to completion without
preemption and each CPU has its own slot, so there is nothing to race with.

The copy loop writes straight into the map value and masks its index with
`HANDSHAKE_CAP - 1`, which is what proves to the verifier that the write is in
range. `HANDSHAKE_CAP` must therefore stay a power of two.

Check the program still passes the kernel verifier after any change here:

```shell
sudo ./target/release/unipe --verify
```

That loads the program and exits without attaching to a NIC.

### Remaining limitation: ClientHellos larger than one segment

XDP sees individual packets, so a sample can only ever hold what arrived in one
of them. At a 1500-byte MTU that is about 1460 bytes of payload. Most clients
fit — malware, IoT and embedded TLS stacks send compact hellos — but OpenSSL
3.6 and current Chrome send ~1500-1700 byte ClientHellos once a post-quantum
key share is included, and those span two TCP segments.

When that happens the record header says the hello is longer than what we
captured, `tls_sample_complete` is false, and **no JA3 is emitted**. A hash over
half a hello would match nothing, so guessing would be worse than staying quiet.
Reassembling across segments in the XDP program is the next step.

To see how often this is biting, the engine logs a handshake line alongside
throughput, counted once per flow:

```
handshakes: 214 hellos sampled, 173 complete, 96 ja3, 77 ja3s
```

`hellos sampled` well above `complete` means truncation; `hellos sampled` at
zero means the `HANDSHAKES` map is not being populated at all, which is a
different problem. All `ja3s` and no `ja3` means the next section.

### The tap vantage decides which detectors can fire

"Unidirectional" in this project means the sensor has **no return path**: it
never transmits, probes, resets or blocks. It does *not* mean the sensor sees
only one direction of traffic. A data diode is a one-way link *into* the
enclave, and what crosses it is a mirror of the monitored link — and a SPAN
port or optical TAP mirrors both directions of that link. So the enclave
normally sees both halves of every conversation while remaining unable to send
anything back. Both halves arrive as *ingress* on the monitoring NIC.

Pointing XDP at a host's own interface is a different situation, and it is
worth understanding before reading any results from one. **XDP is a
receive-path hook.** It runs in the driver RX path, or at `netif_receive_skb`
in `--skb` mode, while outbound packets leave via `dev_queue_xmit` and never
reach it. There is no XDP egress. Monitoring `wlan0` on a laptop therefore
shows every reply and none of the requests, and two things become structurally
impossible:

- **JA3.** The ClientHello is outbound. Only JA3S is reachable, which is why a
  live browsing capture reports `46 hellos sampled, 46 complete, 0 ja3, 46 ja3s`
  — nothing is truncated, there simply are no ClientHellos to see.
- **Data exfiltration.** Data leaving is outbound, so there is no volume to
  measure.

The engine detects this and says so once, rather than letting those detectors
look clean when they are really just blind:

```
WARNING tap looks one-directional: 214 of 214 flows are replies inbound.
JA3 needs the ClientHello and exfiltration needs outbound volume, so neither
can be detected from here
```

Direction is inferred from the ports rather than the addresses, so the check
also works on an edge span where both endpoints are public.

Everything else is written to work from whichever direction is available.
Beaconing in particular folds both halves of a conversation onto one key, so it
neither double-counts on a mirrored link nor goes blind on a one-way one.

## The model

`models/ml.py` is a logistic regression over ten features, written out by hand
with no third-party packages. It is deliberately linear and small: it trains in
about a second and every weight can be read and argued with.

The rules decide *what* a threat is and supply the evidence; the model decides
*how much to believe it*. Final confidence is

```
confidence = rule_confidence + 0.4 * model_probability * (1 - rule_confidence)
```

The model can only ever *raise* confidence. It was trained on flow shape, so it
has a real opinion about floods and scans but none at all about, say, a TLS
version — and a plain weighted average let that silence veto perfectly good
rules, pushing them under the reporting gate. Agreement now closes 40% of the
gap to certainty; disagreement leaves the rule where it was.

The model's probability is recorded in `evidence.ml_probability` so a
reviewer can see both halves. Anything still below `[detector] min_confidence`
(default 0.5) is dropped rather than reported. If `artifacts/flow_model.json` is missing the
engine logs a warning and runs on rule confidence alone.

Rule confidence itself comes from `ratio_confidence`: 0.5 at the threshold,
rising toward 0.95 at three times the threshold.

### Training and validation

The brief asks for synthetic / lab traffic (iperf3, hping3, dnscat2/iodine,
published DGA algorithms, sandboxed C2 timing). There is no public capture that
matches this exporter's exact field set, so `train.py` generates **lab-faithful
synthetic flows named after those tools**. Every sample goes through the same
`extract()` the live pipeline uses.

| Lab tool (brief) | Profile in `unipe_ai/data/` | What it trains |
| --- | --- | --- |
| iperf3 / Ostinato / TRex | `iperf3`, browsing, streaming | flow model negatives |
| hping3 SYN/UDP | `hping3_syn`, `hping3_udp` | flow model positives |
| port scan | `port_scan` | flow model positives |
| dnscat2 / iodine | `dnscat2`, `iodine` | DNS tunnel *rules* (shape) |
| DGArchive / published algos | `dga_conficker`, `cryptolocker`, … | **DNS logistic model** |
| sandboxed C2 emulator | `beacon_intervals()` | beaconing hold-out eval |

Two models are written:

- `artifacts/flow_model.json` — volumetric / scan / spoof / exfil shape
- `artifacts/dns_model.json` — DGA vs benign query names
- `artifacts/dataset_manifest.json` — tool map + held-out metrics

DNS tunnelling stays rule-based (length / labels / TXT); DGA uses the trained
DNS model when the artifact is present, with the old 3-of-4 signal vote as
fallback. Slowloris is skipped: it needs HTTP semantics this metadata path
does not parse.

Held-out validation (seed 7, after `python3 train.py`):

**Flow model** (~6000 samples, 70/30 split)

| metric | validation |
| --- | --- |
| accuracy | ~0.82 |
| precision | ~0.94 |
| recall | ~0.70 |
| F1 | ~0.80 |

Precision over recall is intentional: iperf3-shaped benign load is in the
negative class on purpose, so the model does not treat every high-rate flow as
an attack. The rules still catch floods; the model only *confirms*.

**DNS model** (~8000 names)

| metric | validation |
| --- | --- |
| accuracy | ~0.88 |
| precision | ~0.88 |
| recall | ~0.89 |
| F1 | ~0.88 |

**Beaconing** (200 synthetic C2 vs browsing timing trials): accuracy 1.0 on the
hold-out generator (real lab captures would replace this section later).

Retrain with `python3 train.py`. Metrics live inside each model file and in
the manifest.

## Throughput

`bench.py` drives the real window → extract → detect path with synthetic
batches. On one core of the development machine (Python 3.14, 60 batches of
2000 flows):

```
flows received    120000
flows scored      115903
wall time         9.31 s
ingest throughput 12,882 flows/sec
scoring rate      12,443 flows/sec
worst batch       237.9 ms
```

Repeated runs land between 12,800 and 13,300 flows/sec, so treat ~12,000
flows/sec as the sustained figure.

**Detection latency** is bounded by the exporter tick plus the scoring time for
one batch. At the default `--interval-ms 250` and a realistic batch of a few
hundred flows that is roughly 250 ms + 20 ms; the 238 ms worst case above comes
from a deliberately oversized 2000-flow batch. Every alert carries a measured
`latency_ms` so the real figure is always visible.

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
- `encrypted.ja3_blocklist` — JA3 md5 hashes of known-bad clients. Empty by
  default; fill it from a public feed such as abuse.ch SSLBL, or from your own
  sandbox. A hit raises a high-severity `known_bad_ja3` alert.
- `dns.dga_ignore_parents` — CDNs mint random hostnames on purpose, so a
  CloudFront distribution id is indistinguishable from a DGA label by any
  statistical test. The parent domain is the only thing that separates them.

## Detecting DGA without a wordlist

Per-character Shannon entropy is the obvious DGA test and it does not work on
its own, because entropy is bounded by the length of the string: a 12-character
label can never exceed log2(12) = 3.58 bits/char no matter how random it is.
Raising the threshold high enough to exclude real hostnames also excludes every
short DGA label, and lowering it flags things like `ingestion-edge`.

So `models/dnsabuse.py` scores the longest label on four independent signals
and needs at least three (`dns.dga_min_signals`) before it will alert:

| Signal | What it measures |
| --- | --- |
| `improbable_letter_pairs` | fraction of the label's bigrams that appear in `COMMON_BIGRAMS`, the ~150 most frequent English letter pairs |
| `near_max_entropy` | entropy as a fraction of `log2(len)`, so it means "almost every character is different" regardless of length |
| `too_few_vowels` | vowels per letter; below about a quarter the name is unpronounceable |
| `digit_heavy` | digits per character |

Each signal fires on plenty of legitimate names by itself — brand names run
short on vowels, CDN shards carry digits — but real hostnames rarely trip three
at once. Measured on the hostnames from a live browsing capture:

| Name | Signals | Verdict |
| --- | --- | --- |
| `prod.ingestion-edge.prod.dataservices.mozgcp.net` | 0 | quiet |
| `mozilla-ohttp.fastly-edge.com` | 0 | quiet |
| `part-0020.t-0009.fb-t-msedge.net` | 1 | quiet |
| `xkvhdlqpzmwrtn.biz` | 3 | DGA |
| `kq7bxz1mvhqp3wr.com` | 4 | DGA |
| `dp0wn1kjwhg75.cloudfront.net` | 4 | allowlisted parent |

The evidence block on each alert lists which signals fired and their underlying
values, so a reviewer can see why rather than just the verdict.

## What live traffic changed

The first run against real browsing traffic produced alerts that were all false
positives, and each one pointed at a specific modelling mistake:

- **Both halves of a session are separate flows here**, so the reply direction
  has the service port as its *source*. Checking only `dst_port` labelled every
  QUIC response as running on an odd port. The port checks now accept a flow if
  *either* end is a known service port.
- **The same applies to beaconing**, but the fix is not to drop the reply
  direction — on a receive-only tap that is the *only* direction there is, and
  dropping it silenced the detector completely. Both halves of a conversation
  now fold onto one key, so it works on a one-way tap and does not
  double-count on a mirrored one.
- **A conversation that ever carried real traffic is not a beacon.** The
  volume gate looks at the busiest window rather than the average: a beacon is
  small every single time, whereas a browser keepalive is small only because
  the page it belongs to already finished loading.
- **BitTorrent looks like C2 until you count peers.** A swarm wakes many
  remotes on the same ~30s schedule (often on 6881–6989). That is suppressed
  by ignoring common P2P ports and dropping any local host that has ≥3 peers
  on a near-identical period. Lone implants still alert.
- **Numeric labels are not DGA.** An all-digit label such as a Discord
  snowflake has no vowels and no letter pairs for the trivial reason that it
  has no letters, which tripped three of the four randomness signals at once.
  The two pronounceability signals now require `dns.dga_min_letters` letters
  before they count for anything.
- **`encrypted_low_volume_session` was removed.** A long-lived TLS session with
  few small packets describes C2 accurately and also describes every idle
  browser keepalive. Shape on its own cannot separate them; what can is
  *regularity*, so packet-size shape is now evidence on a beaconing alert
  rather than an alert of its own.
- **QUIC was only ever parsed on ports 443 and 80**, which made
  `quic_on_nonstandard_port` unreachable — the only thing it could ever fire on
  was the reply direction. Both the eBPF sampler and `parse_quic` now identify
  QUIC by its long-header and fixed bits plus a known version, on any port.

## Tests

```shell
python3 -m pytest tests/
```
