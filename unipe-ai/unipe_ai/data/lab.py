"""lab-faithful synthetic flows named after the brief's dataset tools.

each profile is the flow-record shape our exporter would emit if you pointed
the tap at that tool in a lab. training on these keeps the write-up honest:
"trained on synthetic traffic calibrated to iperf3 / hping3 / dnscat2 / …"
without needing the tools installed to retrain.
"""

from __future__ import annotations

import random
from typing import Any

from unipe_ai.data.dga import benign_qname, dga_qname, tunnel_qname

# tool -> what it stands for in the problem statement
TOOL_MAP = {
    "iperf3": "benign sustained load (tcp/udp throughput)",
    "browsing": "benign interactive web / tls",
    "streaming": "benign inbound media",
    "normal_dns": "benign resolver lookups",
    "hping3_syn": "volumetric SYN flood",
    "hping3_udp": "volumetric UDP flood",
    "icmp_flood": "volumetric ICMP flood",
    "port_scan": "recon / port scanning",
    "exfil": "asymmetric outbound data movement",
    "spoofed": "martian / spoofed sources",
    "dnscat2": "DNS tunnelling (hex labels)",
    "iodine": "DNS tunnelling (base32-ish labels)",
    "dga_conficker": "DGA family conficker-shaped",
    "dga_cryptolocker": "DGA family cryptolocker-shaped",
    "dga_necurs": "DGA family necurs-shaped",
    "dga_banjori": "DGA family banjori-shaped",
    "c2_beacon": "sandboxed C2 emulator timing (used in beacon eval)",
}


def benign_flow(rng: random.Random) -> dict[str, Any]:
    kind = rng.choice(["iperf3", "browsing", "streaming", "normal_dns", "lan", "idle"])
    if kind == "iperf3":
        # high volume but completed handshake and large payloads — not a flood
        packets = rng.randint(5_000, 80_000)
        return _tagged(
            "iperf3",
            protocol=rng.choice([6, 17]),
            src_ip=f"192.168.1.{rng.randint(2, 200)}",
            dst_ip=f"10.0.0.{rng.randint(2, 200)}",
            dst_port=rng.choice([5201, 5001]),
            packets=packets,
            bytes=packets * rng.randint(1200, 1500),
            duration_ms=rng.randint(5_000, 60_000),
            syn_count=1 if rng.random() < 0.5 else 0,
            ack_count=packets if rng.random() < 0.5 else 0,
        )
    if kind == "browsing":
        packets = rng.randint(10, 400)
        return _tagged(
            "browsing",
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
    if kind == "streaming":
        packets = rng.randint(2_000, 40_000)
        return _tagged(
            "streaming",
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
    if kind == "normal_dns":
        qname = benign_qname(rng)
        return _dns_flow("normal_dns", qname, rng)
    if kind == "lan":
        return _tagged(
            "lan",
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
    return _tagged(
        "idle",
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


def malicious_flow(rng: random.Random, include_dns: bool = True) -> dict[str, Any]:
    kinds = [
        "hping3_syn",
        "hping3_udp",
        "icmp_flood",
        "port_scan",
        "exfil",
        "spoofed",
    ]
    if include_dns:
        kinds.extend(["dnscat2", "iodine", "dga"])
    kind = rng.choice(kinds)
    if kind == "hping3_syn":
        packets = rng.randint(500, 20_000)
        return _tagged(
            "hping3_syn",
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
    if kind == "hping3_udp":
        packets = rng.randint(1, 3)
        return _tagged(
            "hping3_udp",
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
        return _tagged(
            "icmp_flood",
            protocol=1,
            src_ip=f"203.0.113.{rng.randint(1, 254)}",
            dst_ip="198.51.100.10",
            packets=packets,
            bytes=packets * 84,
            duration_ms=rng.randint(500, 4000),
        )
    if kind == "port_scan":
        return _tagged(
            "port_scan",
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
        return _tagged(
            "exfil",
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
    if kind == "spoofed":
        return _tagged(
            "spoofed",
            protocol=17,
            src_ip=rng.choice(["0.0.0.0", "169.254.3.9", "224.1.2.3", "255.255.255.255"]),
            dst_ip="198.51.100.10",
            dst_port=rng.randint(1, 65535),
            packets=rng.randint(1, 5),
            bytes=rng.randint(28, 500),
            duration_ms=rng.randint(1, 100),
        )
    if kind == "dnscat2":
        return _dns_flow("dnscat2", tunnel_qname(rng, "dnscat2"), rng, qtype=16)
    if kind == "iodine":
        return _dns_flow("iodine", tunnel_qname(rng, "iodine"), rng, qtype=16)
    family = rng.choice(["conficker", "cryptolocker", "necurs", "banjori"])
    return _dns_flow(f"dga_{family}", dga_qname(rng, family), rng)


def beacon_intervals(rng: random.Random, malicious: bool) -> list[float]:
    """activity timestamps for the sandboxed-C2 vs browsing timing eval."""
    start = 1_000.0
    if malicious:
        period = rng.choice([15.0, 30.0, 60.0, 120.0, 300.0])
        jitter = period * rng.uniform(0.01, 0.08)
        times = [start]
        for _ in range(8):
            times.append(times[-1] + period + rng.uniform(-jitter, jitter))
        return times
    # browsing: irregular gaps
    times = [start]
    for gap in [rng.uniform(1, 8) for _ in range(8)]:
        # occasional long think-time
        if rng.random() < 0.3:
            gap = rng.uniform(40, 400)
        times.append(times[-1] + gap)
    return times


def _dns_flow(
    tool: str,
    qname: str,
    rng: random.Random,
    qtype: int = 1,
) -> dict[str, Any]:
    payload = _dns_payload(qname, qtype)
    return _tagged(
        tool,
        protocol=17,
        src_ip=f"192.168.1.{rng.randint(2, 200)}",
        dst_ip="192.168.1.1",
        src_port=rng.randint(40000, 60000),
        dst_port=53,
        packets=1,
        bytes=max(60, len(payload) // 2),
        duration_ms=rng.randint(1, 80),
        is_dns=True,
        payload=payload,
        payload_len=len(payload) // 2,
    )


def _dns_payload(qname: str, qtype: int = 1) -> str:
    data = bytearray(b"\x00\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00")
    for label in qname.split("."):
        encoded = label.encode("ascii", "ignore")[:63]
        data.append(len(encoded))
        data.extend(encoded)
    data.append(0)
    data.extend(qtype.to_bytes(2, "big"))
    data.extend((1).to_bytes(2, "big"))
    return data.hex()


def _tagged(tool: str, **overrides: Any) -> dict[str, Any]:
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
        "lab_tool": tool,
    }
    base.update(overrides)
    return base
