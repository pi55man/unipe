from __future__ import annotations

import ipaddress
from typing import Any

from unipe_ai.alerts import make_flow_id
from unipe_ai.features.payload import parse_dns, parse_quic, parse_tls

DNS_PORT = 53
QUIC_PORTS = {443, 80}


def extract(flow: dict[str, Any]) -> dict[str, Any]:
    """Derive detection features from a serialized unipe flow."""
    feat = dict(flow)

    packets = _num(flow.get("packets"), 0.0)
    bytes_ = _num(flow.get("bytes"), 0.0)
    duration_ms = max(_num(flow.get("duration_ms"), 0.0), 1.0)
    duration_s = duration_ms / 1000.0

    syn = _num(flow.get("syn_count"), 0.0)
    ack = _num(flow.get("ack_count"), 0.0)
    fin = _num(flow.get("fin_count"), 0.0)
    rst = _num(flow.get("rst_count"), 0.0)
    protocol = int(_num(flow.get("protocol"), 0.0))
    ttl = int(_num(flow.get("ttl"), 0.0))

    src_ip = str(flow.get("src_ip", ""))
    dst_ip = str(flow.get("dst_ip", ""))

    feat["packet_rate"] = packets / duration_s
    feat["byte_rate"] = bytes_ / duration_s
    feat["syn_ack_ratio"] = syn / max(ack, 1.0)
    feat["ack_syn_ratio"] = ack / max(syn, 1.0)
    feat["tcp_flag_total"] = syn + ack + fin + rst
    feat["is_tcp"] = protocol == 6
    feat["is_udp"] = protocol == 17
    feat["is_icmp"] = protocol == 1
    feat["is_syn_only"] = bool(feat["is_tcp"] and syn > 0 and ack == 0)
    feat["is_land"] = src_ip == dst_ip and src_ip != ""
    feat["src_is_martian"] = _is_martian(src_ip)
    feat["dst_is_martian"] = _is_martian(dst_ip)
    feat["src_is_loopback"] = _is_loopback(src_ip)
    feat["dst_is_loopback"] = _is_loopback(dst_ip)
    feat["src_is_private"] = _is_private(src_ip)
    feat["dst_is_private"] = _is_private(dst_ip)
    feat["dst_is_multicast"] = _is_multicast(dst_ip)
    # True only for routable global unicast (excludes private/multicast/broadcast/martians).
    feat["dst_is_public_unicast"] = _is_public_unicast(dst_ip)
    # Observed TTLs are hop-decremented; only TTL 0 is inherently invalid here.
    feat["ttl_suspicious"] = ttl == 0
    src_port = int(_num(flow.get("src_port"), 0.0))
    dst_port = int(_num(flow.get("dst_port"), 0.0))
    feat["is_benign_udp"] = bool(feat["is_udp"] and _is_benign_udp_port(src_port, dst_port))

    feat["flow_id"] = make_flow_id(protocol, src_ip, src_port, dst_ip, dst_port)
    feat["avg_packet_size"] = bytes_ / max(packets, 1.0)
    # cumulative counters survive the windowing step; fall back to this window
    feat["total_bytes"] = _num(flow.get("total_bytes"), bytes_)
    feat["total_packets"] = _num(flow.get("total_packets"), packets)

    payload = str(flow.get("payload", ""))
    if bool(flow.get("is_dns")) or src_port == DNS_PORT or dst_port == DNS_PORT:
        feat.update(parse_dns(payload))
    if feat["is_tcp"]:
        feat.update(parse_tls(payload))
    if feat["is_udp"] and (src_port in QUIC_PORTS or dst_port in QUIC_PORTS):
        feat.update(parse_quic(payload))
    return feat


# DNS, mDNS, LLMNR, SSDP, DHCP, NTP, NetBIOS — noisy on LANs, not DDoS.
_BENIGN_UDP_PORTS = {53, 67, 68, 123, 137, 138, 1900, 5353, 5355}


def _is_benign_udp_port(src_port: int, dst_port: int) -> bool:
    return src_port in _BENIGN_UDP_PORTS or dst_port in _BENIGN_UDP_PORTS


def _num(value: Any, default: float) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _parse_ip(value: str) -> ipaddress.IPv4Address | None:
    try:
        return ipaddress.IPv4Address(value)
    except (ipaddress.AddressValueError, ValueError):
        return None


_LAN_NETS = (
    ipaddress.IPv4Network("10.0.0.0/8"),
    ipaddress.IPv4Network("172.16.0.0/12"),
    ipaddress.IPv4Network("192.168.0.0/16"),
    ipaddress.IPv4Network("169.254.0.0/16"),
)


def _is_private(value: str) -> bool:
    ip = _parse_ip(value)
    return bool(ip and any(ip in net for net in _LAN_NETS))


def _is_loopback(value: str) -> bool:
    ip = _parse_ip(value)
    return bool(ip and ip.is_loopback)


def _is_multicast(value: str) -> bool:
    ip = _parse_ip(value)
    return bool(ip and ip.is_multicast)


def _is_public_unicast(value: str) -> bool:
    ip = _parse_ip(value)
    if ip is None:
        return False
    return not (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
        or ip == ipaddress.IPv4Address("255.255.255.255")
    )


def _is_martian(value: str) -> bool:
    """Return True for addresses that should not appear as Internet sources."""
    ip = _parse_ip(value)
    if ip is None:
        return True
    return bool(
        ip.is_unspecified
        or ip.is_loopback
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_link_local
        or ip == ipaddress.IPv4Address("255.255.255.255")
    )
