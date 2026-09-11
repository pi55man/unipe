from __future__ import annotations

import hashlib
import socket
import ssl
import threading

import pytest

from unipe_ai.alerts import SCHEMA_VERSION
from unipe_ai.engine import TapDirection
from unipe_ai.features.extract import extract
from unipe_ai.features.payload import GREASE, parse_tls
from unipe_ai.features.window import FlowWindow
from unipe_ai.models.beaconing import BeaconingConfig, BeaconTracker
from unipe_ai.models.detector import Detector
from unipe_ai.models.dnsabuse import DnsConfig, _dga_signals, detect_dns_abuse
from unipe_ai.models.encrypted import EncryptedConfig, detect_encrypted
from unipe_ai.models.exfiltration import ExfiltrationConfig, detect_exfiltration
from unipe_ai.models.scanning import ScanningConfig, detect_scanning
from unipe_ai.models.spoofing import SpoofingConfig, detect_spoofing
from unipe_ai.models.volumetric import VolumetricConfig, detect_volumetric


def _flow(**overrides):
    base = {
        "src_ip": "1.2.3.4",
        "dst_ip": "10.0.0.5",
        "src_port": 12345,
        "dst_port": 80,
        "protocol": 6,
        "packets": 10,
        "bytes": 600,
        "duration_ms": 1000,
        "syn_count": 1,
        "ack_count": 1,
        "fin_count": 0,
        "rst_count": 0,
        "is_dns": False,
        "timestamp": 1.0,
        "ttl": 64,
        "icmp_type": 0,
        "icmp_code": 0,
        "payload_len": 0,
        "payload": "",
    }
    base.update(overrides)
    return extract(base)


def test_extract_rates_and_martian():
    feat = _flow(src_ip="127.0.0.1", packets=100, duration_ms=1000, syn_count=5, ack_count=0)
    assert feat["packet_rate"] == 100.0
    assert feat["is_syn_only"] is True
    assert feat["src_is_martian"] is True


def test_volumetric_syn_flood():
    flows = [
        _flow(
            src_ip=f"203.0.113.{i}",
            dst_ip="198.51.100.10",
            packets=200,
            duration_ms=1000,
            syn_count=10,
            ack_count=0,
            protocol=6,
            ttl=64,
        )
        for i in range(25)
    ]
    alerts = detect_volumetric(
        flows,
        VolumetricConfig(
            syn_flood_min_flows=20,
            syn_flood_min_syn_ratio=5.0,
            syn_only_fraction=0.7,
            min_unique_sources=20,
            dst_packet_rate=1000.0,
        ),
    )
    subtypes = {a["subtype"] for a in alerts}
    assert "syn_flood" in subtypes


def test_spoofing_martian_and_land():
    alerts = detect_spoofing(
        [
            _flow(src_ip="0.0.0.0", dst_ip="8.8.8.8"),
            _flow(src_ip="8.8.8.8", dst_ip="8.8.8.8"),
        ]
    )
    subtypes = {a["subtype"] for a in alerts}
    assert "martian_source" in subtypes
    assert "land_attack" in subtypes


def test_spoofing_ttl_inconsistency():
    flows = [
        _flow(src_ip="203.0.113.9", ttl=40),   # 64-family
        _flow(src_ip="203.0.113.9", ttl=110),  # 128-family
        _flow(src_ip="203.0.113.9", ttl=220),  # 255-family
    ]
    alerts = detect_spoofing(flows, SpoofingConfig(ttl_variance_min_values=3, ttl_min_families=3))
    assert any(a["subtype"] == "ttl_inconsistency" for a in alerts)


def test_spoofing_ignores_anycast_ttl_mix():
    """GitHub/CDN anycast: hop-decremented 64-origin and 255-origin is normal."""
    alerts = detect_spoofing(
        [
            _flow(src_ip="140.82.112.26", ttl=44),
            _flow(src_ip="140.82.112.26", ttl=237),
            _flow(src_ip="140.82.112.26", ttl=239),
        ]
    )
    assert not any(a["subtype"] == "ttl_inconsistency" for a in alerts)


def test_spoofing_ignores_benign_lan_noise():
    """Hop-decremented TTLs and mDNS must not look like spoofing."""
    alerts = detect_spoofing(
        [
            _flow(src_ip="104.18.34.249", dst_ip="192.168.1.10", ttl=57, packets=20),
            _flow(src_ip="103.55.88.62", dst_ip="192.168.1.10", ttl=60, packets=20),
            _flow(
                src_ip="192.168.1.33",
                dst_ip="224.0.0.251",
                src_port=5353,
                dst_port=5353,
                protocol=17,
                ttl=255,
            ),
        ]
    )
    subtypes = {a["subtype"] for a in alerts}
    assert "ttl_anomaly" not in subtypes
    assert "private_to_public" not in subtypes


def test_private_to_public_still_fires_for_unicast():
    alerts = detect_spoofing(
        [_flow(src_ip="192.168.1.33", dst_ip="8.8.8.8", protocol=17, ttl=64)],
        SpoofingConfig(alert_private_to_public=True),
    )
    assert any(a["subtype"] == "private_to_public" for a in alerts)


def test_private_to_public_off_by_default_on_lan():
    alerts = detect_spoofing(
        [_flow(src_ip="192.168.1.33", dst_ip="8.8.8.8", protocol=17, ttl=64)]
    )
    assert not any(a["subtype"] == "private_to_public" for a in alerts)


def test_udp_lan_chatter_is_not_a_flood():
    flows = [
        _flow(
            src_ip=f"203.0.113.{i}",
            dst_ip="192.168.1.35",
            src_port=443,
            dst_port=40000 + i,
            protocol=17,
            packets=8,
            bytes=900,
            duration_ms=2000,
        )
        for i in range(31)
    ]
    alerts = detect_volumetric(flows)
    assert not any(a["subtype"] == "udp_flood" for a in alerts)


def test_udp_flood_still_fires_on_public_high_rate():
    flows = [
        _flow(
            src_ip=f"203.0.113.{i}",
            dst_ip="198.51.100.10",
            src_port=12345,
            dst_port=80,
            protocol=17,
            packets=500,
            bytes=60_000,
            duration_ms=1000,
        )
        for i in range(31)
    ]
    alerts = detect_volumetric(
        flows,
        VolumetricConfig(
            udp_flood_min_flows=25,
            min_unique_sources=30,
            udp_flood_packet_rate=1000.0,
            alert_lan_destinations=False,
        ),
    )
    assert any(a["subtype"] == "udp_flood" for a in alerts)


def test_rand_source_udp_is_flood_not_martian_spam():
    flows = [
        _flow(
            src_ip=f"127.0.0.{i + 1}",
            dst_ip="127.0.0.1",
            src_port=12345,
            dst_port=9999,
            protocol=17,
            packets=1,
            bytes=28,
            duration_ms=1,
        )
        for i in range(40)
    ]
    vol = detect_volumetric(flows)
    assert any(a["subtype"] == "udp_flood" for a in vol)
    detector = Detector(config_path=None)
    alerts = detector.score(flows)
    subtypes = {a["subtype"] for a in alerts}
    assert "udp_flood" in subtypes
    assert "martian_source" not in subtypes
    assert "martian_source_storm" not in subtypes


def test_loopback_src_is_not_martian_spam():
    alerts = detect_spoofing(
        [
            _flow(src_ip="127.0.0.1", dst_ip="8.8.8.8", protocol=17, packets=1)
            for _ in range(20)
        ]
    )
    assert not any(a["subtype"].startswith("martian") for a in alerts)


def test_high_rate_ignores_short_https_burst():
    """1ms-floored duration must not invent a 2000 pps DDoS from a tiny TLS flow."""
    alerts = detect_volumetric(
        [
            _flow(
                src_ip="104.18.34.249",
                dst_ip="192.168.1.10",
                src_port=443,
                dst_port=33326,
                protocol=6,
                packets=2,
                bytes=143,
                duration_ms=1,
                syn_count=0,
                ack_count=2,
            )
        ]
    )
    assert not any(a["subtype"] == "high_rate_flow" for a in alerts)


def test_detector_pipeline():
    detector = Detector(config_path=None)
    detector.volumetric_cfg = VolumetricConfig(flow_packet_rate=50.0, flow_byte_rate=1e12)
    detector.spoofing_cfg = SpoofingConfig()
    alerts = detector.score([_flow(src_ip="0.0.0.0", packets=500, duration_ms=1000)])
    types = {a["threat_class"] for a in alerts}
    assert "ip_spoofing" in types


# --- alert schema ---------------------------------------------------------


def test_alerts_carry_the_standard_schema():
    detector = Detector(config_path=None)
    alerts = detector.score(
        [
            _flow(
                src_ip=f"203.0.113.{i}",
                dst_ip="198.51.100.10",
                packets=2000,
                bytes=120_000,
                duration_ms=1000,
                syn_count=2000,
                ack_count=0,
            )
            for i in range(40)
        ]
    )
    assert alerts
    for alert in alerts:
        assert alert["schema_version"] == SCHEMA_VERSION
        assert alert["timestamp"] > 0
        assert alert["flow_id"]
        assert alert["threat_class"]
        assert alert["severity"] in {"low", "medium", "high"}
        assert 0.0 <= alert["confidence"] <= 1.0
        assert isinstance(alert["evidence"], dict) and alert["evidence"]


# --- bugs that were fixed -------------------------------------------------


def test_stale_flow_does_not_hide_a_flood():
    """A long benign flow to the victim must not dilute the measured rate."""
    flood = [
        _flow(
            src_ip=f"203.0.113.{i}",
            dst_ip="198.51.100.10",
            protocol=17,
            src_port=1024 + i,
            dst_port=9999,
            packets=600,
            bytes=60_000,
            duration_ms=1000,
        )
        for i in range(35)
    ]
    stale = _flow(
        src_ip="8.8.4.4",
        dst_ip="198.51.100.10",
        protocol=6,
        packets=500,
        bytes=400_000,
        duration_ms=3_600_000,
    )
    subtypes = {a["subtype"] for a in detect_volumetric(flood + [stale])}
    assert "fan_in_flood" in subtypes


def test_syn_flood_to_lan_victim_still_alerts():
    """The LAN mute must not swallow a real SYN flood at an RFC1918 address."""
    flows = [
        _flow(
            src_ip=f"203.0.113.{i}",
            dst_ip="192.168.1.10",
            src_port=1024 + i,
            dst_port=80,
            packets=300,
            duration_ms=1000,
            syn_count=300,
            ack_count=0,
        )
        for i in range(40)
    ]
    subtypes = {a["subtype"] for a in detect_volumetric(flows)}
    assert "syn_flood" in subtypes
    # the generic fan-in alert stays muted for LAN destinations
    assert "fan_in_flood" not in subtypes


def test_icmp_flood_to_lan_victim_still_alerts():
    flows = [
        _flow(
            src_ip=f"203.0.113.{i}",
            dst_ip="192.168.1.10",
            protocol=1,
            src_port=0,
            dst_port=0,
            packets=200,
            bytes=16_800,
            duration_ms=1000,
            syn_count=0,
            ack_count=0,
        )
        for i in range(30)
    ]
    subtypes = {a["subtype"] for a in detect_volumetric(flows)}
    assert "icmp_flood" in subtypes


# --- streaming window -----------------------------------------------------


def test_window_emits_only_new_traffic():
    window = FlowWindow()
    first = window.deltas([_raw(packets=100, bytes=6000)], now=1000.0)
    assert first and first[0]["packets"] == 100

    second = window.deltas([_raw(packets=140, bytes=8400)], now=1001.0)
    assert second and second[0]["packets"] == 40
    assert second[0]["bytes"] == 2400
    assert second[0]["total_packets"] == 140


def test_window_skips_idle_flows():
    window = FlowWindow()
    window.deltas([_raw(packets=100)], now=1000.0)
    assert window.deltas([_raw(packets=100)], now=1001.0) == []


def test_window_handles_recycled_map_entry():
    """The LRU map can reuse a 5-tuple; counters going backwards means new flow."""
    window = FlowWindow()
    window.deltas([_raw(packets=100)], now=1000.0)
    again = window.deltas([_raw(packets=5)], now=1001.0)
    assert again and again[0]["packets"] == 5


# --- new threat classes ---------------------------------------------------


def test_beaconing_detects_regular_checkins():
    tracker = BeaconTracker(BeaconingConfig(min_intervals=4, alert_cooldown_s=0.0))
    beacon = _flow(
        src_ip="192.168.1.50",
        dst_ip="185.220.101.7",
        dst_port=8080,
        packets=4,
        bytes=800,
        duration_ms=200,
    )
    alerts = []
    for i in range(6):
        alerts = tracker.update([beacon], now=1000.0 + i * 60.0)
    assert any(a["subtype"] == "periodic_beacon" for a in alerts)
    assert alerts[0]["threat_class"] == "c2_beaconing"


def test_beaconing_ignores_irregular_traffic():
    tracker = BeaconTracker(BeaconingConfig(min_intervals=4, alert_cooldown_s=0.0))
    browsing = _flow(src_ip="192.168.1.50", dst_ip="104.18.2.3", dst_port=443, packets=4)
    alerts = []
    for gap in (0.0, 3.0, 41.0, 47.0, 190.0, 201.0, 640.0):
        alerts = tracker.update([browsing], now=1000.0 + gap)
    assert not alerts


def test_beaconing_works_from_the_inbound_direction_alone():
    """XDP is receive-only, so the outbound half may never be observed.

    The beacon still has to be found, and reported oriented local -> remote
    whichever direction the tap happened to carry.
    """
    tracker = BeaconTracker(BeaconingConfig(min_intervals=4, alert_cooldown_s=0.0))
    inbound = _flow(
        src_ip="185.220.101.7",
        dst_ip="192.168.1.35",
        src_port=8080,
        dst_port=57270,
        packets=4,
        bytes=800,
    )
    alerts = []
    for i in range(6):
        alerts = tracker.update([inbound], now=1000.0 + i * 15.0)
    assert len(alerts) == 1
    assert alerts[0]["src_ip"] == "192.168.1.35"
    assert alerts[0]["dst_ip"] == "185.220.101.7"
    assert alerts[0]["dst_port"] == 8080


def test_beaconing_counts_a_mirrored_conversation_once():
    """On a tap carrying both directions the two halves must not double-count."""
    tracker = BeaconTracker(BeaconingConfig(min_intervals=4, alert_cooldown_s=0.0))
    out = _flow(
        src_ip="192.168.1.35", dst_ip="185.220.101.7",
        src_port=57270, dst_port=8080, packets=4, bytes=400,
    )
    back = _flow(
        src_ip="185.220.101.7", dst_ip="192.168.1.35",
        src_port=8080, dst_port=57270, packets=4, bytes=400,
    )
    alerts = []
    for i in range(6):
        alerts = tracker.update([out, back], now=1000.0 + i * 15.0)
    assert len(alerts) == 1


def test_beaconing_ignores_a_conversation_that_ever_carried_real_traffic():
    """One heavy window means a keepalive on a real session, not a beacon."""
    tracker = BeaconTracker(BeaconingConfig(min_intervals=4, alert_cooldown_s=0.0))
    quiet = _flow(
        src_ip="192.168.1.35", dst_ip="172.217.119.4",
        src_port=57270, dst_port=443, protocol=17, packets=4, bytes=800,
    )
    page_load = dict(quiet, packets=900, bytes=1_200_000)
    alerts = []
    for i in range(6):
        batch = [page_load] if i == 1 else [quiet]
        alerts = tracker.update(batch, now=1000.0 + i * 15.0)
    assert not alerts


def test_beaconing_ignores_lan_peers():
    tracker = BeaconTracker(BeaconingConfig(min_intervals=4, alert_cooldown_s=0.0))
    lan = _flow(src_ip="192.168.1.50", dst_ip="192.168.1.1", dst_port=443, packets=4)
    alerts = []
    for i in range(6):
        alerts = tracker.update([lan], now=1000.0 + i * 60.0)
    assert not alerts


def test_one_directional_tap_is_reported():
    tap = TapDirection()
    # every flow a reply, which is all an XDP hook on a host's own NIC sees
    tap.note([_flow(src_port=443, dst_port=40000 + i, is_new_flow=True) for i in range(250)])
    tap.maybe_warn()
    assert tap.warned
    assert tap.to_server == 0


def test_two_directional_tap_is_not_reported():
    tap = TapDirection()
    both = []
    for i in range(250):
        both.append(_flow(src_port=40000 + i, dst_port=443, is_new_flow=True))
        both.append(_flow(src_port=443, dst_port=40000 + i, is_new_flow=True))
    tap.note(both)
    tap.maybe_warn()
    assert not tap.warned


def test_tap_direction_stays_quiet_until_it_has_enough_flows():
    tap = TapDirection()
    tap.note([_flow(src_port=443, dst_port=40000 + i, is_new_flow=True) for i in range(10)])
    tap.maybe_warn()
    assert not tap.warned


def test_dga_domain_is_flagged():
    feat = _dns_flow("kq7bxz1mvhqp3wr.com")
    alerts = detect_dns_abuse([feat])
    assert any(a["subtype"] == "dga_domain" for a in alerts)


@pytest.mark.parametrize(
    "qname",
    [
        "xkvhdlqpzmwrtn.biz",
        "ycxwbmqhtdvkzn.ru",
        "1qaz2wsx3edc4rfv.net",
        "ffcjkbrvxqzpmw.info",
    ],
)
def test_more_dga_samples_are_flagged(qname):
    alerts = detect_dns_abuse([_dns_flow(qname)])
    assert any(a["subtype"] == "dga_domain" for a in alerts)


def test_normal_domain_is_not_flagged():
    alerts = detect_dns_abuse([_dns_flow("www.google.com"), _dns_flow("github.com")])
    assert not alerts


@pytest.mark.parametrize(
    "qname",
    [
        # every one of these was a false positive on a live browsing capture
        "prod.ingestion-edge.prod.dataservices.mozgcp.net",
        "part-0020.t-0009.fb-t-msedge.net",
        "mozilla-ohttp.fastly-edge.com",
        "incoming.telemetry.mozilla.org",
        "static.xx.fbcdn.net",
        # a discord snowflake: all digits, so the vowel and bigram signals
        # fire only because there are no letters to measure
        "1211781489931452447.discordsays.com",
        "1758912000000.metrics.example.com",
    ],
)
def test_long_legitimate_hostnames_are_not_dga(qname):
    alerts = detect_dns_abuse([_dns_flow(qname)])
    assert not [a for a in alerts if a["subtype"] == "dga_domain"]


def test_cdn_hostnames_random_by_design_are_allowlisted():
    """A CloudFront id really is random, so only its parent domain saves it."""
    label = "dp0wn1kjwhg75"
    assert sum(_dga_signals(label, DnsConfig()).values()) >= 3
    alerts = detect_dns_abuse([_dns_flow(f"{label}.cloudfront.net")])
    assert not [a for a in alerts if a["subtype"] == "dga_domain"]


def test_dns_tunnel_is_flagged():
    qname = "a1b2c3d4e5f6g7h8.i9j0k1l2m3n4o5p6.q7r8s9t0u1v2.tunnel.example.com"
    alerts = detect_dns_abuse([_dns_flow(qname, qtype=16)])
    assert any(a["subtype"] == "dns_tunnel" for a in alerts)


def test_dns_tunnel_volume_is_flagged():
    flows = [_dns_flow(f"chunk{i:04x}data{i:04x}.tun.example.com") for i in range(20)]
    alerts = detect_dns_abuse(flows)
    assert any(a["subtype"] == "dns_tunnel_volume" for a in alerts)


def test_tls_on_odd_port_is_flagged_without_decryption():
    feat = _flow(dst_port=4444, protocol=6, payload=_client_hello(0x0303))
    alerts = detect_encrypted([feat])
    subtypes = {a["subtype"] for a in alerts}
    assert "tls_on_nonstandard_port" in subtypes


def test_legacy_tls_version_is_flagged():
    feat = _flow(dst_port=443, protocol=6, payload=_client_hello(0x0301))
    alerts = detect_encrypted([feat])
    assert any(a["subtype"] == "legacy_tls_version" for a in alerts)


def test_normal_tls_on_443_is_quiet():
    feat = _flow(dst_port=443, protocol=6, payload=_client_hello(0x0303))
    assert not detect_encrypted([feat])


def test_reply_direction_to_an_ephemeral_port_is_not_a_nonstandard_port():
    """443 -> 49820 is the server answering, not TLS hiding on a weird port."""
    feat = _flow(src_port=443, dst_port=49820, protocol=6, payload=_client_hello(0x0303))
    assert not [a for a in detect_encrypted([feat]) if "nonstandard_port" in a["subtype"]]


def test_quic_reply_direction_is_not_a_nonstandard_port():
    feat = _flow(src_port=443, dst_port=49820, protocol=17, payload=_quic_initial())
    assert not detect_encrypted([feat])


def test_quic_on_an_odd_port_is_flagged():
    """Needs port-independent parsing: we only ever looked at 443 and 80 before."""
    feat = _flow(src_port=51000, dst_port=4444, protocol=17, payload=_quic_initial())
    assert [a["subtype"] for a in detect_encrypted([feat])] == ["quic_on_nonstandard_port"]


def test_quic_on_443_is_quiet():
    feat = _flow(src_port=51000, dst_port=443, protocol=17, payload=_quic_initial())
    assert not detect_encrypted([feat])


def test_random_udp_is_not_read_as_quic():
    """The fixed bit plus a known version keeps stray UDP out of the QUIC path."""
    feat = _flow(src_port=51000, dst_port=4444, protocol=17, payload="c0deadbeef0102")
    assert feat["quic_is_initial"] is False
    assert not detect_encrypted([feat])


def test_idle_encrypted_session_is_not_an_alert_on_its_own():
    """Shape alone cannot tell C2 from a browser keepalive sitting open."""
    feat = _flow(
        dst_port=443,
        protocol=6,
        payload=_client_hello(0x0303),
        packets=14,
        bytes=1092,
        duration_ms=59_000,
    )
    assert not detect_encrypted([feat])


# --- JA3 / JA3S fingerprinting --------------------------------------------


def test_ja3_is_computed_from_a_complete_client_hello():
    feat = _flow(dst_port=443, protocol=6, payload=_client_hello())
    assert feat["tls_sample_complete"] is True
    # version, ciphers (GREASE dropped), extensions, curves, point formats
    assert feat["tls_ja3"] == "771,4865-4866-49195,0-10-11-16,29-23,0"
    assert feat["tls_ja3_hash"] == hashlib.md5(
        feat["tls_ja3"].encode(), usedforsecurity=False
    ).hexdigest()
    assert feat["tls_sni"] == "example.com"
    assert feat["tls_alpn"] == ("h2",)


def test_ja3_is_not_guessed_from_a_truncated_sample():
    """A hash over half a hello would match nothing, so we must not emit one."""
    # 50 bytes is 100 hex chars: enough for the headers, not the whole hello
    feat = _flow(dst_port=443, protocol=6, payload=_client_hello()[:100])
    assert feat["tls_is_client_hello"] is True
    assert feat["tls_sample_complete"] is False
    assert feat["tls_ja3_hash"] == ""


def test_ja3s_is_computed_from_the_server_hello():
    feat = _flow(src_port=443, dst_port=51000, protocol=6, payload=_server_hello())
    assert feat["tls_is_server_hello"] is True
    assert feat["tls_ja3s"] == "771,4865,43"
    assert feat["tls_ja3s_hash"]


def test_blocklisted_ja3_is_flagged():
    feat = _flow(dst_ip="45.9.148.3", dst_port=443, protocol=6, payload=_client_hello())
    cfg = EncryptedConfig(ja3_blocklist=(feat["tls_ja3_hash"],))
    alerts = detect_encrypted([feat], cfg)
    assert any(a["subtype"] == "known_bad_ja3" for a in alerts)


def test_tls_without_sni_to_a_public_ip_is_flagged():
    feat = _flow(dst_ip="45.9.148.3", dst_port=443, protocol=6, payload=_client_hello(sni=""))
    alerts = detect_encrypted([feat])
    assert any(a["subtype"] == "tls_without_sni" for a in alerts)


def test_ja3_parses_a_real_openssl_client_hello():
    """Validate against a genuine TLS stack, not just our own encoder."""
    raw = _capture_real_client_hello()
    out = parse_tls(raw.hex())
    assert out["tls_is_client_hello"] is True
    assert out["tls_sample_complete"] is True
    assert out["tls_client_version"] == 0x0303
    assert out["tls_sni"] == "example.com"
    assert len(out["tls_ciphers"]) > 5
    assert out["tls_curves"]
    # five comma-separated fields, and no GREASE survived into any of them
    fields = out["tls_ja3"].split(",")
    assert len(fields) == 5
    assert all(int(v) not in GREASE for v in fields[1].split("-"))
    assert len(out["tls_ja3_hash"]) == 32


def _capture_real_client_hello() -> bytes:
    """Let python's ssl module talk to a plain socket and grab what it sends."""
    server = socket.socket()
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    port = server.getsockname()[1]

    def connect():
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection(("127.0.0.1", port), timeout=5) as sock:
                ctx.wrap_socket(sock, server_hostname="example.com").do_handshake()
        except OSError:
            pass  # the handshake never completes, we only want the first flight

    threading.Thread(target=connect, daemon=True).start()
    conn, _ = server.accept()
    try:
        return conn.recv(8192)
    finally:
        conn.close()
        server.close()


def test_payload_is_only_sampled_for_handshakes():
    """Application data is never captured, so there is nothing to parse."""
    feat = _flow(dst_port=443, protocol=6, payload="")
    assert feat["tls_is_handshake"] is False
    assert not detect_encrypted([feat])


def test_vertical_port_scan_is_flagged():
    flows = [
        _flow(
            src_ip="203.0.113.77",
            dst_ip="198.51.100.5",
            src_port=40000 + i,
            dst_port=i + 1,
            packets=1,
            bytes=60,
            duration_ms=5,
            syn_count=1,
            ack_count=0,
        )
        for i in range(30)
    ]
    alerts = detect_scanning(flows)
    assert any(a["subtype"] == "vertical_port_scan" for a in alerts)


def test_horizontal_sweep_is_flagged():
    flows = [
        _flow(
            src_ip="203.0.113.77",
            dst_ip=f"198.51.100.{i + 1}",
            src_port=40000 + i,
            dst_port=22,
            packets=1,
            bytes=60,
            duration_ms=5,
            syn_count=1,
            ack_count=0,
        )
        for i in range(30)
    ]
    alerts = detect_scanning(flows)
    assert any(a["subtype"] == "horizontal_sweep" for a in alerts)


def test_normal_sessions_are_not_a_scan():
    flows = [
        _flow(
            src_ip="192.168.1.10",
            dst_ip=f"104.18.2.{i + 1}",
            src_port=40000 + i,
            dst_port=443,
            packets=80,
            bytes=90_000,
            duration_ms=20_000,
            syn_count=1,
            ack_count=79,
        )
        for i in range(30)
    ]
    assert not detect_scanning(flows, ScanningConfig())


def test_exfiltration_needs_an_asymmetric_pair():
    outbound = _flow(
        src_ip="192.168.1.50",
        dst_ip="185.220.101.7",
        src_port=51000,
        dst_port=443,
        packets=40_000,
        bytes=50_000_000,
        duration_ms=300_000,
    )
    inbound = _flow(
        src_ip="185.220.101.7",
        dst_ip="192.168.1.50",
        src_port=443,
        dst_port=51000,
        packets=2_000,
        bytes=200_000,
        duration_ms=300_000,
    )
    alerts = detect_exfiltration([outbound, inbound])
    assert any(a["subtype"] == "asymmetric_outbound_volume" for a in alerts)


def test_balanced_transfer_is_not_exfiltration():
    outbound = _flow(
        src_ip="192.168.1.50",
        dst_ip="185.220.101.7",
        src_port=51000,
        dst_port=443,
        packets=40_000,
        bytes=50_000_000,
        duration_ms=300_000,
    )
    inbound = _flow(
        src_ip="185.220.101.7",
        dst_ip="192.168.1.50",
        src_port=443,
        dst_port=51000,
        packets=40_000,
        bytes=48_000_000,
        duration_ms=300_000,
    )
    assert not detect_exfiltration([outbound, inbound])


def test_exfiltration_stays_quiet_without_the_reverse_flow():
    """On a one-way span a missing reverse direction proves nothing."""
    outbound = _flow(
        src_ip="192.168.1.50",
        dst_ip="185.220.101.7",
        dst_port=443,
        packets=40_000,
        bytes=50_000_000,
        duration_ms=300_000,
    )
    assert not detect_exfiltration([outbound])
    assert detect_exfiltration([outbound], ExfiltrationConfig(require_reverse_flow=False))


def test_model_confirms_a_rule_but_never_vetoes_it():
    """The model reads flow shape and knows nothing about TLS versions.

    Averaging its opinion in used to drag such rules under the reporting gate.
    """
    legacy = _flow(
        src_ip="192.168.1.9", dst_ip="45.9.148.3", dst_port=443,
        protocol=6, payload=_client_hello(0x0301),
    )
    alerts = Detector(config_path=None).score([legacy])
    version_alerts = [a for a in alerts if a["subtype"] == "legacy_tls_version"]
    assert version_alerts, "a trained model should not be able to suppress a rule"
    assert version_alerts[0]["confidence"] >= 0.7


def test_detector_wires_up_every_threat_class():
    """One mixed batch through the real Detector, not the modules directly."""
    batch = []
    batch += [
        _flow(
            src_ip=f"203.0.113.{i}",
            dst_ip="198.51.100.10",
            src_port=1024 + i,
            dst_port=80,
            packets=400,
            duration_ms=1000,
            syn_count=400,
            ack_count=0,
        )
        for i in range(35)
    ]
    batch += [
        _flow(
            src_ip="203.0.113.77",
            dst_ip="198.51.100.5",
            src_port=40000 + i,
            dst_port=i + 1,
            packets=1,
            bytes=60,
            duration_ms=5,
            syn_count=1,
            ack_count=0,
        )
        for i in range(30)
    ]
    batch += [
        _dns_flow("kq7bxz1mvhqp3wr.com"),
        _dns_flow("a1b2c3d4e5f6g7h8.i9j0k1l2m3n4o5p6.q7r8s9t0u1.tun.example.com", qtype=16),
        _flow(
            src_ip="192.168.1.9",
            dst_ip="45.9.148.3",
            dst_port=4444,
            protocol=6,
            payload=_client_hello(0x0301),
        ),
        _flow(
            src_ip="192.168.1.50",
            dst_ip="185.220.101.7",
            src_port=51000,
            dst_port=443,
            packets=40_000,
            bytes=50_000_000,
            duration_ms=300_000,
        ),
        _flow(
            src_ip="185.220.101.7",
            dst_ip="192.168.1.50",
            src_port=443,
            dst_port=51000,
            packets=2_000,
            bytes=200_000,
            duration_ms=300_000,
        ),
    ]

    alerts = Detector(config_path=None).score(batch)
    assert all(a["confidence"] >= 0.5 for a in alerts), "confidence gate leaked a weak alert"
    classes = {a["threat_class"] for a in alerts}
    # beaconing needs several windows, so it has its own test
    assert classes == {
        "volumetric_ddos",
        "ip_spoofing",
        "dns_abuse",
        "encrypted_malware",
        "recon_scanning",
        "data_exfiltration",
    }


# --- helpers for the new tests --------------------------------------------


def _raw(**overrides):
    """an un-extracted flow, the way the exporter sends it."""
    base = {
        "src_ip": "1.2.3.4",
        "dst_ip": "10.0.0.5",
        "src_port": 12345,
        "dst_port": 80,
        "protocol": 6,
        "packets": 10,
        "bytes": 600,
        "duration_ms": 1000,
        "syn_count": 0,
        "ack_count": 0,
        "fin_count": 0,
        "rst_count": 0,
    }
    base.update(overrides)
    return base


def _dns_flow(qname: str, qtype: int = 1):
    return _flow(
        src_ip="192.168.1.50",
        dst_ip="192.168.1.1",
        src_port=40000,
        dst_port=53,
        protocol=17,
        is_dns=True,
        packets=1,
        bytes=80,
        duration_ms=10,
        payload=_dns_payload(qname, qtype),
    )


def _dns_payload(qname: str, qtype: int = 1) -> str:
    # 12-byte header, then length-prefixed labels, then qtype and qclass
    data = bytearray(b"\x00\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00")
    for label in qname.split("."):
        data.append(len(label))
        data.extend(label.encode())
    data.append(0)
    data.extend(qtype.to_bytes(2, "big"))
    data.extend(b"\x00\x01")
    return data.hex()


def _ext(ext_type: int, body: bytes) -> bytes:
    return ext_type.to_bytes(2, "big") + len(body).to_bytes(2, "big") + body


def _tls_record(handshake_type: int, body: bytes) -> bytes:
    handshake = bytes([handshake_type]) + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + len(handshake).to_bytes(2, "big") + handshake


def _quic_initial(version: int = 0x00000001) -> str:
    """long header with the fixed bit set and packet type 0 (Initial)."""
    data = bytearray([0xC0])
    data += version.to_bytes(4, "big")
    data += b"\x08" + bytes(8)  # destination connection id
    return data.hex()


def _client_hello(
    client_version: int = 0x0303,
    sni: str = "example.com",
    ciphers: tuple[int, ...] = (0x0A0A, 0x1301, 0x1302, 0xC02B),
) -> str:
    """a real ClientHello, complete enough to fingerprint.

    0x0a0a is a GREASE cipher and must be dropped from the JA3.
    """
    body = bytearray()
    body += client_version.to_bytes(2, "big")
    body += bytes(32)  # random
    body += b"\x00"  # empty session id
    cipher_bytes = b"".join(c.to_bytes(2, "big") for c in ciphers)
    body += len(cipher_bytes).to_bytes(2, "big") + cipher_bytes
    body += b"\x01\x00"  # one compression method: null

    exts = bytearray()
    if sni:
        name = sni.encode()
        entry = b"\x00" + len(name).to_bytes(2, "big") + name
        exts += _ext(0x0000, len(entry).to_bytes(2, "big") + entry)
    curves = b"".join(c.to_bytes(2, "big") for c in (0x001D, 0x0017))
    exts += _ext(0x000A, len(curves).to_bytes(2, "big") + curves)
    exts += _ext(0x000B, b"\x01\x00")  # ec point formats: uncompressed
    alpn = b"\x02h2"
    exts += _ext(0x0010, len(alpn).to_bytes(2, "big") + alpn)
    body += len(exts).to_bytes(2, "big") + exts

    return _tls_record(0x01, bytes(body)).hex()


def _server_hello(server_version: int = 0x0303, cipher: int = 0x1301) -> str:
    body = bytearray()
    body += server_version.to_bytes(2, "big")
    body += bytes(32)  # random
    body += b"\x00"  # empty session id
    body += cipher.to_bytes(2, "big")
    body += b"\x00"  # null compression
    exts = _ext(0x002B, b"\x03\x04")  # supported_versions: tls 1.3
    body += len(exts).to_bytes(2, "big") + exts
    return _tls_record(0x02, bytes(body)).hex()
