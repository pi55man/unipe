"""tests for entity dossiers, aggregation/correlation, and coverage/health."""

from __future__ import annotations

from pathlib import Path

from unipe_ai.aggregation import IncidentAggregator
from unipe_ai.alerts import make_alert
from unipe_ai.coverage import coverage_notes, visibility_block
from unipe_ai.engine import Throughput
from unipe_ai.entities import EntityStore, MAX_ENTITIES
from unipe_ai.models.detector import Detector
from unipe_ai.models.volumetric import VolumetricConfig


def _alert(**kwargs):
    base = dict(
        threat_class="volumetric_ddos",
        subtype="udp_flood",
        severity="high",
        confidence=0.8,
        message="udp flood",
        evidence={"packet_rate": 5000.0},
        flow_id="17/*:*->198.51.100.10:80",
        timestamp=1000.0,
        src_ip="203.0.113.1",
        dst_ip="198.51.100.10",
        src_port=0,
        dst_port=80,
        protocol=17,
    )
    base.update(kwargs)
    return make_alert(**base)


def test_entity_store_persists(tmp_path: Path):
    path = tmp_path / "entities.json"
    store = EntityStore(path)
    store.observe_flows(
        [
            {
                "src_ip": "10.0.0.1",
                "dst_ip": "198.51.100.10",
                "protocol": 6,
                "dst_port": 443,
                "src_port": 50000,
                "dns_qname": "",
                "tls_sni": "ex.example",
            }
        ],
        now=100.0,
    )
    store.note_alert(
        _alert(src_ip="10.0.0.1", dst_ip="198.51.100.10", timestamp=101.0)
    )
    store.flush(force=True)
    assert path.is_file()

    reloaded = EntityStore(path)
    ent = reloaded.get("10.0.0.1")
    assert ent is not None
    assert ent["first_seen"] == 100.0
    assert "volumetric_ddos" in ent["threat_classes"]
    assert "198.51.100.10" in ent["partners"]
    assert "ex.example" in ent["domains"]
    assert ent["alerts"]


def test_entity_store_is_bounded(tmp_path: Path):
    store = EntityStore(tmp_path / "entities.json")
    for i in range(MAX_ENTITIES + 50):
        store.observe_flows(
            [{"src_ip": f"10.0.{i // 256}.{i % 256}", "dst_ip": "1.2.3.4",
              "protocol": 6, "dst_port": 80, "src_port": 1234}],
            now=float(i),
        )
    store.flush(force=True)
    assert len(store.all()) <= MAX_ENTITIES


def test_aggregator_suppresses_identical_repeat(tmp_path: Path):
    agg = IncidentAggregator(tmp_path / "inc.json", quiet_s=60.0)
    a = _alert(timestamp=1000.0)
    first = agg.process([a], now=1000.0)
    second = agg.process([dict(a)], now=1000.5)
    assert len(first) == 1
    assert first[0]["occurrence_count"] == 1
    assert first[0]["incident_id"]
    assert second == []


def test_aggregator_escalates_on_severity_and_new_detector(tmp_path: Path):
    agg = IncidentAggregator(tmp_path / "inc.json", quiet_s=60.0)
    first = agg.process([_alert(severity="medium", timestamp=1000.0)], now=1000.0)
    assert first
    # same flood key, higher severity — escalate even inside quiet window
    esc = agg.process(
        [_alert(severity="high", confidence=0.9, timestamp=1001.0)],
        now=1001.0,
    )
    assert len(esc) == 1
    assert "severity_increase" in esc[0]["escalation_reasons"]
    assert esc[0]["occurrence_count"] >= 2

    # new subtype on same victim entity opens a different agg key, then correlates
    other = agg.process(
        [
            make_alert(
                threat_class="recon_scanning",
                subtype="vertical_port_scan",
                severity="medium",
                confidence=0.7,
                message="scan",
                evidence={"unique_ports": 40},
                flow_id="6/203.0.113.9:*->198.51.100.10:*",
                timestamp=1002.0,
                src_ip="203.0.113.9",
                dst_ip="198.51.100.10",
                src_port=0,
                dst_port=0,
                protocol=6,
            )
        ],
        now=1002.0,
    )
    assert other
    assert other[0]["incident_id"] != first[0]["incident_id"]


def test_aggregator_correlates_chain_probabilistically(tmp_path: Path):
    agg = IncidentAggregator(tmp_path / "inc.json", quiet_s=60.0)
    scan = make_alert(
        threat_class="recon_scanning",
        subtype="vertical_port_scan",
        severity="medium",
        confidence=0.7,
        message="scan",
        evidence={},
        flow_id="6/10.0.0.5:*->198.51.100.10:*",
        timestamp=2000.0,
        src_ip="10.0.0.5",
        dst_ip="198.51.100.10",
    )
    dga = make_alert(
        threat_class="dns_abuse",
        subtype="dga_domain",
        severity="high",
        confidence=0.8,
        message="dga",
        evidence={"qname": "abcxyz.example"},
        flow_id="17/10.0.0.5:53000->198.51.100.10:53",
        timestamp=2010.0,
        src_ip="10.0.0.5",
        dst_ip="198.51.100.10",
        src_port=53000,
        dst_port=53,
        protocol=17,
    )
    a1 = agg.process([scan], now=2000.0)
    a2 = agg.process([dga], now=2010.0)
    assert a1 and a2
    # dga should soft-link to the scan on the same entity
    assert a2[0].get("related_incident_ids") or a2[0].get("correlation_hypothesis")
    hyp = a2[0].get("correlation_hypothesis") or ""
    assert "probabilistic" in hyp.lower()


def test_aggregator_survives_restart(tmp_path: Path):
    path = tmp_path / "inc.json"
    agg = IncidentAggregator(path, quiet_s=60.0)
    first = agg.process([_alert(timestamp=3000.0)], now=3000.0)
    assert first
    iid = first[0]["incident_id"]
    agg2 = IncidentAggregator(path, quiet_s=60.0)
    silenced = agg2.process([_alert(timestamp=3001.0)], now=3001.0)
    assert silenced == []
    assert iid in agg2._open


def test_detector_uses_aggregator_not_raw_cooldown():
    detector = Detector(config_path=None)
    detector.volumetric_cfg = VolumetricConfig(
        udp_flood_min_flows=25,
        min_unique_sources=10,
        udp_flood_packet_rate=1000.0,
        alert_lan_destinations=True,
    )
    flows = [
        {
            "src_ip": f"203.0.113.{i}",
            "dst_ip": "198.51.100.10",
            "src_port": 12345,
            "dst_port": 80,
            "protocol": 17,
            "packets": 1,
            "bytes": 60,
            "duration_ms": 50,
            "syn_count": 0,
            "ack_count": 0,
            "fin_count": 0,
            "rst_count": 0,
            "timestamp": 1000.0,
            "is_dns": False,
            "ttl": 64,
            "icmp_type": 0,
            "icmp_code": 0,
            "payload_len": 0,
            "payload": "",
        }
        for i in range(40)
    ]
    from unipe_ai.features.extract import extract

    feats = [extract(f) for f in flows]
    first = [a for a in detector.score(feats, now=1000.0) if a["subtype"] == "udp_flood"]
    second = [a for a in detector.score(feats, now=1000.5) if a["subtype"] == "udp_flood"]
    third = [a for a in detector.score(feats, now=1061.0) if a["subtype"] == "udp_flood"]
    assert first
    assert first[0].get("incident_id")
    assert not second
    assert third
    assert third[0]["occurrence_count"] >= 2


def test_coverage_notes_one_way_and_exfil():
    tap = {
        "one_directional": True,
        "message": "tap looks one-directional: replies inbound",
        "to_server": 5,
        "to_client": 200,
        "total": 205,
    }
    notes = coverage_notes(
        {
            "threat_class": "data_exfiltration",
            "subtype": "asymmetric_outbound_volume",
            "evidence": {},
        },
        tap=tap,
        health={"flows_dropped_cap": 100, "coverage_degraded": True},
    )
    blob = " ".join(notes).lower()
    assert "passive" in blob
    assert "decrypt" in blob or "payload" in blob
    assert "reverse" in blob
    assert "not assurance" in blob or "degraded" in blob


def test_visibility_block_flags():
    vis = visibility_block(
        {"one_directional": True, "message": "x", "to_server": 0, "to_client": 200},
        {"flows_dropped_cap": 0, "coverage_degraded": True},
    )
    assert vis["passive_only"] is True
    assert vis["decryption"] is False
    assert vis["payload_content"] is False
    assert vis["one_directional_tap"] is True
    assert vis["blind_spots"]


def test_throughput_tracks_drops():
    t = Throughput(every_secs=0)
    t.add(100, 50, 1, 0.01, dropped=50)
    snap = t.snapshot(
        tap={"one_directional": False, "to_server": 100, "to_client": 100, "total": 200, "message": ""},
        socket="/tmp/x",
        alerts_path="/tmp/a",
        entities_path="/tmp/e",
        incidents_path="/tmp/i",
    )
    assert snap["flows_dropped_cap"] == 50
    assert snap["coverage_degraded"] is True
    assert snap["visibility"]["passive_only"] is True
    assert "entities_path" in snap
