from pathlib import Path
import pandas as pd

from analysis.parser import parse_csv_bytes
from analysis.attack_detection import run_attack_detections

ROOT = Path(__file__).resolve().parents[1]


def load_sample(name):
    return parse_csv_bytes((ROOT / "samples" / name).read_bytes()).frame


def test_port_scan_is_scoped_to_source_and_target():
    frame = load_sample("attack-port-scan.csv")
    alerts, _ = run_attack_detections(frame)
    scan = [a for a in alerts if a["rule"] == "Possible port scan"]
    assert scan
    assert scan[0]["source"] == "192.168.1.50"
    assert scan[0]["destination"] == "192.168.1.20"


def test_syn_burst_has_separate_threshold():
    alerts, _ = run_attack_detections(load_sample("attack-syn-burst.csv"))
    assert any(a["rule"] == "TCP SYN burst indicator" for a in alerts)


def test_dns_tunneling_indicator_requires_multiple_suspicious_names():
    alerts, _ = run_attack_detections(load_sample("attack-dns-tunnel-indicator.csv"))
    assert any(a["rule"] == "Possible DNS tunneling indicator" for a in alerts)


def test_beaconing_requires_valid_timestamps_and_regular_intervals():
    alerts, status = run_attack_detections(load_sample("attack-beaconing-indicator.csv"))
    assert status["Beaconing indicators"] == "Available with timestamps"
    assert any(a["rule"] == "Periodic outbound communication (possible beaconing)" for a in alerts)


def test_lateral_movement_indicator_uses_internal_admin_ports():
    alerts, _ = run_attack_detections(load_sample("attack-lateral-movement-indicator.csv"))
    assert any(a["rule"] == "Possible lateral movement / admin-service sweep" for a in alerts)


def test_large_outbound_transfer_is_an_indicator_not_a_verdict():
    alerts, _ = run_attack_detections(load_sample("attack-outbound-transfer-indicator.csv"))
    result = next(a for a in alerts if a["rule"] == "Large outbound transfer (possible exfiltration)")
    assert "not establish data theft" in result["why_it_matters"]


def test_visible_web_attack_markers_are_reported():
    alerts, _ = run_attack_detections(load_sample("attack-web-indicator.csv"))
    assert any(a["rule"] == "Suspicious web request pattern" for a in alerts)


def test_no_timestamps_does_not_claim_beaconing_available():
    frame = pd.DataFrame({"source": ["192.168.1.1"] * 6, "destination": ["1.1.1.1"] * 6, "protocol": ["TLS"] * 6})
    alerts, status = run_attack_detections(frame)
    assert status["Beaconing indicators"].startswith("Unavailable")
    assert not any("beaconing" in a["rule"].lower() for a in alerts)


def test_benign_regular_web_requests_do_not_trigger_web_indicator():
    frame = pd.DataFrame({
        "source": ["192.168.1.2"], "destination": ["192.168.1.3"],
        "protocol": ["HTTP"], "info": ["GET /products?page=2 HTTP/1.1"],
    })
    alerts, _ = run_attack_detections(frame)
    assert not any(a["rule"] == "Suspicious web request pattern" for a in alerts)


def test_time_window_flooding_indicator():
    frame = pd.DataFrame({
        "timestamp": [i * 0.08 for i in range(120)],
        "source": ["192.168.1.55"] * 120,
        "destination": ["192.168.1.10"] * 120,
        "protocol": ["UDP"] * 120,
        "length": [1200] * 120,
    })
    alerts, _ = run_attack_detections(frame)
    assert any(a["rule"] == "Possible traffic flood" for a in alerts)


def test_normal_sample_does_not_trigger_advanced_attack_patterns():
    alerts, _ = run_attack_detections(load_sample("normal-traffic.csv"))
    assert alerts == []
