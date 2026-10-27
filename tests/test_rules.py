import pandas as pd
from analysis.parser import parse_csv_bytes
from analysis.rules import run_detections, investigation_score

def test_parser_normalizes_common_columns():
    result = parse_csv_bytes(b"Source IP,Destination IP,Protocol,Length,Info\n192.168.1.1,192.168.1.2,TCP,60,Dst Port: 443\n")
    assert result.ok
    assert {"source", "destination", "protocol", "length", "info"}.issubset(result.frame.columns)

def test_packet_threshold_is_strictly_greater_than_50():
    frame = pd.DataFrame({"source": ["192.168.1.10"] * 50, "destination": ["192.168.1.2"] * 50, "protocol": ["TCP"] * 50})
    alerts, _ = run_detections(frame)
    assert not any(a["rule"] == "High packet volume" for a in alerts)
    frame.loc[len(frame)] = ["192.168.1.10", "192.168.1.2", "TCP"]
    alerts, _ = run_detections(frame)
    assert any(a["rule"] == "High packet volume" for a in alerts)

def test_investigation_score_is_capped_and_deduplicated_by_rule():
    alerts = [{"rule": "High packet volume", "points": 20}, {"rule": "High packet volume", "points": 20}]
    result = investigation_score(alerts)
    assert result["total"] == 20
    assert len(result["factors"]) == 1


def test_port_scan_does_not_combine_ports_from_unrelated_sources():
    rows = []
    for source, ports in (("192.168.1.10", range(1000, 1006)), ("192.168.1.11", range(2000, 2006))):
        for port in ports:
            rows.append({"source": source, "destination": "192.168.1.20", "protocol": "TCP", "info": f"Dst Port: {port}"})
    frame = pd.DataFrame(rows)
    alerts, _ = run_detections(frame, {"unique_ports": 10})
    assert not any(a["rule"] == "Possible port scanning" for a in alerts)
