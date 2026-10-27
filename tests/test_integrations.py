from pathlib import Path
from integrations import parse_security_log_bytes

ROOT = Path(__file__).resolve().parents[1]


def test_suricata_eve_imports_alerts():
    data = (ROOT / "samples" / "suricata-eve-sample.jsonl").read_bytes()
    result = parse_security_log_bytes(data, "suricata-eve-sample.jsonl")
    assert result["format"] == "Suricata EVE"
    assert len(result["alerts"]) == 2
    assert result["alerts"][0]["detection_source"] == "Suricata EVE"


def test_zeek_conn_log_normalizes_fields():
    data = (ROOT / "samples" / "zeek-conn-sample.log").read_bytes()
    result = parse_security_log_bytes(data, "zeek-conn-sample.log")
    assert result["format"] == "Zeek TSV"
    assert len(result["frame"]) == 4
    assert {"timestamp", "source", "destination", "destination_port"}.issubset(result["frame"].columns)


def test_unsupported_security_log_format_fails_clearly():
    try:
        parse_security_log_bytes(b"not a supported log", "sample.txt")
    except ValueError as exc:
        assert "Unsupported format" in str(exc)
    else:
        raise AssertionError("Expected unsupported format to raise ValueError")
