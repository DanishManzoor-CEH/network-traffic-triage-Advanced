"""Import and normalize Suricata EVE JSONL and Zeek TSV logs.

This is a log-import integration, not an embedded Suricata/Zeek engine runner.
"""
from __future__ import annotations

import csv
import io
import json
from typing import Any

import pandas as pd


def parse_security_log_bytes(data: bytes, filename: str = "uploaded.log") -> dict[str, Any]:
    if not data:
        raise ValueError("The security log is empty.")
    if len(data) > 10 * 1024 * 1024:
        raise ValueError("Security log exceeds the 10 MB limit.")
    text = data.decode("utf-8-sig", errors="replace")
    first = next((line.strip() for line in text.splitlines() if line.strip()), "")
    if first.startswith("{") or filename.lower().endswith( (".json", ".jsonl") ):
        return _parse_suricata_eve(text)
    if "#fields" in text or "#separator" in text:
        return _parse_zeek_tsv(text)
    raise ValueError("Unsupported format. Upload Suricata EVE JSON/JSONL or a Zeek TSV log containing #fields.")


def _parse_suricata_eve(text: str) -> dict[str, Any]:
    alerts, rows, warnings = [], [], []
    for line_no, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            warnings.append(f"Skipped malformed JSON on line {line_no}.")
            continue
        if not isinstance(event, dict):
            warnings.append(f"Skipped non-object JSON on line {line_no}.")
            continue
        event_type = str(event.get("event_type", ""))
        src, dst = event.get("src_ip", ""), event.get("dest_ip", "")
        proto = event.get("proto", "")
        alert_data = event.get("alert") or {}
        if event_type == "alert" or alert_data:
            alerts.append({
                "rule": f"Suricata: {alert_data.get('signature', 'Alert event')}",
                "severity": {1: "High", 2: "Medium", 3: "Low"}.get(alert_data.get("severity"), "Medium"),
                "source": src or None, "destination": dst or None, "protocol": proto or None,
                "evidence": f"Suricata EVE alert; category={alert_data.get('category', 'not supplied')}; signature_id={alert_data.get('signature_id', 'not supplied')}.",
                "observed": json.dumps({k: event.get(k) for k in ("timestamp", "src_port", "dest_port", "flow_id", "community_id") if event.get(k) is not None}, ensure_ascii=False),
                "threshold": "External Suricata rule; consult the installed rule definition",
                "why_it_matters": "Suricata emitted an alert for this event. Review the signature and context; an IDS alert is not proof of compromise.",
                "benign_explanations": "Rule false positive, authorised testing, or benign traffic matching a signature.",
                "investigation_steps": ["Review the Suricata signature and packet context.", "Correlate with flow, endpoint, and server logs.", "Validate whether the alert was blocked or only observed."],
                "points": 25 if alert_data.get("severity") == 1 else 15,
                "attack_category": alert_data.get("category") or "External IDS alert",
                "detection_source": "Suricata EVE", "confidence_note": "Imported IDS alert; validate signature and context.",
            })
        rows.append({
            "timestamp": event.get("timestamp", ""), "source": src, "destination": dst,
            "protocol": proto, "length": event.get("pkt_len", ""), "byte_basis": "Suricata pkt_len",
            "info": event.get("http", {}).get("url", "") if isinstance(event.get("http"), dict) else "",
            "tcp_flags": event.get("tcp", {}).get("tcp_flags", "") if isinstance(event.get("tcp"), dict) else "",
            "source_port": event.get("src_port", ""), "destination_port": event.get("dest_port", ""),
            "domain": event.get("dns", {}).get("rrname", "") if isinstance(event.get("dns"), dict) else "",
        })
    if not rows and not alerts:
        raise ValueError("No usable Suricata EVE JSON events were found.")
    return {"format": "Suricata EVE", "alerts": alerts, "frame": pd.DataFrame(rows), "warnings": warnings}


def _parse_zeek_tsv(text: str) -> dict[str, Any]:
    separator = "\x09"
    fields: list[str] | None = None
    rows: list[dict[str, Any]] = []
    warnings: list[str] = []
    for line_no, line in enumerate(text.splitlines(), start=1):
        if not line:
            continue
        if line.startswith("#separator"):
            # Zeek commonly writes #separator \\x09. Tab remains the default.
            continue
        if line.startswith("#fields"):
            fields = line.split("\t", 1)[1].split("\t") if "\t" in line else line[len("#fields"):].strip().split()
            continue
        if line.startswith("#"):
            continue
        if not fields:
            continue
        values = line.split(separator)
        if len(values) != len(fields):
            warnings.append(f"Skipped Zeek row {line_no}: field count did not match #fields header.")
            continue
        record = dict(zip(fields, values))
        def pick(*keys):
            for key in keys:
                value = record.get(key, "")
                if value not in ("", "-"):
                    return value
            return ""
        proto = pick("proto", "service")
        info_parts = []
        for k in ("service", "conn_state", "history", "query", "host", "uri", "method", "status_code"):
            if record.get(k) not in (None, "", "-"):
                info_parts.append(f"{k}={record[k]}")
        rows.append({
            "timestamp": pick("ts", "timestamp"), "source": pick("id.orig_h", "src_ip"),
            "destination": pick("id.resp_h", "dest_ip"), "protocol": proto,
            "length": pick("orig_ip_bytes", "orig_bytes", "resp_bytes"),
            "byte_basis": ("Zeek orig_ip_bytes" if pick("orig_ip_bytes") else "Zeek orig_bytes" if pick("orig_bytes") else "Zeek resp_bytes" if pick("resp_bytes") else ""),
            "info": " ".join(info_parts), "source_port": pick("id.orig_p", "src_port"),
            "destination_port": pick("id.resp_p", "dest_port"), "domain": pick("query", "host"),
            "tcp_flags": pick("history"),
        })
    if not rows:
        raise ValueError("No Zeek rows could be parsed. Confirm this is a tab-separated Zeek log with a #fields header.")
    return {"format": "Zeek TSV", "alerts": [], "frame": pd.DataFrame(rows), "warnings": warnings}
