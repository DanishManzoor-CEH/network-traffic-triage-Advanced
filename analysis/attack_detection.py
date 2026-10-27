"""Evidence-based, heuristic attack-pattern detectors for Wireshark/Zeek CSV data.

These detectors identify patterns worth investigating. They do not prove that an attack
occurred or succeeded. Missing fields make a detector unavailable rather than negative.
"""
from __future__ import annotations

import ipaddress
import math
import re
from collections import defaultdict
from statistics import median, pstdev

import pandas as pd

DEFAULT_ATTACK_THRESHOLDS = {
    "scan_ports": 10,
    "scan_hosts": 10,
    "syn_packets_per_10s": 20,
    "packets_per_10s": 100,
    "dns_suspicious_names": 3,
    "beacon_min_events": 6,
    "lateral_destinations": 3,
    "exfil_bytes": 5 * 1024 * 1024,
}

ADMIN_PORTS = {22, 23, 135, 139, 445, 3389, 5985, 5986, 1433, 3306, 5432, 5900}
WEB_MARKERS = {
    "path traversal": re.compile(r"(?:\.\./|\.\.\\|%2e%2e(?:%2f|/|%5c))", re.I),
    "SQL injection-like syntax": re.compile(r"(?:\bunion\s+(?:all\s+)?select\b|\bor\s+['\"]?1['\"]?\s*=\s*['\"]?1|\bsleep\s*\(|\bbenchmark\s*\()", re.I),
    "script injection-like syntax": re.compile(r"(?:<\s*script\b|javascript\s*:|onerror\s*=|onload\s*=)", re.I),
    "command injection-like syntax": re.compile(r"(?:;\s*(?:cat|curl|wget|sh|bash)\b|\|\s*(?:sh|bash)\b|`[^`]+`)", re.I),
}
DOMAIN_RE = re.compile(r"(?i)(?<![\w.-])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}(?![\w.-])")


def _alert(rule: str, severity: str, source=None, destination=None, protocol=None,
           evidence="", observed="", threshold="", why="", benign="", steps=None,
           points=15, category=None) -> dict:
    return {
        "rule": rule, "severity": severity, "source": source, "destination": destination,
        "protocol": protocol, "evidence": evidence, "observed": observed,
        "threshold": threshold, "why_it_matters": why,
        "benign_explanations": benign, "investigation_steps": steps or [],
        "points": points, "attack_category": category or rule,
        "detection_source": "Built-in heuristic", "confidence_note": "Pattern-based indicator; not proof of an attack.",
    }


def _ports(row: pd.Series) -> set[int]:
    result: set[int] = set()
    for key in ("destination_port", "dst_port", "dstport"):
        if key in row.index:
            try:
                p = int(float(str(row[key]).strip()))
                if 1 <= p <= 65535:
                    result.add(p)
            except (TypeError, ValueError):
                pass
    info = str(row.get("info", ""))
    patterns = (
        r"(?i)\b(?:dst|destination)\s*port\s*[:=]\s*(\d{1,5})",
        r"(?i)\b(?:tcp|udp)\s+dstport\s*[:=]\s*(\d{1,5})",
        r"(?i)\bdport\s*[:=]\s*(\d{1,5})",
    )
    for pattern in patterns:
        for value in re.findall(pattern, info):
            p = int(value)
            if 1 <= p <= 65535:
                result.add(p)
    return result


def _is_private(value: object) -> bool | None:
    try:
        return ipaddress.ip_address(str(value).strip()).is_private
    except ValueError:
        return None


def _time_seconds(df: pd.DataFrame) -> pd.Series:
    """Return numeric seconds, supporting Wireshark relative seconds or absolute timestamps."""
    if "timestamp" not in df.columns:
        return pd.Series(float("nan"), index=df.index)
    raw = df["timestamp"].astype(str).str.strip()
    numeric = pd.to_numeric(raw, errors="coerce")
    if numeric.notna().mean() >= 0.7:
        return numeric.astype(float)
    try:
        parsed = pd.to_datetime(raw, errors="coerce", format="mixed", utc=True)
    except (TypeError, ValueError):
        parsed = pd.to_datetime(raw, errors="coerce", utc=True)
    seconds = parsed.astype("int64", copy=False).astype(float) / 1e9
    seconds[parsed.isna()] = float("nan")
    return seconds


def _entropy(text: str) -> float:
    if not text:
        return 0.0
    total = len(text)
    return -sum((text.count(ch) / total) * math.log2(text.count(ch) / total) for ch in set(text))


def _domains(row: pd.Series) -> set[str]:
    values = []
    for key in ("domain", "query", "dns_query", "qname"):
        if key in row.index and str(row[key]).strip():
            values.append(str(row[key]).strip().lower().rstrip("."))
    values.append(str(row.get("info", "")))
    found: set[str] = set()
    for value in values:
        for domain in DOMAIN_RE.findall(value.lower()):
            domain = domain.rstrip(".")
            if len(domain) >= 4 and "." in domain:
                found.add(domain)
    return found


def _protocol_is(df: pd.DataFrame, label: str) -> pd.Series:
    if "protocol" not in df.columns:
        return pd.Series(False, index=df.index)
    return df["protocol"].astype(str).str.upper().str.contains(label, regex=False)


def run_attack_detections(df: pd.DataFrame, thresholds: dict | None = None) -> tuple[list[dict], dict]:
    """Run advanced attack-pattern heuristics and return (alerts, detector availability)."""
    t = {**DEFAULT_ATTACK_THRESHOLDS, **(thresholds or {})}
    alerts: list[dict] = []
    has_src, has_dst = "source" in df.columns, "destination" in df.columns
    has_proto = "protocol" in df.columns
    has_time = "timestamp" in df.columns and _time_seconds(df).notna().sum() >= 3
    has_length = "length" in df.columns
    has_ports = "info" in df.columns or any(c in df.columns for c in ("destination_port", "dst_port", "dstport"))
    status = {
        "Port scan (source-target scoped)": "Available" if has_src and has_dst and has_ports else "Unavailable: source, destination, and destination-port evidence required",
        "Host discovery (time-windowed)": "Available" if has_src and has_dst else "Unavailable: source/destination columns missing",
        "Flooding indicators": "Available with time windows" if has_src and has_time else "Whole-capture fallback only: valid timestamps unavailable",
        "SYN burst indicators": "Available" if has_src and has_proto and ("tcp_flags" in df.columns or "info" in df.columns) else "Unavailable: source/protocol/flag evidence missing",
        "DNS tunneling indicators": "Available" if has_src and has_proto and any(c in df.columns for c in ("info", "domain", "query", "dns_query", "qname")) else "Unavailable: DNS query-name field may be absent",
        "Beaconing indicators": "Available with timestamps" if has_src and has_dst and has_time else "Unavailable: source, destination, and valid timestamps required",
        "Lateral movement indicators": "Available" if has_src and has_dst and has_ports else "Unavailable: source, destination, and port evidence required",
        "Possible outbound data transfer": "Available" if has_src and has_dst and has_length else "Unavailable: source/destination/length fields required",
        "Web attack indicators": "Available when HTTP request details are visible" if "info" in df.columns else "Unavailable: Info/request details missing",
    }

    if df.empty:
        return alerts, status
    work = df.copy()
    work["_ports"] = work.apply(_ports, axis=1)
    work["_seconds"] = _time_seconds(work)

    # Source-target-scoped port scans. This avoids combining ports from unrelated sources.
    if has_src and has_dst and has_ports:
        subset = work[(work["source"].astype(str) != "") & (work["destination"].astype(str) != "")]
        port_sets: dict[tuple[str, str], set[int]] = defaultdict(set)
        for _, row in subset.iterrows():
            port_sets[(str(row["source"]), str(row["destination"]))].update(row["_ports"])
        for (source, dest), ports in port_sets.items():
            if len(ports) > int(t["scan_ports"]):
                alerts.append(_alert(
                    "Possible port scan", "Medium", source, dest, None,
                    f"{len(ports)} distinct destination ports observed from {source} to {dest}.",
                    "Ports: " + ", ".join(map(str, sorted(ports)[:40])),
                    f"> {t['scan_ports']} distinct ports per source-target pair",
                    "Probing many ports can indicate service discovery or scanning; the capture does not establish intent.",
                    "Authorised vulnerability scans, asset inventory, or an application using multiple services.",
                    ["Confirm whether the source is an approved scanner.", "Review timestamps and TCP responses.", "Correlate with firewall and endpoint logs."], 25, "Reconnaissance"))

    # Host discovery within one-minute windows when possible; whole capture otherwise.
    if has_src and has_dst:
        valid = work[(work["source"].astype(str) != "") & (work["destination"].astype(str) != "")]
        if has_time:
            valid = valid.copy()
            valid["_window"] = (valid["_seconds"] // 60).astype("Int64")
            groups = valid.groupby(["source", "_window"], dropna=True)
        else:
            groups = valid.groupby("source")
        for group_key, group in groups:
            source = str(group_key[0] if isinstance(group_key, tuple) else group_key)
            destinations = group["destination"].astype(str).nunique()
            if destinations > int(t["scan_hosts"]):
                window_desc = " in a 60-second window" if has_time else " across this capture"
                alerts.append(_alert("Possible host discovery", "Medium", source, None, None,
                    f"{destinations} unique destinations contacted by {source}{window_desc}.",
                    f"{destinations} unique destination addresses.", f"> {t['scan_hosts']} destinations per source/window",
                    "Rapidly contacting many hosts can indicate network discovery, but legitimate management tools do this too.",
                    "Monitoring, inventory, backup agents, or authorised scanners.",
                    ["Identify the source asset and owner.", "Check whether discovery was expected.", "Review contacted ports and destination roles."], 25, "Reconnaissance"))

    # Packet and SYN bursts in ten-second buckets. Fallback is explicitly whole-capture only.
    if has_src:
        valid = work[work["source"].astype(str) != ""]
        if has_time:
            valid = valid.copy()
            valid["_window"] = (valid["_seconds"] // 10).astype("Int64")
            for (source, window), group in valid.groupby(["source", "_window"], dropna=True):
                count = len(group)
                if count > int(t["packets_per_10s"]):
                    alerts.append(_alert("Possible traffic flood", "Medium", str(source), None, None,
                        f"{count} packets from {source} in a 10-second window.", f"{count} packets / 10 seconds",
                        f"> {t['packets_per_10s']} packets per source per 10 seconds",
                        "A sudden packet-rate spike can be consistent with flooding but may also reflect legitimate load.",
                        "Load tests, busy applications, monitoring, or a short capture of a normal burst.",
                        ["Check destination concentration and packet sizes.", "Review interface and firewall counters.", "Correlate with service health and connection outcomes."], 25, "Denial-of-service indicator"))
        else:
            for source, group in valid.groupby("source"):
                if len(group) > int(t["packets_per_10s"]):
                    alerts.append(_alert("High volume (timing unavailable)", "Low", str(source), None, None,
                        f"{len(group)} packets from {source}; timestamps were unavailable or invalid.", f"{len(group)} packets in capture",
                        f"> {t['packets_per_10s']} packets (whole-capture fallback; not a rate)",
                        "Whole-capture volume cannot establish a flood rate without trustworthy timestamps.",
                        "Busy services or long capture duration.", ["Re-export with timestamps before interpreting as a rate."], 10, "Traffic anomaly"))

    # SYN-only counts, independent of the original generic packet threshold.
    if has_src and has_proto:
        if "tcp_flags" in work.columns:
            flag_text = work["tcp_flags"].astype(str).str.upper()
        else:
            flag_text = work.get("info", pd.Series("", index=work.index)).astype(str).str.upper()
        syn_mask = flag_text.str.contains(r"\bSYN\b", regex=True) & ~flag_text.str.contains(r"\bACK\b", regex=True)
        syn_rows = work[syn_mask & _protocol_is(work, "TCP") & (work["source"].astype(str) != "")]
        if has_time and not syn_rows.empty:
            syn_rows = syn_rows.copy()
            syn_rows["_window"] = (syn_rows["_seconds"] // 10).astype("Int64")
            syn_groups = syn_rows.groupby(["source", "_window"], dropna=True)
        else:
            syn_groups = syn_rows.groupby("source")
        for group_key, group in syn_groups:
            source = str(group_key[0] if isinstance(group_key, tuple) else group_key)
            count = len(group)
            if count > int(t["syn_packets_per_10s"]):
                qualifier = "in a 10-second window" if has_time else "across the capture; rate unavailable"
                alerts.append(_alert("TCP SYN burst indicator", "Medium", source, None, "TCP",
                    f"{count} TCP rows appear to contain SYN without ACK from {source} {qualifier}.",
                    f"{count} SYN-like rows.", f"> {t['syn_packets_per_10s']} SYN-like rows per 10 seconds when timestamps exist",
                    "SYN bursts may reflect scanning, retries, unavailable services, or denial-of-service behavior; flags and responses must be validated.",
                    "Connection churn, client retries, load testing, or authorised scanning.",
                    ["Validate the exported TCP flags.", "Check destination ports and SYN-ACK/RST responses.", "Correlate with server and firewall telemetry."], 25, "Denial-of-service / reconnaissance indicator"))

    # DNS query-name anomaly indicators: long/high-entropy labels and diversity.
    if has_src and has_proto:
        dns_rows = work[_protocol_is(work, "DNS") & (work["source"].astype(str) != "")]
        per_source: dict[str, set[str]] = defaultdict(set)
        suspicious: dict[str, set[str]] = defaultdict(set)
        for _, row in dns_rows.iterrows():
            source = str(row["source"])
            for domain in _domains(row):
                per_source[source].add(domain)
                first_label = domain.split(".")[0]
                if len(first_label) >= 24 and _entropy(first_label) >= 3.4:
                    suspicious[source].add(domain)
        for source, domains in suspicious.items():
            if len(domains) >= int(t["dns_suspicious_names"]):
                examples = sorted(domains)[:5]
                alerts.append(_alert("Possible DNS tunneling indicator", "Medium", source, None, "DNS",
                    f"{len(domains)} long/high-entropy DNS names observed from {source}; sample: {', '.join(examples)}.",
                    f"{len(domains)} suspicious-looking names across {len(per_source[source])} extracted names.",
                    f">= {t['dns_suspicious_names']} names with label length >=24 and entropy >=3.4 bits/character",
                    "Encoded-looking DNS labels can occur in tunneling, but CDNs, tracking, and generated identifiers can look similar.",
                    "CDNs, analytics, anti-abuse tokens, service discovery, and legitimate generated names.",
                    ["Review full query names and query volume over time.", "Check the resolver and endpoint process making requests.", "Correlate with DNS response codes and endpoint telemetry."], 25, "DNS tunneling indicator"))

    # Beaconing: repeated source-destination pair with near-regular intervals.
    if has_src and has_dst and has_time:
        valid = work[(work["source"].astype(str) != "") & (work["destination"].astype(str) != "") & work["_seconds"].notna()]
        for (source, dest), group in valid.groupby(["source", "destination"]):
            times = sorted(set(float(x) for x in group["_seconds"].tolist()))
            if len(times) < int(t["beacon_min_events"]):
                continue
            intervals = [b - a for a, b in zip(times, times[1:]) if b > a]
            if len(intervals) < int(t["beacon_min_events"]) - 1:
                continue
            med = median(intervals)
            if med < 5 or med > 3600:
                continue
            cv = (pstdev(intervals) / (sum(intervals) / len(intervals))) if len(intervals) > 1 and sum(intervals) else 1.0
            if cv <= 0.15:
                alerts.append(_alert("Periodic outbound communication (possible beaconing)", "Low", str(source), str(dest), None,
                    f"{len(times)} distinct timestamps; median interval {med:.1f}s; interval coefficient of variation {cv:.3f}.",
                    f"Regular communication approximately every {med:.1f} seconds.", "At least 6 events; interval variation <= 0.15; median interval 5–3600 seconds",
                    "Regular callbacks can be consistent with command-and-control, but scheduled jobs and monitoring often behave periodically.",
                    "Health checks, telemetry, scheduled tasks, software update checks.",
                    ["Identify the destination domain/process where possible.", "Compare against known business applications.", "Correlate with DNS, TLS, endpoint, and proxy logs."], 15, "Possible command-and-control indicator"))

    # Lateral movement indicators: internal source contacting several internal hosts on admin ports.
    if has_src and has_dst and has_ports:
        lateral: dict[str, set[str]] = defaultdict(set)
        port_evidence: dict[str, set[int]] = defaultdict(set)
        for _, row in work.iterrows():
            src, dst = str(row.get("source", "")), str(row.get("destination", ""))
            if not src or not dst or _is_private(src) is not True or _is_private(dst) is not True:
                continue
            matched = set(row["_ports"]) & ADMIN_PORTS
            if matched:
                lateral[src].add(dst)
                port_evidence[src].update(matched)
        for source, destinations in lateral.items():
            if len(destinations) >= int(t["lateral_destinations"]):
                alerts.append(_alert("Possible lateral movement / admin-service sweep", "Medium", source, None, "TCP/UDP",
                    f"Internal host {source} contacted {len(destinations)} internal hosts on administrative/service ports {sorted(port_evidence[source])}.",
                    f"{len(destinations)} internal destinations; ports {sorted(port_evidence[source])}.",
                    f">= {t['lateral_destinations']} internal destinations on common administrative ports",
                    "Broad internal access to remote administration or file-sharing services can warrant lateral-movement investigation.",
                    "IT administration, endpoint management, backup, inventory, or vulnerability scanning.",
                    ["Confirm the source host and approved management role.", "Review authentication logs on destinations.", "Correlate with endpoint telemetry and change records."], 25, "Lateral movement indicator"))

    # Possible exfiltration: aggregate bytes from private source to non-private destination.
    if has_src and has_dst and has_length:
        lengths = pd.to_numeric(work["length"].astype(str).str.replace(",", "", regex=False), errors="coerce").fillna(0).clip(lower=0)
        outbound: dict[tuple[str, str], int] = defaultdict(int)
        for idx, row in work.iterrows():
            src, dst = str(row.get("source", "")), str(row.get("destination", ""))
            if src and dst and _is_private(src) is True and _is_private(dst) is False:
                outbound[(src, dst)] += int(lengths.loc[idx])
        byte_basis = "packet length field"
        if "byte_basis" in work.columns:
            basis_values = [str(x) for x in work["byte_basis"].dropna().unique() if str(x).strip()]
            if basis_values:
                byte_basis = ", ".join(basis_values[:2])
        for (source, dest), byte_count in outbound.items():
            if byte_count >= int(t["exfil_bytes"]):
                alerts.append(_alert("Large outbound transfer (possible exfiltration)", "Medium", source, dest, None,
                    f"Estimated {byte_count:,} bytes from private source {source} to non-private destination {dest}; basis: {byte_basis}.",
                    f"~{byte_count:,} bytes summed from the available byte/length field ({byte_basis}).",
                    f">= {int(t['exfil_bytes']):,} bytes per source-destination pair",
                    "Large outbound transfers can be worth checking for data loss, but byte counters alone do not establish data theft.",
                    "Cloud backups, software uploads, video calls, file sync, or legitimate large transfers.",
                    ["Confirm transfer direction and destination ownership.", "Compare with normal host baseline and business purpose.", "Check proxy, DLP, endpoint, and cloud audit logs."], 20, "Possible data exfiltration indicator"))

    # Visible web request indicators. Only analyze text actually present in the CSV.
    if "info" in work.columns:
        for _, row in work.iterrows():
            info = str(row.get("info", ""))
            protocol = str(row.get("protocol", "")).upper()
            if not info or not ("HTTP" in protocol or re.search(r"\b(?:GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+\S+\s+HTTP/", info, re.I)):
                continue
            matched = [name for name, pattern in WEB_MARKERS.items() if pattern.search(info)]
            if matched:
                source, dest = str(row.get("source", "")) or None, str(row.get("destination", "")) or None
                alerts.append(_alert("Suspicious web request pattern", "Medium", source, dest, "HTTP",
                    f"Visible request details matched: {', '.join(matched)}. Request content is untrusted input and may be incomplete.",
                    f"Matched indicators: {', '.join(matched)}. Raw request text is omitted from alert metadata.", "Validated visible request marker; no successful exploitation inferred",
                    "The request resembles a common traversal/injection pattern, but it may be a scanner test or a blocked request.",
                    "Authorised security testing, WAF test traffic, benign encoded parameters, or false-positive string matches.",
                    ["Check HTTP response status and server-side logs.", "Determine whether the request reached the application.", "Review WAF and application telemetry; do not infer compromise from request text alone."], 20, "Web attack indicator"))

    severity_order = {"High": 3, "Medium": 2, "Low": 1, "Informational": 0}
    alerts.sort(key=lambda a: (severity_order.get(a["severity"], 0), a["points"]), reverse=True)
    return alerts, status
