from __future__ import annotations
import re
import pandas as pd

DEFAULT_THRESHOLDS = {
    "packets_per_source": 50,
    "unique_destinations": 10,
    "unique_ports": 10,
    "icmp_packets": 30,
    "dns_packets": 30,
    "repeated_pair_packets": 40,
}
POINTS = {
    "High packet volume": 20,
    "Possible host scanning": 25,
    "Possible port scanning": 25,
    "High ICMP activity": 10,
    "High DNS activity": 10,
    "Repeated source-to-destination communication": 15,
    "TCP SYN-heavy activity": 20,
}

def _alert(rule, severity, source, destination, protocol, evidence, observed, threshold, why, benign, steps):
    return {
        "rule": rule, "severity": severity, "source": source, "destination": destination,
        "protocol": protocol, "evidence": evidence, "observed": observed, "threshold": threshold,
        "why_it_matters": why, "benign_explanations": benign, "investigation_steps": steps,
        "points": POINTS.get(rule, 0),
    }

def _extract_ports(info: object) -> set[int]:
    text = str(info)
    patterns = (
        r"(?i)\b(?:dst|destination)\s*port\s*[:=]\s*(\d{1,5})",
        r"(?i)\b(?:tcp|udp)\s+dstport\s*[:=]\s*(\d{1,5})",
        r"(?i)\bdport\s*[:=]\s*(\d{1,5})",
    )
    ports = set()
    for pattern in patterns:
        for value in re.findall(pattern, text):
            port = int(value)
            if 1 <= port <= 65535:
                ports.add(port)
    return ports

def run_detections(df: pd.DataFrame, thresholds: dict | None = None) -> tuple[list[dict], dict]:
    t = {**DEFAULT_THRESHOLDS, **(thresholds or {})}
    alerts = []
    has_src = "source" in df.columns
    has_dst = "destination" in df.columns
    has_proto = "protocol" in df.columns
    has_info = "info" in df.columns
    status = {
        "High packet volume": "Available" if has_src else "Unavailable: source column missing",
        "Possible host scanning": "Available" if has_src and has_dst else "Unavailable: source/destination column missing",
        "Possible port scanning": "Available" if has_src and has_dst and (has_info or "destination_port" in df.columns) else "Unavailable: source/destination and port evidence missing",
        "High ICMP activity": "Available" if has_src and has_proto else "Unavailable: source/protocol column missing",
        "High DNS activity": "Available" if has_src and has_proto else "Unavailable: source/protocol column missing",
        "Repeated source-to-destination communication": "Available" if has_src and has_dst else "Unavailable: source/destination column missing",
        "TCP SYN-heavy activity": "Unavailable: explicit flag evidence not found",
    }

    if has_src:
        src_rows = df[df["source"] != ""]
        counts = src_rows.groupby("source").size()
        for source, count in counts.items():
            if count > t["packets_per_source"]:
                alerts.append(_alert("High packet volume", "Medium", str(source), None, None,
                    f"{int(count)} packets from {source}.", f"{int(count)} packets observed from this source.",
                    f"> {t['packets_per_source']} packets per source",
                    "High volume may reflect scanning, a busy service, or unexpected automation.",
                    "Busy servers, backups, monitoring, updates, or authorised testing.",
                    ["Identify the device owning this IP.", "Check whether the workload was expected.", "Correlate with firewall and endpoint logs."]))

    if has_src and has_dst:
        usable = df[(df["source"] != "") & (df["destination"] != "")]
        for source, group in usable.groupby("source"):
            count = int(group["destination"].nunique())
            if count > t["unique_destinations"]:
                alerts.append(_alert("Possible host scanning", "Medium", str(source), None, None,
                    f"{count} unique destinations contacted by {source}.", f"{count} unique destination IPs observed.",
                    f"> {t['unique_destinations']} unique destinations per source",
                    "Contacting many hosts can be consistent with discovery or scanning, but is not proof.",
                    "Asset discovery, vulnerability scanning, service discovery, or monitoring.",
                    ["Confirm the source device and owner.", "Check whether a scan was authorised.", "Review timestamps, ports, and firewall decisions."]))
        pair_counts = usable.groupby(["source", "destination"]).size()
        for (source, destination), count in pair_counts.items():
            if count > t["repeated_pair_packets"]:
                protocol = "Unknown"
                if has_proto:
                    rows = usable[(usable["source"] == source) & (usable["destination"] == destination)]
                    if not rows.empty:
                        protocol = str(rows["protocol"].mode().iloc[0])
                alerts.append(_alert("Repeated source-to-destination communication", "Low", str(source), str(destination), protocol,
                    f"{int(count)} packets between {source} and {destination}; common protocol: {protocol}.",
                    f"{int(count)} packets in this source-destination pair.", f"> {t['repeated_pair_packets']} packets per pair",
                    "Persistent communication may be normal, but unexpected repeated connections merit context.",
                    "Normal application sessions, API traffic, backups, or health checks.",
                    ["Identify the application and expected service.", "Compare timing and protocol with normal operation.", "Check destination ownership and related logs."]))

    if has_src and has_proto:
        for label, rule, key in [
            ("ICMP", "High ICMP activity", "icmp_packets"),
            ("DNS", "High DNS activity", "dns_packets"),
        ]:
            subset = df[df["protocol"].astype(str).str.upper().str.startswith(label) & (df["source"] != "")]
            for source, count in subset.groupby("source").size().items():
                if count > t[key]:
                    why = ("High ICMP volume can accompany diagnostics, discovery, or unusual network behaviour."
                           if label == "ICMP" else
                           "Frequent DNS requests may reflect normal applications or unusual lookup behaviour.")
                    benign = ("Ping sweeps, monitoring, troubleshooting, or health checks."
                              if label == "ICMP" else
                              "Browsers, busy clients, resolvers, service discovery, or retries.")
                    alerts.append(_alert(rule, "Medium" if label == "ICMP" else "Low", str(source), None, label,
                        f"{int(count)} {label} packets from {source}.", f"{int(count)} matching packets.",
                        f"> {t[key]} {label} packets per source", why, benign,
                        ["Check whether the activity is expected.", "Review timing and destination details.", "Correlate with firewall and endpoint telemetry."]))

    if has_src and has_dst and (has_info or "destination_port" in df.columns):
        # Keep port counts scoped to a source-target pair to avoid combining unrelated clients.
        pair_ports = {}
        for _, row in df.iterrows():
            source = str(row.get("source", "")).strip()
            dest = str(row.get("destination", "")).strip()
            if not source or not dest:
                continue
            ports = _extract_ports(row.get("info", ""))
            if "destination_port" in df.columns:
                try:
                    port = int(float(str(row.get("destination_port", "")).strip()))
                    if 1 <= port <= 65535:
                        ports.add(port)
                except (TypeError, ValueError):
                    pass
            pair_ports.setdefault((source, dest), set()).update(ports)
        found = False
        for (source, destination), ports in pair_ports.items():
            if ports:
                found = True
            if len(ports) > t["unique_ports"]:
                alerts.append(_alert("Possible port scanning", "Medium", source, destination, None,
                    f"{len(ports)} unique destination ports observed from {source} to {destination}.",
                    f"Ports: {', '.join(map(str, sorted(ports)[:30]))}.",
                    f"> {t['unique_ports']} unique destination ports per source-target pair",
                    "Many destination ports can indicate service discovery or scanning, depending on context.",
                    "Authorised scanning, service checks, or an application contacting several services.",
                    ["Confirm the source host and whether scanning was authorised.", "Review timestamps and connection outcomes.", "Correlate with firewall logs."]))
        status["Possible port scanning"] = ("Available: explicit port labels extracted from Info/port column" if found
                                           else "Unavailable: no recognised explicit destination-port labels")

    if "tcp_flags" in df.columns:
        flag_text = df["tcp_flags"].astype(str).str.upper()
    elif has_info:
        flag_text = df["info"].astype(str).str.upper()
    else:
        flag_text = pd.Series("", index=df.index)
    syn_mask = flag_text.str.contains(r"\bSYN\b", regex=True) & ~flag_text.str.contains(r"\bACK\b", regex=True)
    if has_src and syn_mask.any():
        status["TCP SYN-heavy activity"] = "Available: explicit SYN-like strings found; verify export format"
        syn_df = df[syn_mask & (df["source"] != "")]
        for source, count in syn_df.groupby("source").size().items():
            if count > t["packets_per_source"]:
                alerts.append(_alert("TCP SYN-heavy activity", "Medium", str(source), None, "TCP",
                    f"{int(count)} SYN-like rows from {source}; ACK exclusion is approximate.",
                    f"{int(count)} rows appear to contain SYN without ACK.", f"> {t['packets_per_source']} SYN-like packets per source",
                    "SYN bursts can arise from ordinary connection attempts, scanning, unavailable services, or SYN-flood behaviour.",
                    "Browsers opening connections, retries, service checks, or authorised scanning.",
                    ["Validate flag parsing against Wireshark.", "Check destination ports and responses.", "Correlate with server/firewall logs."]))

    order = {"High": 3, "Medium": 2, "Low": 1}
    alerts.sort(key=lambda a: (order.get(a["severity"], 0), a["points"]), reverse=True)
    return alerts, status

def investigation_score(alerts: list[dict]) -> dict:
    seen, factors, total = set(), [], 0
    for alert in alerts:
        rule = alert["rule"]
        if rule in seen:
            continue
        seen.add(rule)
        points = int(alert.get("points", 0))
        total += points
        factors.append({"Factor": rule, "Points": f"+{points}"})
    total = min(total, 100)
    label = "Routine activity" if total == 0 else "Activity to review" if total < 25 else "Elevated activity" if total < 50 else "Priority investigation"
    return {"total": total, "label": label, "factors": factors}
