from __future__ import annotations

import streamlit as st
import pandas as pd

from analysis.parser import MAX_UPLOAD_BYTES, parse_csv_bytes
from analysis.statistics import build_summary
from analysis.rules import DEFAULT_THRESHOLDS, run_detections, investigation_score
from analysis.attack_detection import DEFAULT_ATTACK_THRESHOLDS, run_attack_detections
from integrations import parse_security_log_bytes
from ai.groq_helper import MODEL_NAME, get_groq_api_key, explain_alert, generate_report

ROOT = __import__("pathlib").Path(__file__).parent
SAMPLES = {
    "Normal Sample": ROOT / "samples" / "normal-traffic.csv",
    "Suspicious Sample": ROOT / "samples" / "high-volume-traffic.csv",
    "Mixed SOC Lab (original)": ROOT / "samples" / "mixed-soc-lab.csv",
    "Port Scan Lab": ROOT / "samples" / "port-scan-lab.csv",
    "Host Discovery Lab": ROOT / "samples" / "host-discovery-lab.csv",
    "DNS Anomaly Lab": ROOT / "samples" / "dns-anomaly-lab.csv",
    "ICMP Sweep Lab": ROOT / "samples" / "icmp-sweep-lab.csv",
    "TCP SYN Burst Lab": ROOT / "samples" / "syn-burst-lab.csv",
    "Repeated Connection Lab": ROOT / "samples" / "repeated-connection-lab.csv",
    "Combined Anomaly SOC Lab": ROOT / "samples" / "combined-anomaly-soc-lab.csv",
    "Attack Patterns Combined Lab": ROOT / "samples" / "attack-patterns-combined-lab.csv",
    "Port Scan Indicator Lab": ROOT / "samples" / "attack-port-scan.csv",
    "SYN Burst Indicator Lab": ROOT / "samples" / "attack-syn-burst.csv",
    "DNS Tunneling Indicator Lab": ROOT / "samples" / "attack-dns-tunnel-indicator.csv",
    "Beaconing Indicator Lab": ROOT / "samples" / "attack-beaconing-indicator.csv",
    "Lateral Movement Indicator Lab": ROOT / "samples" / "attack-lateral-movement-indicator.csv",
    "Outbound Transfer Indicator Lab": ROOT / "samples" / "attack-outbound-transfer-indicator.csv",
    "Web Attack Indicator Lab": ROOT / "samples" / "attack-web-indicator.csv",
}

st.set_page_config(page_title="Network Traffic Triage", page_icon="🛡️", layout="wide")
st.markdown("""
<style>
.block-container {padding-top: 1.4rem; max-width: 1450px;}
[data-testid="stAppViewContainer"] {background: #0b1220;}
[data-testid="stSidebar"] {background: #111c2e;}
div[data-testid="stMetric"] {background:#142238;border:1px solid #2b3e59;padding:12px;border-radius:12px;}
</style>
""", unsafe_allow_html=True)

st.title("🛡️ Network Traffic Triage Tool")
st.caption("Educational, explainable review of Wireshark CSV exports.")
st.warning("Alerts indicate activity worth investigating; they do not prove malicious behaviour.")
st.info("Only analyse traffic from systems and networks you own or are authorised to monitor.")
st.info(
    "Uploaded CSVs are processed by the app server. Raw packet rows are not sent to Groq. "
    "If you explicitly request AI output, only allow-listed summary statistics and alert metadata are sent."
)

def get_thresholds() -> dict:
    return {
        "packets_per_source": int(st.session_state["th_packets"]),
        "unique_destinations": int(st.session_state["th_destinations"]),
        "unique_ports": int(st.session_state["th_ports"]),
        "icmp_packets": int(st.session_state["th_icmp"]),
        "dns_packets": int(st.session_state["th_dns"]),
        "repeated_pair_packets": int(st.session_state["th_pair"]),
    }

def get_attack_thresholds() -> dict:
    return {
        "scan_ports": int(st.session_state["adv_scan_ports"]),
        "scan_hosts": int(st.session_state["adv_scan_hosts"]),
        "syn_packets_per_10s": int(st.session_state["adv_syn"]),
        "packets_per_10s": int(st.session_state["adv_flood"]),
        "dns_suspicious_names": int(st.session_state["adv_dns"]),
        "beacon_min_events": int(st.session_state["adv_beacon"]),
        "lateral_destinations": int(st.session_state["adv_lateral"]),
        "exfil_bytes": int(st.session_state["adv_exfil_mb"]) * 1024 * 1024,
    }

with st.sidebar:
    st.header("Traffic source")
    for label, path in SAMPLES.items():
        if st.button(f"Load {label}", use_container_width=True, key=f"sample_{label}"):
            st.session_state["demo_bytes"] = path.read_bytes()
            st.session_state["demo_name"] = path.name
            st.session_state.pop("uploaded_bytes", None)
    if st.button("Clear selected data", use_container_width=True):
        st.session_state.pop("demo_bytes", None)
        st.session_state.pop("demo_name", None)
        st.session_state.pop("uploaded_bytes", None)
        st.rerun()

    st.divider()
    st.header("Detection thresholds")
    st.caption("Educational defaults; tune for your environment.")
    st.number_input("Packets per source", 1, 10_000_000, DEFAULT_THRESHOLDS["packets_per_source"], key="th_packets")
    st.number_input("Unique destination IPs", 1, 1_000_000, DEFAULT_THRESHOLDS["unique_destinations"], key="th_destinations")
    st.number_input("Unique destination ports", 1, 65_535, DEFAULT_THRESHOLDS["unique_ports"], key="th_ports")
    st.number_input("ICMP packets per source", 1, 10_000_000, DEFAULT_THRESHOLDS["icmp_packets"], key="th_icmp")
    st.number_input("DNS packets per source", 1, 10_000_000, DEFAULT_THRESHOLDS["dns_packets"], key="th_dns")
    st.number_input("Packets per source-destination pair", 1, 10_000_000, DEFAULT_THRESHOLDS["repeated_pair_packets"], key="th_pair")
    with st.expander("Advanced detector thresholds"):
        st.caption("Rate-based thresholds require valid timestamps. Defaults are illustrative, not universal.")
        st.number_input("Ports per source-target", 1, 65535, DEFAULT_ATTACK_THRESHOLDS["scan_ports"], key="adv_scan_ports")
        st.number_input("Hosts per source/window", 1, 100000, DEFAULT_ATTACK_THRESHOLDS["scan_hosts"], key="adv_scan_hosts")
        st.number_input("SYN-like rows per 10 seconds", 1, 1000000, DEFAULT_ATTACK_THRESHOLDS["syn_packets_per_10s"], key="adv_syn")
        st.number_input("Packets per 10 seconds", 1, 10000000, DEFAULT_ATTACK_THRESHOLDS["packets_per_10s"], key="adv_flood")
        st.number_input("Suspicious DNS names", 1, 1000, DEFAULT_ATTACK_THRESHOLDS["dns_suspicious_names"], key="adv_dns")
        st.number_input("Events for beaconing", 4, 1000, DEFAULT_ATTACK_THRESHOLDS["beacon_min_events"], key="adv_beacon")
        st.number_input("Internal admin-service destinations", 1, 1000, DEFAULT_ATTACK_THRESHOLDS["lateral_destinations"], key="adv_lateral")
        st.number_input("Outbound transfer threshold (MB)", 1, 10000, DEFAULT_ATTACK_THRESHOLDS["exfil_bytes"] // (1024 * 1024), key="adv_exfil_mb")
    if st.button("Reset thresholds"):
        for key in ("th_packets", "th_destinations", "th_ports", "th_icmp", "th_dns", "th_pair", "adv_scan_ports", "adv_scan_hosts", "adv_syn", "adv_flood", "adv_dns", "adv_beacon", "adv_lateral", "adv_exfil_mb"):
            st.session_state.pop(key, None)
        st.rerun()

    st.divider()
    st.header("Optional Groq AI")
    ai_enabled = st.checkbox(
        "Enable AI for this session",
        value=False,
        key="ai_enabled",
        help="Checking this does not send a request. You must also click an AI action.",
    )
    st.caption(f"Model: `{MODEL_NAME}`")
    if ai_enabled and not get_groq_api_key():
        st.warning("No Groq API key found. Configure GROQ_API_KEY in Streamlit secrets or your environment.")

upload = st.file_uploader(
    "Upload Wireshark packet-list CSV",
    type=["csv"],
    help=f"Maximum size: {MAX_UPLOAD_BYTES // (1024 * 1024)} MB.",
)
if upload is not None:
    st.session_state["uploaded_bytes"] = upload.getvalue()
    st.session_state.pop("demo_bytes", None)
    st.session_state.pop("demo_name", None)

data = None
filename = None
if st.session_state.get("uploaded_bytes") is not None:
    data, filename = st.session_state["uploaded_bytes"], upload.name if upload else "uploaded.csv"
elif st.session_state.get("demo_bytes") is not None:
    data, filename = st.session_state["demo_bytes"], st.session_state.get("demo_name", "sample.csv")

if data is None:
    st.markdown("""
    ### Quick start
    Use a sample dataset in the sidebar, or upload a Wireshark CSV.

    In Wireshark, stop the capture and use the File menu's packet-dissections export option to export the packet list as CSV. Menu wording can vary by version.
    """)
    st.stop()

st.caption(f"Active file: {filename}")
try:
    parsed = parse_csv_bytes(data)
except ValueError as exc:
    st.error(str(exc))
    st.stop()

df = parsed.frame
for warning in parsed.warnings:
    st.warning(warning)
if parsed.missing_fields:
    st.warning("Missing columns: " + ", ".join(parsed.missing_fields) + ". Some rules will be unavailable.")
if df.empty:
    st.error("No usable rows were found in this CSV.")
    st.stop()

summary = build_summary(df)
thresholds = get_thresholds()
alerts, rule_status = run_detections(df, thresholds)
attack_alerts, attack_status = run_attack_detections(df, get_attack_thresholds())
# Prefer richer, source-target/time-window findings when they duplicate an original rule.
advanced_port_pairs = {(a.get("source"), a.get("destination")) for a in attack_alerts if a["rule"] == "Possible port scan"}
advanced_host_sources = {a.get("source") for a in attack_alerts if a["rule"] == "Possible host discovery"}
advanced_syn_sources = {a.get("source") for a in attack_alerts if a["rule"] == "TCP SYN burst indicator"}
base_alerts = []
for alert in alerts:
    duplicate_port = alert["rule"] == "Possible port scanning" and (alert.get("source"), alert.get("destination")) in advanced_port_pairs
    duplicate_host = alert["rule"] == "Possible host scanning" and alert.get("source") in advanced_host_sources
    duplicate_syn = alert["rule"] == "TCP SYN-heavy activity" and alert.get("source") in advanced_syn_sources
    if not (duplicate_port or duplicate_host or duplicate_syn):
        base_alerts.append(alert)
all_alerts = base_alerts + attack_alerts
all_status = {**rule_status, **attack_status}
score = investigation_score(all_alerts)

st.subheader("Traffic overview")
cols = st.columns(4)
cols[0].metric("Packets", f"{summary['total_packets']:,}")
cols[1].metric("Unique sources", f"{summary['unique_sources']:,}")
cols[2].metric("Unique destinations", f"{summary['unique_destinations']:,}")
cols[3].metric("Average packet length", f"{summary['average_length']:.1f} bytes" if summary["average_length"] is not None else "Unavailable")

left, right = st.columns(2)
with left:
    st.markdown("#### Top source hosts")
    if not summary["top_sources"].empty:
        st.bar_chart(summary["top_sources"].set_index("Source")["Packets"])
        st.dataframe(summary["top_sources"], hide_index=True, use_container_width=True)
    else:
        st.info("Source column unavailable.")
with right:
    st.markdown("#### Top destinations")
    if not summary["top_destinations"].empty:
        st.bar_chart(summary["top_destinations"].set_index("Destination")["Packets"])
        st.dataframe(summary["top_destinations"], hide_index=True, use_container_width=True)
    else:
        st.info("Destination column unavailable.")

st.markdown("#### Protocol distribution")
if not summary["protocol_distribution"].empty:
    st.bar_chart(summary["protocol_distribution"].set_index("Protocol")["Packets"])
    st.dataframe(summary["protocol_distribution"], hide_index=True, use_container_width=True)
else:
    st.info("Protocol column unavailable.")

st.subheader("Detection results")
a, b = st.columns([1, 3])
a.metric("Investigation score", score["total"])
b.markdown(f"**Triage label:** {score['label']}")
st.caption("This score is a triage aid, not a probability of maliciousness.")
if score["factors"]:
    st.dataframe(pd.DataFrame(score["factors"]), hide_index=True, use_container_width=True)
else:
    st.success("No configured thresholds were exceeded in the available fields.")

with st.expander("Rule and detector availability"):
    st.json(all_status)

st.subheader("Advanced attack-pattern findings")
st.caption("These are heuristic indicators, not determinations that an attack succeeded.")
if attack_alerts:
    categories = pd.Series([a.get("attack_category", a["rule"]) for a in attack_alerts]).value_counts()
    st.dataframe(categories.rename_axis("Attack pattern / category").reset_index(name="Findings"), hide_index=True, use_container_width=True)
    for i, alert in enumerate(attack_alerts):
        with st.expander(f"[{alert['severity']}] {alert['rule']} — {alert.get('source') or 'source unavailable'}"):
            st.write("**Evidence:**", alert["evidence"])
            st.write("**Observed:**", alert["observed"])
            st.write("**Threshold / condition:**", alert["threshold"])
            st.write("**Why it matters:**", alert["why_it_matters"])
            st.write("**Benign explanations:**", alert["benign_explanations"])
            st.write("**Interpretation note:**", alert.get("confidence_note", "Pattern-based indicator; not proof of an attack."))
            st.write("**Next steps:**")
            for step in alert["investigation_steps"]:
                st.write(f"- {step}")
else:
    st.info("No advanced attack-pattern indicators matched the current sample and thresholds. This does not mean the traffic is guaranteed benign.")

severity_choices = ["High", "Medium", "Low"]
severity_filter = st.multiselect("Filter severity", severity_choices, default=severity_choices)
source_filter = st.text_input("Filter source IP")
destination_filter = st.text_input("Filter destination IP")
query = st.text_input("Search alert evidence")
visible_alerts = []
for alert in all_alerts:
    if alert["severity"] not in severity_filter:
        continue
    if source_filter and source_filter.lower() not in str(alert.get("source") or "").lower():
        continue
    if destination_filter and destination_filter.lower() not in str(alert.get("destination") or "").lower():
        continue
    if query and query.lower() not in " ".join(str(alert.get(k, "")) for k in ("rule", "evidence", "observed")).lower():
        continue
    visible_alerts.append(alert)

if not visible_alerts:
    st.info("No alerts match the selected filters.")
for i, alert in enumerate(visible_alerts):
    title = f"[{alert['severity']}] {alert['rule']} — {alert.get('source') or 'source unavailable'}"
    with st.expander(title, expanded=(i == 0)):
        st.write("**Evidence:**", alert["evidence"])
        st.write("**Observed:**", alert["observed"])
        st.write("**Threshold:**", alert["threshold"])
        st.write("**Why it matters:**", alert["why_it_matters"])
        st.write("**Possible benign causes:**", alert["benign_explanations"])
        st.write("**Investigation steps:**")
        for step in alert["investigation_steps"]:
            st.write(f"- {step}")
        if st.button("Generate AI explanation", key=f"explain_{i}", disabled=not ai_enabled):
            if not get_groq_api_key():
                st.error("Configure GROQ_API_KEY before requesting AI output.")
            else:
                with st.spinner("Generating explanation…"):
                    try:
                        st.session_state[f"explanation_{i}"] = explain_alert(alert, summary)
                    except Exception as exc:
                        st.error(f"Groq request failed: {exc}")
        if st.session_state.get(f"explanation_{i}"):
            st.markdown("**AI explanation (advisory):**")
            st.markdown(st.session_state[f"explanation_{i}"])

st.subheader("Optional Suricata / Zeek log integration")
st.caption("Import existing logs for correlation. This does not run the Suricata or Zeek engine inside Streamlit.")
security_log = st.file_uploader(
    "Upload Suricata EVE JSON/JSONL or Zeek TSV log",
    type=["json", "jsonl", "log", "tsv"],
    key="security_log_upload",
    help="Supported inputs: Suricata EVE JSON Lines, or Zeek logs containing a #fields header.",
)
if security_log is not None:
    try:
        imported = parse_security_log_bytes(security_log.getvalue(), security_log.name)
        st.success(f"Parsed {imported['format']} input.")
        for warning in imported.get("warnings", []):
            st.warning(warning)
        imported_alerts = imported.get("alerts", [])
        imported_frame = imported.get("frame", pd.DataFrame())
        if not imported_frame.empty:
            st.write("**Normalized log records (preview)**")
            st.dataframe(imported_frame.head(100), hide_index=True, use_container_width=True)
            if imported["format"] == "Zeek TSV":
                zeek_rules, _ = run_detections(imported_frame, thresholds)
                zeek_advanced, _ = run_attack_detections(imported_frame, get_attack_thresholds())
                imported_alerts = zeek_rules + zeek_advanced
        if imported_alerts:
            st.write(f"**Imported findings: {len(imported_alerts)}**")
            for i, ext_alert in enumerate(imported_alerts[:200]):
                with st.expander(f"[{ext_alert.get('severity', 'Medium')}] {ext_alert.get('rule', 'Imported finding')} — {ext_alert.get('source') or 'source unavailable'}"):
                    st.write("**Evidence:**", ext_alert.get("evidence", "Not supplied"))
                    st.write("**Observed:**", ext_alert.get("observed", "Not supplied"))
                    st.write("**Interpretation:**", ext_alert.get("why_it_matters", "Validate the original log and surrounding context."))
                    st.write("**Next steps:**")
                    for step in ext_alert.get("investigation_steps", []):
                        st.write(f"- {step}")
        else:
            st.info("No imported IDS alerts or heuristic findings were generated from this log. Check the supported fields and log coverage.")
    except ValueError as exc:
        st.error(str(exc))

st.subheader("Optional AI report")
st.write("The report uses computed statistics and alert metadata only. No raw packet rows are included.")
if st.button("Generate AI report", type="primary", disabled=not ai_enabled):
    if not get_groq_api_key():
        st.error("Configure GROQ_API_KEY before requesting AI output.")
    else:
        with st.spinner("Generating report…"):
            try:
                st.session_state["ai_report"] = generate_report(summary, all_alerts, score, {**thresholds, **get_attack_thresholds()})
            except Exception as exc:
                st.error(f"Groq report request failed: {exc}")
if st.session_state.get("ai_report"):
    st.markdown(st.session_state["ai_report"])
    st.download_button("Download report (.md)", st.session_state["ai_report"], "network-traffic-triage-report.md", "text/markdown")

with st.expander("Analyst workflow and limitations"):
    st.markdown("""
    1. Observe the evidence before forming a conclusion.
    2. Identify the source, destination, protocol, and time context.
    3. Check whether the activity is expected for the environment.
    4. Correlate with endpoint, DNS, firewall, authentication, and application logs.
    5. Document what is known, what is suspected, and what remains unverified.

    CSV exports may omit details available in PCAP/PCAPNG. Encryption limits payload visibility. NAT can complicate attribution. Thresholds vary by environment. This educational tool does not perform malware analysis or automatically block traffic.
    """)
st.caption("Educational use only. Alerts are not proof of compromise.")
