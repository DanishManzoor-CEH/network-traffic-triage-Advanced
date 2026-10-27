# Network Traffic Triage Tool

An educational Streamlit app that analyses Wireshark packet-list CSV exports using deterministic, explainable rules. Optional Groq AI explanations and Markdown reports are generated only after the user enables AI and explicitly clicks an AI action.

## Features

- CSV upload, validation, and common Wireshark column normalization.
- Packet totals, unique hosts, average packet length, protocol distribution, top sources and destinations.
- Rules for high packet volume, possible host scanning, explicit destination-port variety, ICMP/DNS activity, repeated source-destination communication, and conditional SYN-heavy activity.
- Configurable thresholds, alert filters, evidence, benign explanations, and suggested investigation steps.
- Original traffic samples plus synthetic attack-pattern datasets for scanning, SYN bursts, DNS tunneling indicators, beaconing, lateral movement, outbound transfer, and visible web request indicators.
- Advanced attack-pattern detections with configurable thresholds, timestamp-aware windows, evidence, benign explanations, and explicit limitations.
- Optional import of Suricata EVE JSONL alerts and Zeek TSV logs; the app imports existing logs and does not run either engine itself.
- Optional Groq model `openai/gpt-oss-120b` for alert explanations and report generation.
- No database or intentional disk persistence of uploaded packet rows.

## Privacy boundary

The AI helper uses an allow-list of aggregate statistics and alert metadata. It never receives the raw DataFrame or raw packet rows. Attack alerts avoid embedding raw web request text in their metadata; source/destination identifiers and selected alert evidence may still be included when AI is explicitly requested. AI is opt-in: checking the box does not send a request; a user must click an explanation or report button. When AI is requested, selected summaries and alert metadata are sent to Groq.

On Streamlit Community Cloud, uploaded CSV data is processed on the hosting server. For strict local-only processing, run locally and keep AI disabled. Only analyse traffic you own or are authorised to monitor.

## Python and dependencies

Recommended environment: **Python 3.12 (64-bit)** on Windows and Python 3.12 in Streamlit Community Cloud. The project pins:

- `streamlit==1.65.0`
- `pandas==3.0.6`
- `groq==1.7.0`
- `pytest==8.4.2`

`runtime.txt` requests Python 3.12. Verify the selected version in Streamlit Cloud's Advanced settings; deployment UI options can change over time.

## Local Windows setup

1. Install Python 3.12 from https://www.python.org/downloads/ and enable **Add Python to PATH**.
2. Download/extract this repository and open a terminal in its root folder.
3. Verify Python:

   ```powershell
   py -3.12 --version
   ```

4. Create and activate a virtual environment:

   ```powershell
   py -3.12 -m venv .venv
   .\.venv\Scripts\Activate.ps1
   ```

   In Command Prompt use `.venv\Scripts\activate.bat`.

5. Install dependencies and run tests:

   ```powershell
   python -m pip install --upgrade pip
   pip install -r requirements.txt
   python -m pytest -q
   ```

6. Start Streamlit:

   ```powershell
   python -m streamlit run app.py
   ```

7. Open the local URL printed in the terminal, normally `http://localhost:8501`. Use the sample buttons before uploading real data. The sidebar includes normal traffic, the original anomaly labs, individual advanced attack-pattern labs, and a combined attack-pattern lab.

## Configure Groq locally

1. Create an API key at https://console.groq.com/keys .
2. Copy `.streamlit/secrets.toml.example` to `.streamlit/secrets.toml`.
3. Replace the placeholder:

   ```toml
   GROQ_API_KEY = "gsk_your_real_key_here"
   GROQ_MODEL = "openai/gpt-oss-120b"
   ```

4. Restart Streamlit, enable AI in the sidebar, and click an AI explanation or report button.
5. Never put a real key in source code, screenshots, or GitHub. `.gitignore` excludes `.streamlit/secrets.toml`.

## Push to GitHub

Create an empty repository at https://github.com/new, then from the project root run:

```powershell
git init
git add .
git status
```

Inspect the staged files. Ensure `.streamlit/secrets.toml` and any real API key are not staged. Then:

```powershell
git commit -m "Build network traffic triage tool"
git branch -M main
git remote add origin https://github.com/YOUR-USERNAME/network-traffic-triage.git
git push -u origin main
```

Replace the example repository URL with your own. If you already have a Git repository, use the existing remote rather than adding a duplicate.

## Deploy to Streamlit Community Cloud

1. Push the project to GitHub.
2. Visit https://share.streamlit.io/ and sign in with GitHub.
3. Choose **Create app**, select your repository and `main` branch, and set the main file path to `app.py`.
4. Open **Advanced settings** and select Python 3.12.
5. In **Secrets**, add TOML with your real key:

   ```toml
   GROQ_API_KEY = "gsk_your_real_key_here"
   GROQ_MODEL = "openai/gpt-oss-120b"
   ```

6. Deploy and inspect build logs if there is an error.
7. Test the sample datasets: normal traffic, port scan, host discovery, DNS anomaly, ICMP sweep, TCP SYN burst, repeated connections, and combined SOC lab. To test AI, enable it and click an AI action.
8. For future updates, push commits to GitHub; Streamlit Community Cloud normally redeploys from the connected branch.

Official guide: https://docs.streamlit.io/deploy/streamlit-community-cloud/deploy-your-app/deploy

## Included synthetic anomaly samples

All files in `samples/` are synthetic training/demo data, not captured real-world traffic. Use the sidebar buttons to load them:

| Sample | Designed to exercise | Expected default detection (if fields are parsed as provided) |
|---|---|---|
| `port-scan-lab.csv` | Many destination ports on one host | Possible port scanning |
| `host-discovery-lab.csv` | One source contacting many destination IPs | Possible host scanning |
| `dns-anomaly-lab.csv` | DNS burst from one source | High DNS activity |
| `icmp-sweep-lab.csv` | High ICMP volume and multiple destinations | High ICMP activity; possible host scanning |
| `syn-burst-lab.csv` | More than 50 SYN-like rows without ACK | TCP SYN-heavy activity; high packet volume |
| `repeated-connection-lab.csv` | More than 40 packets for one source/destination pair | Repeated source-to-destination communication |
| `combined-anomaly-soc-lab.csv` | Multiple patterns in one dataset | Several alerts across the rules above |

These are rule-triggering examples, not proof of maliciousness. A real production deployment should tune thresholds to its baseline and validate flags and columns against the actual Wireshark export.

## Wireshark CSV export

1. Open Wireshark and capture traffic in an authorised environment.
2. Stop the capture.
3. Use the File menu's packet-dissections export option and choose CSV (wording varies by version).
4. Include available columns such as Source, Destination, Protocol, Length, and Info.
5. Upload the exported packet list CSV.

## Detection rules

All rules use strict greater-than comparisons. Defaults are educational examples, not universal security thresholds.

| Rule | Default threshold | Caveat |
|---|---:|---|
| High packet volume | >50 packets per source | Busy services may exceed this. |
| Possible host scanning | >10 unique destinations per source | Asset discovery and monitoring may trigger it. |
| Possible port scanning | >10 explicit destination ports per destination | Requires recognized port labels in Info. |
| High ICMP activity | >30 ICMP packets per source | Diagnostics may trigger it. |
| High DNS activity | >30 DNS packets per source | Busy clients and retries may trigger it. |
| Repeated source-destination communication | >40 packets per pair | Normal application traffic may trigger it. |
| TCP SYN-heavy activity | >50 SYN-like rows per source | CSV flag parsing is approximate and requires explicit SYN strings. |

The investigation score counts each distinct triggered rule once and caps at 100. It is not a probability or confidence percentage.

## Limitations

- CSV exports can omit details present in PCAP/PCAPNG.
- Encryption limits payload visibility.
- Thresholds need environmental tuning.
- NAT can complicate attribution.
- Protocol labels and flag strings depend on export columns and Wireshark interpretation.
- No malware analysis, autonomous blocking, or threat-intelligence enrichment is implemented.
- AI output can be wrong or incomplete; validate it against evidence and other telemetry.

## License

No license is selected in this starter repository. Add a complete license before granting others reuse rights.


## Advanced attack-pattern detection

The advanced engine is in `analysis/attack_detection.py`. It runs alongside the original `analysis/rules.py` engine; the original dashboard, filters, investigation score, and optional AI features remain in place.

| Detector | Evidence used | Important limitation |
|---|---|---|
| Source-target-scoped port scan | Distinct destination ports grouped by source and target | Requires explicit destination-port labels/column; scan intent is not established. |
| Time-windowed host discovery | Distinct destinations per source in 60-second windows | Without valid timestamps, it falls back to whole-capture counts and labels the limitation. |
| Flooding indicator | Packets per source per 10-second window | A rate spike can be legitimate; this is not a DDoS attribution system. |
| TCP SYN burst indicator | SYN-like rows without ACK per 10-second window | TCP flag formats vary; validate against the source export and inspect responses. |
| DNS tunneling indicator | Multiple long, high-entropy DNS labels from a source | Generated domains, CDNs, and analytics can look similar; this is a heuristic only. |
| Periodic outbound communication | Repeated source-target events with regular timestamp intervals | Scheduled jobs and monitoring can also be periodic; no C2 conclusion is made. |
| Lateral movement indicator | Internal source reaches multiple internal destinations on common admin/service ports | Requires destination-port evidence; IT management can trigger it. |
| Large outbound transfer | Sum of packet lengths from private source to non-private destination | Packet length totals are not application payload bytes and do not prove data theft. |
| Suspicious web request pattern | Visible HTTP request text matching traversal/injection-like markers | HTTPS encryption and limited CSV fields often hide request payloads; a match does not prove exploit success. |

Advanced thresholds can be adjusted in the sidebar. Rate-based detections require usable timestamps. If the required fields are missing, the app reports the limitation instead of claiming that the behavior was absent.

### Suricata / Zeek import

Use **Optional Suricata / Zeek log integration** below the findings in the app to upload either:

- **Suricata EVE JSON Lines** (`.jsonl` or JSON event lines): alert events are normalized and displayed with signature, category, severity, and available flow metadata.
- **Zeek TSV logs** (`.log` / `.tsv` with a `#fields` header): connection fields are normalized and passed through the built-in detection engines.

This is a log-import integration, not an embedded IDS process. To generate these logs, install and configure Suricata or Zeek separately in an authorised lab or monitoring environment. The app does not start captures, execute IDS commands, or automatically block traffic. Suricata signatures and Zeek logs still require validation in context.

### New synthetic attack-pattern samples

| Sample | Intended exercise |
|---|---|
| `attack-port-scan.csv` | One source probing many destination ports on one target |
| `attack-syn-burst.csv` | SYN-like rows concentrated in a short interval |
| `attack-dns-tunnel-indicator.csv` | Several long/high-entropy DNS query labels |
| `attack-beaconing-indicator.csv` | Regular communication at 60-second intervals |
| `attack-lateral-movement-indicator.csv` | One internal host contacting multiple internal hosts on admin/service ports |
| `attack-outbound-transfer-indicator.csv` | Large aggregate packet-length volume from a private source to an external destination |
| `attack-web-indicator.csv` | Visible traversal, SQL injection-like, and script injection-like request markers |
| `attack-patterns-combined-lab.csv` | Combined scenarios for reviewing multiple findings together |
| `suricata-eve-sample.jsonl` | Synthetic Suricata EVE alert events for import testing |
| `zeek-conn-sample.log` | Synthetic Zeek connection log for normalization testing |

All these samples are synthetic and designed to exercise specific rules. They are not evidence that the patterns always indicate attacks in real networks.

### Run tests

```powershell
python -m pytest -q
```

Tests cover the original parser and thresholds, source-target scan scoping, each new detector, benign web traffic, missing timestamps, and Suricata/Zeek import. For production use, add representative authorised captures and tune thresholds to the environment.
