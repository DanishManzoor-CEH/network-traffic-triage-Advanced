from __future__ import annotations

from dataclasses import dataclass
import io
import re
import pandas as pd

MAX_UPLOAD_BYTES = 10 * 1024 * 1024
MAX_ROWS = 250_000

ALIASES = {
    "source": {"source", "sourceip", "src", "ipsrc", "sourceaddress", "srcip"},
    "destination": {"destination", "destinationip", "dst", "ipdst", "destinationaddress", "dstip"},
    "protocol": {"protocol", "proto", "wscolprotocol"},
    "length": {"length", "len", "packetlength", "framelen", "framelength"},
    "info": {"info", "details", "packetinfo", "summary"},
    "timestamp": {"time", "timestamp", "datetime", "frametime"},
    "tcp_flags": {"tcpflags", "flags", "tcpflag", "tcpflagsraw"},
    "source_port": {"sourceport", "srcport", "sport", "ipsrcport", "tcpsrcport", "udpsrcport"},
    "destination_port": {"destinationport", "dstport", "dport", "ipdstport", "tcpdstport", "udpdstport"},
    "domain": {"domain", "query", "dnsquery", "qname", "queryname", "rrname"},
}

@dataclass
class ParseResult:
    frame: pd.DataFrame
    ok: bool
    warnings: list[str]
    missing_fields: list[str]

def _normalise_name(value: object) -> str:
    return re.sub(r"[^a-z0-9]", "", str(value).strip().lower())

def parse_csv_bytes(data: bytes) -> ParseResult:
    if not isinstance(data, (bytes, bytearray)):
        raise ValueError("Input must be file bytes.")
    if not data:
        raise ValueError("The uploaded file is empty.")
    if len(data) > MAX_UPLOAD_BYTES:
        raise ValueError(f"File exceeds the {MAX_UPLOAD_BYTES // (1024 * 1024)} MB limit.")
    warnings: list[str] = []
    try:
        frame = pd.read_csv(io.BytesIO(data), dtype=str, keep_default_na=False, encoding="utf-8-sig", on_bad_lines="skip")
    except UnicodeDecodeError:
        try:
            frame = pd.read_csv(io.BytesIO(data), dtype=str, keep_default_na=False, encoding="latin-1", on_bad_lines="skip")
            warnings.append("The file was decoded with a fallback text encoding.")
        except Exception as exc:
            raise ValueError("CSV could not be decoded or parsed.") from exc
    except Exception as exc:
        raise ValueError("CSV could not be parsed. Check the export format and header row.") from exc

    if len(frame) > MAX_ROWS:
        frame = frame.iloc[:MAX_ROWS].copy()
        warnings.append(f"Only the first {MAX_ROWS:,} rows were analysed to protect app resources.")
    if len(frame.columns) == 0:
        raise ValueError("The file does not contain a CSV header row.")

    renames, used = {}, set()
    for col in frame.columns:
        norm = _normalise_name(col)
        for canonical, aliases in ALIASES.items():
            if norm in aliases and canonical not in used:
                renames[col] = canonical
                used.add(canonical)
                break
    frame = frame.rename(columns=renames)
    for col in frame.columns:
        frame[col] = frame[col].astype(str).str.strip()

    required = {"source": "Source", "destination": "Destination", "protocol": "Protocol"}
    missing = [label for col, label in required.items() if col not in frame.columns]
    for label in missing:
        warnings.append(f"No {label} column was detected; related rules or metrics may be unavailable.")
    if "info" not in frame.columns:
        warnings.append("No Info/details column was detected; explicit port parsing may be unavailable.")
    return ParseResult(frame=frame, ok=True, warnings=warnings, missing_fields=missing)
