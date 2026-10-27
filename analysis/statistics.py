from __future__ import annotations
import pandas as pd

def _protocol_group(value: object) -> str:
    text = str(value).strip().upper()
    for name, markers in {
        "TCP": ("TCP",), "UDP": ("UDP",), "DNS": ("DNS",), "ICMP": ("ICMP",),
        "ARP": ("ARP",), "HTTP": ("HTTP",), "HTTPS/TLS": ("TLS", "HTTPS", "SSL"),
    }.items():
        if text == name or any(text.startswith(marker) for marker in markers):
            return name
    return text or "Unknown"

def build_summary(df: pd.DataFrame) -> dict:
    src = df["source"].replace("", pd.NA) if "source" in df.columns else pd.Series(dtype="string")
    dst = df["destination"].replace("", pd.NA) if "destination" in df.columns else pd.Series(dtype="string")
    src_counts = src.dropna().value_counts()
    dst_counts = dst.dropna().value_counts()
    protocols = df["protocol"].map(_protocol_group).value_counts() if "protocol" in df.columns else pd.Series(dtype="int64")
    avg_len = None
    if "length" in df.columns:
        nums = pd.to_numeric(df["length"].str.replace(",", "", regex=False), errors="coerce").dropna()
        if not nums.empty:
            avg_len = float(nums.mean())
    return {
        "total_packets": int(len(df)),
        "unique_sources": int(src.dropna().nunique()),
        "unique_destinations": int(dst.dropna().nunique()),
        "most_active_source": str(src_counts.index[0]) if len(src_counts) else None,
        "most_contacted_destination": str(dst_counts.index[0]) if len(dst_counts) else None,
        "most_common_protocol": str(protocols.index[0]) if len(protocols) else None,
        "average_length": avg_len,
        "top_sources": src_counts.head(10).rename_axis("Source").reset_index(name="Packets"),
        "top_destinations": dst_counts.head(10).rename_axis("Destination").reset_index(name="Packets"),
        "protocol_distribution": protocols.rename_axis("Protocol").reset_index(name="Packets"),
        "source_counts": {str(k): int(v) for k, v in src_counts.head(10).items()},
        "destination_counts": {str(k): int(v) for k, v in dst_counts.head(10).items()},
        "protocol_counts": {str(k): int(v) for k, v in protocols.items()},
    }
