from __future__ import annotations

import csv
import os
from typing import Dict, Iterable, Optional

from utils import app_dir


LOG_FILENAME = "captured_data.log"


def log_path() -> str:
    return os.path.join(app_dir(), LOG_FILENAME)


def ensure_logfile_exists() -> None:
    path = log_path()
    if not os.path.exists(path):
        with open(path, "w", encoding="utf-8") as f:
            f.write("Time | Source IP | Destination IP | Protocol | Port | Payload\n")


def write_log_line(packet_dict: Dict[str, str]) -> None:
    """
    Append one packet line to `captured_data.log`.
    Format: Time | Source IP | Destination IP | Protocol | Port | Payload
    """
    ensure_logfile_exists()
    line = (
        f"{packet_dict.get('time', '-')}"
        f" | {packet_dict.get('src_ip', '-')}"
        f" | {packet_dict.get('dst_ip', '-')}"
        f" | {packet_dict.get('protocol', '-')}"
        f" | {packet_dict.get('port', '-')}"
        f" | {packet_dict.get('payload', '-')}\n"
    )
    with open(log_path(), "a", encoding="utf-8") as f:
        f.write(line)


def export_csv(rows: Iterable[Dict[str, str]], out_path: str) -> str:
    """
    Export current table rows to CSV.
    Returns the output path.
    """
    fieldnames = ["time", "src_ip", "dst_ip", "protocol", "port", "payload"]
    with open(out_path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        for r in rows:
            w.writerow({k: r.get(k, "-") for k in fieldnames})
    return out_path


def export_pcap(packets: list, out_path: str) -> str:
    """
    Export captured raw Scapy packets to a PCAP file.
    """
    try:
        from scapy.utils import wrpcap
    except Exception as e:
        raise RuntimeError("Scapy is required for PCAP export. Install: pip install scapy") from e

    wrpcap(out_path, packets)
    return out_path
