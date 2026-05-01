from __future__ import annotations

from dataclasses import dataclass, asdict
from typing import Any, Dict, Optional, Tuple

from utils import now_str


@dataclass(frozen=True)
class PacketInfo:
    time: str
    src_ip: str
    dst_ip: str
    protocol: str
    port: str  # keep as string for "sport→dport" or "-"
    payload: str

    def to_dict(self) -> Dict[str, str]:
        return asdict(self)


def _safe_getattr(obj: Any, name: str, default: Any = None) -> Any:
    try:
        return getattr(obj, name)
    except Exception:
        return default


def analyze_packet(pkt: Any) -> PacketInfo:
    """
    Extract basic metadata (best-effort):
      - Source IP / Destination IP
      - Protocol (TCP/UDP/ICMP/DNS/Other)
      - Port numbers (sport→dport when available)
    Returns a structured PacketInfo.
    """
    time_s = now_str()
    src_ip = "-"
    dst_ip = "-"
    protocol = "Other"
    port = "-"
    payload = "Encrypted / Binary Data"

    # Lazy import scapy layers so the module can be imported even if scapy isn't installed yet.
    try:
        from scapy.layers.inet import IP, TCP, UDP, ICMP
        from scapy.layers.dns import DNS
        from scapy.packet import Raw
    except Exception:
        # If scapy isn't available, we can still return a minimal record.
        return PacketInfo(time=time_s, src_ip=src_ip, dst_ip=dst_ip, protocol=protocol, port=port, payload=payload)

    if pkt is None:
        return PacketInfo(time=time_s, src_ip=src_ip, dst_ip=dst_ip, protocol=protocol, port=port, payload=payload)

    if pkt.haslayer(IP):
        ip = pkt.getlayer(IP)
        src_ip = _safe_getattr(ip, "src", "-") or "-"
        dst_ip = _safe_getattr(ip, "dst", "-") or "-"

    # Protocol detection order: DNS over UDP/TCP -> mark as DNS; else TCP/UDP/ICMP.
    if pkt.haslayer(DNS):
        protocol = "DNS"
    elif pkt.haslayer(TCP):
        protocol = "TCP"
    elif pkt.haslayer(UDP):
        protocol = "UDP"
    elif pkt.haslayer(ICMP):
        protocol = "ICMP"

    # Ports
    if pkt.haslayer(TCP):
        t = pkt.getlayer(TCP)
        sport = _safe_getattr(t, "sport", None)
        dport = _safe_getattr(t, "dport", None)
        if sport is not None or dport is not None:
            port = f"{sport or '-'}→{dport or '-'}"
    elif pkt.haslayer(UDP):
        u = pkt.getlayer(UDP)
        sport = _safe_getattr(u, "sport", None)
        dport = _safe_getattr(u, "dport", None)
        if sport is not None or dport is not None:
            port = f"{sport or '-'}→{dport or '-'}"

    # Payload extraction (safe + bounded for UI responsiveness)
    if pkt.haslayer(Raw):
        raw_layer = pkt.getlayer(Raw)
        raw_bytes = _safe_getattr(raw_layer, "load", b"") or b""
        try:
            decoded = raw_bytes.decode("utf-8", errors="ignore").strip()
        except Exception:
            decoded = ""

        if decoded:
            # Keep printable subset and trim aggressively to avoid huge GUI updates.
            cleaned = "".join(ch if ch.isprintable() else " " for ch in decoded)
            cleaned = " ".join(cleaned.split())
            if cleaned:
                MAX_PAYLOAD_LEN = 80
                payload = cleaned[:MAX_PAYLOAD_LEN]
                if len(cleaned) > MAX_PAYLOAD_LEN:
                    payload += "..."

    return PacketInfo(time=time_s, src_ip=src_ip, dst_ip=dst_ip, protocol=protocol, port=port, payload=payload)
