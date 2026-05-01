from __future__ import annotations

import os
import queue
import tempfile
import threading
import tkinter as tk
from tkinter import messagebox, ttk, filedialog, simpledialog
import webbrowser
from typing import Any, Dict, List, Optional, Tuple

from analyzer import analyze_packet
from logger import export_csv, export_pcap, write_log_line
from sniffer import PacketSniffer, list_interfaces
from utils import app_dir, now_str


AUTH_USERNAME = "admin"
AUTH_PASSWORD = "admin123"

# ── Theme palette ──
BG_DARK      = "#12121a"   # main window background
BG_CARD      = "#1e1e2f"   # card / panel surfaces
BG_INPUT     = "#2a2a3d"   # input fields
FG_LIGHT     = "#ffffff"   # primary text
FG_MUTED     = "#a0a0b8"   # secondary / muted text

# Functional button colors
BTN_GREEN    = "#00b894"   # start / success
BTN_RED      = "#e74c3c"   # stop / danger
BTN_BLUE     = "#3498db"   # primary action
BTN_CYAN     = "#00cec9"   # secondary export
BTN_PURPLE   = "#a29bfe"   # tertiary export
BTN_DARK     = "#2d2d44"   # neutral / utility

# Protocol accent colors
TCP_COLOR    = "#74b9ff"
UDP_COLOR    = "#55efc4"
ICMP_COLOR   = "#ffeaa7"


def _shade_color(color: str, delta: int) -> str:
    """Adjust hex color brightness."""
    color = color.lstrip("#")
    r = max(0, min(255, int(color[0:2], 16) + delta))
    g = max(0, min(255, int(color[2:4], 16) + delta))
    b = max(0, min(255, int(color[4:6], 16) + delta))
    return f"#{r:02x}{g:02x}{b:02x}"


def _open_project_info() -> None:
    """Open the local Project Info HTML page in the browser.

    Uses pathlib for robust file-URI generation (handles spaces & special chars)
    and falls back to os.startfile on Windows for EXE compatibility.
    """
    from pathlib import Path

    static_path = Path(app_dir()) / "Project_info.html"
    if static_path.exists():
        try:
            _open_html(static_path)
            return
        except Exception as e:
            messagebox.showerror("Project Info Failed", str(e))
            return

    # Fallback: generate a temporary HTML page.
    html = f"""<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <title>Network Packet Sniffer - Project Info</title>
  <style>
    body {{ font-family: Arial, sans-serif; margin: 24px; }}
    .card {{ border: 1px solid #ddd; border-radius: 10px; padding: 18px; max-width: 820px; }}
    h1 {{ margin-top: 0; }}
    code {{ background: #f6f6f6; padding: 2px 6px; border-radius: 6px; }}
  </style>
</head>
<body>
  <div class="card">
    <h1>Network Packet Sniffer with GUI</h1>
    <p><b>Developer</b>: Sreeja</p>
    <p><b>Tech</b>: <code>Python</code>, <code>Scapy</code>, <code>Tkinter</code>, <code>threading</code></p>
    <p><b>Features</b>:</p>
    <ul>
      <li>Real-time packet capture + table view</li>
      <li>Protocol filtering (All/TCP/UDP/ICMP/DNS)</li>
      <li>Logging to <code>captured_data.log</code></li>
      <li>Export as CSV and PCAP</li>
      <li>Basic intrusion detection alerts</li>
    </ul>
    <p><b>Project folder</b>: <code>{app_dir()}</code></p>
  </div>
</body>
</html>
"""
    try:
        tmp = Path(tempfile.gettempdir()) / "project_info_sniffer.html"
        tmp.write_text(html, encoding="utf-8")
        _open_html(tmp)
    except Exception as e:
        messagebox.showerror("Project Info Failed", str(e))


def _open_html(path: "Path") -> None:
    """Open an HTML file in the default browser.

    Tries os.startfile first on Windows (most reliable from EXEs),
    then falls back to webbrowser.
    """
    if os.name == "nt":
        try:
            os.startfile(str(path))
            return
        except Exception:
            pass
    try:
        webbrowser.open_new_tab(path.as_uri())
    except Exception:
        webbrowser.open_new_tab(str(path))


class SnifferGUI:
    """
    Tkinter GUI + controller for:
      - interface selection
      - start/stop sniffing (threaded)
      - real-time table updates
      - filtering
      - logging
      - basic IDS alerts
      - export CSV/PCAP
    """

    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title("Network Packet Sniffer with GUI")
        self.root.geometry("1260x760")
        self.root.minsize(1050, 650)
        self.root.configure(bg=BG_DARK)

        # Thread-safe event queue for UI updates from sniffing thread
        self._ui_queue: "queue.Queue[Tuple[str, Any]]" = queue.Queue()

        # Captured data stores (for export/IDS/stats)
        self._captured_rows: List[Dict[str, str]] = []
        self._captured_packets: List[Any] = []

        # IDS state
        self._src_ip_counts: Dict[str, int] = {}
        self._src_ip_ports: Dict[str, set] = {}

        # Stats
        self._stats = {"TCP": 0, "UDP": 0, "ICMP": 0}

        # Alert control: show only once per capture session.
        self.alert_shown = False

        # Session-only log export details (no packet data).
        self.session_start_time: Optional[str] = None
        self.session_stop_time: Optional[str] = None
        self.session_interface_name: Optional[str] = None

        # Sniffer instance (created on Start with selected interface)
        self.sniffer: Optional[PacketSniffer] = None

        # Cached filter value for background thread (Tk variables are not thread-safe)
        self._filter_value = "All"
        self._filter_lock = threading.Lock()

        # Map dropdown display text -> real interface id used by Scapy/pcap.
        self._iface_display_to_real: Dict[str, str] = {}
        self._iface_display_to_ip: Dict[str, str] = {}

        # Exactly one interface should be labeled as "Wi-Fi" in the dropdown.
        self._selected_wifi_real_iface: Optional[str] = None
        self._selected_wifi_ip: Optional[str] = None

        self._build_ui()
        self._refresh_interfaces()

        # Keep cached filter in sync (main thread)
        self._set_filter_value(self.filter_var.get())
        self.filter_var.trace_add("write", lambda *_: self._set_filter_value(self.filter_var.get()))

        # Periodic UI queue pump for real-time updates
        self.root.after(100, self._drain_ui_queue)

    def _set_filter_value(self, value: str) -> None:
        with self._filter_lock:
            self._filter_value = value or "All"

    def _get_filter_value(self) -> str:
        with self._filter_lock:
            return self._filter_value

    def _build_ui(self) -> None:
        # Root container
        container = tk.Frame(self.root, bg=BG_DARK)
        container.pack(fill=tk.BOTH, expand=True)
        container.grid_columnconfigure(0, weight=1)
        container.grid_rowconfigure(3, weight=1)

        # ═══════════════════════════════════════════════════════
        # Row 0 ── Title + live status dot
        # ═══════════════════════════════════════════════════════
        title_bar = tk.Frame(container, bg=BG_DARK)
        title_bar.grid(row=0, column=0, sticky="ew", padx=24, pady=(18, 12))

        self.status_dot = tk.Canvas(title_bar, width=14, height=14, bg=BG_DARK, highlightthickness=0)
        self.status_dot.pack(side="left", padx=(0, 10))
        self._draw_status_dot("idle")

        tk.Label(
            title_bar,
            text="Network Packet Sniffer",
            bg=BG_DARK,
            fg=FG_LIGHT,
            font=("Segoe UI", 22, "bold"),
        ).pack(side="left")

        tk.Label(
            title_bar,
            text="Real-time capture dashboard",
            bg=BG_DARK,
            fg=FG_MUTED,
            font=("Segoe UI", 11),
        ).pack(side="left", padx=(12, 0), pady=(6, 0))

        # ═══════════════════════════════════════════════════════
        # Row 1 ── Control Panel (Interface + Filter + Start/Stop)
        # ═══════════════════════════════════════════════════════
        control_card = tk.Frame(container, bg=BG_CARD)
        control_card.grid(row=1, column=0, sticky="ew", padx=24, pady=(0, 14))
        control_card.configure(padx=20, pady=16)
        control_card.grid_columnconfigure(1, weight=1)

        # -- Left: Interface & Filter --
        ctrl_left = tk.Frame(control_card, bg=BG_CARD)
        ctrl_left.grid(row=0, column=0, sticky="w")

        tk.Label(
            ctrl_left,
            text="Interface",
            bg=BG_CARD,
            fg=FG_MUTED,
            font=("Segoe UI", 10),
        ).grid(row=0, column=0, sticky="w", pady=(0, 4))
        self.iface_var = tk.StringVar(value="")
        self.iface_combo = ttk.Combobox(
            ctrl_left,
            textvariable=self.iface_var,
            width=42,
            state="readonly",
            font=("Segoe UI", 11),
        )
        self.iface_combo.grid(row=1, column=0, padx=(0, 20), sticky="w")

        tk.Label(
            ctrl_left,
            text="Protocol Filter",
            bg=BG_CARD,
            fg=FG_MUTED,
            font=("Segoe UI", 10),
        ).grid(row=0, column=1, sticky="w", pady=(0, 4))
        self.filter_var = tk.StringVar(value="All")
        self.filter_combo = ttk.Combobox(
            ctrl_left,
            textvariable=self.filter_var,
            width=14,
            state="readonly",
            values=["All", "TCP", "UDP", "ICMP", "DNS"],
            font=("Segoe UI", 11),
        )
        self.filter_combo.grid(row=1, column=1, sticky="w")

        # -- Right: Start / Stop --
        ctrl_right = tk.Frame(control_card, bg=BG_CARD)
        ctrl_right.grid(row=0, column=2, sticky="e")

        self.start_btn = self._make_modern_button(
            ctrl_right,
            "Start Sniffing",
            BTN_GREEN,
            self._shade(BTN_GREEN, -22),
            self.start_sniffing,
            font_size=13,
            width=15,
            height=2,
        )
        self.start_btn.pack(side="left", padx=(0, 10))

        self.stop_btn = self._make_modern_button(
            ctrl_right,
            "Stop Sniffing",
            BTN_RED,
            self._shade(BTN_RED, -22),
            self.stop_sniffing,
            font_size=13,
            width=15,
            height=2,
        )
        self.stop_btn.configure(state=tk.DISABLED)
        self.stop_btn.pack(side="left")

        # ═══════════════════════════════════════════════════════
        # Row 2 ── Actions (left) + Stats (right)
        # ═══════════════════════════════════════════════════════
        mid_row = tk.Frame(container, bg=BG_DARK)
        mid_row.grid(row=2, column=0, sticky="ew", padx=24, pady=(0, 14))
        mid_row.grid_columnconfigure(0, weight=1)

        # -- Action Buttons Card --
        action_card = tk.Frame(mid_row, bg=BG_CARD)
        action_card.pack(side="left", fill="y", padx=0, pady=0)
        action_card.configure(padx=16, pady=14)

        tk.Label(
            action_card,
            text="Export & Tools",
            bg=BG_CARD,
            fg=FG_MUTED,
            font=("Segoe UI", 10),
        ).grid(row=0, column=0, columnspan=6, sticky="w", pady=(0, 10))

        self.export_excel_btn = self._make_modern_button(
            action_card,
            "Export Excel",
            BTN_BLUE,
            self._shade(BTN_BLUE, -20),
            self.export_to_excel,
            font_size=11,
            width=13,
            height=1,
        )
        self.export_excel_btn.grid(row=1, column=0, padx=(0, 8), pady=2)

        self.export_csv_btn = self._make_modern_button(
            action_card,
            "Export Logs",
            BTN_CYAN,
            self._shade(BTN_CYAN, -18),
            self.export_logs,
            font_size=11,
            width=13,
            height=1,
        )
        self.export_csv_btn.grid(row=1, column=1, padx=(0, 8), pady=2)

        self.export_pcap_btn = self._make_modern_button(
            action_card,
            "Export PCAP",
            BTN_PURPLE,
            self._shade(BTN_PURPLE, -18),
            self.export_as_pcap,
            font_size=11,
            width=13,
            height=1,
        )
        self.export_pcap_btn.grid(row=1, column=2, padx=(0, 8), pady=2)

        self.refresh_btn = self._make_modern_button(
            action_card,
            "Refresh",
            BTN_DARK,
            self._shade(BTN_DARK, 22),
            self.refresh_view,
            font_size=11,
            width=12,
            height=1,
        )
        self.refresh_btn.grid(row=1, column=3, padx=(8, 0), pady=2)

        # -- Stats Card --
        stats_card = tk.Frame(mid_row, bg=BG_CARD)
        stats_card.pack(side="right", fill="y", padx=0, pady=0)
        stats_card.configure(padx=20, pady=14)

        tk.Label(
            stats_card,
            text="Packet Statistics",
            bg=BG_CARD,
            fg=FG_MUTED,
            font=("Segoe UI", 10),
        ).grid(row=0, column=0, columnspan=3, sticky="w", pady=(0, 10))

        self.tcp_var = tk.StringVar(value="0")
        self.udp_var = tk.StringVar(value="0")
        self.icmp_var = tk.StringVar(value="0")

        # TCP stat
        tcp_card = tk.Frame(stats_card, bg="#1a2a3a", padx=18, pady=10)
        tcp_card.grid(row=1, column=0, padx=(0, 10))
        tk.Label(tcp_card, text="TCP", bg="#1a2a3a", fg=TCP_COLOR, font=("Segoe UI", 10)).pack()
        tk.Label(tcp_card, textvariable=self.tcp_var, bg="#1a2a3a", fg=FG_LIGHT, font=("Segoe UI", 16, "bold")).pack()

        # UDP stat
        udp_card = tk.Frame(stats_card, bg="#1a2a3a", padx=18, pady=10)
        udp_card.grid(row=1, column=1, padx=(0, 10))
        tk.Label(udp_card, text="UDP", bg="#1a2a3a", fg=UDP_COLOR, font=("Segoe UI", 10)).pack()
        tk.Label(udp_card, textvariable=self.udp_var, bg="#1a2a3a", fg=FG_LIGHT, font=("Segoe UI", 16, "bold")).pack()

        # ICMP stat
        icmp_card = tk.Frame(stats_card, bg="#1a2a3a", padx=18, pady=10)
        icmp_card.grid(row=1, column=2)
        tk.Label(icmp_card, text="ICMP", bg="#1a2a3a", fg=ICMP_COLOR, font=("Segoe UI", 10)).pack()
        tk.Label(icmp_card, textvariable=self.icmp_var, bg="#1a2a3a", fg=FG_LIGHT, font=("Segoe UI", 16, "bold")).pack()

        # ═══════════════════════════════════════════════════════
        # Row 3 ── Packet Table
        # ═══════════════════════════════════════════════════════
        table_outer = tk.Frame(container, bg=BG_DARK)
        table_outer.grid(row=3, column=0, sticky="nsew", padx=(24, 24), pady=(0, 0))
        table_outer.grid_columnconfigure(0, weight=1)
        table_outer.grid_rowconfigure(0, weight=1)

        table_frame = tk.Frame(table_outer, bg=BG_CARD)
        table_frame.grid(row=0, column=0, sticky="nsew", padx=8, pady=8)
        table_frame.grid_columnconfigure(0, weight=1)
        table_frame.grid_rowconfigure(0, weight=1)

        cols = ("time", "src_ip", "dst_ip", "protocol", "port", "payload")
        self.tree = ttk.Treeview(table_frame, columns=cols, show="headings")

        self.tree.heading("time", text="Time")
        self.tree.heading("src_ip", text="Source IP")
        self.tree.heading("dst_ip", text="Destination IP")
        self.tree.heading("protocol", text="Protocol")
        self.tree.heading("port", text="Port")
        self.tree.heading("payload", text="Payload")

        self.tree.column("time", width=160, anchor=tk.CENTER, stretch=True)
        self.tree.column("src_ip", width=190, anchor=tk.CENTER, stretch=True)
        self.tree.column("dst_ip", width=190, anchor=tk.CENTER, stretch=True)
        self.tree.column("protocol", width=100, anchor=tk.CENTER, stretch=True)
        self.tree.column("port", width=120, anchor=tk.CENTER, stretch=True)
        self.tree.column("payload", width=340, anchor=tk.W, stretch=True)

        vsb = ttk.Scrollbar(table_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)
        self.tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")

        # ═══════════════════════════════════════════════════════
        # Row 4 ── Status Bar
        # ═══════════════════════════════════════════════════════
        status_bar = tk.Frame(container, bg="#0d0d15")
        status_bar.grid(row=4, column=0, sticky="ew", padx=24, pady=(10, 0))
        status_bar.configure(padx=24, pady=8)

        self.status_var = tk.StringVar(value="Ready — select an interface to begin")
        tk.Label(
            status_bar,
            textvariable=self.status_var,
            bg="#0d0d15",
            fg=FG_MUTED,
            font=("Segoe UI", 10),
        ).pack(side="left")

        self.packet_count_var = tk.StringVar(value="Packets: 0")
        tk.Label(
            status_bar,
            textvariable=self.packet_count_var,
            bg="#0d0d15",
            fg=FG_MUTED,
            font=("Segoe UI", 10),
        ).pack(side="right")

    def _shade(self, color: str, delta: int) -> str:
        # Adjust color brightness for hover effect.
        color = color.lstrip("#")
        r = max(0, min(255, int(color[0:2], 16) + delta))
        g = max(0, min(255, int(color[2:4], 16) + delta))
        b = max(0, min(255, int(color[4:6], 16) + delta))
        return f"#{r:02x}{g:02x}{b:02x}"

    def _draw_status_dot(self, state: str) -> None:
        color = {"idle": "#636e72", "running": BTN_GREEN, "stopped": BTN_RED}.get(state, "#636e72")
        self.status_dot.delete("all")
        self.status_dot.create_oval(2, 2, 12, 12, fill=color, outline="")

    def _make_modern_button(
        self,
        parent: tk.Widget,
        text: str,
        base_color: str,
        hover_color: str,
        command: Any,
        *,
        font_size: int = 12,
        width: int = 14,
        height: int = 2,
    ) -> tk.Button:
        btn = tk.Button(
            parent,
            text=text,
            command=command,
            bg=base_color,
            fg=FG_LIGHT,
            activebackground=hover_color,
            activeforeground=FG_LIGHT,
            font=("Segoe UI", font_size, "bold"),
            width=width,
            height=height,
            relief=tk.FLAT,
            bd=0,
            cursor="hand2",
            padx=10,
            pady=4,
        )
        btn.bind("<Enter>", lambda _e, b=btn, c=hover_color: b.configure(bg=c))
        btn.bind("<Leave>", lambda _e, b=btn, c=base_color: b.configure(bg=c))
        return btn

    def _refresh_interfaces(self) -> None:
        # Build dropdown entries with friendly names + per-interface IP.
        # Keep a mapping so we can pass the *real* interface id to sniffing.
        self._iface_display_to_real.clear()
        self._iface_display_to_ip.clear()

        active_ip = self._get_system_active_ip()

        try:
            # Requirement: use Scapy get_if_list()
            from scapy.all import get_if_list  # type: ignore

            interfaces = list(get_if_list())
        except Exception as e:
            print(f"[Interface Detection] Failed to call scapy.get_if_list(): {e}")
            interfaces = []

        # Debug: print all interfaces Scapy sees
        print("[Interface Detection] Scapy interfaces:")

        # Strict allowlist (per requirements)
        def _is_valid_ip(ip: str) -> bool:
            return ip.startswith("10.") or ip.startswith("192.168.")

        # Strict blocklist (per requirements)
        def _is_blocked_ip(ip: str) -> bool:
            return ip.startswith("127.") or ip.startswith("169.254.")

        valid_candidates: List[Tuple[str, str]] = []

        for real_iface in interfaces:
            ip = self._get_iface_ip(real_iface) or ""

            # Debug info for every interface
            blocked = _is_blocked_ip(ip) if ip else False
            valid = _is_valid_ip(ip) if ip else False
            print(f"  - {real_iface} | ip={ip or 'None'} | valid={valid} | blocked={blocked}")

            # Filter: only show interfaces with valid IPs (10.x.x.x / 192.168.x.x)
            if not ip:
                continue
            if blocked:
                continue
            if not valid:
                continue

            valid_candidates.append((real_iface, ip))

        # Pick exactly one Wi-Fi interface based on internet reachability (best-effort).
        self._selected_wifi_real_iface = None
        self._selected_wifi_ip = None
        self._select_wifi_interface(valid_candidates, active_ip)

        entries: List[str] = []
        for real_iface, ip in valid_candidates:
            friendly = self._friendly_iface_name(real_iface, ip)
            display = f"{friendly} ({ip})"
            self._iface_display_to_real[display] = real_iface
            self._iface_display_to_ip[display] = ip
            entries.append(display)

        if not entries:
            print(
                "[Interface Detection] No interfaces matched allowed IP prefixes. "
                "Ensure Npcap is installed and Scapy can enumerate interfaces; "
                "also try running the app as Administrator."
            )
            # Fallback: show nothing-but-informative entry to avoid empty combobox.
            display = "(No valid 10.x.x.x / 192.168.x.x interfaces found)"
            self.iface_combo["values"] = [display]
            self.iface_var.set(display)
            return

        # Auto-select active interface based on system IP when possible.
        selected_display = None
        if active_ip:
            for d in entries:
                if self._iface_display_to_ip.get(d) == active_ip:
                    selected_display = d
                    break

        # Default selection: first entry.
        if selected_display is None:
            selected_display = entries[0]

        self.iface_combo["values"] = entries
        self.iface_var.set(selected_display)

    def _get_system_active_ip(self) -> Optional[str]:
        """
        Determine the primary system IP (best-effort).
        Uses socket only; used to auto-select the closest matching interface.
        """
        try:
            import socket

            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            # Doesn't send packets; just lets OS pick a route.
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            if ip:
                return ip
        except Exception:
            return None
        return None

    def _get_iface_ip(self, real_iface: str) -> Optional[str]:
        """
        Get interface IP using Scapy when possible.
        """
        try:
            from scapy.all import conf, get_if_addr  # type: ignore

            # Primary: scapy.get_if_addr
            ip = get_if_addr(real_iface)
            if ip:
                return str(ip)

            # Fallback: scapy.conf.ifaces (best-effort; structure varies by scapy version)
            iface_obj = None
            try:
                iface_obj = conf.ifaces.get(real_iface)  # type: ignore[attr-defined]
            except Exception:
                iface_obj = None

            # Try common fields
            if iface_obj is not None:
                # Some scapy iface objects expose `.ip` or `.ips`
                ip1 = getattr(iface_obj, "ip", None)
                if ip1:
                    return str(ip1)
                ips = getattr(iface_obj, "ips", None)
                if ips and isinstance(ips, (list, tuple)) and ips:
                    # Keep only the first IPv4-ish item
                    first = str(ips[0])
                    if first and first[0].isdigit():
                        return first
        except Exception as e:
            print(f"[Interface Detection] Failed to get IP for {real_iface}: {e}")

        return None

    def _can_reach_internet(self, ip: str, timeout_s: float = 0.8) -> bool:
        """
        Best-effort connectivity check from a given local source IP.
        Used only for labeling the dropdown (GUI). Does not affect sniffing.
        """
        try:
            import socket

            with socket.create_connection(
                ("1.1.1.1", 53), timeout=timeout_s, source_address=(ip, 0)
            ):
                return True
        except Exception:
            return False

    def _select_wifi_interface(
        self, valid_candidates: List[Tuple[str, str]], active_ip: Optional[str]
    ) -> None:
        """
        Ensure only one interface becomes "Wi-Fi":
          - Prefer the active interface if it has internet reachability
          - Otherwise pick the first internet-reachable candidate
          - Otherwise fallback to the active interface (if present)
          - Otherwise pick the first candidate
        """
        if not valid_candidates:
            return

        # Prefer active IP candidate that appears to have internet access.
        if active_ip:
            for real_iface, ip in valid_candidates:
                if ip == active_ip and self._can_reach_internet(ip):
                    self._selected_wifi_real_iface = real_iface
                    self._selected_wifi_ip = ip
                    return

        # Otherwise, pick first internet-reachable candidate.
        for real_iface, ip in valid_candidates:
            if self._can_reach_internet(ip):
                self._selected_wifi_real_iface = real_iface
                self._selected_wifi_ip = ip
                return

        # Fallback to active IP if it exists in candidates.
        if active_ip:
            for real_iface, ip in valid_candidates:
                if ip == active_ip:
                    self._selected_wifi_real_iface = real_iface
                    self._selected_wifi_ip = ip
                    return

        # Final fallback: first candidate.
        self._selected_wifi_real_iface, self._selected_wifi_ip = valid_candidates[0]

    def _friendly_iface_name(self, real_iface: str, ip: str) -> str:
        """
        Convert technical interface ID into user-friendly label.
        """
        low = (real_iface or "").lower()
        ip_low = (ip or "").strip()

        # If we couldn't determine IP, prefer generic label.
        if not ip_low:
            return "Other Network"

        # Virtual link-local adapters.
        if ip_low.startswith("169.254."):
            return "Virtual Adapter"

        # Wi-Fi labeling: only the selected candidate is allowed to be "Wi-Fi".
        if (self._selected_wifi_ip and ip_low == self._selected_wifi_ip) or (
            self._selected_wifi_real_iface and real_iface == self._selected_wifi_real_iface
        ):
            return "Wi-Fi"

        # Ethernet heuristics.
        eth_markers = ["eth", "ethernet", "gigabit", "en0", "en1", "802.3"]
        if any(m in low for m in eth_markers):
            return "Ethernet"

        # Fallback for anything else with a known IP.
        return "Other Network"

    def _authenticate(self) -> bool:
        # Authentication popup before sniffing starts
        user = simpledialog.askstring("Authentication", "Username:", parent=self.root)
        if user is None:
            return False
        pwd = simpledialog.askstring("Authentication", "Password:", show="*", parent=self.root)
        if pwd is None:
            return False
        if user == AUTH_USERNAME and pwd == AUTH_PASSWORD:
            return True
        messagebox.showerror("Authentication Failed", "Invalid username or password.")
        return False

    def start_sniffing(self) -> None:
        if self.sniffer is not None and self.sniffer.is_running():
            return

        if not self._authenticate():
            return

        selected_display = self.iface_var.get().strip()
        real_iface = self._iface_display_to_real.get(selected_display)
        if not real_iface or real_iface == "":
            messagebox.showerror("No Interface", "Please select a valid network interface.")
            return

        # Store session details for session_log.txt (no packet data)
        self.session_start_time = now_str()
        self.session_stop_time = None
        # Dropdown is like "Wi-Fi (192.168.1.5)" -> store only friendly name
        self.session_interface_name = selected_display.split(" (", 1)[0].strip() or selected_display

        # Reset IDS counters on new session (keeps UI cleaner)
        self._src_ip_counts.clear()
        self._src_ip_ports.clear()
        self.alert_shown = False

        # Create sniffer; callback runs in background thread
        self.sniffer = PacketSniffer(iface=real_iface, on_packet=self._on_packet_from_sniffer)
        self.sniffer.start()

        self.start_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        self._draw_status_dot("running")
        self.status_var.set(f"Capturing on {self.session_interface_name}…")

    def stop_sniffing(self) -> None:
        if self.sniffer is not None:
            self.sniffer.stop()
        # Store stop time for session export
        self.session_stop_time = now_str()
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        self._draw_status_dot("stopped")
        self.status_var.set(f"Capture stopped — {self.session_stop_time}")

    def export_logs(self) -> None:
        """
        Export ONLY session details (no packet data) to `session_log.txt`.
        """
        out_path = os.path.join(app_dir(), "session_log.txt")

        start_t = self.session_start_time or "-"
        stop_t = self.session_stop_time or "-"
        iface = self.session_interface_name or "-"

        content = (
            "------------------------\n"
            "Network Sniffer Session Log\n"
            "------------------------\n"
            f"Start Time: {start_t}\n"
            f"Stop Time: {stop_t}\n"
            f"Interface: {iface}\n"
        )

        try:
            with open(out_path, "w", encoding="utf-8") as f:
                f.write(content)
            messagebox.showinfo("Export Logs", f"Session log saved to:\n{out_path}")
        except Exception as e:
            messagebox.showerror("Export Logs Failed", str(e))

    def _on_packet_from_sniffer(self, pkt: Any) -> None:
        """
        Background thread callback:
          - analyze packet
          - apply GUI filter
          - log + enqueue UI update
          - update stats + IDS
        """
        info = analyze_packet(pkt).to_dict()

        # Apply protocol filter before displaying/logging
        wanted = self._get_filter_value()
        if wanted and wanted != "All" and info.get("protocol") != wanted:
            return

        # Store raw + structured for export
        self._captured_packets.append(pkt)
        self._captured_rows.append(info)

        # Log to file
        try:
            write_log_line(info)
        except Exception:
            # Avoid killing the capture thread on log errors
            pass

        # Update stats (keep counts for core protocols only)
        proto = info.get("protocol", "Other")
        if proto in self._stats:
            self._stats[proto] += 1
            self._ui_queue.put(("stats", dict(self._stats)))

        # Basic IDS checks (best-effort)
        self._run_basic_ids(info)

        # Enqueue table row update for main thread
        self._ui_queue.put(("row", info))

    def _run_basic_ids(self, info: Dict[str, str]) -> None:
        """
        Detect:
          - Too many packets from same IP (possible flood)
          - Port scanning (many distinct destination ports from same source)
        """
        src = info.get("src_ip", "-")
        if not src or src == "-":
            return

        # Thresholds (simple heuristics)
        FLOOD_THRESHOLD = 200
        PORTSCAN_DISTINCT_PORTS = 25

        self._src_ip_counts[src] = self._src_ip_counts.get(src, 0) + 1
        if self._src_ip_counts[src] == FLOOD_THRESHOLD:
            if not self.alert_shown:
                self.alert_shown = True
                self._ui_queue.put(
                    (
                        "alert",
                        f"Possible packet flood detected from {src} (>= {FLOOD_THRESHOLD} packets).",
                    )
                )

        port_str = info.get("port", "-")
        # Parse "sport→dport" if present and numeric
        if "→" in port_str:
            try:
                _sport, dport = port_str.split("→", 1)
                dport_i = int(dport)
            except Exception:
                dport_i = None
            if dport_i is not None:
                s = self._src_ip_ports.get(src)
                if s is None:
                    s = set()
                    self._src_ip_ports[src] = s
                s.add(dport_i)
                if len(s) == PORTSCAN_DISTINCT_PORTS:
                    if not self.alert_shown:
                        self.alert_shown = True
                        self._ui_queue.put(
                            (
                                "alert",
                                f"Possible port scan detected from {src} (>= {PORTSCAN_DISTINCT_PORTS} distinct destination ports).",
                            )
                        )

    def _drain_ui_queue(self) -> None:
        # Main-thread UI updater: drain queued events quickly
        try:
            while True:
                kind, payload = self._ui_queue.get_nowait()
                if kind == "row":
                    self._add_row_to_table(payload)
                elif kind == "stats":
                    self._set_stats(payload)
                elif kind == "alert":
                    self._show_alert(payload)
        except queue.Empty:
            pass
        finally:
            self.root.after(100, self._drain_ui_queue)

    def _add_row_to_table(self, info: Dict[str, str]) -> None:
        values = (
            info.get("time", "-"),
            info.get("src_ip", "-"),
            info.get("dst_ip", "-"),
            info.get("protocol", "-"),
            info.get("port", "-"),
            info.get("payload", "Encrypted / Binary Data"),
        )
        self.tree.insert("", tk.END, values=values)
        self.packet_count_var.set(f"Packets: {len(self._captured_rows)}")

        # Auto-scroll to latest row for real-time feel
        children = self.tree.get_children()
        if children:
            self.tree.see(children[-1])

    def _set_stats(self, stats: Dict[str, int]) -> None:
        self.tcp_var.set(str(stats.get("TCP", 0)))
        self.udp_var.set(str(stats.get("UDP", 0)))
        self.icmp_var.set(str(stats.get("ICMP", 0)))

    def _show_alert(self, message: str) -> None:
        # Keep popup on main thread
        messagebox.showwarning("Security Alert", message)

    def refresh_view(self) -> None:
        """
        Clear the GUI table and reset counters/alerts.
        Does NOT stop packet capture and does NOT change captured packet storage.
        """
        for item in self.tree.get_children():
            self.tree.delete(item)

        # Reset stats displayed in the dashboard
        self._stats = {"TCP": 0, "UDP": 0, "ICMP": 0}
        self.tcp_var.set("0")
        self.udp_var.set("0")
        self.icmp_var.set("0")
        self.packet_count_var.set("Packets: 0")

        # Reset IDS state + alert throttling
        self._src_ip_counts.clear()
        self._src_ip_ports.clear()
        self.alert_shown = False

    def export_to_excel(self) -> None:
        """
        Export captured packet rows to `captured_data.xlsx` using pandas + openpyxl.
        Only exports the session table data stored in `_captured_rows`.
        """
        if not self._captured_rows:
            messagebox.showinfo("Export to Excel", "No captured packets to export yet.")
            return

        out_path = filedialog.asksaveasfilename(
            title="Export to Excel",
            defaultextension=".xlsx",
            initialfile="captured_data.xlsx",
            filetypes=[("Excel files", "*.xlsx"), ("All files", "*.*")],
        )
        if not out_path:
            return

        def _worker() -> None:
            try:
                import pandas as pd  # type: ignore
            except Exception:
                self.root.after(
                    0,
                    lambda: messagebox.showerror(
                        "Export to Excel Failed",
                        "Missing dependency: pandas/openpyxl. Install with `pip install pandas openpyxl`.",
                    ),
                )
                return

            try:
                df = pd.DataFrame(self._captured_rows)
                rename_map = {
                    "time": "Time",
                    "src_ip": "Source IP",
                    "dst_ip": "Destination IP",
                    "protocol": "Protocol",
                    "port": "Port",
                    "payload": "Payload",
                }
                df = df.rename(columns=rename_map)

                required_cols = [
                    "Time",
                    "Source IP",
                    "Destination IP",
                    "Protocol",
                    "Port",
                    "Payload",
                ]
                for c in required_cols:
                    if c not in df.columns:
                        df[c] = "-"
                df = df[required_cols]

                # pandas uses openpyxl to write .xlsx when engine="openpyxl"
                df.to_excel(out_path, index=False, engine="openpyxl")

                self.root.after(
                    0,
                    lambda: messagebox.showinfo(
                        "Export to Excel",
                        f"Exported Excel to:\n{out_path}",
                    ),
                )
            except Exception as e:
                self.root.after(
                    0,
                    lambda: messagebox.showerror("Export to Excel Failed", str(e)),
                )

        # Export in a background thread to keep UI responsive.
        threading.Thread(target=_worker, name="ExcelExportThread", daemon=True).start()

    def export_as_csv(self) -> None:
        if not self._captured_rows:
            messagebox.showinfo("Export CSV", "No captured packets to export yet.")
            return

        out_path = filedialog.asksaveasfilename(
            title="Export as CSV",
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")],
        )
        if not out_path:
            return
        try:
            export_csv(self._captured_rows, out_path)
            messagebox.showinfo("Export CSV", f"Exported CSV to:\n{out_path}")
        except Exception as e:
            messagebox.showerror("Export CSV Failed", str(e))

    def export_as_pcap(self) -> None:
        if not self._captured_packets:
            messagebox.showinfo("Export PCAP", "No captured packets to export yet.")
            return

        out_path = filedialog.asksaveasfilename(
            title="Export as PCAP",
            defaultextension=".pcap",
            filetypes=[("PCAP files", "*.pcap"), ("All files", "*.*")],
        )
        if not out_path:
            return
        try:
            export_pcap(self._captured_packets, out_path)
            messagebox.showinfo("Export PCAP", f"Exported PCAP to:\n{out_path}")
        except Exception as e:
            messagebox.showerror("Export PCAP Failed", str(e))

    def open_project_info(self) -> None:
        """Open the local Project Info HTML page in the browser."""
        _open_project_info()


def _make_welcome_btn(parent, text, base, hover, cmd):
    btn = tk.Button(
        parent,
        text=text,
        command=cmd,
        bg=base,
        fg=FG_LIGHT,
        activebackground=hover,
        activeforeground=FG_LIGHT,
        font=("Segoe UI", 13, "bold"),
        width=18,
        height=2,
        relief=tk.FLAT,
        bd=0,
        cursor="hand2",
        padx=10,
        pady=6,
    )
    btn.bind("<Enter>", lambda _e, b=btn, c=hover: b.configure(bg=c))
    btn.bind("<Leave>", lambda _e, b=btn, c=base: b.configure(bg=c))
    return btn


def run_gui() -> None:
    root = tk.Tk()
    root.title("Network Packet Sniffer")
    root.geometry("900x600")
    root.minsize(800, 500)
    root.configure(bg=BG_DARK)

    # ── ttk styles for a modern dark look ──
    try:
        style = ttk.Style()
        if "clam" in style.theme_names():
            style.theme_use("clam")

        style.configure(
            "TCombobox",
            fieldbackground=BG_INPUT,
            background=BG_INPUT,
            foreground=FG_LIGHT,
            arrowcolor=FG_LIGHT,
            borderwidth=0,
        )
        style.map(
            "TCombobox",
            fieldbackground=[("readonly", BG_INPUT)],
            foreground=[("readonly", FG_LIGHT)],
            selectbackground=[("readonly", BG_INPUT)],
        )

        style.configure(
            "Treeview",
            background="#1e1e32",
            fieldbackground="#1e1e32",
            foreground=FG_LIGHT,
            rowheight=36,
            borderwidth=0,
            font=("Segoe UI", 11),
        )
        style.configure(
            "Treeview.Heading",
            background="#252540",
            foreground=FG_LIGHT,
            relief="flat",
            font=("Segoe UI", 11, "bold"),
            padding=(10, 10),
        )
        style.map(
            "Treeview",
            background=[("selected", "#3498db")],
            foreground=[("selected", "#ffffff")],
        )
        style.map(
            "Treeview.Heading",
            background=[("active", "#2a2a48")],
        )

        style.configure(
            "Vertical.TScrollbar",
            background="#2a2a3d",
            troughcolor="#12121a",
            borderwidth=0,
            arrowcolor="#a0a0b8",
            width=12,
        )
        style.map(
            "Vertical.TScrollbar",
            background=[("active", "#3a3a55"), ("pressed", "#3a3a55")],
        )
    except Exception:
        pass

    def launch_dashboard() -> None:
        for widget in root.winfo_children():
            widget.destroy()
        root.geometry("1260x760")
        root.minsize(1050, 650)
        SnifferGUI(root)

    # ═══════════════════════════════════════════════════════
    # Welcome Screen
    # ═══════════════════════════════════════════════════════
    welcome = tk.Frame(root, bg=BG_DARK)
    welcome.pack(fill=tk.BOTH, expand=True)

    center = tk.Frame(welcome, bg=BG_DARK)
    center.place(relx=0.5, rely=0.45, anchor="center")

    tk.Label(
        center,
        text="Network Packet Sniffer",
        bg=BG_DARK,
        fg=FG_LIGHT,
        font=("Segoe UI", 36, "bold"),
    ).pack(pady=(0, 12))

    tk.Label(
        center,
        text="Real-time packet capture, analysis & export dashboard",
        bg=BG_DARK,
        fg=FG_MUTED,
        font=("Segoe UI", 14),
    ).pack(pady=(0, 8))

    desc = (
        "Capture live network traffic, filter by protocol, detect intrusions, "
        "and export sessions to Excel, CSV, or PCAP formats."
    )
    tk.Label(
        center,
        text=desc,
        bg=BG_DARK,
        fg=FG_MUTED,
        font=("Segoe UI", 11),
        wraplength=520,
        justify="center",
    ).pack(pady=(0, 40))

    btn_frame = tk.Frame(center, bg=BG_DARK)
    btn_frame.pack()

    _make_welcome_btn(
        btn_frame,
        "Project Info",
        BTN_DARK,
        _shade_color(BTN_DARK, 22),
        _open_project_info,
    ).pack(side="left", padx=(0, 16))

    _make_welcome_btn(
        btn_frame,
        "Start Application",
        BTN_GREEN,
        _shade_color(BTN_GREEN, -22),
        launch_dashboard,
    ).pack(side="left")

    root.mainloop()

