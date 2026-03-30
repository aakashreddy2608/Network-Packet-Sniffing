from __future__ import annotations

import os
import sys
from datetime import datetime


def app_dir() -> str:
    """Return the project directory path (where files are stored)."""
    return os.path.dirname(os.path.abspath(__file__))


def now_str() -> str:
    """Human-readable timestamp for UI/logs."""
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def ensure_windows_admin_hint() -> None:
    """
    Scapy sniffing on Windows often requires:
    - running the terminal as Administrator
    - Npcap installed (WinPcap-compatible mode)
    """
    if os.name != "nt":
        return
    # Keep this as a hint function; don't print automatically on import.
    return


def fatal(msg: str, exit_code: int = 1) -> None:
    print(msg, file=sys.stderr)
    raise SystemExit(exit_code)
