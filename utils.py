from __future__ import annotations

import os
import subprocess
import sys
from datetime import datetime


def app_dir() -> str:
    """Return the project directory path (where files are stored).

    Handles both normal Python execution and frozen EXE builds (PyInstaller, etc.).
    """
    if getattr(sys, "frozen", False):
        # PyInstaller sets sys._MEIPASS to the bundled extraction folder.
        meipass = getattr(sys, "_MEIPASS", None)
        if meipass:
            return meipass
        return os.path.dirname(sys.executable)
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


def is_admin() -> bool:
    """Check whether the current Windows process has Administrator privileges."""
    if os.name != "nt":
        return True
    try:
        import ctypes

        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


def restart_as_admin() -> None:
    """Relaunch the current script with Administrator privileges via UAC prompt."""
    if os.name != "nt":
        return
    import ctypes

    params = subprocess.list2cmdline(sys.argv)
    ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, params, None, 1)
    sys.exit(0)
