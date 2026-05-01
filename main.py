from __future__ import annotations

import tkinter as tk
from tkinter import messagebox

from gui import run_gui
from utils import is_admin, restart_as_admin


def main() -> None:
    # On Windows, packet capture requires Administrator privileges.
    if not is_admin():
        root = tk.Tk()
        root.withdraw()
        ans = messagebox.askyesno(
            "Administrator Privileges Required",
            "Network packet sniffing requires Administrator rights on Windows.\n\n"
            "Would you like to restart the application as Administrator?",
        )
        root.destroy()
        if ans:
            restart_as_admin()
        else:
            root = tk.Tk()
            root.withdraw()
            messagebox.showwarning(
                "Warning",
                "Running without Administrator privileges.\n"
                "Packet capture may fail or show no interfaces.",
            )
            root.destroy()

    run_gui()


if __name__ == "__main__":
    main()

