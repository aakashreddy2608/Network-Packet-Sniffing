# Network Packet Sniffer with GUI

A modern, dark-themed desktop application for real-time network packet capture, analysis, and export — built with Python, Scapy, and Tkinter.

---

## Features

- **Welcome Screen** — Launch dashboard or view project info before starting
- **Real-time Packet Capture** — Live table view with auto-scroll
- **Protocol Filtering** — Filter by TCP, UDP, ICMP, DNS, or show all
- **Modern Dark UI** — Clean card-based layout with live status indicators and packet statistics
- **Basic IDS Alerts** — Detects possible packet floods and port scans
- **Multi-format Export** — Export sessions to Excel, CSV, PCAP, or session logs
- **Admin Access Check** — Automatic UAC elevation prompt on Windows
- **Authentication** — Built-in login before starting capture

---

## Requirements

- Windows 10/11
- [Npcap](https://npcap.com/) (recommended: enable WinPcap-compatible mode)
- Python 3.10+ (for source execution)

---

## Setup

Install Python dependencies:

```bash
python -m pip install -r requirements.txt
```

---

## Run from Source

```bash
python main.py
```

> The app will automatically prompt for Administrator privileges if not already elevated.

---

## Build EXE (Optional)

Use PyInstaller to create a standalone Windows executable:

```bash
python -m PyInstaller main.spec --noconfirm
```

The EXE will be output to `dist/main/main.exe`.

---

## Default Login

| Field    | Value     |
|----------|-----------|
| Username | `admin`   |
| Password | `admin123`|

---

## Output Files

| File                | Description                          |
|---------------------|--------------------------------------|
| `captured_data.log` | Raw captured packet data             |
| `session_log.txt`   | Session metadata (start, stop, iface)|

---

## Tech Stack

- Python 3
- Scapy
- Tkinter / ttk
- threading
- pandas / openpyxl (Excel export)

---

## Developer

**Sreeja**
