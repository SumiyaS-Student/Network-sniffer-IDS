# Network Packet Sniffer & Intrusion Detection System (IDS)

A desktop application for real-time network packet capture, protocol analysis,
visual statistics, and defensive intrusion detection. Built with Python and
Tkinter, packaged with PyInstaller.

## Features

- **Live packet capture** — select a network interface and capture traffic in real time (requires Npcap/WinPcap/libpcap and admin/root privileges)
- **Protocol analysis** — automatic L2–L4 and common application protocol detection (ARP, IP, TCP, UDP, HTTP, HTTPS, FTP, SSH, SMTP, DNS, ...)
- **Intrusion detection** — real-time defensive IDS with:
  - SYN flood detection
  - Port scan detection
  - ICMP / UDP flood detection
  - Ping sweep detection
  - Packet-rate anomaly warnings
- **Statistics dashboard** — live charts and protocol distribution visualisation (matplotlib)
- **Export** — save captures as CSV or PCAP for offline analysis in Wireshark
- **Email alerts** — optional SMTP alerting with DPAPI-encrypted credential storage
- **Professional GUI** — multi-view Tkinter interface: Dashboard, Live Capture, Packet Details, IDS, Statistics, Logs, Export, Settings
- **Authentication** — PBKDF2-hashed local password with login lockout, session timeout, and audit logging

## Technologies

- Python 3.12
- Tkinter (GUI)
- Scapy (packet capture & parsing)
- Matplotlib (charts)
- Pillow (image handling)
- PyInstaller (packaging to `.exe`)
- Windows DPAPI (credential encryption)

## Project Structure

```
├── app/
│   ├── analysis/         Packet parsing, protocol detection, statistics
│   ├── authentication/   Local auth manager (PBKDF2, sessions, lockout)
│   ├── capture/          Interface manager, sniffer, packet queue
│   ├── email/            SMTP alert client
│   ├── export/           CSV and PCAP exporters
│   ├── gui/              Tkinter views (dashboard, capture, IDS, etc.)
│   ├── ids/              Intrusion detection engine (alerts, detectors)
│   ├── logging/          Centralised application logging
│   └── utils/            Paths, crypto, security, demo generator, time utils
├── assets/               Application assets
├── main.py               Application entry point
├── config.py             Configuration model + JSON persistence
├── requirements.txt
└── NetworkSnifferIDS.spec  PyInstaller build spec
```

## Installation

```bash
# 1. Create and activate a virtual environment (recommended)
python -m venv venv
venv\Scripts\activate        # Windows

# 2. Install dependencies
pip install -r requirements.txt

# 3. (Windows) Install Npcap: https://npcap.com
```

## Usage

```bash
python main.py
```

On first launch you will be prompted to set a local password. Live capture
requires the program to run with **elevated (Administrator/root) privileges**.

> **SMTP / project info:** the app maintains a local `config.json` (auto-created
> on first run with safe defaults). SMTP credentials, IDS thresholds and
> project details can be edited from the GUI (**Settings** view) or directly in
> that file. It is never committed to the repository.

## Demo Mode

For demonstration without live traffic, the GUI provides a demo data generator
that simulates realistic packet flows and IDS scenarios.

## Tests

```bash
python tests/test_suite.py
# or
python -m unittest discover tests
```

## Building an Executable

```bash
pip install pyinstaller
pyinstaller NetworkSnifferIDS.spec
```

The standalone executable is produced in `dist/`.

---

> Educational / laboratory project for portfolio demonstration purposes.