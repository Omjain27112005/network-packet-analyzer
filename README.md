# Network Packet Analyzer

> A real-time network packet capture and anomaly detection tool built with Python, Scapy, and Rich.

![Python](https://img.shields.io/badge/python-3.10%2B-blue?logo=python)
![License](https://img.shields.io/badge/license-MIT-green)
![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey)

---

## 🚀 Features

- **Live packet capture** on any network interface via Scapy
- **Real-time terminal dashboard** powered by Rich (protocols, top IPs, alerts)
- **Anomaly detection** — port scan detection & traffic spike detection
- **Time-windowed analysis** — sliding windows prevent stale false positives
- **Session reports** — auto-generated JSON or plain-text on exit
- **Thread-safe** — capture and dashboard run concurrently without data races

---

## 📋 Requirements

| Requirement | Details |
|-------------|---------|
| Python | 3.10 or newer |
| Scapy | `pip install scapy` |
| Rich | `pip install rich` |
| **Windows only** | [Npcap](https://npcap.com) must be installed |
| **Linux/macOS** | Run with `sudo` for raw socket access |

---

## ⚙️ Installation

```bash
# 1. Clone the repository
git clone https://github.com/Omjain27112005/network-packet-analyzer.git
cd network-packet-analyzer

# 2. (Recommended) Create and activate a virtual environment
python -m venv venv

# Windows
venv\Scripts\activate

# Linux / macOS
source venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Windows users: Install Npcap
#    Download from https://npcap.com and run the installer
```

---

## ▶️ Usage

```bash
# Capture on auto-detected interface (default)
python main.py

# Capture on a specific interface
python main.py --interface Wi-Fi        # Windows
python main.py --interface wlan0        # Linux

# Capture exactly 500 packets then stop
python main.py --count 500

# Capture for 60 seconds then stop
python main.py --timeout 60

# Enable verbose/debug logging
python main.py --verbose

# Combine options
python main.py --interface eth0 --timeout 120 --verbose
```

Press **Ctrl+C** at any time to stop the capture. A session report is automatically saved to the `reports/` folder.

---

## 🖥️ Dashboard Layout

```
┌─ 📡 Network Packet Analyzer ─────────────────────────────────────┐
│   UPTIME      PACKETS       DATA       UNIQUE IPs     ALERTS     │
├─────────────────────────────┬─────────────────────────────────────┤
│   Protocol Breakdown        │   Top 10 Source IPs                 │
│   TCP   ████░░░░  60.0%     │   1. 192.168.1.1   1,200 pkts      │
│   UDP   ██░░░░░░  30.0%     │   2. 8.8.8.8         400 pkts      │
│   ICMP  █░░░░░░░  10.0%     │   ...                               │
├─────────────────────────────┴─────────────────────────────────────┤
│   🛡 Alerts                                                        │
│   No anomalies detected — network traffic looks normal.           │
└───────────────────────────────────────────────────────────────────┘
  Ctrl+C to stop capture and generate report
```

---

## 🔍 Anomaly Detection

### Port Scan Detection
Fires when a single source IP contacts more than **10 unique destination ports** within a **2-minute sliding window**.

- Uses a time-windowed approach — ports seen more than 2 minutes ago are evicted
- Prevents false positives in long-running sessions

### Traffic Spike Detection
Fires when a single source IP sends more than **100 packets** within a **60-second sliding window**.

All thresholds are configurable in [`config.py`](config.py).

---

## 🗂️ Project Structure

```
network-packet-analyzer/
├── main.py              # Entry point — CLI args, lifecycle orchestration
├── config.py            # All tuneable parameters (thresholds, dirs, etc.)
├── requirements.txt     # Direct dependencies only
├── src/
│   ├── analyzer.py      # Statistical engine + anomaly detection
│   ├── capture.py       # Scapy packet sniffer
│   ├── dashboard.py     # Rich live terminal dashboard
│   ├── parser.py        # Scapy packet → TypedDict decoder
│   └── reporter.py      # Session report generator (JSON / TXT)
├── tests/
│   ├── test_analyzer.py # Unit tests for PacketAnalyzer
│   ├── test_parser.py   # Unit tests for parse_packet()
│   └── test_reporter.py # Unit tests for Reporter
├── reports/             # Auto-generated session reports (git-ignored)
├── docs/                # Additional documentation
└── samples/             # Sample .pcap files for offline testing
```

---

## 🧪 Running Tests

```bash
pip install pytest
pytest tests/ -v
```

---

## ⚙️ Configuration

Edit [`config.py`](config.py) to tune the tool without touching any module:

| Parameter | Default | Description |
|-----------|---------|-------------|
| `INTERFACE` | `None` | Network interface (`None` = auto-detect) |
| `PACKET_COUNT` | `0` | Packets to capture (`0` = unlimited) |
| `CAPTURE_TIMEOUT` | `None` | Capture duration in seconds (`None` = no limit) |
| `PORT_SCAN_THRESHOLD` | `10` | Unique ports before port-scan alert fires |
| `PORT_SCAN_WINDOW_SECONDS` | `120` | Time window for port-scan tracking |
| `TRAFFIC_SPIKE_THRESHOLD` | `100` | Packets/window before spike alert fires |
| `TRAFFIC_WINDOW_SECONDS` | `60` | Sliding window duration for spike detection |
| `REPORT_DIR` | `"reports"` | Output directory for session reports |
| `REPORT_FORMAT` | `"json"` | Report format: `"json"` or `"txt"` |
| `DASHBOARD_REFRESH_SECONDS` | `1.0` | Dashboard refresh interval |
| `TOP_N_IPS` | `10` | Number of top IPs shown in dashboard |

---

## 📄 License

This project is licensed under the **MIT License** — see [LICENSE](LICENSE) for details.

---

## 👤 Author

**Omjain27112005** — [GitHub Profile](https://github.com/Omjain27112005)
