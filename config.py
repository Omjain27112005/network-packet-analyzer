# config.py

"""
Central Configuration
=====================
All tuneable parameters live here.
Change values in this file to affect the entire application —
no hunting through individual modules.
"""

from __future__ import annotations

# ── Capture ───────────────────────────────────────────────────────────────────
INTERFACE: str | None = None        # None = auto-detect (recommended)
PACKET_COUNT: int = 0               # 0 = capture forever
CAPTURE_TIMEOUT: int | None = None  # None = no timeout (FIX: was missing value)

# ── Anomaly Detection ─────────────────────────────────────────────────────────
PORT_SCAN_THRESHOLD: int = 10        # unique dest ports per source IP → alert
TRAFFIC_SPIKE_THRESHOLD: int = 100   # packets per window from one IP → alert
TRAFFIC_WINDOW_SECONDS: int = 60     # sliding window size in seconds

# ── Port Scan Time Window ─────────────────────────────────────────────────────
# How long (seconds) to remember a port contact for port-scan detection.
# Ports seen older than this are evicted, preventing false positives in
# long-running sessions. Set to 0 to disable time-based eviction.
PORT_SCAN_WINDOW_SECONDS: int = 120  # evict ports older than 2 minutes

# ── Reporting ─────────────────────────────────────────────────────────────────
REPORT_DIR: str = "reports"
REPORT_FORMAT: str = "json"          # "json" | "txt"

# ── Dashboard ─────────────────────────────────────────────────────────────────
DASHBOARD_REFRESH_SECONDS: float = 1.0   # how often the UI re-renders
TOP_N_IPS: int = 10                       # how many IPs to show in tables