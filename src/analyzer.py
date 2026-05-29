# src/analyzer.py

"""
Packet Analyzer Module
======================
The statistical brain of the application.

Consumes parsed packet dicts from parser.py, maintains rolling
in-memory counters, and runs two anomaly detection algorithms:

    1. Port Scan Detection   — sliding set of unique dest ports per source IP
    2. Traffic Spike         — sliding window packet count per source IP

All public methods are thread-safe via a single reentrant lock,
allowing the capture thread and dashboard thread to access state
concurrently without data races.
"""

from __future__ import annotations

import logging
import threading
from collections import Counter, defaultdict
from datetime import datetime
from typing import Any

from config import (
    PORT_SCAN_THRESHOLD,
    TRAFFIC_SPIKE_THRESHOLD,
    TRAFFIC_WINDOW_SECONDS,
)

logger = logging.getLogger(__name__)


class PacketAnalyzer:
    """
    Stateful packet analyzer — instantiate once, share across threads.

    Usage:
        analyzer = PacketAnalyzer()
        analyzer.process(parsed_packet)   # call from capture thread
        stats = analyzer.get_stats()       # call from dashboard thread
        alerts = analyzer.get_alerts()
    """

    def __init__(self) -> None:
        # ── Thread safety ─────────────────────────────────────────────────
        # RLock (reentrant) allows the same thread to acquire the lock
        # multiple times without deadlocking.
        self._lock = threading.RLock()

        # ── Session metadata ──────────────────────────────────────────────
        self._start_time: datetime = datetime.now()

        # ── Packet counters ───────────────────────────────────────────────
        self._total_packets: int = 0
        self._total_bytes: int = 0

        # Counter maps protocol name → packet count
        # e.g. {"TCP": 4000, "UDP": 500, "ICMP": 21}
        self._protocol_counts: Counter = Counter()

        # ── Per-IP tracking ───────────────────────────────────────────────
        # Total bytes sent by each source IP
        self._bytes_per_ip: defaultdict[str, int] = defaultdict(int)

        # Total packets sent by each source IP
        self._packets_per_ip: defaultdict[str, int] = defaultdict(int)

        # ── Port scan detection ───────────────────────────────────────────
        # Set of unique destination ports contacted by each source IP.
        # A set ensures we count distinct ports, not packet volume.
        self._ports_per_ip: defaultdict[str, set] = defaultdict(set)

        # ── Traffic spike detection ───────────────────────────────────────
        # List of datetime objects for each packet received from a source IP.
        # We keep only timestamps within the sliding window.
        self._timestamps_per_ip: defaultdict[str, list] = defaultdict(list)

        # ── Alerts ────────────────────────────────────────────────────────
        # Chronological list of detected anomaly dicts
        self._alerts: list[dict[str, Any]] = []

    # ── Public API ────────────────────────────────────────────────────────────

    def process(self, parsed_packet: dict) -> None:
        """
        Ingest one parsed packet and update all internal state.

        Called once per captured packet from the capture thread.
        Thread-safe.

        Args:
            parsed_packet: Dict produced by parser.parse_packet().
        """
        with self._lock:
            self._update_counters(parsed_packet)
            self._run_anomaly_detection(parsed_packet)

    def get_stats(self) -> dict[str, Any]:
        """
        Return a snapshot of all current statistics.

        Called by the dashboard thread every refresh cycle.
        Returns a copy so the caller can safely read without holding the lock.

        Returns:
            Dict containing totals, protocol breakdown, top IPs, and alerts.
        """
        with self._lock:
            elapsed = (datetime.now() - self._start_time).total_seconds()

            return {
                "start_time"       : self._start_time.isoformat(timespec="seconds"),
                "elapsed_seconds"  : round(elapsed, 1),
                "total_packets"    : self._total_packets,
                "total_bytes"      : self._total_bytes,
                "protocol_counts"  : dict(self._protocol_counts),
                "packets_per_ip"   : dict(self._packets_per_ip),
                "bytes_per_ip"     : dict(self._bytes_per_ip),
                "unique_ips"       : len(self._packets_per_ip),
                "alert_count"      : len(self._alerts),
                "alerts"           : list(self._alerts),
            }

    def get_alerts(self) -> list[dict[str, Any]]:
        """
        Return a copy of all generated alerts so far.

        Returns:
            List of alert dicts, each with keys:
            type, src_ip, detail, timestamp.
        """
        with self._lock:
            return list(self._alerts)

    def reset(self) -> None:
        """
        Clear all counters and restart the session timer.
        Useful for testing or implementing a 'clear' command.
        """
        with self._lock:
            self.__init__()
            logger.info("Analyzer state reset.")

    # ── Private — counter updates ─────────────────────────────────────────────

    def _update_counters(self, packet: dict) -> None:
        """
        Update all running counters with data from one packet.
        Must be called while holding self._lock.
        """
        self._total_packets += 1
        self._total_bytes += packet.get("size", 0)
        self._protocol_counts[packet["protocol"]] += 1

        src_ip = packet["src_ip"]
        self._packets_per_ip[src_ip] += 1
        self._bytes_per_ip[src_ip] += packet.get("size", 0)

    # ── Private — anomaly detection ───────────────────────────────────────────

    def _run_anomaly_detection(self, packet: dict) -> None:
        """
        Run all anomaly detectors against the incoming packet.
        Must be called while holding self._lock.
        """
        self._detect_port_scan(packet)
        self._detect_traffic_spike(packet)

    def _detect_port_scan(self, packet: dict) -> None:
        """
        Port scan detection using a per-IP set of unique destination ports.

        Algorithm:
            - Add dst_port to a set keyed by src_ip.
            - A Python set stores only unique values — repeated hits to the
              same port do not increment the count.
            - When the set size exceeds PORT_SCAN_THRESHOLD, fire an alert
              and clear the set to suppress duplicate alerts.

        Why a set?
            Port scanning is about unique port diversity, not packet volume.
            An attacker contacting 15 different ports is suspicious.
            A browser hitting port 443 ten thousand times is not.
        """
        src_ip = packet["src_ip"]
        dst_port = packet.get("dst_port")

        # ICMP packets have no destination port — skip
        if dst_port is None:
            return

        self._ports_per_ip[src_ip].add(dst_port)

        if len(self._ports_per_ip[src_ip]) > PORT_SCAN_THRESHOLD:
            alert = {
                "type"         : "PORT_SCAN",
                "src_ip"       : src_ip,
                "ports_count"  : len(self._ports_per_ip[src_ip]),
                "ports"        : sorted(self._ports_per_ip[src_ip]),
                "timestamp"    : datetime.now().isoformat(timespec="seconds"),
            }
            self._alerts.append(alert)
            logger.warning(
                "PORT SCAN detected — src: %s | unique ports: %d",
                src_ip,
                alert["ports_count"],
            )
            # Reset so we don't fire the same alert every subsequent packet
            self._ports_per_ip[src_ip].clear()

    def _detect_traffic_spike(self, packet: dict) -> None:
        """
        Traffic spike detection using a sliding window of timestamps.

        Algorithm:
            - Append current timestamp to a list keyed by src_ip.
            - Remove all timestamps older than TRAFFIC_WINDOW_SECONDS.
            - If the remaining count exceeds TRAFFIC_SPIKE_THRESHOLD, alert.

        Why a sliding window?
            All-time packet count grows forever and becomes meaningless.
            A window of the last N seconds gives a current packets-per-minute
            rate that reacts to sudden bursts while ignoring historical data.
        """
        src_ip = packet["src_ip"]
        now = datetime.now()

        self._timestamps_per_ip[src_ip].append(now)

        # Evict timestamps outside the sliding window
        cutoff = now.timestamp() - TRAFFIC_WINDOW_SECONDS
        self._timestamps_per_ip[src_ip] = [
            t for t in self._timestamps_per_ip[src_ip]
            if t.timestamp() > cutoff
        ]

        recent_count = len(self._timestamps_per_ip[src_ip])

        if recent_count > TRAFFIC_SPIKE_THRESHOLD:
            alert = {
                "type"              : "TRAFFIC_SPIKE",
                "src_ip"            : src_ip,
                "packets_per_window": recent_count,
                "window_seconds"    : TRAFFIC_WINDOW_SECONDS,
                "timestamp"         : now.isoformat(timespec="seconds"),
            }
            self._alerts.append(alert)
            logger.warning(
                "TRAFFIC SPIKE detected — src: %s | %d packets in %ds",
                src_ip,
                recent_count,
                TRAFFIC_WINDOW_SECONDS,
            )
            # Reset to suppress duplicate alerts until the next spike
            self._timestamps_per_ip[src_ip].clear()