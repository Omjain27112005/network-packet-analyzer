# tests/test_analyzer.py

"""
Unit tests for src/analyzer.py — PacketAnalyzer
"""

import time
import pytest
from src.analyzer import PacketAnalyzer


# ── Helpers ───────────────────────────────────────────────────────────────────

def _make_packet(src_ip="1.2.3.4", dst_ip="5.6.7.8",
                 protocol="TCP", src_port=12345, dst_port=80, size=100):
    """Create a minimal parsed packet dict for testing."""
    return {
        "timestamp" : "2026-01-01T00:00:00.000",
        "src_ip"    : src_ip,
        "dst_ip"    : dst_ip,
        "protocol"  : protocol,
        "src_port"  : src_port,
        "dst_port"  : dst_port,
        "size"      : size,
        "ttl"       : 64,
        "tcp_flags" : "S",
        "icmp_type" : None,
    }


# ── Basic counter tests ───────────────────────────────────────────────────────

class TestCounters:
    def test_initial_state(self):
        analyzer = PacketAnalyzer()
        stats = analyzer.get_stats()
        assert stats["total_packets"] == 0
        assert stats["total_bytes"] == 0
        assert stats["unique_ips"] == 0
        assert stats["alert_count"] == 0

    def test_process_increments_total_packets(self):
        analyzer = PacketAnalyzer()
        analyzer.process(_make_packet())
        assert analyzer.get_stats()["total_packets"] == 1

    def test_process_accumulates_bytes(self):
        analyzer = PacketAnalyzer()
        analyzer.process(_make_packet(size=200))
        analyzer.process(_make_packet(size=300))
        assert analyzer.get_stats()["total_bytes"] == 500

    def test_protocol_counts(self):
        analyzer = PacketAnalyzer()
        analyzer.process(_make_packet(protocol="TCP"))
        analyzer.process(_make_packet(protocol="TCP"))
        analyzer.process(_make_packet(protocol="UDP"))
        counts = analyzer.get_stats()["protocol_counts"]
        assert counts["TCP"] == 2
        assert counts["UDP"] == 1

    def test_unique_ips_count(self):
        analyzer = PacketAnalyzer()
        analyzer.process(_make_packet(src_ip="1.1.1.1"))
        analyzer.process(_make_packet(src_ip="2.2.2.2"))
        analyzer.process(_make_packet(src_ip="1.1.1.1"))   # duplicate
        assert analyzer.get_stats()["unique_ips"] == 2

    def test_packets_per_ip(self):
        analyzer = PacketAnalyzer()
        for _ in range(5):
            analyzer.process(_make_packet(src_ip="10.0.0.1"))
        assert analyzer.get_stats()["packets_per_ip"]["10.0.0.1"] == 5

    def test_bytes_per_ip(self):
        analyzer = PacketAnalyzer()
        analyzer.process(_make_packet(src_ip="10.0.0.1", size=100))
        analyzer.process(_make_packet(src_ip="10.0.0.1", size=200))
        assert analyzer.get_stats()["bytes_per_ip"]["10.0.0.1"] == 300


# ── Port scan detection ───────────────────────────────────────────────────────

class TestPortScanDetection:
    def test_no_alert_below_threshold(self):
        analyzer = PacketAnalyzer()
        # Send packets to 5 different ports (threshold is 10)
        for port in range(1, 6):
            analyzer.process(_make_packet(src_ip="1.2.3.4", dst_port=port))
        assert analyzer.get_stats()["alert_count"] == 0

    def test_port_scan_alert_fires_above_threshold(self):
        analyzer = PacketAnalyzer()
        # Send packets to 11 different ports (threshold is 10)
        for port in range(1, 12):
            analyzer.process(_make_packet(src_ip="1.2.3.4", dst_port=port))
        alerts = analyzer.get_alerts()
        assert len(alerts) == 1
        assert alerts[0]["type"] == "PORT_SCAN"
        assert alerts[0]["src_ip"] == "1.2.3.4"

    def test_port_scan_repeated_ports_not_counted(self):
        analyzer = PacketAnalyzer()
        # Same port 100 times should NOT trigger a port scan alert
        for _ in range(100):
            analyzer.process(_make_packet(src_ip="1.2.3.4", dst_port=443))
        assert analyzer.get_stats()["alert_count"] == 0

    def test_port_scan_icmp_skipped(self):
        analyzer = PacketAnalyzer()
        # ICMP has no dst_port — should never contribute to port scan
        for _ in range(20):
            analyzer.process(_make_packet(
                src_ip="1.2.3.4", protocol="ICMP", dst_port=None
            ))
        assert analyzer.get_stats()["alert_count"] == 0

    def test_port_scan_alert_resets_after_firing(self):
        analyzer = PacketAnalyzer()
        # Trigger first alert
        for port in range(1, 12):
            analyzer.process(_make_packet(src_ip="1.2.3.4", dst_port=port))
        assert len(analyzer.get_alerts()) == 1
        # Sending a few more packets should NOT immediately fire a second alert
        for port in range(100, 104):
            analyzer.process(_make_packet(src_ip="1.2.3.4", dst_port=port))
        assert len(analyzer.get_alerts()) == 1   # still just one


# ── Traffic spike detection ───────────────────────────────────────────────────

class TestTrafficSpikeDetection:
    def test_no_alert_below_threshold(self):
        analyzer = PacketAnalyzer()
        for _ in range(50):
            analyzer.process(_make_packet(src_ip="1.2.3.4"))
        assert analyzer.get_stats()["alert_count"] == 0

    def test_traffic_spike_alert_fires(self):
        analyzer = PacketAnalyzer()
        # 101 packets from same IP within window → spike
        for _ in range(101):
            analyzer.process(_make_packet(src_ip="9.9.9.9"))
        alerts = analyzer.get_alerts()
        assert any(a["type"] == "TRAFFIC_SPIKE" for a in alerts)

    def test_traffic_spike_isolates_ips(self):
        analyzer = PacketAnalyzer()
        # Spread 101 packets across 101 different IPs — no spike per IP
        for i in range(101):
            analyzer.process(_make_packet(src_ip=f"10.0.0.{i % 256}"))
        # Only one packet per IP — no spike alert
        spike_alerts = [a for a in analyzer.get_alerts() if a["type"] == "TRAFFIC_SPIKE"]
        assert len(spike_alerts) == 0


# ── Thread safety ─────────────────────────────────────────────────────────────

class TestThreadSafety:
    def test_concurrent_processing(self):
        """Multiple threads processing packets simultaneously should not crash."""
        import threading
        analyzer = PacketAnalyzer()
        errors = []

        def send_packets(src_ip: str):
            try:
                for port in range(1, 20):
                    analyzer.process(_make_packet(src_ip=src_ip, dst_port=port))
            except Exception as exc:
                errors.append(exc)

        threads = [
            threading.Thread(target=send_packets, args=(f"10.0.0.{i}",))
            for i in range(10)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert errors == [], f"Errors during concurrent processing: {errors}"
        stats = analyzer.get_stats()
        assert stats["total_packets"] == 190   # 10 threads × 19 packets


# ── Reset ─────────────────────────────────────────────────────────────────────

class TestReset:
    def test_reset_clears_all_state(self):
        analyzer = PacketAnalyzer()
        for _ in range(10):
            analyzer.process(_make_packet())
        analyzer.reset()
        stats = analyzer.get_stats()
        assert stats["total_packets"] == 0
        assert stats["alert_count"] == 0
        assert stats["unique_ips"] == 0
