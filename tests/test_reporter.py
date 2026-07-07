# tests/test_reporter.py

"""
Unit tests for src/reporter.py — Reporter
"""

import json
import os
import pytest
import tempfile

from src.reporter import Reporter
import config


# ── Helpers ───────────────────────────────────────────────────────────────────

def _make_stats(total_packets=100, total_bytes=50000,
                alert_count=2, alerts=None):
    """Return a minimal stats dict matching PacketAnalyzer.get_stats() shape."""
    if alerts is None:
        alerts = [
            {
                "type": "PORT_SCAN",
                "src_ip": "1.2.3.4",
                "ports_count": 12,
                "ports": list(range(1, 13)),
                "timestamp": "2026-01-01T12:00:00",
            }
        ]
    return {
        "start_time"      : "2026-01-01T11:00:00",
        "elapsed_seconds" : 60.0,
        "total_packets"   : total_packets,
        "total_bytes"     : total_bytes,
        "protocol_counts" : {"TCP": 70, "UDP": 20, "ICMP": 10},
        "packets_per_ip"  : {"1.2.3.4": 50, "5.6.7.8": 50},
        "bytes_per_ip"    : {"1.2.3.4": 25000, "5.6.7.8": 25000},
        "unique_ips"      : 2,
        "alert_count"     : alert_count,
        "alerts"          : alerts,
    }


# ── JSON report ───────────────────────────────────────────────────────────────

class TestReporterJSON:
    def test_generate_creates_file(self, tmp_path, monkeypatch):
        monkeypatch.setattr(config, "REPORT_DIR", str(tmp_path))
        monkeypatch.setattr(config, "REPORT_FORMAT", "json")

        reporter = Reporter()
        filepath = reporter.generate(_make_stats())

        assert os.path.isfile(filepath)

    def test_json_report_is_valid_json(self, tmp_path, monkeypatch):
        monkeypatch.setattr(config, "REPORT_DIR", str(tmp_path))
        monkeypatch.setattr(config, "REPORT_FORMAT", "json")

        reporter = Reporter()
        filepath = reporter.generate(_make_stats())

        with open(filepath, encoding="utf-8") as fh:
            data = json.load(fh)   # will raise if invalid JSON

        assert "meta" in data
        assert "session" in data
        assert "summary" in data
        assert "protocol_breakdown" in data
        assert "top_source_ips" in data
        assert "alerts" in data

    def test_json_report_summary_values(self, tmp_path, monkeypatch):
        monkeypatch.setattr(config, "REPORT_DIR", str(tmp_path))
        monkeypatch.setattr(config, "REPORT_FORMAT", "json")

        reporter = Reporter()
        stats    = _make_stats(total_packets=500, total_bytes=100_000)
        filepath = reporter.generate(stats)

        with open(filepath, encoding="utf-8") as fh:
            data = json.load(fh)

        assert data["summary"]["total_packets"] == 500
        assert data["summary"]["total_bytes"]   == 100_000
        assert data["summary"]["unique_ips"]    == 2

    def test_json_filepath_contains_timestamp(self, tmp_path, monkeypatch):
        monkeypatch.setattr(config, "REPORT_DIR", str(tmp_path))
        monkeypatch.setattr(config, "REPORT_FORMAT", "json")

        reporter = Reporter()
        filepath = reporter.generate(_make_stats())

        filename = os.path.basename(filepath)
        assert filename.startswith("session_")
        assert filename.endswith(".json")

    def test_json_alerts_included(self, tmp_path, monkeypatch):
        monkeypatch.setattr(config, "REPORT_DIR", str(tmp_path))
        monkeypatch.setattr(config, "REPORT_FORMAT", "json")

        reporter = Reporter()
        filepath = reporter.generate(_make_stats())

        with open(filepath, encoding="utf-8") as fh:
            data = json.load(fh)

        assert len(data["alerts"]) == 1
        assert data["alerts"][0]["type"] == "PORT_SCAN"


# ── Text report ───────────────────────────────────────────────────────────────

class TestReporterText:
    def test_generate_text_creates_file(self, tmp_path, monkeypatch):
        monkeypatch.setattr(config, "REPORT_DIR", str(tmp_path))
        monkeypatch.setattr(config, "REPORT_FORMAT", "txt")

        reporter = Reporter()
        filepath = reporter.generate(_make_stats())

        assert os.path.isfile(filepath)
        assert filepath.endswith(".txt")

    def test_text_report_contains_key_info(self, tmp_path, monkeypatch):
        monkeypatch.setattr(config, "REPORT_DIR", str(tmp_path))
        monkeypatch.setattr(config, "REPORT_FORMAT", "txt")

        reporter = Reporter()
        filepath = reporter.generate(_make_stats(total_packets=999))

        content = open(filepath, encoding="utf-8").read()
        assert "999" in content               # total packets
        assert "NETWORK PACKET ANALYZER" in content
        assert "ALERTS" in content


# ── Edge cases ────────────────────────────────────────────────────────────────

class TestReporterEdgeCases:
    def test_empty_stats_no_crash(self, tmp_path, monkeypatch):
        monkeypatch.setattr(config, "REPORT_DIR", str(tmp_path))
        monkeypatch.setattr(config, "REPORT_FORMAT", "json")

        reporter = Reporter()
        stats = _make_stats(total_packets=0, total_bytes=0,
                            alert_count=0, alerts=[])
        # Should not raise
        filepath = reporter.generate(stats)
        assert os.path.isfile(filepath)

    def test_report_dir_created_if_missing(self, tmp_path, monkeypatch):
        new_dir = str(tmp_path / "nested" / "reports")
        monkeypatch.setattr(config, "REPORT_DIR", new_dir)
        monkeypatch.setattr(config, "REPORT_FORMAT", "json")

        assert not os.path.exists(new_dir)
        reporter = Reporter()
        reporter.generate(_make_stats())
        assert os.path.isdir(new_dir)
