# src/reporter.py

"""
Reporter Module
===============
Generates a structured session report when capture ends.

Writes a timestamped JSON (or plain-text) file to the reports/
directory containing the full session summary — packet statistics,
protocol breakdown, top talkers, and all detected anomalies.

Output example:
    reports/session_2026-05-29_14-48-41.json
"""

from __future__ import annotations

import json
import logging
import os
from datetime import datetime
from typing import Any

from config import REPORT_DIR, REPORT_FORMAT

logger = logging.getLogger(__name__)


class Reporter:
    """
    Generates and persists session reports from analyzer stats.

    Usage:
        reporter = Reporter()
        filepath = reporter.generate(analyzer.get_stats())
        print(f"Report saved to {filepath}")
    """

    def generate(self, stats: dict[str, Any]) -> str:
        """
        Build a report from the given stats snapshot and write it to disk.

        Args:
            stats: Dict returned by PacketAnalyzer.get_stats().

        Returns:
            Absolute path to the written report file.

        Raises:
            OSError: If the reports directory cannot be created or the
                     file cannot be written.
        """
        os.makedirs(REPORT_DIR, exist_ok=True)

        report = self._build_report(stats)
        filepath = self._build_filepath()

        if REPORT_FORMAT == "json":
            self._write_json(filepath, report)
        else:
            self._write_text(filepath, report)

        logger.info("Report saved → %s", filepath)
        return filepath

    # ── Private — report assembly ─────────────────────────────────────────────

    def _build_report(self, stats: dict[str, Any]) -> dict[str, Any]:
        """
        Transform raw analyzer stats into a clean, structured report dict.

        Args:
            stats: Raw stats from PacketAnalyzer.get_stats().

        Returns:
            Structured report dict ready for serialization.
        """
        end_time = datetime.now()

        # Top 10 source IPs by packet count
        top_ips = sorted(
            stats["packets_per_ip"].items(),
            key=lambda x: x[1],
            reverse=True,
        )[:10]

        return {
            "meta": {
                "tool"        : "Network Packet Analyzer",
                "version"     : "1.0.0",
                "generated_at": end_time.isoformat(timespec="seconds"),
            },
            "session": {
                "start_time"      : stats["start_time"],
                "end_time"        : end_time.isoformat(timespec="seconds"),
                "duration_seconds": stats["elapsed_seconds"],
            },
            "summary": {
                "total_packets": stats["total_packets"],
                "total_bytes"  : stats["total_bytes"],
                "total_mb"     : round(stats["total_bytes"] / (1024 * 1024), 3),
                "unique_ips"   : stats["unique_ips"],
                "alert_count"  : stats["alert_count"],
            },
            "protocol_breakdown": {
                protocol: {
                    "packets": count,
                    "share_pct": round(
                        (count / max(stats["total_packets"], 1)) * 100, 1
                    ),
                }
                for protocol, count in stats["protocol_counts"].items()
            },
            "top_source_ips": [
                {
                    "ip"     : ip,
                    "packets": pkt_count,
                    "bytes"  : stats["bytes_per_ip"].get(ip, 0),
                }
                for ip, pkt_count in top_ips
            ],
            "alerts": stats["alerts"],
        }

    def _build_filepath(self) -> str:
        """
        Build a timestamped output filepath.

        Returns:
            e.g. 'reports/session_2026-05-29_14-48-41.json'
        """
        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        extension = "json" if REPORT_FORMAT == "json" else "txt"
        filename  = f"session_{timestamp}.{extension}"
        return os.path.join(REPORT_DIR, filename)

    # ── Private — writers ─────────────────────────────────────────────────────

    @staticmethod
    def _write_json(filepath: str, report: dict[str, Any]) -> None:
        """Serialize report as indented JSON."""
        with open(filepath, "w", encoding="utf-8") as fh:
            json.dump(report, fh, indent=2, ensure_ascii=False)

    @staticmethod
    def _write_text(filepath: str, report: dict[str, Any]) -> None:
        """Serialize report as human-readable plain text."""
        lines = [
            "=" * 60,
            "  NETWORK PACKET ANALYZER — SESSION REPORT",
            "=" * 60,
            "",
            f"  Generated : {report['meta']['generated_at']}",
            f"  Start     : {report['session']['start_time']}",
            f"  End       : {report['session']['end_time']}",
            f"  Duration  : {report['session']['duration_seconds']}s",
            "",
            "  SUMMARY",
            "  -------",
            f"  Total Packets : {report['summary']['total_packets']:,}",
            f"  Total Data    : {report['summary']['total_mb']} MB",
            f"  Unique IPs    : {report['summary']['unique_ips']}",
            f"  Alerts        : {report['summary']['alert_count']}",
            "",
            "  PROTOCOLS",
            "  ---------",
        ]

        for proto, data in report["protocol_breakdown"].items():
            lines.append(
                f"  {proto:<8} {data['packets']:>6,} packets  ({data['share_pct']}%)"
            )

        lines += ["", "  TOP SOURCE IPs", "  --------------"]
        for rank, entry in enumerate(report["top_source_ips"], start=1):
            lines.append(
                f"  {rank:>2}. {entry['ip']:<20} "
                f"{entry['packets']:>6,} pkts  "
                f"{entry['bytes'] / 1024:.1f} KB"
            )

        if report["alerts"]:
            lines += ["", "  ALERTS", "  ------"]
            for alert in report["alerts"]:
                lines.append(
                    f"  [{alert['timestamp']}] {alert['type']} — {alert['src_ip']}"
                )

        lines += ["", "=" * 60]

        with open(filepath, "w", encoding="utf-8") as fh:
            fh.write("\n".join(lines))