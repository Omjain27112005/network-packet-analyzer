# main.py

"""
Network Packet Analyzer — Entry Point
======================================
Wires all modules together and manages the application lifecycle.

    Run:
        python main.py
        python main.py --interface Wi-Fi
        python main.py --count 100
        python main.py --timeout 60
        python main.py --verbose

    Stop:
        Press Ctrl+C — triggers clean shutdown and generates report.
"""

from __future__ import annotations

import argparse
import logging
import sys

from src.analyzer import PacketAnalyzer
from src.capture import start_capture
from src.dashboard import Dashboard
from src.parser import parse_packet
from src.reporter import Reporter


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="Real-time network packet capture and anomaly detection."
    )
    parser.add_argument(
        "--interface", "-i",
        type=str,
        default=None,
        help="Network interface to capture on (default: auto-detect).",
    )
    parser.add_argument(
        "--count", "-c",
        type=int,
        default=0,
        help="Number of packets to capture (default: 0 = unlimited).",
    )
    parser.add_argument(
        "--timeout", "-t",
        type=int,
        default=None,
        help="Stop capture after N seconds (default: no limit).",
    )
    # FIX: Added --verbose flag so log level is configurable without editing code
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        default=False,
        help="Enable verbose (INFO-level) logging for debugging.",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    # FIX: Log level is now controlled by --verbose flag instead of being hardcoded
    log_level = logging.INFO if args.verbose else logging.WARNING
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    )
    logger = logging.getLogger(__name__)
    logger.info("Verbose logging enabled.")

    # Instantiate all components
    analyzer  = PacketAnalyzer()
    dashboard = Dashboard(analyzer)
    reporter  = Reporter()

    def handle_packet(raw_packet) -> None:
        """Capture → Parse → Analyze pipeline per packet."""
        parsed = parse_packet(raw_packet)
        if parsed is not None:
            analyzer.process(parsed)

    # Start live dashboard in background thread
    dashboard.start()

    try:
        # Blocking call — runs until Ctrl+C, count, or timeout
        start_capture(
            packet_handler=handle_packet,
            interface=args.interface,
            packet_count=args.count,
            timeout=args.timeout,
        )

    except RuntimeError as exc:
        # Npcap not installed or permission denied
        print(f"\n[ERROR] {exc}", file=sys.stderr)
        sys.exit(1)

    finally:
        # Always runs — even on Ctrl+C or error
        dashboard.stop()

        # Generate and save the session report
        stats    = analyzer.get_stats()
        filepath = reporter.generate(stats)

        # Print clean summary to terminal
        _print_summary(stats, filepath)


def _print_summary(stats: dict, report_path: str) -> None:
    """Print a clean session summary after capture ends."""
    print("\n" + "═" * 52)
    print("  SESSION SUMMARY")
    print("═" * 52)
    print(f"  Duration    : {stats['elapsed_seconds']}s")
    print(f"  Packets     : {stats['total_packets']:,}")
    print(f"  Data        : {stats['total_bytes'] / (1024*1024):.2f} MB")
    print(f"  Unique IPs  : {stats['unique_ips']}")
    print(f"  Protocols   : {stats['protocol_counts']}")
    print(f"  Alerts      : {stats['alert_count']}")

    if stats["alerts"]:
        print("\n  ANOMALIES DETECTED:")
        for alert in stats["alerts"]:
            print(f"   🚨 {alert['type']} — {alert['src_ip']}")

    print(f"\n  Report → {report_path}")
    print("═" * 52 + "\n")


if __name__ == "__main__":
    main()