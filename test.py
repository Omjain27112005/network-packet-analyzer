# test_run.py  ← DELETE after testing

"""
Smoke test — full pipeline with live dashboard.
Runs until you press Ctrl+C.
"""

import logging
from src.capture import start_capture
from src.parser import parse_packet
from src.analyzer import PacketAnalyzer
from src.dashboard import Dashboard

logging.basicConfig(level=logging.WARNING)   # suppress INFO during live UI


def main() -> None:
    analyzer  = PacketAnalyzer()
    dashboard = Dashboard(analyzer)

    def handle_packet(raw_packet) -> None:
        parsed = parse_packet(raw_packet)
        if parsed:
            analyzer.process(parsed)

    dashboard.start()

    try:
        start_capture(handle_packet)          # runs forever until Ctrl+C
    finally:
        dashboard.stop()
        print("\n✅ Capture stopped.")


if __name__ == "__main__":
    main()