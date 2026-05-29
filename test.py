# test_run.py  ← DELETE after testing

"""
Smoke test for capture + parser working together.
Captures 15 packets and prints the structured parsed dict.
"""

import logging
from src.capture import start_capture
from src.parser import parse_packet

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)


def handle_packet(raw_packet) -> None:
    parsed = parse_packet(raw_packet)

    # parse_packet returns None for non-IP packets — skip them
    if parsed is None:
        return

    print(
        f"  [{parsed['protocol']:<5}] "
        f"{parsed['src_ip']:<18} → {parsed['dst_ip']:<18} "
        f"port {str(parsed['dst_port'] or 'N/A'):<6} "
        f"{parsed['size']} bytes "
        f"flags={parsed['tcp_flags'] or '-'}"
    )


if __name__ == "__main__":
    print("Capturing 20 packets...\n")
    start_capture(handle_packet, packet_count=20)
    print("\nDone.")