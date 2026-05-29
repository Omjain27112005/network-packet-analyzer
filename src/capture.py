# src/capture.py

"""
Packet Capture Module
=====================
Responsible for opening a raw socket on the specified network interface
and streaming live packets to a consumer via a callback handler.

Dependencies:
    - scapy   : pip install scapy
    - npcap   : required on Windows (https://npcap.com)
"""

from __future__ import annotations

import logging
from typing import Callable, Optional

from scapy.all import conf, sniff
from scapy.packet import Packet

logger = logging.getLogger(__name__)


def get_default_interface() -> str:
    """
    Retrieve the default network interface as detected by Scapy.

    Returns:
        str: Interface name (e.g. 'Wi-Fi' on Windows, 'wlan0' on Linux).
    """
    return str(conf.iface)


def start_capture(
    packet_handler: Callable[[Packet], None],
    interface: Optional[str] = None,
    packet_count: int = 0,
    timeout: Optional[int] = None,
) -> None:
    """
    Begin live packet capture on the specified network interface.

    Runs indefinitely until interrupted via KeyboardInterrupt (Ctrl+C),
    the packet_count limit is reached, or the timeout expires.

    Args:
        packet_handler: Callback invoked for every captured packet.
                        Signature: handler(packet: Packet) -> None
        interface:      Network interface to capture on.
                        Defaults to Scapy's auto-detected interface.
        packet_count:   Maximum packets to capture. 0 = unlimited.
        timeout:        Stop capture after N seconds. None = no limit.

    Raises:
        RuntimeError: If Scapy fails to open the capture socket
                      (e.g. Npcap not installed on Windows).
    """
    if interface is None:
        interface = get_default_interface()

    logger.info("Starting capture on interface: %s", interface)
    logger.info(
        "Config — count: %s | timeout: %s",
        packet_count if packet_count > 0 else "unlimited",
        f"{timeout}s" if timeout else "none",
    )
    logger.info("Press Ctrl+C to stop capture.\n")

    try:
        sniff(
            iface=interface,
            prn=packet_handler,        # called for every packet
            count=packet_count,        # 0 = run forever
            timeout=timeout,           # None = no timeout
            store=False,               # do NOT store packets in memory
        )

    except KeyboardInterrupt:
        # Raised when user presses Ctrl+C — expected, not an error
        logger.info("Capture interrupted by user.")

    except OSError as exc:
        # Typically: Npcap not installed, or insufficient permissions
        raise RuntimeError(
            "Failed to open capture socket. "
            "On Windows, ensure Npcap is installed (https://npcap.com). "
            "On Linux/Mac, try running with sudo."
        ) from exc

    except Exception as exc:
        logger.error("Unexpected error during capture: %s", exc)
        raise