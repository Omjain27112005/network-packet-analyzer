# src/parser.py

"""
Packet Parser Module
====================
Responsible for decoding raw Scapy packet objects into clean,
structured Python dictionaries that downstream modules consume.

Every packet entering this module is a raw Scapy object.
Every packet leaving is a typed dict — or None if unparseable.
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Optional, TypedDict

from scapy.all import ARP, ICMP, IP, TCP, UDP
from scapy.packet import Packet

logger = logging.getLogger(__name__)


# ── FIX: Use TypedDict instead of bare dict for strong typing ─────────────────
# Replaces: ParsedPacket = dict
# Now IDEs provide autocompletion and type-checkers can validate usage.
class ParsedPacket(TypedDict):
    """Structured representation of a captured network packet."""
    timestamp : str          # ISO format with millisecond precision
    src_ip    : str          # Source IP address
    dst_ip    : str          # Destination IP address
    protocol  : str          # "TCP", "UDP", "ICMP", or "OTHER"
    src_port  : Optional[int]  # None for ICMP/OTHER
    dst_port  : Optional[int]  # None for ICMP/OTHER
    size      : int          # Total IP packet length in bytes
    ttl       : int          # IP time-to-live field
    tcp_flags : Optional[str]  # e.g. "S", "SA", "A" — None for UDP/ICMP
    icmp_type : Optional[int]  # e.g. 8=echo request — None for TCP/UDP


def parse_packet(raw_packet: Packet) -> Optional[ParsedPacket]:
    """
    Extract structured fields from a raw Scapy packet.

    Only packets with an IP layer are processed. Non-IP packets
    (ARP, raw Ethernet frames, etc.) are silently discarded by
    returning None — callers must check the return value.

    Args:
        raw_packet: A Scapy Packet object from sniff().

    Returns:
        ParsedPacket dict on success, None if packet is non-IP
        or an unexpected parse error occurs.
    """
    try:
        # Discard anything without an IP layer (ARP, raw Ethernet, etc.)
        if IP not in raw_packet:
            return None

        ip_layer = raw_packet[IP]

        # Detect transport protocol and extract layer-specific fields
        protocol, src_port, dst_port, tcp_flags = _extract_transport(raw_packet)

        # ICMP type is useful for ping / traceroute detection
        icmp_type = _extract_icmp_type(raw_packet)

        return ParsedPacket(
            timestamp = datetime.now().isoformat(timespec="milliseconds"),
            src_ip    = ip_layer.src,
            dst_ip    = ip_layer.dst,
            protocol  = protocol,
            src_port  = src_port,          # None for ICMP
            dst_port  = dst_port,          # None for ICMP
            size      = ip_layer.len,      # total IP packet size in bytes
            ttl       = ip_layer.ttl,
            tcp_flags = tcp_flags,         # e.g. "S", "SA", "A" — None for UDP/ICMP
            icmp_type = icmp_type,         # e.g. 8 = echo request — None for TCP/UDP
        )

    except Exception as exc:
        # Never let a malformed packet crash the capture loop
        logger.debug("Failed to parse packet: %s", exc)
        return None


# ── Private helpers ───────────────────────────────────────────────────────────

def _extract_transport(
    packet: Packet,
) -> tuple[str, Optional[int], Optional[int], Optional[str]]:
    """
    Identify the transport protocol and extract port/flag information.

    Args:
        packet: A Scapy Packet known to have an IP layer.

    Returns:
        Tuple of (protocol, src_port, dst_port, tcp_flags).
        Port values and tcp_flags are None when not applicable.
    """
    if TCP in packet:
        tcp = packet[TCP]
        return (
            "TCP",
            tcp.sport,
            tcp.dport,
            _decode_tcp_flags(tcp.flags),
        )

    if UDP in packet:
        udp = packet[UDP]
        return ("UDP", udp.sport, udp.dport, None)

    if ICMP in packet:
        return ("ICMP", None, None, None)

    return ("OTHER", None, None, None)


def _decode_tcp_flags(flags) -> str:
    """
    Convert Scapy's TCP flags object into a readable string.

    Scapy returns flags as a FlagValue object. Converting to str
    gives a compact representation like "S", "SA", "A", "FA".

    Args:
        flags: Scapy TCP flags field value.

    Returns:
        String representation, e.g. "S" for SYN, "SA" for SYN-ACK.
    """
    return str(flags)


def _extract_icmp_type(packet: Packet) -> Optional[int]:
    """
    Extract the ICMP type field if the packet has an ICMP layer.

    Common ICMP types:
        0  — Echo reply   (ping response)
        8  — Echo request (ping)
        3  — Destination unreachable
        11 — Time exceeded (TTL expired — used by traceroute)

    Args:
        packet: A Scapy Packet object.

    Returns:
        ICMP type as int, or None if packet is not ICMP.
    """
    if ICMP in packet:
        return int(packet[ICMP].type)
    return None