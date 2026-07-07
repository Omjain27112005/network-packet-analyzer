# tests/test_parser.py

"""
Unit tests for src/parser.py — parse_packet()

Note: These tests use mock Scapy packet objects to avoid
needing a live network interface or root privileges.
"""

import pytest
from unittest.mock import MagicMock, patch
from src.parser import parse_packet, ParsedPacket


# ── Helpers ───────────────────────────────────────────────────────────────────

def _make_mock_ip_packet(src="1.2.3.4", dst="5.6.7.8",
                          length=100, ttl=64,
                          has_tcp=False, has_udp=False, has_icmp=False,
                          sport=12345, dport=80, tcp_flags="S",
                          icmp_type_val=8):
    """Build a minimal mock Scapy Packet for parser unit tests."""
    from scapy.all import IP, TCP, UDP, ICMP

    pkt = MagicMock()

    # Simulate IP layer membership
    def contains(layer):
        if layer is IP:
            return True
        if layer is TCP:
            return has_tcp
        if layer is UDP:
            return has_udp
        if layer is ICMP:
            return has_icmp
        return False

    pkt.__contains__ = contains

    # Mock IP layer fields
    ip_mock = MagicMock()
    ip_mock.src = src
    ip_mock.dst = dst
    ip_mock.len = length
    ip_mock.ttl = ttl

    # Mock transport layer
    tcp_mock = MagicMock()
    tcp_mock.sport = sport
    tcp_mock.dport = dport
    tcp_mock.flags = tcp_flags

    udp_mock = MagicMock()
    udp_mock.sport = sport
    udp_mock.dport = dport

    icmp_mock = MagicMock()
    icmp_mock.type = icmp_type_val

    def getitem(layer):
        if layer is IP:
            return ip_mock
        if layer is TCP:
            return tcp_mock
        if layer is UDP:
            return udp_mock
        if layer is ICMP:
            return icmp_mock
        raise KeyError(layer)

    pkt.__getitem__ = getitem
    return pkt


# ── Core behaviour ────────────────────────────────────────────────────────────

class TestParsePacket:
    def test_returns_none_for_non_ip_packet(self):
        """Non-IP packets (e.g., ARP) must return None."""
        from scapy.all import IP
        pkt = MagicMock()
        pkt.__contains__ = lambda self, layer: False   # no IP layer
        result = parse_packet(pkt)
        assert result is None

    def test_tcp_packet_parsed_correctly(self):
        pkt = _make_mock_ip_packet(has_tcp=True, sport=54321, dport=443, tcp_flags="SA")
        result = parse_packet(pkt)
        assert result is not None
        assert result["protocol"]  == "TCP"
        assert result["src_port"]  == 54321
        assert result["dst_port"]  == 443
        assert result["tcp_flags"] == "SA"
        assert result["icmp_type"] is None

    def test_udp_packet_parsed_correctly(self):
        pkt = _make_mock_ip_packet(has_udp=True, sport=1234, dport=53)
        result = parse_packet(pkt)
        assert result is not None
        assert result["protocol"]  == "UDP"
        assert result["src_port"]  == 1234
        assert result["dst_port"]  == 53
        assert result["tcp_flags"] is None

    def test_icmp_packet_parsed_correctly(self):
        pkt = _make_mock_ip_packet(has_icmp=True, icmp_type_val=8)
        result = parse_packet(pkt)
        assert result is not None
        assert result["protocol"]  == "ICMP"
        assert result["src_port"]  is None
        assert result["dst_port"]  is None
        assert result["icmp_type"] == 8

    def test_ip_fields_extracted(self):
        pkt = _make_mock_ip_packet(src="10.0.0.1", dst="8.8.8.8", length=200, ttl=128, has_tcp=True)
        result = parse_packet(pkt)
        assert result["src_ip"] == "10.0.0.1"
        assert result["dst_ip"] == "8.8.8.8"
        assert result["size"]   == 200
        assert result["ttl"]    == 128

    def test_returns_none_on_exception(self):
        """If anything goes wrong, parse_packet should return None, not raise."""
        broken_pkt = MagicMock(side_effect=RuntimeError("broken"))
        result = parse_packet(broken_pkt)
        assert result is None

    def test_timestamp_format(self):
        pkt = _make_mock_ip_packet(has_tcp=True)
        result = parse_packet(pkt)
        assert result is not None
        # Should be ISO format with milliseconds: YYYY-MM-DDTHH:MM:SS.mmm
        ts = result["timestamp"]
        assert "T" in ts
        assert len(ts) > 10


# ── TypedDict shape ───────────────────────────────────────────────────────────

class TestParsedPacketShape:
    def test_parsed_packet_has_all_required_keys(self):
        required_keys = {
            "timestamp", "src_ip", "dst_ip", "protocol",
            "src_port", "dst_port", "size", "ttl",
            "tcp_flags", "icmp_type",
        }
        pkt = _make_mock_ip_packet(has_tcp=True)
        result = parse_packet(pkt)
        assert result is not None
        assert required_keys.issubset(result.keys()), (
            f"Missing keys: {required_keys - set(result.keys())}"
        )
