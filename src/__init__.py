# src/__init__.py

"""
Network Packet Analyzer — Source Package
=========================================
Exposes the public API for each submodule.
"""

from src.capture import get_default_interface, start_capture
from src.parser import parse_packet

__all__ = [
    "start_capture",
    "get_default_interface",
    "parse_packet",
]