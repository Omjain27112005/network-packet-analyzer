# src/dashboard.py

"""
Dashboard Module
================
Renders a live-updating terminal UI using the Rich library.

Runs on a separate daemon thread — reads stats from the analyzer
every DASHBOARD_REFRESH_SECONDS and re-renders the entire layout.

Layout:
    ┌─ Header ──────────────────────────────────────┐
    │  Session info, uptime, total packets/bytes    │
    ├─ Left Panel ──────────┬─ Right Panel ─────────┤
    │  Protocol breakdown   │  Top source IPs       │
    ├─ Alerts ──────────────────────────────────────┤
    │  Detected anomalies (port scans, spikes)      │
    └───────────────────────────────────────────────┘
"""

from __future__ import annotations

import threading
import time
import logging
from datetime import datetime
from typing import TYPE_CHECKING

from rich.console import Console
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich import box

from config import DASHBOARD_REFRESH_SECONDS, TOP_N_IPS

if TYPE_CHECKING:
    from src.analyzer import PacketAnalyzer

logger = logging.getLogger(__name__)


class Dashboard:
    """
    Live terminal dashboard for the packet analyzer.

    Usage:
        dashboard = Dashboard(analyzer)
        dashboard.start()       # launches background render thread
        ...                     # capture runs in main thread
        dashboard.stop()        # called on Ctrl+C before report
    """

    def __init__(self, analyzer: PacketAnalyzer) -> None:
        self._analyzer = analyzer
        self._console = Console()
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None

    # ── Public API ────────────────────────────────────────────────────────────

    def start(self) -> None:
        """
        Launch the dashboard render loop on a daemon thread.
        Returns immediately — rendering happens in the background.
        """
        self._thread = threading.Thread(
            target=self._render_loop,
            name="dashboard-thread",
            daemon=True,          # dies automatically when main thread exits
        )
        self._thread.start()
        logger.debug("Dashboard thread started.")

    def stop(self) -> None:
        """Signal the render loop to exit cleanly."""
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=2.0)
        logger.debug("Dashboard thread stopped.")

    # ── Private — render loop ─────────────────────────────────────────────────

    def _render_loop(self) -> None:
        """
        Main loop: refresh the terminal display every N seconds.
        Runs on the dashboard daemon thread.
        """
        with Live(
            self._build_layout(self._analyzer.get_stats()),
            console=self._console,
            refresh_per_second=1,
            screen=False,
        ) as live:
            while not self._stop_event.is_set():
                stats = self._analyzer.get_stats()
                live.update(self._build_layout(stats))
                time.sleep(DASHBOARD_REFRESH_SECONDS)

    # ── Private — layout builders ─────────────────────────────────────────────

    def _build_layout(self, stats: dict) -> Layout:
        """
        Assemble the full terminal layout from current stats.

        Args:
            stats: Dict returned by PacketAnalyzer.get_stats().

        Returns:
            Rich Layout object ready to render.
        """
        layout = Layout()

        layout.split_column(
            Layout(self._build_header(stats),   name="header",  size=7),
            Layout(name="body",                               ratio=1),
            Layout(self._build_alerts(stats),   name="alerts",  size=8),
            Layout(self._build_footer(),        name="footer",  size=1),
        )

        layout["body"].split_row(
            Layout(self._build_protocols(stats), name="protocols", ratio=1),
            Layout(self._build_top_ips(stats),   name="top_ips",   ratio=2),
        )

        return layout

    def _build_header(self, stats: dict) -> Panel:
        """Top bar — session summary metrics."""
        elapsed = int(stats["elapsed_seconds"])
        hours, remainder = divmod(elapsed, 3600)
        minutes, seconds = divmod(remainder, 60)
        uptime_str = f"{hours:02d}:{minutes:02d}:{seconds:02d}"

        total_mb = stats["total_bytes"] / (1024 * 1024)

        table = Table(box=None, show_header=False, padding=(0, 4))
        table.add_column(justify="center")
        table.add_column(justify="center")
        table.add_column(justify="center")
        table.add_column(justify="center")
        table.add_column(justify="center")

        table.add_row(
            self._metric("UPTIME",          uptime_str,                    "cyan"),
            self._metric("PACKETS",         f"{stats['total_packets']:,}", "green"),
            self._metric("DATA",            f"{total_mb:.2f} MB",          "blue"),
            self._metric("UNIQUE IPs",      str(stats["unique_ips"]),       "magenta"),
            self._metric("ALERTS",          str(stats["alert_count"]),
                         "red" if stats["alert_count"] > 0 else "green"),
        )

        return Panel(
            table,
            title="[bold cyan]📡  Network Packet Analyzer[/bold cyan]",
            subtitle=f"[dim]Started: {stats['start_time']}[/dim]",
            border_style="cyan",
        )

    def _build_protocols(self, stats: dict) -> Panel:
        """Left panel — protocol breakdown with percentage bars."""
        protocol_counts = stats["protocol_counts"]
        total = stats["total_packets"] or 1   # avoid division by zero

        table = Table(
            box=box.SIMPLE,
            show_header=True,
            header_style="bold dim",
            expand=True,
        )
        table.add_column("Protocol", style="bold white", width=10)
        table.add_column("Packets",  justify="right", width=10)
        table.add_column("Share",    justify="right", width=8)
        table.add_column("Bar",      ratio=1)

        # Color map per protocol
        color_map = {
            "TCP"  : "green",
            "UDP"  : "blue",
            "ICMP" : "yellow",
            "OTHER": "dim white",
        }

        for protocol, count in sorted(
            protocol_counts.items(), key=lambda x: x[1], reverse=True
        ):
            pct = (count / total) * 100
            bar = self._progress_bar(pct, width=20)
            color = color_map.get(protocol, "white")

            table.add_row(
                f"[{color}]{protocol}[/{color}]",
                f"[{color}]{count:,}[/{color}]",
                f"[dim]{pct:.1f}%[/dim]",
                f"[{color}]{bar}[/{color}]",
            )

        return Panel(
            table,
            title="[bold]Protocol Breakdown[/bold]",
            border_style="dim",
        )

    def _build_top_ips(self, stats: dict) -> Panel:
        """Right panel — top N source IPs by packet count."""
        packets_per_ip = stats["packets_per_ip"]
        bytes_per_ip   = stats["bytes_per_ip"]

        # Sort by packet count descending, take top N
        top_ips = sorted(
            packets_per_ip.items(),
            key=lambda x: x[1],
            reverse=True,
        )[:TOP_N_IPS]

        table = Table(
            box=box.SIMPLE,
            show_header=True,
            header_style="bold dim",
            expand=True,
        )
        table.add_column("#",          width=4,  justify="right")
        table.add_column("Source IP",  ratio=1)
        table.add_column("Packets",    width=10, justify="right")
        table.add_column("Bytes",      width=12, justify="right")
        table.add_column("Type",       width=8)

        for rank, (ip, pkt_count) in enumerate(top_ips, start=1):
            ip_type = self._classify_ip(ip)
            bytes_val = bytes_per_ip.get(ip, 0)

            table.add_row(
                f"[dim]{rank}[/dim]",
                f"[cyan]{ip}[/cyan]",
                f"[white]{pkt_count:,}[/white]",
                f"[dim]{self._format_bytes(bytes_val)}[/dim]",
                ip_type,
            )

        return Panel(
            table,
            title=f"[bold]Top {TOP_N_IPS} Source IPs[/bold]",
            border_style="dim",
        )

    def _build_alerts(self, stats: dict) -> Panel:
        """Bottom panel — list of detected anomalies."""
        alerts = stats["alerts"]

        if not alerts:
            content = Text(
                "  No anomalies detected — network traffic looks normal.",
                style="dim green",
            )
            return Panel(
                content,
                title="[bold green]🛡  Alerts[/bold green]",
                border_style="green",
            )

        table = Table(
            box=box.SIMPLE,
            show_header=True,
            header_style="bold dim",
            expand=True,
        )
        table.add_column("Time",     width=12)
        table.add_column("Type",     width=16)
        table.add_column("Source IP",width=20)
        table.add_column("Detail",   ratio=1)

        for alert in reversed(alerts[-5:]):   # show 5 most recent
            a_type = alert["type"]
            color  = "red" if a_type == "PORT_SCAN" else "yellow"

            detail = (
                f"{alert.get('ports_count', '?')} unique ports scanned"
                if a_type == "PORT_SCAN"
                else f"{alert.get('packets_per_window', '?')} pkts / {alert.get('window_seconds', 60)}s"
            )

            # Trim timestamp to HH:MM:SS
            ts = alert["timestamp"].split("T")[-1] if "T" in alert["timestamp"] else alert["timestamp"]

            table.add_row(
                f"[dim]{ts}[/dim]",
                f"[bold {color}]{a_type}[/bold {color}]",
                f"[{color}]{alert['src_ip']}[/{color}]",
                f"[dim]{detail}[/dim]",
            )

        return Panel(
            table,
            title=f"[bold red]🚨  Alerts  ({len(alerts)} total)[/bold red]",
            border_style="red",
        )

    def _build_footer(self) -> Text:
        """Single-line footer with keyboard shortcuts."""
        return Text(
            "  Ctrl+C to stop capture and generate report",
            style="dim",
        )

    # ── Private — formatting helpers ──────────────────────────────────────────

    @staticmethod
    def _metric(label: str, value: str, color: str) -> Text:
        """Render a labeled metric value for the header row."""
        text = Text()
        text.append(f"{value}\n", style=f"bold {color}")
        text.append(label, style="dim")
        return text

    @staticmethod
    def _progress_bar(pct: float, width: int = 20) -> str:
        """Render a simple ASCII progress bar."""
        filled = int((pct / 100) * width)
        return "█" * filled + "░" * (width - filled)

    @staticmethod
    def _format_bytes(num_bytes: int) -> str:
        """Human-readable byte size."""
        if num_bytes >= 1_048_576:
            return f"{num_bytes / 1_048_576:.1f} MB"
        if num_bytes >= 1_024:
            return f"{num_bytes / 1_024:.1f} KB"
        return f"{num_bytes} B"

    @staticmethod
    def _classify_ip(ip: str) -> str:
        """Label an IP as local or remote based on its range."""
        if ip.startswith("192.168.") or ip.startswith("10.") or ip.startswith("172."):
            return "[dim]local[/dim]"
        if ip.startswith("127."):
            return "[dim]loopback[/dim]"
        return "[cyan]remote[/cyan]"