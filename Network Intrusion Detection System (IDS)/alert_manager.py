"""
alert_manager.py — IDS Alert System
Handles alert formatting, console output, and log file writing.
"""

import json
import logging
from datetime import datetime
from dataclasses import dataclass, asdict
from typing import Optional

from rich.console import Console
from rich.panel import Panel
from rich.text import Text

import config

console = Console()

# ─── Configure file logger ───────────────────────────────────
if config.ALERT_TO_LOG:
    logging.basicConfig(
        filename=config.LOG_FILE,
        level=logging.INFO,
        format="%(asctime)s | %(message)s",
    )


@dataclass
class Alert:
    """Represents a detected security alert."""
    timestamp:   str
    alert_id:    str
    severity:    str
    name:        str
    description: str
    category:    str
    src_ip:      Optional[str]
    dst_ip:      Optional[str]
    src_port:    Optional[int]
    dst_port:    Optional[int]
    protocol:    str
    extra:       dict


_alert_counter: int = 0


def fire_alert(
    sig_id: str,
    name: str,
    description: str,
    severity: str,
    category: str,
    src_ip: Optional[str] = None,
    dst_ip: Optional[str] = None,
    src_port: Optional[int] = None,
    dst_port: Optional[int] = None,
    protocol: str = "?",
    extra: Optional[dict] = None,
) -> Alert:
    """Create, display, and log an alert."""
    global _alert_counter
    _alert_counter += 1

    alert = Alert(
        timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        alert_id=f"ALERT-{_alert_counter:04d}",
        severity=severity,
        name=name,
        description=description,
        category=category,
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        protocol=protocol,
        extra=extra or {},
    )

    if config.ALERT_TO_CONSOLE:
        _print_alert(alert)

    if config.ALERT_TO_LOG:
        _log_alert(alert)

    return alert


def _print_alert(alert: Alert) -> None:
    """Print a richly formatted alert to the console."""
    colour = config.SEVERITY_COLOURS.get(alert.severity, "white")

    src = f"{alert.src_ip}:{alert.src_port}" if alert.src_port else str(alert.src_ip)
    dst = f"{alert.dst_ip}:{alert.dst_port}" if alert.dst_port else str(alert.dst_ip)

    body = Text()
    body.append(f"[{alert.alert_id}]  ", style="dim")
    body.append(f"{alert.severity}  ", style=colour)
    body.append(f"{alert.name}\n", style="bold white")
    body.append(f"  {alert.description}\n", style="dim")
    body.append(f"\n  Protocol : ", style="dim")
    body.append(alert.protocol, style="cyan")
    body.append(f"\n  Source   : ", style="dim")
    body.append(src or "—", style="red")
    body.append(f"\n  Dest     : ", style="dim")
    body.append(dst or "—", style="yellow")

    if alert.extra:
        for k, v in alert.extra.items():
            body.append(f"\n  {k:<10}: ", style="dim")
            body.append(str(v), style="green")

    border = "red" if alert.severity in ("CRITICAL", "HIGH") else "yellow"
    console.print(Panel(body, title=f"🚨 {alert.severity} ALERT", border_style=border))


def _log_alert(alert: Alert) -> None:
    """Write alert as JSON to the log file."""
    logging.info(json.dumps(asdict(alert)))


def print_stats(stats: dict) -> None:
    """Print a periodic statistics summary to the console."""
    console.rule("[bold green]IDS Statistics")
    console.print(f"  [dim]Total packets :[/dim] [bold]{stats.get('total_packets', 0)}[/bold]")
    console.print(f"  [dim]Total alerts  :[/dim] [bold red]{stats.get('total_alerts', 0)}[/bold red]")
    console.print(f"  [dim]TCP           :[/dim] {stats.get('tcp', 0)}")
    console.print(f"  [dim]UDP           :[/dim] {stats.get('udp', 0)}")
    console.print(f"  [dim]ICMP          :[/dim] {stats.get('icmp', 0)}")
    console.print(f"  [dim]ARP           :[/dim] {stats.get('arp', 0)}")
    console.print(f"  [dim]DNS           :[/dim] {stats.get('dns', 0)}")
    console.rule()
