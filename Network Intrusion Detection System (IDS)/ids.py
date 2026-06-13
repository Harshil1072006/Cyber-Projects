"""
ids.py — Network Intrusion Detection System
Main engine: captures packets, runs them through signature + anomaly detection,
and fires alerts on matches.

Usage:
    # Auto-detect interface
    python ids.py

    # Specify interface
    python ids.py --interface eth0

    # Windows
    python ids.py --interface "Ethernet"

    # With BPF filter
    python ids.py --filter "tcp port 80"

IMPORTANT: Requires admin/root privileges for raw packet capture.
"""

import sys
import time
import argparse
import threading
from collections import defaultdict, deque
from datetime import datetime

from rich.console import Console
from rich.live import Live
from rich.table import Table
from rich.text import Text

try:
    from scapy.all import sniff, get_if_list, conf
except ImportError:
    print("❌ Scapy not installed. Run: pip install -r requirements.txt")
    sys.exit(1)

import config
from packet_parser import parse_packet, ParsedPacket
from signatures import SIGNATURES, Signature
from alert_manager import fire_alert, print_stats

console = Console()

# ─── Shared state ────────────────────────────────────────────
_lock = threading.Lock()

# Per-IP sliding windows for anomaly detection
_ip_syn_times:   dict[str, deque] = defaultdict(deque)
_ip_icmp_times:  dict[str, deque] = defaultdict(deque)
_ip_ports_seen:  dict[str, deque] = defaultdict(deque)  # (time, port) tuples
_ip_bf_times:    dict[str, dict[int, deque]] = defaultdict(lambda: defaultdict(deque))

# Known ARP table: ip -> mac
_arp_table: dict[str, str] = {}

# Statistics
_stats = defaultdict(int)


# ─── Anomaly Detection ───────────────────────────────────────

def _check_port_scan(parsed: ParsedPacket) -> None:
    """Detect port scan: many unique ports from one source in a time window."""
    if not parsed.src_ip or not parsed.dst_port:
        return
    if parsed.src_ip in config.WHITELISTED_IPS:
        return

    now = time.time()
    window = config.PORT_SCAN_TIME_WINDOW
    threshold = config.PORT_SCAN_THRESHOLD

    with _lock:
        q = _ip_ports_seen[parsed.src_ip]
        q.append((now, parsed.dst_port))
        # Evict old entries
        while q and q[0][0] < now - window:
            q.popleft()
        # Count unique ports
        unique_ports = len({p for _, p in q})

    if unique_ports >= threshold:
        fire_alert(
            sig_id="ANOM-001",
            name="Port Scan Detected",
            description=f"{unique_ports} unique ports probed in {window}s",
            severity="HIGH",
            category="recon",
            src_ip=parsed.src_ip,
            dst_ip=parsed.dst_ip,
            protocol="TCP",
            extra={"unique_ports": unique_ports},
        )


def _check_syn_flood(parsed: ParsedPacket) -> None:
    """Detect SYN flood: high rate of SYN packets from one source."""
    if parsed.protocol != "TCP" or not parsed.flags or "S" not in parsed.flags:
        return
    if "A" in (parsed.flags or ""):
        return  # SYN-ACK is fine
    if not parsed.src_ip or parsed.src_ip in config.WHITELISTED_IPS:
        return

    now = time.time()
    window = config.DOS_TIME_WINDOW
    threshold = config.DOS_SYN_THRESHOLD

    with _lock:
        q = _ip_syn_times[parsed.src_ip]
        q.append(now)
        while q and q[0] < now - window:
            q.popleft()
        count = len(q)

    if count >= threshold:
        fire_alert(
            sig_id="DOS-001",
            name="SYN Flood Detected",
            description=f"{count} SYN packets from {parsed.src_ip} in {window}s",
            severity="CRITICAL",
            category="dos",
            src_ip=parsed.src_ip,
            dst_ip=parsed.dst_ip,
            protocol="TCP",
            extra={"syn_count": count},
        )


def _check_icmp_flood(parsed: ParsedPacket) -> None:
    """Detect ICMP flood."""
    if parsed.protocol != "ICMP" or parsed.icmp_type != 8:
        return  # Only echo requests
    if not parsed.src_ip or parsed.src_ip in config.WHITELISTED_IPS:
        return

    now = time.time()
    window = config.ICMP_TIME_WINDOW
    threshold = config.ICMP_FLOOD_THRESHOLD

    with _lock:
        q = _ip_icmp_times[parsed.src_ip]
        q.append(now)
        while q and q[0] < now - window:
            q.popleft()
        count = len(q)

    if count >= threshold:
        fire_alert(
            sig_id="DOS-002",
            name="ICMP Flood Detected",
            description=f"{count} ICMP echo requests from {parsed.src_ip} in {window}s",
            severity="HIGH",
            category="dos",
            src_ip=parsed.src_ip,
            dst_ip=parsed.dst_ip,
            protocol="ICMP",
            extra={"icmp_count": count},
        )


def _check_brute_force(parsed: ParsedPacket) -> None:
    """Detect brute force: high connection rate to a specific port."""
    if parsed.protocol != "TCP" or not parsed.dst_port:
        return
    if not parsed.src_ip or parsed.src_ip in config.WHITELISTED_IPS:
        return

    bf_ports = [s.dst_ports for s in SIGNATURES if s.category == "brute_force"]
    flat_bf_ports = {p for ports in bf_ports for p in ports}

    if parsed.dst_port not in flat_bf_ports:
        return

    now = time.time()
    window = config.BRUTE_FORCE_TIME_WINDOW
    threshold = config.BRUTE_FORCE_THRESHOLD

    with _lock:
        q = _ip_bf_times[parsed.src_ip][parsed.dst_port]
        q.append(now)
        while q and q[0] < now - window:
            q.popleft()
        count = len(q)

    if count >= threshold:
        port_name = config.SENSITIVE_PORTS.get(parsed.dst_port, str(parsed.dst_port))
        fire_alert(
            sig_id="BF-GEN",
            name=f"Brute Force on {port_name}",
            description=f"{count} connection attempts to port {parsed.dst_port} in {window}s",
            severity="HIGH",
            category="brute_force",
            src_ip=parsed.src_ip,
            dst_ip=parsed.dst_ip,
            src_port=parsed.src_port,
            dst_port=parsed.dst_port,
            protocol="TCP",
            extra={"attempt_count": count, "service": port_name},
        )


def _check_arp_spoofing(parsed: ParsedPacket) -> None:
    """Detect ARP spoofing: IP mapped to a different MAC than previously seen."""
    if parsed.protocol != "ARP" or parsed.arp_op != "reply":
        return

    ip = parsed.arp_src_ip
    mac = parsed.arp_src_mac

    if not ip or not mac:
        return

    with _lock:
        if ip in _arp_table:
            if _arp_table[ip] != mac:
                fire_alert(
                    sig_id="ARP-001",
                    name="ARP Spoofing Detected",
                    description=f"{ip} was {_arp_table[ip]}, now claiming to be {mac}",
                    severity="CRITICAL",
                    category="mitm",
                    src_ip=ip,
                    protocol="ARP",
                    extra={"old_mac": _arp_table[ip], "new_mac": mac},
                )
        _arp_table[ip] = mac


def _check_payload_signatures(parsed: ParsedPacket) -> None:
    """Check packet payload against keyword-based signatures."""
    if not parsed.payload_text:
        return

    payload_lower = parsed.payload_text.lower()

    for sig in SIGNATURES:
        if not sig.payload_keywords:
            continue
        if sig.protocol and sig.protocol != parsed.protocol:
            continue
        if sig.dst_ports and parsed.dst_port not in sig.dst_ports:
            continue

        for kw in sig.payload_keywords:
            if kw.lower() in payload_lower:
                fire_alert(
                    sig_id=sig.id,
                    name=sig.name,
                    description=sig.description,
                    severity=sig.severity,
                    category=sig.category,
                    src_ip=parsed.src_ip,
                    dst_ip=parsed.dst_ip,
                    src_port=parsed.src_port,
                    dst_port=parsed.dst_port,
                    protocol=parsed.protocol,
                    extra={"matched_keyword": kw},
                )
                break  # One alert per signature per packet


def _check_dns_tunneling(parsed: ParsedPacket) -> None:
    """Detect unusually long DNS queries — potential DNS tunneling."""
    if parsed.protocol != "DNS" or not parsed.dns_query:
        return
    if len(parsed.dns_query) > 100:
        fire_alert(
            sig_id="C2-001",
            name="DNS Tunneling Indicator",
            description=f"Unusually long DNS query ({len(parsed.dns_query)} chars)",
            severity="HIGH",
            category="c2",
            src_ip=parsed.src_ip,
            dst_ip=parsed.dst_ip,
            protocol="DNS",
            extra={"query": parsed.dns_query[:80] + "...", "length": len(parsed.dns_query)},
        )


# ─── Main Packet Handler ─────────────────────────────────────

def _process_packet(pkt) -> None:
    """Called for every captured packet."""
    parsed = parse_packet(pkt)
    if not parsed:
        return

    with _lock:
        _stats["total_packets"] += 1
        proto = parsed.protocol.lower()
        if proto in _stats or True:
            _stats[proto] += 1

    # Run all detection engines
    _check_syn_flood(parsed)
    _check_icmp_flood(parsed)
    _check_port_scan(parsed)
    _check_brute_force(parsed)
    _check_arp_spoofing(parsed)
    _check_payload_signatures(parsed)
    _check_dns_tunneling(parsed)


# ─── CLI ─────────────────────────────────────────────────────

def build_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="ids",
        description="Network Intrusion Detection System — Real-time threat monitoring",
    )
    p.add_argument("-i", "--interface", default=config.INTERFACE,
                   help="Network interface to listen on (default: auto-detect)")
    p.add_argument("-f", "--filter", default=config.CAPTURE_FILTER,
                   help="BPF filter string (e.g. 'tcp port 80')")
    p.add_argument("--list-ifaces", action="store_true",
                   help="List available network interfaces and exit")
    p.add_argument("--stats-interval", type=int, default=30,
                   help="Print statistics every N seconds (default: 30)")
    return p.parse_args()


def _stats_printer(interval: int) -> None:
    """Background thread: periodically prints stats."""
    while True:
        time.sleep(interval)
        with _lock:
            snap = dict(_stats)
        print_stats(snap)


def main() -> None:
    args = build_args()

    if args.list_ifaces:
        console.print("[bold]Available network interfaces:[/bold]")
        for iface in get_if_list():
            console.print(f"  • {iface}")
        return

    console.print()
    console.print("[bold green]╔══════════════════════════════════════════════╗[/bold green]")
    console.print("[bold green]║  🚨 Network Intrusion Detection System (IDS)║[/bold green]")
    console.print("[bold green]║  Real-Time Packet Analysis & Threat Alerts  ║[/bold green]")
    console.print("[bold green]╚══════════════════════════════════════════════╝[/bold green]")
    console.print()
    console.print(f"  [dim]Interface : [/dim][cyan]{args.interface or 'auto'}[/cyan]")
    console.print(f"  [dim]Filter    : [/dim][cyan]{args.filter or 'none (all traffic)'}[/cyan]")
    console.print(f"  [dim]Log file  : [/dim][cyan]{config.LOG_FILE}[/cyan]")
    console.print(f"  [dim]Started   : [/dim][cyan]{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}[/cyan]")
    console.print()
    console.print("[bold yellow]⚠  AUTHORIZED USE ONLY — Only monitor networks you own or have permission to monitor.[/bold yellow]")
    console.print()
    console.print("[dim]Press Ctrl+C to stop...[/dim]")
    console.print()

    # Start periodic stats printer
    stats_thread = threading.Thread(
        target=_stats_printer,
        args=(args.stats_interval,),
        daemon=True,
    )
    stats_thread.start()

    try:
        sniff(
            iface=args.interface,
            filter=args.filter or None,
            prn=_process_packet,
            store=False,  # Don't store packets in memory
        )
    except PermissionError:
        console.print("[bold red]❌ Permission denied — run as administrator/root.[/bold red]")
        sys.exit(1)
    except KeyboardInterrupt:
        console.print("\n[bold green]✔ IDS stopped.[/bold green]")
        with _lock:
            snap = dict(_stats)
        print_stats(snap)


if __name__ == "__main__":
    main()
