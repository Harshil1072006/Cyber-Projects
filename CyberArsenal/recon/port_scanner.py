"""
port_scanner.py — Fast TCP Port Scanner
Scans a target host for open ports using concurrent threads.

Usage:
    python port_scanner.py -t 192.168.1.1
    python port_scanner.py -t example.com -p 1-1024
    python port_scanner.py -t 192.168.1.1 --top100

AUTHORIZED USE ONLY.
"""

import socket
import argparse
import sys
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

from rich.console import Console
from rich.table import Table
from rich import box

console = Console()

# Well-known service names
_SERVICES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB",
    465: "SMTPS", 587: "SMTP-Sub", 993: "IMAPS", 995: "POP3S",
    1433: "MSSQL", 1521: "Oracle", 3306: "MySQL", 3389: "RDP",
    5432: "PostgreSQL", 5900: "VNC", 6379: "Redis", 8080: "HTTP-Alt",
    8443: "HTTPS-Alt", 8888: "Jupyter", 9200: "Elasticsearch",
    27017: "MongoDB", 5000: "Flask", 5001: "AltHTTPS",
}

_TOP_100 = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
    1723, 3306, 3389, 5900, 8080, 8443, 8888, 10000, 27017, 6379, 9200,
    5432, 1433, 1521, 5000, 5001, 8000, 8001, 9000, 4000, 4444, 4848,
    7000, 7001, 7080, 8008, 8090, 8180, 8888, 9090, 9443, 61616,
]


def scan_port(host: str, port: int, timeout: float) -> dict | None:
    """Attempt to connect to host:port. Returns dict if open, else None."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            service = _SERVICES.get(port, "")
            # Try to grab banner
            try:
                s = socket.socket()
                s.settimeout(timeout)
                s.connect((host, port))
                banner = s.recv(1024).decode(errors="replace").strip()[:60]
                s.close()
            except Exception:
                banner = ""
            return {"port": port, "service": service, "banner": banner}
    except (socket.timeout, ConnectionRefusedError, OSError):
        return None


def parse_port_range(port_arg: str) -> list[int]:
    ports = []
    for part in port_arg.split(","):
        part = part.strip()
        if "-" in part:
            start, _, end = part.partition("-")
            ports.extend(range(int(start), int(end) + 1))
        else:
            ports.append(int(part))
    return ports


def main() -> None:
    p = argparse.ArgumentParser(description="Fast TCP Port Scanner — Authorized Use Only")
    p.add_argument("-t", "--target",   required=True, help="Target hostname or IP")
    p.add_argument("-p", "--ports",    default="1-1024", help='Port range, e.g. "22,80,443" or "1-65535"')
    p.add_argument("--top100",         action="store_true", help="Scan top 100 common ports")
    p.add_argument("--threads",        type=int, default=200,  help="Concurrent threads (default: 200)")
    p.add_argument("--timeout",        type=float, default=0.5, help="Per-port timeout (default: 0.5s)")
    args = p.parse_args()

    # Resolve host
    try:
        ip = socket.gethostbyname(args.target)
    except socket.gaierror:
        console.print(f"[red]❌ Could not resolve host: {args.target}[/red]")
        sys.exit(1)

    ports = _TOP_100 if args.top100 else parse_port_range(args.ports)

    console.print()
    console.print(f"[bold green]🔍 Port Scanner[/bold green]")
    console.print(f"  [dim]Target  :[/dim] [cyan]{args.target}[/cyan] ({ip})")
    console.print(f"  [dim]Ports   :[/dim] [cyan]{len(ports)} port(s)[/cyan]")
    console.print(f"  [dim]Threads :[/dim] [cyan]{args.threads}[/cyan]")
    console.print(f"  [dim]Started :[/dim] [cyan]{datetime.now().strftime('%H:%M:%S')}[/cyan]\n")

    open_ports = []

    with ThreadPoolExecutor(max_workers=args.threads) as pool:
        futures = {pool.submit(scan_port, ip, port, args.timeout): port for port in ports}
        for future in as_completed(futures):
            result = future.result()
            if result:
                open_ports.append(result)

    open_ports.sort(key=lambda x: x["port"])

    if not open_ports:
        console.print("[yellow]No open ports found.[/yellow]")
        return

    table = Table(title=f"Open Ports on {args.target}", box=box.ROUNDED, border_style="green")
    table.add_column("Port",    style="bold cyan",  min_width=7)
    table.add_column("Service", style="green",       min_width=14)
    table.add_column("Banner",  style="dim",         overflow="fold")

    for r in open_ports:
        table.add_row(str(r["port"]), r["service"] or "?", r["banner"])

    console.print(table)
    console.print(f"\n[bold]Found [green]{len(open_ports)}[/green] open port(s)[/bold]")
    console.print(f"[dim]Finished: {datetime.now().strftime('%H:%M:%S')}[/dim]\n")


if __name__ == "__main__":
    main()
