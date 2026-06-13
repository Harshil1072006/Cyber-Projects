"""
subdomain_enum.py — Subdomain Enumeration Tool
Discovers subdomains of a target domain via DNS brute-forcing and CT log APIs.

Usage:
    python subdomain_enum.py -d example.com
    python subdomain_enum.py -d example.com --wordlist custom_list.txt --threads 50

AUTHORIZED USE ONLY.
"""

import sys
import argparse
import socket
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

import requests
from rich.console import Console
from rich.table import Table
from rich import box

console = Console()

_DEFAULT_WORDLIST = [
    "www", "mail", "ftp", "admin", "blog", "dev", "api", "test", "staging",
    "app", "portal", "vpn", "ssh", "remote", "ns1", "ns2", "mx", "webmail",
    "mobile", "m", "support", "help", "docs", "static", "cdn", "assets",
    "img", "images", "video", "shop", "store", "pay", "payment", "billing",
    "dashboard", "panel", "cpanel", "whm", "plesk", "webdisk", "autodiscover",
    "autodiscovery", "autoconfig", "imap", "smtp", "pop", "pop3", "exchange",
    "db", "database", "mysql", "postgres", "redis", "mongo", "elastic",
    "git", "gitlab", "github", "bitbucket", "ci", "jenkins", "jira", "conf",
    "internal", "intranet", "corp", "office", "hr", "finance", "legal",
    "beta", "alpha", "preview", "old", "backup", "bak", "archive", "legacy",
    "monitor", "grafana", "kibana", "prometheus", "alertmanager", "status",
    "health", "ping", "metrics", "logs", "logstash", "splunk",
    "s3", "storage", "files", "upload", "uploads", "download", "downloads",
    "auth", "login", "sso", "oauth", "id", "identity", "accounts",
]


def resolve_subdomain(domain: str) -> tuple[str, list[str]] | None:
    """Resolve a domain to IPs. Returns (domain, [ips]) or None."""
    try:
        results = socket.getaddrinfo(domain, None)
        ips = list({r[4][0] for r in results})
        return (domain, ips)
    except (socket.gaierror, socket.herror):
        return None


def fetch_crtsh(domain: str) -> list[str]:
    """Fetch subdomains from crt.sh Certificate Transparency logs."""
    try:
        resp = requests.get(
            f"https://crt.sh/?q=%.{domain}&output=json",
            timeout=15,
            headers={"User-Agent": "Mozilla/5.0 (CyberArsenal/1.0 subdomain-enum)"},
        )
        if resp.status_code == 200:
            data = resp.json()
            subs = set()
            for entry in data:
                name = entry.get("name_value", "")
                for n in name.split("\n"):
                    n = n.strip().lstrip("*.")
                    if n.endswith(f".{domain}") or n == domain:
                        subs.add(n.lower())
            return list(subs)
    except Exception:
        pass
    return []


def main() -> None:
    p = argparse.ArgumentParser(description="Subdomain Enumeration Tool — Authorized Use Only")
    p.add_argument("-d", "--domain",   required=True, help="Target domain (e.g. example.com)")
    p.add_argument("--wordlist",       default=None,  help="Path to custom wordlist file")
    p.add_argument("--threads",        type=int, default=100, help="Concurrent threads (default: 100)")
    p.add_argument("--no-crtsh",       action="store_true", help="Skip Certificate Transparency log lookup")
    args = p.parse_args()

    domain = args.domain.lower().strip()

    console.print()
    console.print(f"[bold green]🔍 Subdomain Enumerator[/bold green]")
    console.print(f"  [dim]Domain  :[/dim] [cyan]{domain}[/cyan]")
    console.print(f"  [dim]Started :[/dim] [cyan]{datetime.now().strftime('%H:%M:%S')}[/cyan]\n")

    subdomains: set[str] = set()

    # ── Certificate Transparency logs ────────────────────────
    if not args.no_crtsh:
        console.print("[dim]▶ Fetching from crt.sh Certificate Transparency logs...[/dim]")
        crt_subs = fetch_crtsh(domain)
        subdomains.update(crt_subs)
        console.print(f"  [green]✔[/green] Found {len(crt_subs)} candidate(s) from crt.sh\n")

    # ── DNS Brute-force ───────────────────────────────────────
    if args.wordlist:
        try:
            with open(args.wordlist) as f:
                words = [l.strip() for l in f if l.strip()]
        except FileNotFoundError:
            console.print(f"[red]❌ Wordlist not found: {args.wordlist}[/red]")
            words = _DEFAULT_WORDLIST
    else:
        words = _DEFAULT_WORDLIST

    candidates = [f"{w}.{domain}" for w in words]
    subdomains.update(candidates)

    console.print(f"[dim]▶ DNS resolving {len(subdomains)} candidate(s) with {args.threads} threads...[/dim]\n")

    found: list[dict] = []

    with ThreadPoolExecutor(max_workers=args.threads) as pool:
        futures = {pool.submit(resolve_subdomain, sub): sub for sub in subdomains}
        for future in as_completed(futures):
            result = future.result()
            if result:
                sub, ips = result
                found.append({"subdomain": sub, "ips": ", ".join(ips)})
                console.print(f"  [green]✔[/green] [bold]{sub}[/bold]  [dim]→ {', '.join(ips)}[/dim]")

    found.sort(key=lambda x: x["subdomain"])

    console.print()
    table = Table(title=f"Discovered Subdomains — {domain}", box=box.ROUNDED, border_style="green")
    table.add_column("Subdomain", style="bold cyan")
    table.add_column("IP Address(es)", style="green")
    for r in found:
        table.add_row(r["subdomain"], r["ips"])
    console.print(table)
    console.print(f"\n[bold]Discovered [green]{len(found)}[/green] live subdomain(s)[/bold]")
    console.print(f"[dim]Finished: {datetime.now().strftime('%H:%M:%S')}[/dim]\n")


if __name__ == "__main__":
    main()
