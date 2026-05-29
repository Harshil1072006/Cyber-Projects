"""
main.py — Entry point for the SQLi scanner.

Usage
-----
Basic crawl:
    python main.py -u https://target.example.com

Authenticated crawl (session cookie):
    python main.py -u https://target.example.com -c "session=abc123xyz"

Single-URL no-crawl mode (tests only the given URL's query parameters):
    python main.py -u "https://target.example.com/search?q=test&cat=1" --no-crawl

IMPORTANT: Only use against targets you are authorized to test
           (HackerOne / Bugcrowd programs with explicit scope permission).
"""

import argparse
import sys
from urllib.parse import urlparse, parse_qs

import requests
from colorama import init as colorama_init, Fore, Style
from rich.console import Console
from rich.table import Table
from rich.progress import track

from crawler import Crawler
from sqli_fuzzer import SQLiFuzzer
from reporter import generate_report

colorama_init(autoreset=True)
console = Console()


# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sqli-scanner",
        description=(
            "Python-based SQL Injection scanner for authorized bug bounty hunting. "
            "Mirrors Burp Suite Pro active scan techniques."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "-u", "--url",
        required=True,
        metavar="URL",
        help="Target base URL (e.g. https://target.example.com)",
    )
    parser.add_argument(
        "-c", "--cookie",
        default=None,
        metavar="NAME=VALUE",
        help=(
            "Session cookie in NAME=VALUE format. "
            "For multiple cookies separate with '; ' (quote the whole string)."
        ),
    )
    parser.add_argument(
        "--no-crawl",
        action="store_true",
        help=(
            "Skip crawling. Treat the -u URL's own query string parameters "
            "as the only endpoint to test."
        ),
    )
    parser.add_argument(
        "-o", "--output",
        default="sqli_report.html",
        metavar="FILE",
        help="Output HTML report filename (default: sqli_report.html)",
    )
    return parser


# ---------------------------------------------------------------------------
# Cookie parsing
# ---------------------------------------------------------------------------

def parse_cookie_string(cookie_str: str) -> dict:
    """
    Parse a raw cookie string into a dict.

    Handles both single cookies (name=value) and multiple cookies separated
    by '; ' (semicolon + space), as browsers send them.
    """
    cookies: dict[str, str] = {}
    for part in cookie_str.split(";"):
        part = part.strip()
        if not part:
            continue
        if "=" in part:
            name, _, value = part.partition("=")
            cookies[name.strip()] = value.strip()
        else:
            cookies[part] = ""
    return cookies


# ---------------------------------------------------------------------------
# Endpoint discovery helpers
# ---------------------------------------------------------------------------

def crawl_target(base_url: str, cookies: dict) -> list[dict]:
    console.print(
        f"\n[bold green]► Crawling[/bold green] [cyan]{base_url}[/cyan] …"
    )
    crawler = Crawler(base_url=base_url, cookies=cookies)
    endpoints = crawler.crawl()
    console.print(
        f"  [green]✔[/green] Discovered [bold]{len(endpoints)}[/bold] endpoint(s)."
    )
    return endpoints


def build_single_endpoint(url: str) -> list[dict]:
    """Build a single endpoint dict from the URL's own query string."""
    parsed = urlparse(url)
    qs_params = parse_qs(parsed.query, keep_blank_values=True)
    flat_params = {k: v[0] for k, v in qs_params.items()}

    if not flat_params:
        console.print(
            "[bold yellow]⚠ No query parameters found in the provided URL.[/bold yellow]\n"
            "  Make sure your URL contains parameters, e.g. ?id=1&cat=2"
        )
        return []

    return [
        {
            "url": url,
            "method": "GET",
            "params": flat_params,
            "type": "query_string",
        }
    ]


# ---------------------------------------------------------------------------
# Fuzzing
# ---------------------------------------------------------------------------

def fuzz_endpoints(
    endpoints: list[dict], session: requests.Session
) -> list[dict]:
    fuzzer = SQLiFuzzer(session=session, timeout=15)

    console.print(
        f"\n[bold green]► Fuzzing[/bold green] [bold]{len(endpoints)}[/bold] endpoint(s) …\n"
    )

    for endpoint in track(endpoints, description="Scanning…", console=console):
        new_findings = fuzzer.fuzz_endpoint(endpoint)
        for finding in new_findings:
            _print_finding(finding)

    return fuzzer.findings


def _print_finding(finding: dict) -> None:
    severity = finding.get("severity", "HIGH")
    colour = "[bold red]" if severity == "CRITICAL" else "[bold yellow]"
    console.print(
        f"\n  {colour}[{severity}][/bold {'red' if severity == 'CRITICAL' else 'yellow'}] "
        f"{finding['type']}"
    )
    console.print(f"    URL  : [cyan]{finding['url']}[/cyan]")
    console.print(f"    Param: [magenta]{finding['param']}[/magenta]")
    console.print(f"    PoC  : [yellow]{finding['payload']}[/yellow]")


# ---------------------------------------------------------------------------
# Summary table
# ---------------------------------------------------------------------------

def print_summary(findings: list[dict]) -> None:
    console.print()
    if not findings:
        console.print(
            "[bold green]✔ Scan complete — no SQL injection vulnerabilities found.[/bold green]"
        )
        return

    table = Table(title="SQLi Findings Summary", style="green", border_style="green")
    table.add_column("#", style="dim", width=4)
    table.add_column("Severity", min_width=10)
    table.add_column("Type", min_width=30)
    table.add_column("Parameter", min_width=15)
    table.add_column("URL", overflow="fold")

    for idx, f in enumerate(findings, start=1):
        sev = f.get("severity", "HIGH")
        sev_display = f"[bold red]{sev}[/bold red]" if sev == "CRITICAL" else f"[bold yellow]{sev}[/bold yellow]"
        table.add_row(str(idx), sev_display, f.get("type", ""), f.get("param", ""), f.get("url", ""))

    console.print(table)
    console.print(
        f"\n[bold]Total vulnerabilities found: "
        f"[{'red' if any(f['severity']=='CRITICAL' for f in findings) else 'yellow'}]"
        f"{len(findings)}[/]\n"
    )


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    # Banner
    console.print(
        "\n[bold green]╔══════════════════════════════════════════╗[/bold green]"
    )
    console.print(
        "[bold green]║   SQLi Scanner — Bug Bounty Edition      ║[/bold green]"
    )
    console.print(
        "[bold green]║   Authorized use only (HackerOne/Bugcrowd)║[/bold green]"
    )
    console.print(
        "[bold green]╚══════════════════════════════════════════╝[/bold green]\n"
    )

    # --- Parse cookies ---
    cookies: dict = {}
    if args.cookie:
        cookies = parse_cookie_string(args.cookie)
        console.print(f"  [dim]Cookies loaded: {list(cookies.keys())}[/dim]")

    # --- Build session ---
    session = requests.Session()
    if cookies:
        session.cookies.update(cookies)
    session.headers.update({
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/124.0.0.0 Safari/537.36"
        )
    })

    # --- Discover endpoints ---
    if args.no_crawl:
        console.print("[dim]--no-crawl mode: using URL query parameters only.[/dim]")
        endpoints = build_single_endpoint(args.url)
    else:
        endpoints = crawl_target(args.url, cookies)

    if not endpoints:
        console.print("[bold yellow]No endpoints to test. Exiting.[/bold yellow]")
        return 0

    # --- Fuzz ---
    findings = fuzz_endpoints(endpoints, session)

    # --- Report ---
    console.print(f"\n[bold green]► Generating report → {args.output}[/bold green]")
    generate_report(findings, output_filename=args.output)

    # --- Summary ---
    print_summary(findings)

    return 0 if not findings else 1


if __name__ == "__main__":
    sys.exit(main())
