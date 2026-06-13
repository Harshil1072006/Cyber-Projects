"""
main.py — Entry point for the SQLi scanner.

Usage
-----
Basic crawl:
    python main.py -u https://target.example.com

With cookies:
    python main.py -u https://target.example.com -c "session=abc123; csrf=xyz"

No-crawl (single URL, test its own query params):
    python main.py -u "https://target.example.com/search?q=test&cat=1" --no-crawl

Enable cookie + header injection, 10 threads:
    python main.py -u https://target.example.com --test-cookies --test-headers --threads 10

IMPORTANT: Only use against targets you are explicitly authorized to test
           (HackerOne / Bugcrowd programs with explicit scope permission).
"""

import argparse
import sys
import concurrent.futures
import threading
from urllib.parse import urlparse, parse_qs
from datetime import datetime

import requests
from colorama import init as colorama_init, Fore, Style
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, BarColumn, TaskProgressColumn, TextColumn
from rich.panel import Panel
from rich.text import Text
from rich import box

from crawler import Crawler
from sqli_fuzzer import SQLiFuzzer
from reporter import generate_report

colorama_init(autoreset=True)
console = Console()

# Thread-safe print lock for live findings
_print_lock = threading.Lock()


# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sqli-scanner",
        description=(
            "Python-based SQL Injection scanner for authorized bug bounty hunting.\n"
            "Detects: Error-Based, Boolean-Blind, Time-Based, UNION-Based, Stacked-Query.\n"
            "Surfaces: Query params, Form fields, Cookies, HTTP Headers.\n\n"
            "AUTHORIZED USE ONLY."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "-u", "--url", required=True, metavar="URL",
        help="Target base URL (e.g. https://target.example.com)",
    )
    parser.add_argument(
        "-c", "--cookie", default=None, metavar="COOKIES",
        help='Session cookies, e.g. "session=abc123; csrf=xyz"',
    )
    parser.add_argument(
        "--no-crawl", action="store_true",
        help="Skip crawling — test only the -u URL's own query string.",
    )
    parser.add_argument(
        "-o", "--output", default="sqli_report.html", metavar="FILE",
        help="Output HTML report filename (default: sqli_report.html)",
    )
    parser.add_argument(
        "--threads", type=int, default=5, metavar="N",
        help="Parallel fuzzing threads (default: 5)",
    )
    parser.add_argument(
        "--max-pages", type=int, default=100, metavar="N",
        help="Maximum pages to crawl (default: 100)",
    )
    parser.add_argument(
        "--test-cookies", action="store_true",
        help="Also inject payloads into session cookie values",
    )
    parser.add_argument(
        "--test-headers", action="store_true",
        help="Also inject payloads into common HTTP headers (X-Forwarded-For, Referer, …)",
    )
    parser.add_argument(
        "--timeout", type=int, default=15, metavar="SECS",
        help="Per-request timeout in seconds (default: 15)",
    )
    return parser


# ---------------------------------------------------------------------------
# Cookie parsing
# ---------------------------------------------------------------------------

def parse_cookie_string(cookie_str: str) -> dict:
    """Parse a raw cookie string into a dict."""
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
# Endpoint discovery
# ---------------------------------------------------------------------------

def crawl_target(
    base_url: str,
    cookies: dict,
    max_pages: int,
    expose_cookies: bool,
    expose_headers: bool,
) -> list[dict]:
    console.print(f"\n[bold green]► Crawling[/bold green] [cyan]{base_url}[/cyan] (max {max_pages} pages) …")
    crawler = Crawler(
        base_url=base_url,
        cookies=cookies,
        max_pages=max_pages,
        expose_cookies=expose_cookies,
        expose_headers=expose_headers,
    )
    endpoints = crawler.crawl()
    console.print(f"  [green]✔[/green] Discovered [bold]{len(endpoints)}[/bold] endpoint(s).")
    return endpoints


def build_single_endpoint(url: str) -> list[dict]:
    """Build a single endpoint from the URL's own query string."""
    parsed    = urlparse(url)
    qs_params = parse_qs(parsed.query, keep_blank_values=True)
    flat      = {k: v[0] for k, v in qs_params.items()}

    if not flat:
        console.print(
            "[bold yellow]⚠ No query parameters found in the provided URL.[/bold yellow]\n"
            "  Make sure the URL contains parameters, e.g. ?id=1&cat=2"
        )
        return []

    return [{
        "url":      url,
        "method":   "GET",
        "params":   flat,
        "type":     "query_string",
        "found_on": url,
    }]


# ---------------------------------------------------------------------------
# Live finding printer
# ---------------------------------------------------------------------------

def _print_finding(finding: dict, req_total: int) -> None:
    severity = finding.get("severity", "HIGH")
    colour   = "bold red" if severity == "CRITICAL" else "bold yellow"
    tc       = finding.get("technique_code", "E")[0].upper()
    db       = finding.get("db_engine", "Unknown")
    ep_type  = finding.get("endpoint_type", "query_string")
    req_num  = finding.get("request_number", "?")
    curl_poc = finding.get("curl_poc", "")

    ep_labels = {
        "query_string": "Query Param",
        "form":         "Form Field",
        "cookie":       "Cookie",
        "header":       "HTTP Header",
        "json_body":    "JSON Field",
    }

    with _print_lock:
        console.print()
        console.print(Panel(
            Text.from_markup(
                f"[{colour}]{severity}[/{colour}]  "
                f"[white]{finding['type']}[/white]\n"
                f"[dim]Technique:[/dim] [yellow]{tc}[/yellow]  "
                f"[dim]DB:[/dim] [cyan]{db}[/cyan]  "
                f"[dim]Inject via:[/dim] [magenta]{ep_labels.get(ep_type, ep_type)}[/magenta]  "
                f"[dim]Request #[/dim][purple]{req_num}[/purple]\n\n"
                f"[dim]URL  :[/dim] [blue]{finding['url']}[/blue]\n"
                f"[dim]Param:[/dim] [red]{finding['param']}[/red]\n"
                f"[dim]Found on page:[/dim] [dim]{finding.get('found_on','?')}[/dim]\n"
                f"[dim]Payload:[/dim] [orange1]{finding['payload']}[/orange1]\n"
                f"[dim]Evidence:[/dim] [green]{finding['evidence'][:150]}[/green]"
            ),
            title=f"[bold]🚨 VULNERABILITY FOUND[/bold]",
            border_style="red" if severity == "CRITICAL" else "yellow",
            expand=False,
        ))
        if curl_poc:
            console.print(f"  [dim]curl PoC →[/dim] [orange1]{curl_poc}[/orange1]\n")


# ---------------------------------------------------------------------------
# Fuzzing (parallel)
# ---------------------------------------------------------------------------

def fuzz_endpoints(
    endpoints: list[dict],
    session: requests.Session,
    args: argparse.Namespace,
) -> list[dict]:
    fuzzer = SQLiFuzzer(
        session=session,
        timeout=args.timeout,
        test_headers=args.test_headers,
        test_cookies=args.test_cookies,
    )

    console.print(
        f"\n[bold green]► Fuzzing[/bold green] [bold]{len(endpoints)}[/bold] endpoint(s) "
        f"with [bold]{args.threads}[/bold] thread(s) …\n"
    )

    with Progress(
        SpinnerColumn(style="green"),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(bar_width=40, style="green", complete_style="bold green"),
        TaskProgressColumn(),
        console=console,
        transient=False,
    ) as progress:
        task = progress.add_task("Scanning endpoints …", total=len(endpoints))

        def _fuzz_one(endpoint: dict) -> list[dict]:
            new_findings = fuzzer.fuzz_endpoint(endpoint)
            for finding in new_findings:
                _print_finding(finding, fuzzer._req_counter)
            progress.advance(task)
            return new_findings

        with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as pool:
            futures = [pool.submit(_fuzz_one, ep) for ep in endpoints]
            concurrent.futures.wait(futures)

    return fuzzer.findings


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

    table = Table(
        title="SQLi Findings Summary",
        box=box.ROUNDED,
        border_style="green",
        show_lines=True,
    )
    table.add_column("#",           style="dim",        width=4)
    table.add_column("Severity",    min_width=10)
    table.add_column("Technique",   min_width=16)
    table.add_column("DB Engine",   min_width=12)
    table.add_column("Inject Via",  min_width=14)
    table.add_column("Req #",       min_width=6)
    table.add_column("Parameter",   min_width=14, style="magenta")
    table.add_column("URL",         overflow="fold")

    for idx, f in enumerate(findings, start=1):
        sev    = f.get("severity", "HIGH")
        tc     = f.get("technique_code", "E")[0].upper()
        db     = f.get("db_engine", "Unknown")
        ep     = f.get("endpoint_type", "query_string")
        req    = str(f.get("request_number", "?"))

        ep_short = {
            "query_string": "Query", "form": "Form",
            "cookie": "Cookie", "header": "Header", "json_body": "JSON"
        }.get(ep, ep)

        sev_display = (
            f"[bold red]{sev}[/bold red]"
            if sev == "CRITICAL"
            else f"[bold yellow]{sev}[/bold yellow]"
        )
        table.add_row(
            str(idx), sev_display,
            f"[yellow]{_technique_short(tc)}[/yellow]",
            f"[cyan]{db}[/cyan]",
            f"[magenta]{ep_short}[/magenta]",
            f"[dim]#{req}[/dim]",
            f.get("param", ""),
            f.get("url", ""),
        )

    console.print(table)

    # Quick stats
    critical = sum(1 for f in findings if f.get("severity") == "CRITICAL")
    high     = sum(1 for f in findings if f.get("severity") == "HIGH")
    console.print(
        f"\n[bold]Total: [{'red' if critical else 'yellow'}]{len(findings)}[/]"
        f"  |  CRITICAL: [red]{critical}[/red]"
        f"  |  HIGH: [yellow]{high}[/yellow][/bold]\n"
    )


def _technique_short(code: str) -> str:
    return {
        "E": "Error-Based",
        "B": "Boolean-Blind",
        "T": "Time-Based",
        "U": "UNION-Based",
        "S": "Stacked-Query",
    }.get(code, code)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    parser = build_parser()
    args   = parser.parse_args()

    # --- Banner ---
    console.print("\n[bold green]╔═══════════════════════════════════════════════╗[/bold green]")
    console.print(  "[bold green]║   SQLi Scanner — Bug Bounty Edition           ║[/bold green]")
    console.print(  "[bold green]║   Error / Boolean / Time / UNION / Stacked    ║[/bold green]")
    console.print(  "[bold green]║   + Header & Cookie injection surfaces         ║[/bold green]")
    console.print(  "[bold green]║   Authorized use only (HackerOne / Bugcrowd)   ║[/bold green]")
    console.print(  "[bold green]╚═══════════════════════════════════════════════╝[/bold green]\n")
    console.print(f"  [dim]Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}[/dim]")
    console.print(f"  [dim]Target : {args.url}[/dim]")
    console.print(f"  [dim]Threads: {args.threads}[/dim]")
    console.print(f"  [dim]Timeout: {args.timeout}s[/dim]")

    extra_surfaces = []
    if args.test_cookies:
        extra_surfaces.append("cookies")
    if args.test_headers:
        extra_surfaces.append("headers")
    if extra_surfaces:
        console.print(f"  [dim]Extra surfaces: {', '.join(extra_surfaces)}[/dim]")

    # --- Cookies ---
    cookies: dict = {}
    if args.cookie:
        cookies = parse_cookie_string(args.cookie)
        console.print(f"  [dim]Cookies loaded: {list(cookies.keys())}[/dim]")

    # --- Session ---
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
        console.print("\n[dim]--no-crawl mode: using URL query parameters only.[/dim]")
        endpoints = build_single_endpoint(args.url)
    else:
        endpoints = crawl_target(
            base_url=args.url,
            cookies=cookies,
            max_pages=args.max_pages,
            expose_cookies=args.test_cookies,
            expose_headers=args.test_headers,
        )

    if not endpoints:
        console.print("[bold yellow]No endpoints to test. Exiting.[/bold yellow]")
        return 0

    # --- Fuzz ---
    findings = fuzz_endpoints(endpoints, session, args)

    # --- Report ---
    console.print(f"\n[bold green]► Generating report → {args.output}[/bold green]")
    generate_report(findings, output_filename=args.output, target_url=args.url)

    # --- Summary ---
    print_summary(findings)

    if findings:
        console.print(
            "[bold]Open the HTML report for full details, step-by-step repro guides, "
            "and curl PoC commands.[/bold]"
        )

    return 0 if not findings else 1


if __name__ == "__main__":
    sys.exit(main())
