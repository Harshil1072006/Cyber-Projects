"""
header_checker.py — HTTP Security Header Auditor (CyberArsenal standalone)
Quickly audit HTTP headers of any URL from the command line.

Usage:
    python header_checker.py https://example.com
    python header_checker.py https://example.com --json
"""

import sys
import json
import argparse
import warnings
import requests
from urllib3.exceptions import InsecureRequestWarning
warnings.filterwarnings("ignore", category=InsecureRequestWarning)

from rich.console import Console
from rich.table import Table
from rich import box

console = Console()

SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "severity": "HIGH",
        "check":   lambda v: v and "max-age=" in v,
        "recommendation": "Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
    },
    "Content-Security-Policy": {
        "severity": "HIGH",
        "check":   lambda v: v and len(v) > 5,
        "recommendation": "Content-Security-Policy: default-src 'self'",
    },
    "X-Frame-Options": {
        "severity": "MEDIUM",
        "check":   lambda v: v and v.upper().strip() in ("DENY", "SAMEORIGIN"),
        "recommendation": "X-Frame-Options: DENY",
    },
    "X-Content-Type-Options": {
        "severity": "MEDIUM",
        "check":   lambda v: v and v.strip().lower() == "nosniff",
        "recommendation": "X-Content-Type-Options: nosniff",
    },
    "Referrer-Policy": {
        "severity": "LOW",
        "check":   lambda v: v is not None,
        "recommendation": "Referrer-Policy: strict-origin-when-cross-origin",
    },
    "Permissions-Policy": {
        "severity": "LOW",
        "check":   lambda v: v is not None,
        "recommendation": "Permissions-Policy: geolocation=(), camera=()",
    },
}

INFO_HEADERS = ["Server", "X-Powered-By", "X-AspNet-Version", "Via"]


def audit(url: str, timeout: int = 10) -> dict:
    try:
        resp = requests.get(url, timeout=timeout, verify=False,
                            headers={"User-Agent": "CyberArsenal/1.0 header-checker"})
    except requests.RequestException as e:
        console.print(f"[red]❌ Connection failed: {e}[/red]")
        sys.exit(1)

    headers = resp.headers
    result = {"url": url, "status_code": resp.status_code, "security": [], "info_leakage": []}

    for hdr, rules in SECURITY_HEADERS.items():
        val = headers.get(hdr)
        ok = rules["check"](val) if val else False
        result["security"].append({
            "header": hdr,
            "status": "ok" if ok else ("missing" if val is None else "misconfigured"),
            "severity": rules["severity"],
            "value": val,
            "recommendation": "" if ok else rules["recommendation"],
        })

    for hdr in INFO_HEADERS:
        val = headers.get(hdr)
        if val:
            result["info_leakage"].append({"header": hdr, "value": val})

    return result


def display(result: dict, as_json: bool = False) -> None:
    if as_json:
        console.print(json.dumps(result, indent=2))
        return

    console.print(f"\n[bold]🔍 Header Audit:[/bold] [cyan]{result['url']}[/cyan]")
    console.print(f"[dim]HTTP Status: {result['status_code']}[/dim]\n")

    table = Table(title="Security Headers", box=box.ROUNDED, border_style="cyan")
    table.add_column("Header",         style="bold cyan",   min_width=30)
    table.add_column("Status",         min_width=14)
    table.add_column("Severity",       min_width=10)
    table.add_column("Value / Action", style="dim",         overflow="fold")

    for h in result["security"]:
        status_colour = {"ok": "green", "missing": "red", "misconfigured": "yellow"}.get(h["status"], "white")
        sev_colour    = {"HIGH": "red", "MEDIUM": "yellow", "LOW": "dim"}.get(h["severity"], "white")
        action = h["value"] or h["recommendation"] or "—"
        table.add_row(
            h["header"],
            f"[{status_colour}]{h['status'].upper()}[/{status_colour}]",
            f"[{sev_colour}]{h['severity']}[/{sev_colour}]",
            action,
        )
    console.print(table)

    if result["info_leakage"]:
        console.print("\n[bold yellow]⚠ Information Disclosure Headers:[/bold yellow]")
        for il in result["info_leakage"]:
            console.print(f"  [dim]{il['header']}:[/dim] [red]{il['value']}[/red]  → [dim]Remove this header[/dim]")

    issues = [h for h in result["security"] if h["status"] != "ok"]
    console.print(f"\n[bold]Summary:[/bold] [red]{len(issues)}[/red] issue(s) found out of {len(result['security'])} headers checked.\n")


def main() -> None:
    p = argparse.ArgumentParser(description="HTTP Security Header Auditor")
    p.add_argument("url",     help="Target URL (e.g. https://example.com)")
    p.add_argument("--json",  action="store_true", help="Output as JSON")
    p.add_argument("--timeout", type=int, default=10, help="Timeout in seconds")
    args = p.parse_args()

    result = audit(args.url, args.timeout)
    display(result, as_json=args.json)


if __name__ == "__main__":
    main()
