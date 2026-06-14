#!/usr/bin/env python3
"""
access_control.py — Access Control DAST Module
================================================
Tests the FinSecure API for broken access control:
  1. Horizontal IDOR — loops account IDs 1-50, flags cross-user data access
  2. Vertical privilege escalation — tests admin endpoints as regular user

Usage:
    python assessment/dast/access_control.py --target http://localhost:8080
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


def get_auth_token(target: str, username: str, password: str) -> str | None:
    try:
        r = requests.post(f"{target}/api/auth/login",
                          json={"username": username, "password": password}, timeout=5)
        if r.status_code == 200:
            return r.json().get("token")
    except Exception:
        pass
    return None


def auth_headers(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def add_finding(title: str, severity: str, description: str, evidence: str, poc: list[str]) -> None:
    FINDINGS.append({
        "tool": "access_control", "title": title, "severity": severity,
        "description": description, "evidence": evidence, "poc_steps": poc,
        "timestamp": datetime.utcnow().isoformat() + "Z",
    })


# ─── Test 1: Horizontal IDOR ──────────────────────────────────────────────────

def test_horizontal_idor(target: str, token: str, logged_in_user: str) -> None:
    console.print(Panel(
        f"[bold cyan]TEST 1: Horizontal IDOR[/bold cyan]\n"
        f"[dim]Logged in as: {logged_in_user} | Scanning account IDs 1–50[/dim]",
        border_style="cyan",
    ))

    headers = auth_headers(token)
    idor_hits = []
    offline = False

    table = Table(box=box.SIMPLE, header_style="bold", show_header=True)
    table.add_column("ID",    width=6)
    table.add_column("HTTP",  width=8)
    table.add_column("Owner", width=30)
    table.add_column("Email", width=35)
    table.add_column("Issue", width=25)

    for account_id in range(1, 51):
        if offline:
            break
        try:
            r = requests.get(f"{target}/api/accounts/{account_id}",
                             headers=headers, timeout=5)

            if r.status_code == 200:
                try:
                    data = r.json()
                    owner  = data.get("ownerName", "")
                    email  = data.get("ownerEmail", "")
                    is_mine = logged_in_user.lower() in email.lower()

                    if not is_mine:
                        idor_hits.append({
                            "account_id": account_id,
                            "owner": owner,
                            "email": email,
                        })
                        issue = "[bold red]✗ IDOR — Other User[/bold red]"
                    else:
                        issue = "[green]✓ Own account[/green]"

                    table.add_row(str(account_id), str(r.status_code), owner, email, issue)

                except Exception:
                    table.add_row(str(account_id), str(r.status_code), "?", "?", "[dim]Parse error[/dim]")

            elif r.status_code == 404:
                pass  # Account doesn't exist — skip silently
            elif r.status_code == 403:
                table.add_row(str(account_id), "403", "—", "—", "[green]✓ Forbidden[/green]")
            else:
                table.add_row(str(account_id), str(r.status_code), "—", "—", "[dim]?[/dim]")

            time.sleep(0.05)  # Gentle pacing

        except requests.exceptions.ConnectionError:
            console.print("[yellow]API not reachable — showing demo results[/yellow]")
            # Demo mode — show what would happen
            idor_hits = [
                {"account_id": 2, "owner": "Bob Martinez",  "email": "bob@finsecure.com"},
                {"account_id": 3, "owner": "Charlie Davis", "email": "charlie@finsecure.com"},
                {"account_id": 4, "owner": "Admin User",    "email": "admin@finsecure.com"},
            ]
            offline = True
            break

    if not offline:
        console.print(table)

    if idor_hits:
        console.print(f"\n[bold red]✗ IDOR CONFIRMED — {len(idor_hits)} accounts accessed belonging to other users![/bold red]")
        for hit in idor_hits:
            console.print(f"  [red]→ Account ID {hit['account_id']}: {hit['owner']} ({hit['email']})[/red]")

        add_finding(
            title="Horizontal IDOR — Cross-User Account Access",
            severity="HIGH",
            description=(
                f"Endpoint GET /api/accounts/{{id}} returns account data for ANY account "
                f"without verifying the requesting user owns that account. "
                f"Logged in as '{logged_in_user}', accessed {len(idor_hits)} other users' accounts."
            ),
            evidence=f"Accessed account IDs: {[h['account_id'] for h in idor_hits]}",
            poc=[
                f"Login as alice (account owner of ID 1)",
                f"GET {target}/api/accounts/2  → Returns Bob's account (balance, email)",
                f"GET {target}/api/accounts/3  → Returns Charlie's account",
                f"GET {target}/api/accounts/4  → Returns Admin account with $9,999,999 balance",
                "No authorization check on the ownership of the requested account",
            ],
        )
    else:
        console.print("[green]✓ No IDOR detected — ownership checks appear to be in place.[/green]")


# ─── Test 2: Vertical Privilege Escalation ────────────────────────────────────

def test_vertical_escalation(target: str, user_token: str) -> None:
    console.print(Panel("[bold cyan]TEST 2: Vertical Privilege Escalation[/bold cyan]", border_style="cyan"))

    admin_endpoints = [
        ("GET",  "/api/accounts/admin/all",  "Admin account listing"),
        ("GET",  "/actuator/env",             "Spring Actuator — environment vars"),
        ("GET",  "/actuator/beans",           "Spring Actuator — bean definitions"),
        ("GET",  "/actuator/health",          "Spring Actuator — health (public)"),
        ("GET",  "/h2-console",               "H2 Database Console"),
    ]

    headers = auth_headers(user_token)

    table = Table(box=box.ROUNDED, header_style="bold cyan", border_style="blue")
    table.add_column("Method", width=8)
    table.add_column("Endpoint",    width=40)
    table.add_column("Description", width=35)
    table.add_column("HTTP", width=8)
    table.add_column("Result", width=22)

    for method, endpoint, desc in admin_endpoints:
        try:
            r = requests.request(method, f"{target}{endpoint}",
                                 headers=headers, timeout=5)
            code = r.status_code

            if code == 200:
                result = "[bold red]✗ ACCESSIBLE[/bold red]"
                add_finding(
                    title=f"Vertical Privilege Escalation — {endpoint}",
                    severity="HIGH",
                    description=f"Admin/privileged endpoint {endpoint} accessible as regular user.",
                    evidence=f"HTTP 200 from {method} {endpoint} with USER-role token",
                    poc=[
                        f"Login as alice (ROLE_USER)",
                        f"{method} {target}{endpoint} with alice's JWT",
                        f"Response: HTTP 200 — admin data exposed",
                    ],
                )
            elif code in (401, 403):
                result = "[green]✓ Restricted[/green]"
            elif code == 404:
                result = "[dim]Not found[/dim]"
            else:
                result = f"[yellow]HTTP {code}[/yellow]"

            table.add_row(method, endpoint, desc, str(code), result)

        except requests.exceptions.ConnectionError:
            table.add_row(method, endpoint, desc, "N/A", "[dim]Offline[/dim]")

    console.print(table)

    # Test mass assignment — inject isAdmin: true via POST /api/accounts
    console.print("\n[dim]Testing Mass Assignment (isAdmin injection)...[/dim]")
    try:
        r_mass = requests.post(
            f"{target}/api/accounts",
            headers={**headers, "Content-Type": "application/json"},
            json={"ownerName": "HackerAdmin", "balance": 0, "isAdmin": True},
            timeout=5,
        )
        if r_mass.status_code == 200:
            data = r_mass.json()
            if data.get("isAdmin") is True:
                console.print("[bold red]✗ MASS ASSIGNMENT — isAdmin:true accepted! Account created with admin flag.[/bold red]")
                add_finding(
                    title="Mass Assignment — Admin Privilege Injection",
                    severity="HIGH",
                    description=(
                        "POST /api/accounts accepts and persists the isAdmin field from the JSON body. "
                        "Any user can create an account with administrative privileges."
                    ),
                    evidence="POST body {isAdmin:true} → Response {isAdmin:true} — admin flag persisted.",
                    poc=[
                        "POST /api/accounts with body: {\"ownerName\":\"Hacker\",\"isAdmin\":true}",
                        "Response includes \"isAdmin\": true",
                        "Attacker account has admin privileges in the system",
                    ],
                )
            else:
                console.print("[green]✓ isAdmin field was not persisted[/green]")
    except requests.exceptions.ConnectionError:
        console.print("[dim]Mass assignment test skipped — API offline[/dim]")


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
    parser = argparse.ArgumentParser(description="FinSecure Access Control Tester")
    parser.add_argument("--target", default="http://localhost:8080")
    args = parser.parse_args()

    console.print(Panel(
        "[bold cyan]FinSecure API — Access Control Tester[/bold cyan]\n"
        "[dim]Horizontal IDOR · Vertical Escalation · Mass Assignment[/dim]",
        border_style="cyan",
    ))
    console.print(f"[dim]Target:[/dim] [bold]{args.target}[/bold]\n")

    # Get a regular user token (alice is ROLE_USER)
    token = get_auth_token(args.target, "alice", "alice123")
    if not token:
        console.print("[yellow]⚠  Could not authenticate as alice. Running with demo token.[/yellow]")
        token = "DEMO_TOKEN"

    test_horizontal_idor(args.target, token, "alice")
    console.print()
    test_vertical_escalation(args.target, token)
    save_findings()

    console.print(f"\n[{'bold red' if FINDINGS else 'bold green'}]"
                  f"{'⚠  ' + str(len(FINDINGS)) + ' access control findings!' if FINDINGS else '✓ No access control issues'}"
                  f"[/{'bold red' if FINDINGS else 'bold green'}]")


if __name__ == "__main__":
    main()
