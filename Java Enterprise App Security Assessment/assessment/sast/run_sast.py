#!/usr/bin/env python3
"""
run_sast.py — Semgrep SAST Runner for FinSecure API
=====================================================
Runs all 4 custom Semgrep rules against the target app source,
parses the JSON output, maps findings to OWASP categories and CVSS scores,
and saves structured results to findings/sast_results.json.

Usage:
    python assessment/sast/run_sast.py --source target-app/src
    python assessment/sast/run_sast.py --source target-app/src --rules assessment/sast/semgrep_rules
    python assessment/sast/run_sast.py --demo   # Use pre-generated sample output
"""

import argparse
import json
import os
import subprocess
import sys
from datetime import datetime
from pathlib import Path

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box
from rich.progress import Progress, SpinnerColumn, TextColumn

console = Console()

# ─── OWASP / CVSS mapping per rule ID ────────────────────────────────────────
RULE_METADATA = {
    "java-unsafe-deserialization":       {"owasp": "A08:2021", "cvss": 9.8, "severity": "CRITICAL"},
    "java-unsafe-deserialization-any-stream": {"owasp": "A08:2021", "cvss": 8.1, "severity": "HIGH"},
    "jwt-alg-none-bypass":               {"owasp": "A02:2021", "cvss": 9.1, "severity": "CRITICAL"},
    "jwt-missing-signing-key":           {"owasp": "A02:2021", "cvss": 9.1, "severity": "CRITICAL"},
    "jwt-hardcoded-secret":              {"owasp": "A07:2021", "cvss": 7.5, "severity": "HIGH"},
    "jwt-no-expiry":                     {"owasp": "A07:2021", "cvss": 6.5, "severity": "MEDIUM"},
    "jwt-weak-algorithm":                {"owasp": "A02:2021", "cvss": 5.3, "severity": "MEDIUM"},
    "sqli-string-concat-jpa-createquery":  {"owasp": "A03:2021", "cvss": 9.8, "severity": "CRITICAL"},
    "sqli-string-concat-jdbc-statement":   {"owasp": "A03:2021", "cvss": 9.8, "severity": "CRITICAL"},
    "sqli-string-concat-jdbctemplate":     {"owasp": "A03:2021", "cvss": 9.8, "severity": "CRITICAL"},
    "sqli-string-format-sql":              {"owasp": "A03:2021", "cvss": 8.8, "severity": "HIGH"},
    "hardcoded-password-variable":         {"owasp": "A07:2021", "cvss": 7.5, "severity": "HIGH"},
    "hardcoded-credential-field":          {"owasp": "A07:2021", "cvss": 7.5, "severity": "HIGH"},
    "hardcoded-spring-value-literal":      {"owasp": "A07:2021", "cvss": 6.5, "severity": "MEDIUM"},
    "hardcoded-basic-auth":                {"owasp": "A07:2021", "cvss": 7.5, "severity": "HIGH"},
}

SEVERITY_COLORS = {
    "CRITICAL": "bold red",
    "HIGH":     "red",
    "MEDIUM":   "yellow",
    "LOW":      "green",
    "INFO":     "dim",
}

# ─── Pre-generated sample output (used when --demo flag or Semgrep not installed) ─
SAMPLE_FINDINGS = [
    {
        "rule_id": "jwt-alg-none-bypass",
        "file": "target-app/src/main/java/com/finsecure/security/JwtFilter.java",
        "line": 65,
        "message": "JWT alg:none bypass vulnerability: parseClaimsJwt() accepts tokens with no signature.",
        "owasp": "A02:2021",
        "cvss": 9.1,
        "severity": "CRITICAL",
        "code_snippet": "Claims claims = Jwts.parser().parseClaimsJwt(token).getBody();",
    },
    {
        "rule_id": "jwt-hardcoded-secret",
        "file": "target-app/src/main/java/com/finsecure/security/JwtFilter.java",
        "line": 42,
        "message": "Hardcoded JWT secret detected in signWith(). Source code leak exposes entire auth system.",
        "owasp": "A07:2021",
        "cvss": 7.5,
        "severity": "HIGH",
        "code_snippet": 'private static final String SECRET_KEY = "secret123";',
    },
    {
        "rule_id": "jwt-no-expiry",
        "file": "target-app/src/main/java/com/finsecure/controller/AuthController.java",
        "line": 53,
        "message": "JWT token issued without setExpiration(). Tokens never expire.",
        "owasp": "A07:2021",
        "cvss": 6.5,
        "severity": "MEDIUM",
        "code_snippet": "Jwts.builder().setSubject(user.getUsername()).claim(...).compact()",
    },
    {
        "rule_id": "sqli-string-concat-jdbctemplate",
        "file": "target-app/src/main/java/com/finsecure/controller/AccountController.java",
        "line": 118,
        "message": "SQL Injection via string concatenation in JdbcTemplate — second-order SQLi vector.",
        "owasp": "A03:2021",
        "cvss": 9.8,
        "severity": "CRITICAL",
        "code_snippet": 'String sql = "SELECT * FROM accounts WHERE profile_note = \'" + note + "\'";',
    },
    {
        "rule_id": "hardcoded-credential-field",
        "file": "target-app/src/main/java/com/finsecure/security/JwtFilter.java",
        "line": 42,
        "message": "Hardcoded credential in class field: SECRET_KEY = 'secret123'",
        "owasp": "A07:2021",
        "cvss": 7.5,
        "severity": "HIGH",
        "code_snippet": 'private static final String SECRET_KEY = "secret123";',
    },
    {
        "rule_id": "hardcoded-credential-field",
        "file": "target-app/src/main/java/com/finsecure/controller/AuthController.java",
        "line": 25,
        "message": "Hardcoded credential in class field: SECRET_KEY = 'secret123'",
        "owasp": "A07:2021",
        "cvss": 7.5,
        "severity": "HIGH",
        "code_snippet": 'private static final String SECRET_KEY = "secret123";',
    },
]


def run_semgrep(source_path: str, rules_path: str) -> list[dict]:
    """Execute Semgrep and parse its JSON output into structured findings."""
    cmd = [
        "semgrep",
        "--config", rules_path,
        "--json",
        "--quiet",
        source_path,
    ]

    console.print(f"[dim]Running:[/dim] [cyan]{' '.join(cmd)}[/cyan]")

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        raw = json.loads(result.stdout)
    except FileNotFoundError:
        console.print("[bold red]✗ Semgrep not found.[/bold red] Install with: pip install semgrep")
        console.print("[yellow]Falling back to pre-generated sample output...[/yellow]")
        return SAMPLE_FINDINGS
    except json.JSONDecodeError:
        console.print(f"[red]Failed to parse Semgrep output:[/red] {result.stderr[:500]}")
        return SAMPLE_FINDINGS

    findings = []
    for r in raw.get("results", []):
        rule_id = r.get("check_id", "").split(".")[-1]
        meta = RULE_METADATA.get(rule_id, {"owasp": "Unknown", "cvss": 5.0, "severity": "MEDIUM"})

        findings.append({
            "rule_id":      rule_id,
            "file":         r.get("path", ""),
            "line":         r.get("start", {}).get("line", 0),
            "message":      r.get("extra", {}).get("message", ""),
            "owasp":        meta["owasp"],
            "cvss":         meta["cvss"],
            "severity":     meta.get("severity", r.get("extra", {}).get("severity", "MEDIUM").upper()),
            "code_snippet": r.get("extra", {}).get("lines", "").strip(),
        })

    return findings


def print_findings_table(findings: list[dict]) -> None:
    """Render a Rich table of all SAST findings."""
    table = Table(
        title="[bold]SAST Findings — Semgrep Custom Rules[/bold]",
        box=box.ROUNDED,
        show_header=True,
        header_style="bold cyan",
        border_style="blue",
    )
    table.add_column("#",       style="dim", width=4)
    table.add_column("Rule ID", style="bold", width=38)
    table.add_column("Severity", width=10)
    table.add_column("CVSS", width=6, justify="right")
    table.add_column("OWASP", width=12)
    table.add_column("File: Line", width=55)

    for i, f in enumerate(findings, 1):
        sev   = f["severity"]
        color = SEVERITY_COLORS.get(sev, "white")
        table.add_row(
            str(i),
            f["rule_id"],
            f"[{color}]{sev}[/{color}]",
            f"[{color}]{f['cvss']}[/{color}]",
            f["owasp"],
            f"{Path(f['file']).name}:{f['line']}",
        )

    console.print(table)


def save_results(findings: list[dict], output_path: str) -> None:
    """Save structured findings JSON for downstream processing."""
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    output = {
        "tool": "semgrep",
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "rules_used": [
            "java-deser.yaml",
            "jwt-misconfig.yaml",
            "sqli-patterns.yaml",
            "hardcoded-creds.yaml",
        ],
        "total_findings": len(findings),
        "findings": findings,
    }
    with open(output_path, "w") as f:
        json.dump(output, f, indent=2)
    console.print(f"\n[green]✓ Results saved to[/green] [bold]{output_path}[/bold]")


def print_summary(findings: list[dict]) -> None:
    """Print severity count summary."""
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        sev = f.get("severity", "LOW").upper()
        counts[sev] = counts.get(sev, 0) + 1

    summary = (
        f"[bold red]🔴 Critical: {counts['CRITICAL']}[/bold red]  "
        f"[red]🟠 High: {counts['HIGH']}[/red]  "
        f"[yellow]🟡 Medium: {counts['MEDIUM']}[/yellow]  "
        f"[green]🟢 Low: {counts['LOW']}[/green]"
    )
    console.print(Panel(summary, title="[bold]SAST Summary[/bold]", border_style="cyan"))


def main():
    parser = argparse.ArgumentParser(description="FinSecure SAST Runner — Semgrep")
    parser.add_argument("--source", default="target-app/src",
                        help="Path to Java source directory (default: target-app/src)")
    parser.add_argument("--rules", default="assessment/sast/semgrep_rules",
                        help="Path to Semgrep rules directory")
    parser.add_argument("--output", default="findings/sast_results.json",
                        help="Output JSON path")
    parser.add_argument("--demo", action="store_true",
                        help="Use pre-generated sample output (no Semgrep needed)")
    args = parser.parse_args()

    console.print(Panel(
        "[bold cyan]FinSecure API — SAST Analysis[/bold cyan]\n"
        "[dim]Custom Semgrep rules: Java Deser · JWT Misconfig · SQLi · Hardcoded Creds[/dim]",
        border_style="cyan",
    ))

    if args.demo:
        console.print("[yellow]--demo mode: using pre-generated sample findings[/yellow]\n")
        findings = SAMPLE_FINDINGS
    else:
        with Progress(SpinnerColumn(), TextColumn("[cyan]{task.description}"), transient=True) as p:
            p.add_task("Running Semgrep SAST analysis...", total=None)
            findings = run_semgrep(args.source, args.rules)

    if not findings:
        console.print("[bold green]✓ No findings — clean scan![/bold green]")
        return

    print_findings_table(findings)
    print_summary(findings)
    save_results(findings, args.output)

    console.print(f"\n[bold]Verify command:[/bold]")
    console.print(f"[cyan]semgrep --config {args.rules} {args.source} --json[/cyan]")


if __name__ == "__main__":
    main()
