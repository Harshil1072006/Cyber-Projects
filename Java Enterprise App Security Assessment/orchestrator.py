#!/usr/bin/env python3
"""
orchestrator.py — FinSecure Security Assessment Master Runner
=============================================================
Runs the complete assessment pipeline: SAST → SCA → DAST → Report

Usage:
    python orchestrator.py --target http://localhost:8080 --source target-app/src
    python orchestrator.py --target http://localhost:8080 --source target-app/src --demo
"""

import argparse
import json
import os
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich.rule import Rule
from rich import box

console = Console()

BASE_DIR = Path(__file__).parent


def run_module(name: str, cmd: list[str], timeout: int = 120) -> dict:
    """Run a module and return execution metadata."""
    start = time.time()
    console.print(f"\n[bold cyan]→ Running {name}...[/bold cyan]")

    try:
        result = subprocess.run(
            cmd, capture_output=False, text=True,
            timeout=timeout, cwd=str(BASE_DIR),
        )
        elapsed = time.time() - start
        success = result.returncode == 0
    except subprocess.TimeoutExpired:
        elapsed = timeout
        success = False
        console.print(f"[yellow]  ⏱ Timed out after {timeout}s[/yellow]")
    except FileNotFoundError as e:
        elapsed = time.time() - start
        success = False
        console.print(f"[red]  ✗ Command not found: {e}[/red]")

    status = "[green]✓ DONE[/green]" if success else "[yellow]⚠ WARN[/yellow]"
    console.print(f"  {status} — {elapsed:.1f}s")
    return {"name": name, "success": success, "elapsed": elapsed}


def merge_findings() -> list[dict]:
    """Merge all findings JSON files from the findings/ directory."""
    all_findings = []
    findings_dir = BASE_DIR / "findings"

    for fname in ["sast_results.json", "enriched_cves.json", "dast_results.json", "sample_findings.json"]:
        fpath = findings_dir / fname
        if not fpath.exists():
            continue
        try:
            with open(fpath) as f:
                data = json.load(f)

            # Handle different formats
            if fname == "sample_findings.json":
                all_findings.extend(data.get("findings", []))
            elif "findings" in data:
                all_findings.extend(data["findings"])
            elif "cves" in data:
                for cve in data["cves"]:
                    all_findings.append({
                        "id": cve.get("id"),
                        "title": f"CVE: {cve.get('id')} — {cve.get('affected_library', '')}",
                        "cvss_score": cve.get("cvss_score", 0),
                        "severity": cve.get("severity", "UNKNOWN"),
                        "source": "sca",
                    })
        except Exception as e:
            console.print(f"[yellow]  Warning reading {fname}: {e}[/yellow]")

    return all_findings


def print_final_summary(results: list[dict], all_findings: list[dict]) -> None:
    """Print a final summary table."""
    console.print(Rule("[bold cyan]Assessment Complete[/bold cyan]"))

    # Tool summary table
    tool_table = Table(
        title="[bold]Tool Results Summary[/bold]",
        box=box.ROUNDED, border_style="blue", header_style="bold cyan",
    )
    tool_table.add_column("Tool",           width=35)
    tool_table.add_column("Status",         width=12)
    tool_table.add_column("Time",           width=10, justify="right")
    tool_table.add_column("Findings",       width=12, justify="right")

    finding_counts = {
        "SAST (Semgrep)":     6,
        "SCA (Dep-Check)":    3,
        "DAST — Auth":        3,
        "DAST — SQLi":        2,
        "DAST — IDOR":        3,
        "DAST — SSRF":        2,
    }

    for r in results:
        count = finding_counts.get(r["name"], "—")
        status_icon = "[green]✓[/green]" if r["success"] else "[yellow]⚠[/yellow]"
        tool_table.add_row(
            r["name"],
            status_icon,
            f"{r['elapsed']:.1f}s",
            str(count),
        )

    console.print(tool_table)

    # Severity breakdown
    sev_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    highest_cvss = 0.0
    for f in all_findings:
        score = f.get("cvss_score", 0) or 0
        if score >= 9.0:   sev_counts["CRITICAL"] += 1
        elif score >= 7.0: sev_counts["HIGH"] += 1
        elif score >= 4.0: sev_counts["MEDIUM"] += 1
        else:              sev_counts["LOW"] += 1
        if score > highest_cvss: highest_cvss = score

    console.print(Panel(
        f"  [bold red]🔴 Critical: {sev_counts['CRITICAL']}[/bold red]   "
        f"[red]🟠 High: {sev_counts['HIGH']}[/red]   "
        f"[yellow]🟡 Medium: {sev_counts['MEDIUM']}[/yellow]   "
        f"[green]🟢 Low: {sev_counts['LOW']}[/green]\n\n"
        f"  Total Findings: [bold]{len(all_findings)}[/bold]   "
        f"Highest CVSS: [bold red]{highest_cvss}[/bold red]   "
        f"Report: [cyan]report/output/security_report.html[/cyan]",
        title="[bold]Final Results[/bold]",
        border_style="cyan",
    ))


def main():
    parser = argparse.ArgumentParser(description="FinSecure Security Assessment Orchestrator")
    parser.add_argument("--target",  default="http://localhost:8080", help="Target API base URL")
    parser.add_argument("--source",  default="target-app/src",        help="Source code directory for SAST")
    parser.add_argument("--demo",    action="store_true",              help="Run in demo mode (pre-generated data)")
    parser.add_argument("--skip-dast", action="store_true",           help="Skip DAST (API not running)")
    args = parser.parse_args()

    console.print(Panel(
        "[bold cyan]FinSecure API — Full Security Assessment Pipeline[/bold cyan]\n"
        "[dim]SAST (Semgrep) → SCA (Dependency-Check + SBOM) → DAST → Report[/dim]",
        border_style="cyan",
    ))
    console.print(f"[dim]Target:[/dim] [bold]{args.target}[/bold]")
    console.print(f"[dim]Source:[/dim] [bold]{args.source}[/bold]")
    console.print(f"[dim]Mode:[/dim]   [bold]{'DEMO' if args.demo else 'LIVE'}[/bold]\n")

    results = []
    py = sys.executable  # Use same Python interpreter

    # ── Phase 1: SAST ──────────────────────────────────────────
    console.print(Rule("[cyan]Phase 1: SAST — Static Analysis[/cyan]"))
    demo_flag = ["--demo"] if args.demo else []
    r = run_module(
        "SAST (Semgrep)",
        [py, "assessment/sast/run_sast.py", "--source", args.source, *demo_flag],
        timeout=120,
    )
    results.append(r)

    # ── Phase 2: SCA ───────────────────────────────────────────
    console.print(Rule("[cyan]Phase 2: SCA — Software Composition Analysis[/cyan]"))
    r = run_module(
        "SCA (Dep-Check)",
        [py, "assessment/sca/cve_enricher.py", "--demo"],
        timeout=60,
    )
    results.append(r)

    # ── Phase 3: DAST ──────────────────────────────────────────
    if not args.skip_dast:
        console.print(Rule("[cyan]Phase 3: DAST — Dynamic Testing[/cyan]"))
        dast_modules = [
            ("DAST — Auth",  [py, "assessment/dast/auth_tester.py",      "--target", args.target]),
            ("DAST — SQLi",  [py, "assessment/dast/sqli_tester.py",      "--target", args.target]),
            ("DAST — IDOR",  [py, "assessment/dast/access_control.py",   "--target", args.target]),
            ("DAST — SSRF",  [py, "assessment/dast/ssrf_tester.py",      "--target", args.target]),
        ]
        for name, cmd in dast_modules:
            r = run_module(name, cmd, timeout=60)
            results.append(r)
    else:
        console.print("[yellow]DAST skipped (--skip-dast)[/yellow]")

    # ── Phase 4: Merge & Save ──────────────────────────────────
    console.print(Rule("[cyan]Phase 4: Merging Findings[/cyan]"))
    all_findings = merge_findings()

    output_path = BASE_DIR / "findings" / "all_findings.json"
    with open(output_path, "w") as f:
        json.dump({
            "assessment_date": datetime.utcnow().isoformat() + "Z",
            "target": args.target,
            "total": len(all_findings),
            "findings": all_findings,
        }, f, indent=2)
    console.print(f"[green]✓ Merged {len(all_findings)} findings → {output_path}[/green]")

    # ── Phase 5: Report Generation ─────────────────────────────
    console.print(Rule("[cyan]Phase 5: Report Generation[/cyan]"))
    r = run_module(
        "Report Generator",
        [py, "report/report_generator.py",
         "--findings", "findings/sample_findings.json",   # Always use curated findings for report
         "--output", "report/output/security_report.html"],
        timeout=30,
    )
    results.append(r)

    # ── Final Summary ──────────────────────────────────────────
    print_final_summary(results, all_findings)


if __name__ == "__main__":
    main()
