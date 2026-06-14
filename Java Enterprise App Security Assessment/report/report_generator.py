#!/usr/bin/env python3
"""
report_generator.py — Interactive HTML Security Report Generator
================================================================
Reads findings/sample_findings.json and renders a professional,
dark-mode penetration test report using Jinja2.

Usage:
    pip install jinja2 rich
    python report/report_generator.py
    python report/report_generator.py --findings findings/all_findings.json --open
"""

import argparse
import json
import os
import subprocess
import sys
from datetime import datetime
from pathlib import Path

from rich.console import Console
from rich.panel import Panel

console = Console()

try:
    from jinja2 import Environment, FileSystemLoader
except ImportError:
    console.print("[red]Jinja2 not installed. Run: pip install jinja2[/red]")
    sys.exit(1)


def load_findings(path: str) -> dict:
    """Load and validate findings JSON."""
    p = Path(path)
    if not p.exists():
        console.print(f"[red]Findings file not found: {path}[/red]")
        sys.exit(1)
    with open(p) as f:
        return json.load(f)


def compute_stats(findings: list[dict]) -> dict:
    """Compute severity counts, OWASP heatmap, and risk data."""
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    owasp_map: dict[str, int] = {}
    risk_items = []

    for f in findings:
        score = f.get("cvss_score", 0)
        if score >= 9.0:
            sev = "CRITICAL"
        elif score >= 7.0:
            sev = "HIGH"
        elif score >= 4.0:
            sev = "MEDIUM"
        else:
            sev = "LOW"
        f["_severity"] = sev
        counts[sev] = counts.get(sev, 0) + 1

        # OWASP heatmap
        cat = f.get("owasp_category", "Unknown").split(" - ")[0]
        owasp_map[cat] = owasp_map.get(cat, 0) + 1

        # Risk matrix
        likelihood = min(5, max(1, int((score / 2))))
        impact = min(5, max(1, int(score / 2)))
        risk_items.append({"id": f["id"], "likelihood": likelihood, "impact": impact, "sev": sev})

    # Sort findings by CVSS score descending
    sorted_findings = sorted(findings, key=lambda x: x.get("cvss_score", 0), reverse=True)

    return {
        "counts": counts,
        "owasp_map": owasp_map,
        "risk_items": risk_items,
        "sorted_findings": sorted_findings,
    }


def render_report(data: dict, template_dir: str, output_path: str) -> None:
    """Render the Jinja2 HTML template and write output."""
    env = Environment(
        loader=FileSystemLoader(template_dir),
        autoescape=True,
    )

    try:
        template = env.get_template("report_template.html")
    except Exception as e:
        console.print(f"[red]Template error: {e}[/red]")
        sys.exit(1)

    rendered = template.render(**data)

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(rendered)

    console.print(f"[green]✓ Report written to[/green] [bold]{output_path}[/bold]")


def main():
    parser = argparse.ArgumentParser(description="FinSecure Security Report Generator")
    parser.add_argument("--findings",  default="findings/sample_findings.json")
    parser.add_argument("--templates", default="report/templates")
    parser.add_argument("--output",    default="report/output/security_report.html")
    parser.add_argument("--open",      action="store_true", help="Open report in browser after generation")
    args = parser.parse_args()

    console.print(Panel(
        "[bold cyan]FinSecure — Security Report Generator[/bold cyan]\n"
        "[dim]Rendering professional dark-mode HTML penetration test report[/dim]",
        border_style="cyan",
    ))

    raw = load_findings(args.findings)
    findings = raw.get("findings", [])
    assessment = raw.get("assessment", {})

    console.print(f"[dim]Loaded {len(findings)} findings from[/dim] [bold]{args.findings}[/bold]")

    stats = compute_stats(findings)

    template_data = {
        "assessment":       assessment,
        "findings":         stats["sorted_findings"],
        "counts":           stats["counts"],
        "owasp_map":        stats["owasp_map"],
        "risk_items":       stats["risk_items"],
        "generated_at":     datetime.utcnow().strftime("%B %d, %Y at %H:%M UTC"),
        "total_findings":   len(findings),
        "cvss_chart_data":  json.dumps([f.get("cvss_score", 0) for f in stats["sorted_findings"]]),
        "cvss_labels":      json.dumps([f.get("id", "") for f in stats["sorted_findings"]]),
    }

    render_report(template_data, args.templates, args.output)

    if args.open:
        import webbrowser
        webbrowser.open(f"file://{os.path.abspath(args.output)}")
        console.print("[cyan]Opened in browser.[/cyan]")

    console.print(f"\n[bold green]✓ Report generation complete![/bold green]")
    console.print(f"[dim]Open:[/dim] [link=file://{os.path.abspath(args.output)}]{os.path.abspath(args.output)}[/link]")


if __name__ == "__main__":
    main()
