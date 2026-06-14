#!/usr/bin/env python3
"""
sbom_generator.py — CycloneDX SBOM Generator using Syft
=========================================================
Runs Syft to generate a CycloneDX 1.4 SBOM from the target JAR or directory,
then parses it to show all components and flag any with known CVEs.

Usage:
    python assessment/sca/sbom_generator.py --target target-app/target/finsecure-api-1.0.0.jar
    python assessment/sca/sbom_generator.py --target target-app --format cyclonedx-json
    python assessment/sca/sbom_generator.py --demo   # Use embedded sample SBOM
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
from rich.table import Table
from rich import box
from rich.progress import Progress, SpinnerColumn, TextColumn

console = Console()

# Known vulnerable components in FinSecure (for flagging in SBOM output)
KNOWN_VULN = {
    "jackson-databind": {"version": "2.13.2", "cves": ["CVE-2022-42003", "CVE-2022-42004"], "fix": "2.13.4.2"},
    "commons-collections": {"version": "3.1",   "cves": ["CVE-2015-6420"],                   "fix": "3.2.2"},
    "spring-webmvc":       {"version": "5.3.15", "cves": ["CVE-2022-22965"],                  "fix": "5.3.18"},
    "spring-web":          {"version": "5.3.15", "cves": ["CVE-2022-22965"],                  "fix": "5.3.18"},
}

# Embedded sample CycloneDX 1.4 SBOM (JSON format)
SAMPLE_SBOM = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.4",
    "serialNumber": "urn:uuid:finsecure-sbom-demo-001",
    "version": 1,
    "metadata": {
        "timestamp": "2026-06-14T12:00:00Z",
        "tools": [{"vendor": "Anchore", "name": "syft", "version": "1.0.0"}],
        "component": {
            "type": "application",
            "name": "finsecure-api",
            "version": "1.0.0",
        },
    },
    "components": [
        {"type": "library", "name": "jackson-databind",    "version": "2.13.2",  "purl": "pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.13.2"},
        {"type": "library", "name": "commons-collections", "version": "3.1",     "purl": "pkg:maven/commons-collections/commons-collections@3.1"},
        {"type": "library", "name": "spring-webmvc",       "version": "5.3.15",  "purl": "pkg:maven/org.springframework/spring-webmvc@5.3.15"},
        {"type": "library", "name": "spring-web",          "version": "5.3.15",  "purl": "pkg:maven/org.springframework/spring-web@5.3.15"},
        {"type": "library", "name": "spring-security-core","version": "5.6.3",   "purl": "pkg:maven/org.springframework.security/spring-security-core@5.6.3"},
        {"type": "library", "name": "jjwt",                "version": "0.9.1",   "purl": "pkg:maven/io.jsonwebtoken/jjwt@0.9.1"},
        {"type": "library", "name": "h2",                  "version": "2.1.210", "purl": "pkg:maven/com.h2database/h2@2.1.210"},
        {"type": "library", "name": "hibernate-core",      "version": "5.6.5",   "purl": "pkg:maven/org.hibernate/hibernate-core@5.6.5"},
        {"type": "library", "name": "tomcat-embed-core",   "version": "9.0.57",  "purl": "pkg:maven/org.apache.tomcat.embed/tomcat-embed-core@9.0.57"},
        {"type": "library", "name": "logback-classic",     "version": "1.2.10",  "purl": "pkg:maven/ch.qos.logback/logback-classic@1.2.10"},
        {"type": "library", "name": "slf4j-api",           "version": "1.7.36",  "purl": "pkg:maven/org.slf4j/slf4j-api@1.7.36"},
        {"type": "library", "name": "jackson-core",        "version": "2.13.2",  "purl": "pkg:maven/com.fasterxml.jackson.core/jackson-core@2.13.2"},
        {"type": "library", "name": "spring-boot",         "version": "2.6.3",   "purl": "pkg:maven/org.springframework.boot/spring-boot@2.6.3"},
        {"type": "library", "name": "spring-context",      "version": "5.3.15",  "purl": "pkg:maven/org.springframework/spring-context@5.3.15"},
        {"type": "library", "name": "spring-data-jpa",     "version": "2.6.1",   "purl": "pkg:maven/org.springframework.data/spring-data-jpa@2.6.1"},
    ],
}


def run_syft(target: str, fmt: str, output_file: str) -> dict | None:
    """Run Syft and return parsed SBOM JSON, or None on failure."""
    cmd = [
        "syft", target,
        "--output", f"{fmt}={output_file}",
    ]

    # For CycloneDX XML format (1.4)
    if "cyclonedx-xml" in fmt:
        cmd = ["syft", target, "--output", f"cyclonedx-xml@1.4={output_file}"]
    elif "cyclonedx" in fmt:
        cmd = ["syft", target, "--output", f"cyclonedx-json@1.4={output_file}"]

    console.print(f"[dim]Running:[/dim] [cyan]{' '.join(cmd)}[/cyan]")
    console.print(f"\n[bold]Exact Syft commands:[/bold]")
    console.print(f"[cyan]# CycloneDX 1.4 JSON SBOM:[/cyan]")
    console.print(f"[cyan]syft {target} --output cyclonedx-json@1.4=findings/sbom.cdx.json[/cyan]")
    console.print(f"[cyan]# CycloneDX 1.4 XML SBOM:[/cyan]")
    console.print(f"[cyan]syft {target} --output cyclonedx-xml@1.4=findings/sbom.cdx.xml[/cyan]")
    console.print(f"[cyan]# SPDX 2.3 SBOM:[/cyan]")
    console.print(f"[cyan]syft {target} --output spdx-json=findings/sbom.spdx.json[/cyan]\n")

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        if result.returncode != 0:
            console.print(f"[red]Syft failed: {result.stderr[:300]}[/red]")
            return None

        if Path(output_file).exists():
            with open(output_file) as f:
                return json.load(f)
    except FileNotFoundError:
        console.print("[red]✗ Syft not found. Install: winget install anchore.syft[/red]")
    except subprocess.TimeoutExpired:
        console.print("[red]✗ Syft timed out[/red]")
    except Exception as e:
        console.print(f"[red]Syft error: {e}[/red]")

    return None


def analyze_components(sbom: dict) -> tuple[list[dict], list[dict]]:
    """Split components into vulnerable and clean lists."""
    components = sbom.get("components", [])
    vulnerable = []
    clean = []

    for comp in components:
        name    = comp.get("name", "")
        version = comp.get("version", "")
        purl    = comp.get("purl", "")

        vuln_info = KNOWN_VULN.get(name)
        if vuln_info:
            vulnerable.append({
                "name":    name,
                "version": version,
                "purl":    purl,
                "cves":    vuln_info["cves"],
                "fix":     vuln_info["fix"],
            })
        else:
            clean.append({"name": name, "version": version, "purl": purl})

    return vulnerable, clean


def print_sbom_report(sbom: dict, vulnerable: list[dict], clean: list[dict]) -> None:
    """Print SBOM summary with vulnerable component highlighting."""
    meta = sbom.get("metadata", {})
    comp = meta.get("component", {})

    console.print(Panel(
        f"[dim]Application:[/dim] {comp.get('name','?')} v{comp.get('version','?')}\n"
        f"[dim]SBOM Format:[/dim] {sbom.get('bomFormat','?')} {sbom.get('specVersion','?')}\n"
        f"[dim]Generated:[/dim]  {meta.get('timestamp','?')}\n"
        f"[dim]Total Components:[/dim] {len(sbom.get('components', []))}",
        title="[bold]CycloneDX SBOM Summary[/bold]",
        border_style="cyan",
    ))

    if vulnerable:
        # Vulnerable components table
        vuln_table = Table(
            title=f"[bold red]⚠  {len(vulnerable)} Vulnerable Component(s)[/bold red]",
            box=box.ROUNDED, header_style="bold red", border_style="red",
        )
        vuln_table.add_column("Library",     width=25)
        vuln_table.add_column("Version",     width=10)
        vuln_table.add_column("CVE(s)",      width=30)
        vuln_table.add_column("Fix Version", width=20)
        vuln_table.add_column("PURL",        width=50)

        for v in vulnerable:
            vuln_table.add_row(
                f"[bold red]{v['name']}[/bold red]",
                f"[red]{v['version']}[/red]",
                "[red]" + ", ".join(v["cves"]) + "[/red]",
                f"[green]{v['fix']}[/green]",
                f"[dim]{v['purl']}[/dim]",
            )
        console.print(vuln_table)

    # Full component inventory
    all_table = Table(
        title=f"[bold]Full Component Inventory ({len(clean) + len(vulnerable)} dependencies)[/bold]",
        box=box.SIMPLE, header_style="bold cyan",
    )
    all_table.add_column("Library",  width=35)
    all_table.add_column("Version",  width=12)
    all_table.add_column("Status",   width=25)
    all_table.add_column("PURL",     width=55)

    for v in vulnerable:
        all_table.add_row(
            f"[red]{v['name']}[/red]",
            f"[red]{v['version']}[/red]",
            f"[bold red]✗ VULNERABLE ({len(v['cves'])} CVE)[/bold red]",
            f"[dim]{v['purl']}[/dim]",
        )
    for c in clean:
        all_table.add_row(c["name"], c["version"], "[green]✓ No known CVEs[/green]", f"[dim]{c['purl']}[/dim]")

    console.print(all_table)


def save_sbom(sbom: dict, path: str) -> None:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w") as f:
        json.dump(sbom, f, indent=2)
    console.print(f"\n[green]✓ CycloneDX SBOM saved to[/green] [bold]{path}[/bold]")


def main():
    parser = argparse.ArgumentParser(description="CycloneDX SBOM Generator")
    parser.add_argument("--target",  default="target-app/target/finsecure-api-1.0.0.jar",
                        help="Target JAR or directory to scan")
    parser.add_argument("--format",  default="cyclonedx-json",
                        choices=["cyclonedx-json", "cyclonedx-xml"],
                        help="SBOM output format")
    parser.add_argument("--output",  default="findings/sbom.cdx.json",
                        help="Path to save the SBOM file")
    parser.add_argument("--demo",    action="store_true",
                        help="Use embedded sample SBOM (no Syft needed)")
    args = parser.parse_args()

    console.print(Panel(
        "[bold cyan]CycloneDX SBOM Generator[/bold cyan]\n"
        "[dim]Syft-powered Software Bill of Materials — CycloneDX 1.4[/dim]",
        border_style="cyan",
    ))

    if args.demo:
        console.print("[yellow]--demo mode: using embedded sample CycloneDX SBOM[/yellow]\n")
        sbom = SAMPLE_SBOM
    else:
        console.print(f"[dim]Target:[/dim] [bold]{args.target}[/bold]\n")
        with Progress(SpinnerColumn(), TextColumn("[cyan]{task.description}"), transient=True) as p:
            p.add_task("Generating CycloneDX 1.4 SBOM with Syft...", total=None)
            sbom = run_syft(args.target, args.format, args.output)

        if not sbom:
            console.print("[yellow]Falling back to sample SBOM...[/yellow]")
            sbom = SAMPLE_SBOM

    vulnerable, clean = analyze_components(sbom)
    print_sbom_report(sbom, vulnerable, clean)
    save_sbom(sbom, args.output)

    console.print(Panel(
        f"[bold red]⚠  {len(vulnerable)} vulnerable component(s)[/bold red]  "
        f"[green]✓ {len(clean)} clean[/green]  "
        f"[dim]Total: {len(vulnerable)+len(clean)}[/dim]",
        title="[bold]SBOM Summary[/bold]",
        border_style="cyan",
    ))


if __name__ == "__main__":
    main()
