#!/usr/bin/env python3
"""
dependency_check.py — OWASP Dependency-Check Runner
=====================================================
Runs OWASP Dependency-Check against pom.xml, parses the XML report,
and extracts CVE ID, CVSS score, affected library, and fix version.

Usage:
    python assessment/sca/dependency_check.py --pom target-app/pom.xml
    python assessment/sca/dependency_check.py --pom target-app/pom.xml --dc-path "C:/Tools/dependency-check/bin/dependency-check.bat"
    python assessment/sca/dependency_check.py --demo   # Parse pre-generated sample XML
"""

import argparse
import json
import os
import subprocess
import sys
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box
from rich.progress import Progress, SpinnerColumn, TextColumn

console = Console()

# Namespace used in OWASP Dependency-Check XML report
DC_NS = {"dc": "https://jeremylong.github.io/DependencyCheck/dependency-check.1.3.xsd"}

# ─── Sample XML output (embedded) — used when --demo or DC not installed ──────
SAMPLE_XML = """<?xml version="1.0" encoding="UTF-8"?>
<analysis xmlns="https://jeremylong.github.io/DependencyCheck/dependency-check.1.3.xsd">
  <projectInfo>
    <name>FinSecure API</name>
    <reportDate>2026-06-14T12:00:00.000Z</reportDate>
  </projectInfo>
  <dependencies>
    <dependency>
      <fileName>jackson-databind-2.13.2.jar</fileName>
      <filePath>/target-app/target/jackson-databind-2.13.2.jar</filePath>
      <vulnerabilities>
        <vulnerability source="NVD">
          <name>CVE-2022-42003</name>
          <cvssV3>
            <baseScore>7.5</baseScore>
            <baseSeverity>HIGH</baseSeverity>
          </cvssV3>
          <description>In FasterXML jackson-databind before 2.13.4.2, resource exhaustion
          can occur because of a lack of a check in primitive array deserializers to avoid
          deep wrapper array nesting, when the UNWRAP_SINGLE_VALUE_ARRAYS feature is enabled.</description>
          <references>
            <reference>
              <url>https://nvd.nist.gov/vuln/detail/CVE-2022-42003</url>
            </reference>
          </references>
          <vulnerableSoftware>
            <software>cpe:2.3:a:fasterxml:jackson-databind:*:*:*:*:*:*:*:*</software>
          </vulnerableSoftware>
        </vulnerability>
        <vulnerability source="NVD">
          <name>CVE-2022-42004</name>
          <cvssV3>
            <baseScore>7.5</baseScore>
            <baseSeverity>HIGH</baseSeverity>
          </cvssV3>
          <description>In FasterXML jackson-databind before 2.13.4.2, resource exhaustion
          can occur in BeanDeserializer._deserializeFromArray.</description>
        </vulnerability>
      </vulnerabilities>
    </dependency>
    <dependency>
      <fileName>commons-collections-3.1.jar</fileName>
      <filePath>/target-app/target/commons-collections-3.1.jar</filePath>
      <vulnerabilities>
        <vulnerability source="NVD">
          <name>CVE-2015-6420</name>
          <cvssV2>
            <score>7.5</score>
            <severity>HIGH</severity>
          </cvssV2>
          <description>Serialized-object interfaces in Apache Commons Collections before 3.2.2
          allow remote attackers to execute arbitrary commands via a crafted serialized Java object
          using the CommonsCollections gadget chain (ysoserial).</description>
          <references>
            <reference>
              <url>https://nvd.nist.gov/vuln/detail/CVE-2015-6420</url>
            </reference>
          </references>
        </vulnerability>
      </vulnerabilities>
    </dependency>
    <dependency>
      <fileName>spring-webmvc-5.3.15.jar</fileName>
      <filePath>/target-app/target/spring-webmvc-5.3.15.jar</filePath>
      <vulnerabilities>
        <vulnerability source="NVD">
          <name>CVE-2022-22965</name>
          <cvssV3>
            <baseScore>9.8</baseScore>
            <baseSeverity>CRITICAL</baseSeverity>
          </cvssV3>
          <description>A Spring MVC or Spring WebFlux application running on JDK 9+ may be
          vulnerable to remote code execution (RCE) via data binding. Known as Spring4Shell.</description>
          <references>
            <reference>
              <url>https://nvd.nist.gov/vuln/detail/CVE-2022-22965</url>
            </reference>
          </references>
        </vulnerability>
      </vulnerabilities>
    </dependency>
  </dependencies>
</analysis>"""

# Fix version recommendations per CVE
FIX_VERSIONS = {
    "CVE-2022-42003": "jackson-databind 2.13.4.2+",
    "CVE-2022-42004": "jackson-databind 2.13.4.2+",
    "CVE-2015-6420":  "commons-collections 3.2.2+",
    "CVE-2022-22965": "spring-boot-starter-parent 2.6.6+",
}


def run_dependency_check(pom_path: str, dc_path: str, output_dir: str) -> str | None:
    """
    Run OWASP Dependency-Check CLI against the pom.xml.
    Returns path to the generated XML report, or None on failure.
    """
    os.makedirs(output_dir, exist_ok=True)
    xml_out = str(Path(output_dir) / "dependency-check-report.xml")

    cmd = [
        dc_path,
        "--project", "FinSecure API",
        "--scan", pom_path,
        "--format", "XML",
        "--out", output_dir,
        "--enableRetired",
    ]

    console.print(f"[dim]Running:[/dim] [cyan]{' '.join(cmd)}[/cyan]")

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        if result.returncode != 0:
            console.print(f"[red]Dependency-Check failed (exit {result.returncode})[/red]")
            console.print(f"[dim]{result.stderr[-500:]}[/dim]")
            return None
        console.print(f"[green]✓ Dependency-Check completed. Report at: {xml_out}[/green]")
        return xml_out
    except FileNotFoundError:
        console.print(f"[red]✗ dependency-check not found at: {dc_path}[/red]")
        console.print("[yellow]Install from: https://github.com/jeremylong/DependencyCheck/releases[/yellow]")
        console.print("[yellow]Or run with: --demo to use sample output[/yellow]")
        return None
    except subprocess.TimeoutExpired:
        console.print("[red]✗ Dependency-Check timed out (>5 minutes)[/red]")
        return None


def parse_xml_report(xml_content: str) -> list[dict]:
    """
    Parse a Dependency-Check XML report and extract all CVE findings.
    Returns a list of structured finding dicts.
    """
    findings = []

    try:
        # Handle both file path and raw XML string
        if Path(xml_content).exists():
            tree = ET.parse(xml_content)
            root = tree.getroot()
        else:
            root = ET.fromstring(xml_content)
    except ET.ParseError as e:
        console.print(f"[red]XML parse error: {e}[/red]")
        return []

    # Strip namespace prefix for easier parsing
    def strip_ns(tag: str) -> str:
        return tag.split("}")[-1] if "}" in tag else tag

    for dep in root.iter():
        if strip_ns(dep.tag) != "dependency":
            continue

        filename = ""
        for child in dep:
            if strip_ns(child.tag) == "fileName":
                filename = child.text or ""
                break

        for vuln in dep.iter():
            if strip_ns(vuln.tag) != "vulnerability":
                continue

            cve_id    = ""
            cvss      = 0.0
            severity  = "UNKNOWN"
            desc      = ""
            fix_ver   = ""

            for v_child in vuln:
                tag = strip_ns(v_child.tag)
                if tag == "name":
                    cve_id = v_child.text or ""
                elif tag == "description":
                    desc = (v_child.text or "").strip().replace("\n", " ")
                elif tag == "cvssV3":
                    for cv in v_child:
                        if strip_ns(cv.tag) == "baseScore":
                            cvss = float(cv.text or 0)
                        elif strip_ns(cv.tag) == "baseSeverity":
                            severity = (cv.text or "UNKNOWN").upper()
                elif tag == "cvssV2" and cvss == 0.0:
                    for cv in v_child:
                        if strip_ns(cv.tag) == "score":
                            cvss = float(cv.text or 0)
                        elif strip_ns(cv.tag) == "severity":
                            severity = (cv.text or "UNKNOWN").upper()

            fix_ver = FIX_VERSIONS.get(cve_id, "See NVD advisory")

            if cve_id:
                findings.append({
                    "cve_id":    cve_id,
                    "library":   filename,
                    "cvss":      cvss,
                    "severity":  severity,
                    "fix_version": fix_ver,
                    "description": desc[:300] + ("..." if len(desc) > 300 else ""),
                })

    return findings


def print_findings(findings: list[dict]) -> None:
    """Render findings as a Rich table."""
    SCOLORS = {"CRITICAL": "bold red", "HIGH": "red", "MEDIUM": "yellow",
               "LOW": "green", "UNKNOWN": "dim"}

    table = Table(
        title="[bold]OWASP Dependency-Check — CVE Findings[/bold]",
        box=box.ROUNDED, header_style="bold cyan", border_style="blue", show_lines=True,
    )
    table.add_column("CVE ID",      width=18)
    table.add_column("Library",     width=30)
    table.add_column("CVSS",        width=6, justify="right")
    table.add_column("Severity",    width=10)
    table.add_column("Fix Version", width=30)

    for f in sorted(findings, key=lambda x: x["cvss"], reverse=True):
        sev   = f["severity"]
        color = SCOLORS.get(sev, "white")
        table.add_row(
            f["cve_id"],
            f["library"],
            f"[{color}]{f['cvss']}[/{color}]",
            f"[{color}]{sev}[/{color}]",
            f["fix_version"],
        )

    console.print(table)

    # Print descriptions
    console.print()
    for f in findings:
        sev   = f["severity"]
        color = SCOLORS.get(sev, "white")
        console.print(Panel(
            f"[dim]Library:[/dim] {f['library']}\n[dim]Fix:[/dim] {f['fix_version']}\n\n{f['description']}",
            title=f"[{color}][bold]{f['cve_id']}[/bold] — {sev} ({f['cvss']})[/{color}]",
            border_style=color.replace("bold ", ""),
            expand=False,
        ))


def save_results(findings: list[dict], output_path: str) -> None:
    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
    with open(output_path, "w") as f:
        json.dump({
            "tool":      "owasp-dependency-check",
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "total":     len(findings),
            "findings":  findings,
        }, f, indent=2)
    console.print(f"\n[green]✓ Results saved to[/green] [bold]{output_path}[/bold]")


def main():
    parser = argparse.ArgumentParser(description="OWASP Dependency-Check Runner & Parser")
    parser.add_argument("--pom",     default="target-app/pom.xml",
                        help="Path to pom.xml to scan")
    parser.add_argument("--dc-path", default="dependency-check",
                        help="Path to dependency-check CLI executable")
    parser.add_argument("--out-dir", default="findings/dc_report",
                        help="Directory for Dependency-Check XML output")
    parser.add_argument("--output",  default="findings/sca_results.json",
                        help="Output JSON path for parsed findings")
    parser.add_argument("--xml",     help="Parse an existing XML report directly")
    parser.add_argument("--demo",    action="store_true",
                        help="Use embedded sample XML (no DC install needed)")
    args = parser.parse_args()

    console.print(Panel(
        "[bold cyan]OWASP Dependency-Check — SCA Runner[/bold cyan]\n"
        "[dim]Scans pom.xml for CVEs · Parses XML report · Extracts CVSS + fix versions[/dim]",
        border_style="cyan",
    ))

    xml_data = None

    if args.demo:
        console.print("[yellow]--demo mode: using embedded sample report[/yellow]\n")
        xml_data = SAMPLE_XML
    elif args.xml:
        console.print(f"[dim]Parsing existing report:[/dim] [bold]{args.xml}[/bold]")
        xml_data = args.xml
    else:
        console.print(f"[dim]Target pom.xml:[/dim] [bold]{args.pom}[/bold]\n")
        console.print("[bold]Exact command to run manually:[/bold]")
        console.print(f"[cyan]dependency-check --project FinSecureAPI --scan {args.pom} --format XML --out {args.out_dir}[/cyan]\n")

        with Progress(SpinnerColumn(), TextColumn("[cyan]{task.description}"), transient=True) as p:
            p.add_task("Running OWASP Dependency-Check (this takes 2-5 minutes on first run)...", total=None)
            xml_path = run_dependency_check(args.pom, args.dc_path, args.out_dir)

        if xml_path:
            xml_data = xml_path
        else:
            console.print("[yellow]Falling back to --demo mode[/yellow]")
            xml_data = SAMPLE_XML

    findings = parse_xml_report(xml_data)

    if not findings:
        console.print("[bold green]✓ No vulnerabilities found.[/bold green]")
        return

    print_findings(findings)
    save_results(findings, args.output)

    critical = sum(1 for f in findings if f["severity"] == "CRITICAL")
    high     = sum(1 for f in findings if f["severity"] == "HIGH")
    console.print(Panel(
        f"[bold red]🔴 Critical: {critical}[/bold red]  [red]🟠 High: {high}[/red]  "
        f"[dim]Total CVEs: {len(findings)}[/dim]",
        title="[bold]SCA Summary[/bold]",
        border_style="cyan",
    ))


if __name__ == "__main__":
    main()
