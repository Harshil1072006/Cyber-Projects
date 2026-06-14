#!/usr/bin/env python3
"""
cve_enricher.py — NVD API CVE Enrichment Tool
===============================================
Takes a list of CVE IDs and fetches full descriptions, CVSS scores,
affected versions, and remediation info from the NIST NVD API v2.0.

Usage:
    python assessment/sca/cve_enricher.py --cves CVE-2022-42003 CVE-2015-6420 CVE-2022-22965
    python assessment/sca/cve_enricher.py --input findings/raw_cves.txt
    python assessment/sca/cve_enricher.py --demo   # Use built-in sample CVEs
"""

import argparse
import json
import os
import time
from datetime import datetime
from pathlib import Path

import requests
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, BarColumn, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich import box

console = Console()

NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Known CVEs in our target app — used for demo / offline fallback
KNOWN_CVES = {
    "CVE-2022-42003": {
        "id": "CVE-2022-42003",
        "published": "2022-10-02",
        "cvss_score": 7.5,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
        "severity": "HIGH",
        "description": (
            "In FasterXML jackson-databind before 2.13.4.2, resource exhaustion can occur "
            "because of a lack of a check in primitive array deserializers to avoid deep "
            "wrapper array nesting, when the UNWRAP_SINGLE_VALUE_ARRAYS feature is enabled. "
            "This results in a Denial of Service (DoS) condition."
        ),
        "affected_library": "com.fasterxml.jackson.core:jackson-databind",
        "affected_versions": "< 2.13.4.2",
        "fixed_version": "2.13.4.2",
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2022-42003",
            "https://github.com/FasterXML/jackson-databind/issues/3582",
        ],
        "cwe": "CWE-400",
    },
    "CVE-2022-42004": {
        "id": "CVE-2022-42004",
        "published": "2022-10-02",
        "cvss_score": 7.5,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
        "severity": "HIGH",
        "description": (
            "In FasterXML jackson-databind before 2.13.4.2, resource exhaustion can occur "
            "because of a lack of a check in BeanDeserializer._deserializeFromArray to avoid "
            "deeply nested arrays when the UNWRAP_SINGLE_VALUE_ARRAYS feature is enabled."
        ),
        "affected_library": "com.fasterxml.jackson.core:jackson-databind",
        "affected_versions": "< 2.13.4.2",
        "fixed_version": "2.13.4.2",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2022-42004"],
        "cwe": "CWE-400",
    },
    "CVE-2015-6420": {
        "id": "CVE-2015-6420",
        "published": "2015-12-15",
        "cvss_score": 7.5,
        "cvss_vector": "CVSS:2.0/AV:N/AC:L/Au:N/C:P/I:P/A:P",
        "severity": "HIGH",
        "description": (
            "Serialized-object interfaces in Apache Commons Collections before 3.2.2 do not properly "
            "restrict classes that can be deserialized, which allows remote attackers to execute "
            "arbitrary commands via a crafted serialized Java object. This enables the well-known "
            "ysoserial CommonsCollections gadget chain for Remote Code Execution."
        ),
        "affected_library": "commons-collections:commons-collections",
        "affected_versions": "< 3.2.2",
        "fixed_version": "3.2.2",
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2015-6420",
            "https://github.com/frohoff/ysoserial",
        ],
        "cwe": "CWE-502",
    },
    "CVE-2022-22965": {
        "id": "CVE-2022-22965",
        "published": "2022-03-31",
        "cvss_score": 9.8,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "severity": "CRITICAL",
        "description": (
            "A Spring MVC or Spring WebFlux application running on JDK 9+ may be vulnerable to "
            "remote code execution (RCE) via data binding. The specific exploit requires the "
            "application to run on Tomcat as a WAR deployment. Known as 'Spring4Shell'. "
            "CVSSv3 score: 9.8 CRITICAL."
        ),
        "affected_library": "org.springframework:spring-webmvc",
        "affected_versions": "5.3.x < 5.3.18, 5.2.x < 5.2.20",
        "fixed_version": "5.3.18",
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2022-22965",
            "https://spring.io/blog/2022/03/31/spring-framework-rce-early-announcement",
        ],
        "cwe": "CWE-94",
    },
}


def fetch_cve_from_nvd(cve_id: str, api_key: str = None) -> dict | None:
    """Fetch CVE details from NIST NVD API v2.0 with retry logic."""
    params = {"cveId": cve_id}
    headers = {}
    if api_key:
        headers["apiKey"] = api_key

    for attempt in range(3):
        try:
            resp = requests.get(NVD_API_BASE, params=params, headers=headers, timeout=15)

            if resp.status_code == 403:
                console.print(f"[yellow]NVD rate limit hit for {cve_id}. Waiting 6s...[/yellow]")
                time.sleep(6)
                continue

            if resp.status_code != 200:
                console.print(f"[red]NVD API error {resp.status_code} for {cve_id}[/red]")
                return KNOWN_CVES.get(cve_id)

            data = resp.json()
            vulns = data.get("vulnerabilities", [])
            if not vulns:
                console.print(f"[yellow]No NVD data found for {cve_id}[/yellow]")
                return KNOWN_CVES.get(cve_id)

            cve_data = vulns[0]["cve"]

            # Extract CVSS v3.1 score (fall back to v2)
            cvss_score = None
            cvss_vector = ""
            severity = "UNKNOWN"
            metrics = cve_data.get("metrics", {})
            if "cvssMetricV31" in metrics:
                m = metrics["cvssMetricV31"][0]["cvssData"]
                cvss_score  = m.get("baseScore")
                cvss_vector = m.get("vectorString", "")
                severity    = m.get("baseSeverity", "")
            elif "cvssMetricV30" in metrics:
                m = metrics["cvssMetricV30"][0]["cvssData"]
                cvss_score  = m.get("baseScore")
                cvss_vector = m.get("vectorString", "")
                severity    = m.get("baseSeverity", "")
            elif "cvssMetricV2" in metrics:
                m = metrics["cvssMetricV2"][0]["cvssData"]
                cvss_score  = m.get("baseScore")
                cvss_vector = m.get("vectorString", "")
                severity    = metrics["cvssMetricV2"][0].get("baseSeverity", "")

            # Description (English)
            descriptions = cve_data.get("descriptions", [])
            description = next(
                (d["value"] for d in descriptions if d.get("lang") == "en"),
                "No description available."
            )

            # References
            refs = [r["url"] for r in cve_data.get("references", [])[:3]]

            # CWE
            weaknesses = cve_data.get("weaknesses", [])
            cwe = "Unknown"
            if weaknesses:
                descs = weaknesses[0].get("description", [])
                cwe = descs[0].get("value", "Unknown") if descs else "Unknown"

            return {
                "id":              cve_id,
                "published":       cve_data.get("published", "")[:10],
                "cvss_score":      cvss_score,
                "cvss_vector":     cvss_vector,
                "severity":        severity,
                "description":     description,
                "affected_library": "See NVD for affected products",
                "affected_versions": "See NVD",
                "fixed_version":    "See NVD advisory",
                "references":      refs,
                "cwe":             cwe,
            }

        except requests.exceptions.Timeout:
            console.print(f"[yellow]Timeout fetching {cve_id} (attempt {attempt+1}/3)[/yellow]")
            time.sleep(2)
        except Exception as e:
            console.print(f"[red]Error fetching {cve_id}: {e}[/red]")
            break

    # Fallback to known CVEs cache
    return KNOWN_CVES.get(cve_id)


def print_cve_table(cves: list[dict]) -> None:
    """Print enriched CVE data as a Rich table."""
    table = Table(
        title="[bold]Enriched CVE Report — NVD API[/bold]",
        box=box.ROUNDED,
        header_style="bold cyan",
        border_style="blue",
        show_lines=True,
    )
    table.add_column("CVE ID",          style="bold", width=18)
    table.add_column("Severity",        width=10)
    table.add_column("CVSS",            width=6, justify="right")
    table.add_column("CWE",             width=10)
    table.add_column("Library",         width=30)
    table.add_column("Fix Version",     width=14)

    SCOLORS = {"CRITICAL": "bold red", "HIGH": "red", "MEDIUM": "yellow",
               "LOW": "green", "UNKNOWN": "dim"}

    for c in cves:
        sev   = (c.get("severity") or "UNKNOWN").upper()
        color = SCOLORS.get(sev, "white")
        score = c.get("cvss_score") or "N/A"
        table.add_row(
            c.get("id", ""),
            f"[{color}]{sev}[/{color}]",
            f"[{color}]{score}[/{color}]",
            c.get("cwe", ""),
            c.get("affected_library", ""),
            c.get("fixed_version", ""),
        )
    console.print(table)

    # Print descriptions
    console.print()
    for c in cves:
        sev   = (c.get("severity") or "UNKNOWN").upper()
        color = SCOLORS.get(sev, "white")
        console.print(Panel(
            f"[dim]Published:[/dim] {c.get('published', 'N/A')}  "
            f"[dim]CVSS Vector:[/dim] {c.get('cvss_vector', 'N/A')}\n\n"
            f"{c.get('description', '')}",
            title=f"[{color}][bold]{c.get('id')}[/bold] — {sev}[/{color}]",
            border_style=color.replace("bold ", ""),
            expand=False,
        ))


def main():
    parser = argparse.ArgumentParser(description="NVD CVE Enrichment Tool")
    parser.add_argument("--cves",  nargs="+", help="CVE IDs to look up")
    parser.add_argument("--input", help="Text file with CVE IDs (one per line)")
    parser.add_argument("--output", default="findings/enriched_cves.json")
    parser.add_argument("--api-key", help="NVD API key (optional, increases rate limit)")
    parser.add_argument("--demo",  action="store_true", help="Use built-in sample CVEs")
    args = parser.parse_args()

    console.print(Panel(
        "[bold cyan]NVD CVE Enrichment Tool[/bold cyan]\n"
        "[dim]Fetches descriptions, CVSS scores, and fix versions from NVD API v2.0[/dim]",
        border_style="cyan",
    ))

    # Determine CVE list
    if args.demo:
        cve_ids = list(KNOWN_CVES.keys())
        console.print(f"[yellow]--demo mode: enriching {len(cve_ids)} known CVEs[/yellow]\n")
    elif args.input:
        cve_ids = Path(args.input).read_text().strip().splitlines()
    elif args.cves:
        cve_ids = args.cves
    else:
        parser.error("Provide --cves, --input, or --demo")
        return

    enriched = []
    with Progress(
        SpinnerColumn(),
        TextColumn("[cyan]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TimeElapsedColumn(),
    ) as progress:
        task = progress.add_task("Fetching CVE data from NVD...", total=len(cve_ids))
        for cve_id in cve_ids:
            cve_id = cve_id.strip().upper()
            progress.update(task, description=f"Fetching {cve_id}...")
            data = fetch_cve_from_nvd(cve_id, args.api_key)
            if data:
                enriched.append(data)
            # NVD public rate limit: 5 req/30s without API key
            if not args.api_key:
                time.sleep(1.5)
            progress.advance(task)

    if enriched:
        print_cve_table(enriched)
        os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
        with open(args.output, "w") as f:
            json.dump({"timestamp": datetime.utcnow().isoformat() + "Z", "cves": enriched}, f, indent=2)
        console.print(f"\n[green]✓ Enriched CVE data saved to[/green] [bold]{args.output}[/bold]")
    else:
        console.print("[red]No CVE data retrieved.[/red]")


if __name__ == "__main__":
    main()
