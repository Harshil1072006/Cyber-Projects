import json
import os
import uuid
import datetime
from pathlib import Path
from rich.console import Console
from rich.table import Table

console = Console()

def load_compliance_map():
    """Load the CWE to Compliance mapping."""
    map_path = Path("findings/compliance_map.json")
    if not map_path.exists():
        # Fallback to empty mappings if not run from root
        return {"mappings": {}}
    
    with open(map_path, 'r') as f:
        return json.load(f)

def get_compliance_tags(cwe_id, compliance_map):
    """Get PCI-DSS, ISO 27001, and SOC 2 tags for a CWE."""
    if not cwe_id or cwe_id not in compliance_map.get("mappings", {}):
        return {}
    
    mapping = compliance_map["mappings"][cwe_id]
    return {
        "pci_dss": mapping.get("pci_dss", []),
        "iso_27001": mapping.get("iso_27001", []),
        "soc2": mapping.get("soc2", []),
        "owasp_category": mapping.get("owasp", "Unknown")
    }

def create_sarif_log():
    """Create the base SARIF envelope."""
    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": []
    }

def create_run(tool_name, tool_version="1.0.0", information_uri=""):
    """Create a SARIF run object for a specific tool."""
    return {
        "tool": {
            "driver": {
                "name": tool_name,
                "version": tool_version,
                "informationUri": information_uri,
                "rules": []
            }
        },
        "results": []
    }

def add_result(run, rule_id, message, severity, stage, cwe=None, cve=None, cvss_score=None, cvss_vector=None, file_path="", line=0, evidence="", remediation="", remediation_effort="Low"):
    """Add a result (finding) to a SARIF run."""
    # Ensure rule exists in driver
    rule_exists = any(r.get("id") == rule_id for r in run["tool"]["driver"]["rules"])
    if not rule_exists:
        run["tool"]["driver"]["rules"].append({
            "id": rule_id,
            "shortDescription": {"text": message[:50] + "..." if len(message) > 50 else message}
        })
    
    # Map severity to SARIF level
    level_map = {
        "CRITICAL": "error",
        "HIGH": "error",
        "MEDIUM": "warning",
        "LOW": "note"
    }
    
    # Get compliance tags
    compliance_map = load_compliance_map()
    compliance_tags = get_compliance_tags(cwe, compliance_map)
    
    result = {
        "ruleId": rule_id,
        "level": level_map.get(severity.upper(), "note"),
        "message": {"text": message},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": file_path},
                    "region": {"startLine": line if line > 0 else 1}
                }
            }
        ],
        "properties": {
            "id": f"FIND-{uuid.uuid4().hex[:6].upper()}",
            "stage": stage.upper(),
            "severity": severity.upper(),
            "evidence": evidence,
            "remediation": remediation,
            "remediation_effort": remediation_effort,
            "gate_blocking": severity.upper() in ["CRITICAL", "HIGH"],
            "status": "Open",
            "compliance": compliance_tags
        }
    }
    
    if cwe:
        result["properties"]["cwe"] = cwe
    if cve:
        result["properties"]["cve"] = cve
    if cvss_score:
        result["properties"]["cvss_score"] = float(cvss_score)
    if cvss_vector:
        result["properties"]["cvss_vector"] = cvss_vector
    if compliance_tags.get("owasp_category"):
        result["properties"]["owasp_category"] = compliance_tags["owasp_category"]
        
    run["results"].append(result)

def save_sarif(sarif_log, file_path):
    """Save the SARIF log to a file."""
    # Ensure directory exists
    os.makedirs(os.path.dirname(file_path), exist_ok=True)
    
    with open(file_path, 'w') as f:
        json.json(sarif_log, f, indent=2)

def print_results_table(sarif_log, tool_name):
    """Print a rich table of findings with compliance tags."""
    if not sarif_log.get("runs") or not sarif_log["runs"][0].get("results"):
        console.print(f"[bold green]✔ No findings detected by {tool_name}[/bold green]")
        return 0
        
    results = sarif_log["runs"][0]["results"]
    
    table = Table(title=f"{tool_name} Findings", show_header=True, header_style="bold magenta")
    table.add_column("Severity", width=10)
    table.add_column("Rule / CVE", width=15)
    table.add_column("File", width=25)
    table.add_column("PCI-DSS / ISO 27001", width=20)
    table.add_column("Description", width=40)
    
    critical_count = 0
    
    for r in results:
        props = r.get("properties", {})
        severity = props.get("severity", "LOW")
        
        # Style severity
        sev_style = "bold red" if severity == "CRITICAL" else "red" if severity == "HIGH" else "yellow" if severity == "MEDIUM" else "blue"
        if severity == "CRITICAL": critical_count += 1
        
        rule_id = r.get("ruleId", "")
        cve = props.get("cve", "")
        display_id = cve if cve else rule_id
        
        # Get file
        file_path = ""
        locs = r.get("locations", [])
        if locs:
            file_path = locs[0].get("physicalLocation", {}).get("artifactLocation", {}).get("uri", "")
            
        # Get compliance string
        comp = props.get("compliance", {})
        pci = comp.get("pci_dss", [])
        iso = comp.get("iso_27001", [])
        
        comp_str = ""
        if pci: comp_str += f"[cyan]PCI: {pci[0].split(' - ')[0]}[/cyan]"
        if iso: comp_str += f"\n[green]ISO: {iso[0].split(' - ')[0]}[/green]"
        
        msg = r.get("message", {}).get("text", "")
        if len(msg) > 60: msg = msg[:57] + "..."
        
        table.add_row(
            f"[{sev_style}]{severity}[/]",
            display_id,
            file_path,
            comp_str,
            msg
        )
        
    console.print(table)
    console.print(f"\nTotal findings: {len(results)} (Critical: {critical_count})")
    
    return critical_count
