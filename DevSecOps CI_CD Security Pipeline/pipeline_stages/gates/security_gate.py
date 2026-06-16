import os
import sys
import json
import glob
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()

def load_all_findings():
    """Load all SARIF findings from the findings directory."""
    findings = []
    
    # First check if sample findings should be used (if no other findings exist)
    sarif_files = glob.glob("findings/*.sarif")
    if not sarif_files:
        console.print("[yellow]No SARIF files found in findings directory.[/yellow]")
        return findings
        
    # If we have generated findings, ignore the sample ones
    generated_files = [f for f in sarif_files if not f.endswith("sample_findings.sarif")]
    files_to_load = generated_files if generated_files else sarif_files
    
    for file_path in files_to_load:
        try:
            with open(file_path, 'r') as f:
                log = json.load(f)
                for run in log.get("runs", []):
                    findings.extend(run.get("results", []))
        except Exception as e:
            console.print(f"[red]Error loading {file_path}: {str(e)}[/red]")
            
    return findings

def evaluate_gate(findings, config_path="gate_config.json"):
    """Evaluate findings against security gate configurations."""
    # Load config
    config = {
        "gates": {"block_on_critical": True, "block_on_high_count": 10},
        "compliance": {"enforce_pci_dss": True, "enforce_iso_27001": True}
    }
    
    if os.path.exists(config_path):
        with open(config_path, 'r') as f:
            config = json.load(f)
            
    gates_config = config.get("gates", {})
    comp_config = config.get("compliance", {})
    
    # Aggregate stats
    stats = {
        "SAST": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "COMPLIANCE": set(), "GATE": "PASS"},
        "SCA": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "COMPLIANCE": set(), "GATE": "PASS"},
        "SECRETS": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "COMPLIANCE": set(), "GATE": "PASS"},
        "IAC": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "COMPLIANCE": set(), "GATE": "PASS"},
        "CONTAINER": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "COMPLIANCE": set(), "GATE": "PASS"},
        "DAST": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "COMPLIANCE": set(), "GATE": "PASS"},
        "TOTAL": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "COMPLIANCE": set(), "GATE": "PASS"}
    }
    
    pipeline_failed = False
    failure_reasons = []
    
    # Process findings
    for finding in findings:
        props = finding.get("properties", {})
        stage = props.get("stage", "UNKNOWN").upper()
        severity = props.get("severity", "LOW").upper()
        comp = props.get("compliance", {})
        
        if stage not in stats:
            stats[stage] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "COMPLIANCE": set(), "GATE": "PASS"}
            
        stats[stage][severity] += 1
        stats["TOTAL"][severity] += 1
        
        # Check Compliance Violations
        if comp_config.get("block_on_compliance_violation", True):
            if comp_config.get("enforce_pci_dss") and comp.get("pci_dss"):
                stats[stage]["COMPLIANCE"].add("PCI-DSS")
                stats["TOTAL"]["COMPLIANCE"].add("PCI-DSS")
                if severity in ["CRITICAL", "HIGH"]:
                    stats[stage]["GATE"] = "FAIL"
                    pipeline_failed = True
                    reason = f"PCI-DSS Violation in {stage} ({comp['pci_dss'][0]})"
                    if reason not in failure_reasons: failure_reasons.append(reason)
                    
            if comp_config.get("enforce_iso_27001") and comp.get("iso_27001"):
                stats[stage]["COMPLIANCE"].add("ISO-27001")
                stats["TOTAL"]["COMPLIANCE"].add("ISO-27001")
                if severity in ["CRITICAL", "HIGH"]:
                    stats[stage]["GATE"] = "FAIL"
                    pipeline_failed = True
                    reason = f"ISO-27001 Violation in {stage} ({comp['iso_27001'][0]})"
                    if reason not in failure_reasons: failure_reasons.append(reason)
                    
            if comp_config.get("enforce_soc2") and comp.get("soc2"):
                stats[stage]["COMPLIANCE"].add("SOC2")
                stats["TOTAL"]["COMPLIANCE"].add("SOC2")
                if severity in ["CRITICAL", "HIGH"]:
                    stats[stage]["GATE"] = "FAIL"
                    pipeline_failed = True
                    reason = f"SOC2 Violation in {stage} ({comp['soc2'][0]})"
                    if reason not in failure_reasons: failure_reasons.append(reason)
                    
        # Check Base Gates
        if gates_config.get("block_on_critical") and severity == "CRITICAL":
            stats[stage]["GATE"] = "FAIL"
            pipeline_failed = True
            reason = f"CRITICAL severity finding in {stage}"
            if reason not in failure_reasons: failure_reasons.append(reason)
            
        if gates_config.get("block_on_secrets") and stage == "SECRETS" and severity in ["CRITICAL", "HIGH"]:
            stats[stage]["GATE"] = "FAIL"
            pipeline_failed = True
            reason = "Hardcoded secret detected"
            if reason not in failure_reasons: failure_reasons.append(reason)
            
        cvss = props.get("cvss_score", 0.0)
        cvss_threshold = gates_config.get("block_on_cvss_above", 10.0)
        if cvss >= cvss_threshold:
            stats[stage]["GATE"] = "FAIL"
            pipeline_failed = True
            reason = f"Finding with CVSS {cvss} >= {cvss_threshold} in {stage}"
            if reason not in failure_reasons: failure_reasons.append(reason)
            
    # Check High count aggregate
    high_threshold = gates_config.get("block_on_high_count", 999)
    if stats["TOTAL"]["HIGH"] >= high_threshold:
        stats["TOTAL"]["GATE"] = "FAIL"
        pipeline_failed = True
        failure_reasons.append(f"Total HIGH severity findings ({stats['TOTAL']['HIGH']}) >= {high_threshold}")
        
    stats["TOTAL"]["GATE"] = "FAIL" if pipeline_failed else "PASS"
    
    # Generate Output
    console.print("\n")
    table = Table(title="Security Gate Decision Matrix", show_header=True, header_style="bold cyan")
    table.add_column("Stage", style="cyan")
    table.add_column("Critical", justify="right", style="red")
    table.add_column("High", justify="right", style="orange3")
    table.add_column("Medium", justify="right", style="yellow")
    table.add_column("Low", justify="right", style="blue")
    table.add_column("Compliance Violations", style="magenta")
    table.add_column("Gate", justify="center")
    
    stages = ["SAST", "SCA", "SECRETS", "IAC", "CONTAINER", "DAST"]
    for s in stages:
        data = stats[s]
        comp_str = ", ".join(data["COMPLIANCE"]) if data["COMPLIANCE"] else "-"
        gate_str = "[bold red]❌ FAIL[/]" if data["GATE"] == "FAIL" else "[bold green]✅ PASS[/]"
        table.add_row(
            s, 
            str(data["CRITICAL"]), 
            str(data["HIGH"]), 
            str(data["MEDIUM"]), 
            str(data["LOW"]), 
            comp_str,
            gate_str
        )
        
    # Add Total Row
    table.add_section()
    tot = stats["TOTAL"]
    comp_str = ", ".join(tot["COMPLIANCE"]) if tot["COMPLIANCE"] else "-"
    gate_str = "[bold red]❌ FAIL[/]" if tot["GATE"] == "FAIL" else "[bold green]✅ PASS[/]"
    table.add_row(
        "[bold]TOTAL[/]", 
        f"[bold]{tot['CRITICAL']}[/]", 
        f"[bold]{tot['HIGH']}[/]", 
        f"[bold]{tot['MEDIUM']}[/]", 
        f"[bold]{tot['LOW']}[/]", 
        comp_str,
        gate_str
    )
    
    console.print(table)
    
    if pipeline_failed:
        panel_text = "\n".join([f"• {r}" for r in failure_reasons])
        console.print(Panel(panel_text, title="[bold red]Pipeline Blocked[/bold red]", border_style="red"))
    else:
        console.print(Panel("All security gates passed.", title="[bold green]Pipeline Approved[/bold green]", border_style="green"))
        
    # Convert sets to lists for JSON serialization
    for stage in stats:
        if "COMPLIANCE" in stats[stage]:
            stats[stage]["COMPLIANCE"] = list(stats[stage]["COMPLIANCE"])

    # Save Decision
    decision = {
        "status": "FAIL" if pipeline_failed else "PASS",
        "reasons": failure_reasons,
        "stats": stats
    }
    
    os.makedirs("findings", exist_ok=True)
    with open("findings/gate_decision.json", 'w') as f:
        json.dump(decision, f, indent=2)
        
    return 1 if pipeline_failed else 0

if __name__ == "__main__":
    findings = load_all_findings()
    sys.exit(evaluate_gate(findings))
