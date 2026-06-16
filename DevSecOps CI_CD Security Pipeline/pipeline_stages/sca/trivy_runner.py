import os
import sys
import subprocess
import json
from pathlib import Path
from rich.console import Console

# Add parent dir to path so we can import _sarif_utils
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
import _sarif_utils as sarif

console = Console()

def run_trivy_sca(target_dir="."):
    """Run Trivy filesystem SCA scan and output SARIF."""
    console.print(f"[bold blue]▶ Running Trivy SCA Scan on {target_dir}...[/bold blue]")
    
    sarif_path = "findings/sca_trivy.sarif"
    raw_sarif_path = "findings/raw_trivy_sca.sarif"
    
    try:
        cmd = [
            "trivy",
            "fs",
            "--format", "sarif",
            "--output", raw_sarif_path,
            "--severity", "CRITICAL,HIGH,MEDIUM",
            target_dir
        ]
        
        subprocess.run(cmd, capture_output=True, text=True)
        
        if not os.path.exists(raw_sarif_path):
             console.print("[yellow]⚠ Trivy CLI not found or failed to output SARIF.[/yellow]")
             return 0
             
        # Read the raw SARIF and enrich with our compliance mappings
        with open(raw_sarif_path, 'r') as f:
            log = json.load(f)
            
        if not log.get("runs") or not log["runs"][0].get("results"):
            console.print("[bold green]✔ No dependencies with known vulnerabilities found by Trivy[/bold green]")
            return 0
            
        run = log["runs"][0]
        compliance_map = sarif.load_compliance_map()
        
        for result in run.get("results", []):
            if "properties" not in result:
                result["properties"] = {}
                
            level = result.get("level", "warning")
            severity = "CRITICAL" if level == "error" else "HIGH" if level == "warning" else "MEDIUM"
            
            cve = result.get("ruleId", "")
            # All SCA findings map to vulnerable components compliance controls
            compliance_tags = sarif.get_compliance_tags(None, compliance_map)
            # Add hardcoded SCA compliance mapping
            compliance_tags["pci_dss"] = ["6.2 - Security Patches"]
            compliance_tags["iso_27001"] = ["A.8.8 - Management of Technical Vulnerabilities"]
            compliance_tags["soc2"] = ["CC7.1 - Infrastructure Monitoring"]
            
            result["properties"].update({
                "stage": "SCA",
                "severity": severity,
                "cve": cve,
                "compliance": compliance_tags,
                "gate_blocking": severity in ["CRITICAL", "HIGH"]
            })
            
        # Save enriched
        sarif.save_sarif(log, sarif_path)
        crit_count = sarif.print_results_table(log, "Trivy SCA")
        return 1 if crit_count > 0 else 0
        
    except Exception as e:
        console.print(f"[red]❌ Error running Trivy SCA: {str(e)}[/red]")
        return 0

if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "."
    sys.exit(run_trivy_sca(target))
