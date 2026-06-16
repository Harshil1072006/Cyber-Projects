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

def run_trivy_image(image_name):
    """Run Trivy container image scan and output SARIF."""
    console.print(f"[bold blue]▶ Running Trivy Container Scan on {image_name}...[/bold blue]")
    
    sarif_path = "findings/container_trivy.sarif"
    raw_sarif_path = "findings/raw_trivy_image.sarif"
    
    try:
        cmd = [
            "trivy",
            "image",
            "--format", "sarif",
            "--output", raw_sarif_path,
            "--severity", "CRITICAL,HIGH",
            image_name
        ]
        
        subprocess.run(cmd, capture_output=True, text=True)
        
        if not os.path.exists(raw_sarif_path):
             console.print("[yellow]⚠ Trivy CLI not found or failed to scan image.[/yellow]")
             return 0
             
        # Read the raw SARIF and enrich with our compliance mappings
        with open(raw_sarif_path, 'r') as f:
            log = json.load(f)
            
        if not log.get("runs") or not log["runs"][0].get("results"):
            console.print("[bold green]✔ No vulnerabilities found in container image[/bold green]")
            return 0
            
        run = log["runs"][0]
        compliance_map = sarif.load_compliance_map()
        
        for result in run.get("results", []):
            if "properties" not in result:
                result["properties"] = {}
                
            level = result.get("level", "warning")
            severity = "CRITICAL" if level == "error" else "HIGH" if level == "warning" else "MEDIUM"
            
            cve = result.get("ruleId", "")
            
            # Container compliance tags
            compliance_tags = sarif.get_compliance_tags(None, compliance_map)
            compliance_tags["pci_dss"] = ["6.2 - Security Patches"]
            compliance_tags["iso_27001"] = ["A.8.8 - Management of Technical Vulnerabilities", "A.12.1.2 - Capacity Management"]
            compliance_tags["soc2"] = ["CC7.1 - Infrastructure Monitoring"]
            
            result["properties"].update({
                "stage": "CONTAINER",
                "severity": severity,
                "cve": cve,
                "compliance": compliance_tags,
                "gate_blocking": severity in ["CRITICAL", "HIGH"]
            })
            
        # Save enriched
        sarif.save_sarif(log, sarif_path)
        crit_count = sarif.print_results_table(log, "Trivy Container Scan")
        return 1 if crit_count > 0 else 0
        
    except Exception as e:
        console.print(f"[red]❌ Error running Trivy image scan: {str(e)}[/red]")
        return 0

if __name__ == "__main__":
    if len(sys.argv) < 2:
        console.print("[red]❌ Usage: python trivy_image_scanner.py <image_name>[/red]")
        sys.exit(1)
    sys.exit(run_trivy_image(sys.argv[1]))
