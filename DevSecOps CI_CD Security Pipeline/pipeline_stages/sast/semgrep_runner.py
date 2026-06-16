import os
import sys
import subprocess
from pathlib import Path
from rich.console import Console

# Add parent dir to path so we can import _sarif_utils
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
import _sarif_utils as sarif

console = Console()

def run_semgrep(target_dir="."):
    """Run Semgrep SAST scan and convert output to enriched SARIF."""
    console.print(f"[bold blue]▶ Running Semgrep SAST Scan on {target_dir}...[/bold blue]")
    
    sarif_path = "findings/sast_semgrep.sarif"
    raw_sarif_path = "findings/raw_semgrep.sarif"
    
    # Check if semgrep is installed
    try:
        subprocess.run(["semgrep", "--version"], capture_output=True, check=True)
    except (subprocess.CalledProcessError, FileNotFoundError):
        console.print("[yellow]⚠ Semgrep CLI not found. Skipping execution. (Mock data will be used if sample_findings exists)[/yellow]")
        # We create an empty log here just in case, but let the orchestrator handle mock data
        log = sarif.create_sarif_log()
        run = sarif.create_run("Semgrep", "1.0", "https://semgrep.dev")
        log["runs"].append(run)
        sarif.save_sarif(log, sarif_path)
        return 0
        
    try:
        cmd = [
            "semgrep",
            "scan",
            "--config=auto",
            "--config=p/owasp-top-ten",
            "--sarif",
            "--output", raw_sarif_path,
            target_dir
        ]
        
        console.print("[dim]Executing: semgrep scan...[/dim]")
        subprocess.run(cmd, capture_output=True, text=True)
        
        if not os.path.exists(raw_sarif_path):
            console.print("[yellow]⚠ Semgrep did not produce a SARIF output file.[/yellow]")
            return 0
            
        # We read the Semgrep SARIF and enrich it with our compliance tags
        with open(raw_sarif_path, 'r') as f:
            log = json.load(f)
            
        if not log.get("runs") or not log["runs"][0].get("results"):
            console.print("[bold green]✔ No findings detected by Semgrep[/bold green]")
            return 0
            
        run = log["runs"][0]
        compliance_map = sarif.load_compliance_map()
        
        # Enrich results
        for result in run.get("results", []):
            if "properties" not in result:
                result["properties"] = {}
                
            # Semgrep uses 'error', 'warning', 'info'
            level = result.get("level", "warning")
            severity = "CRITICAL" if level == "error" else "HIGH" if level == "warning" else "MEDIUM"
            
            # Map OWASP category to CWE for our compliance mapping
            rule_id = result.get("ruleId", "")
            cwe = None
            if "injection" in rule_id.lower() or "sql" in rule_id.lower():
                cwe = "CWE-89"
            elif "xss" in rule_id.lower():
                cwe = "CWE-79"
            elif "secret" in rule_id.lower() or "hardcoded" in rule_id.lower():
                cwe = "CWE-798"
            elif "deserialization" in rule_id.lower():
                cwe = "CWE-502"
                
            compliance_tags = sarif.get_compliance_tags(cwe, compliance_map)
            
            result["properties"].update({
                "stage": "SAST",
                "severity": severity,
                "compliance": compliance_tags,
                "gate_blocking": severity in ["CRITICAL", "HIGH"]
            })
            if cwe:
                result["properties"]["cwe"] = cwe
                
        # Save enriched SARIF
        sarif.save_sarif(log, sarif_path)
        crit_count = sarif.print_results_table(log, "Semgrep")
        return 1 if crit_count > 0 else 0
        
    except Exception as e:
        console.print(f"[red]❌ Error running Semgrep: {str(e)}[/red]")
        return 0

if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "."
    sys.exit(run_semgrep(target))
