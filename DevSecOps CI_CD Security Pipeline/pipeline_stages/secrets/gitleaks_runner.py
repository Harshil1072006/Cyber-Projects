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

def run_gitleaks(target_dir="."):
    """Run Gitleaks secret scanner and convert to SARIF."""
    console.print(f"[bold blue]▶ Running Gitleaks History Scan on {target_dir}...[/bold blue]")
    
    sarif_path = "findings/secrets_gitleaks.sarif"
    raw_json_path = "findings/raw_gitleaks.json"
    
    log = sarif.create_sarif_log()
    run = sarif.create_run("Gitleaks", "8.18.2", "https://github.com/gitleaks/gitleaks")
    
    try:
        # Run Gitleaks
        cmd = [
            "gitleaks",
            "detect",
            "--source", target_dir,
            "--report-format", "json",
            "--report-path", raw_json_path,
            "--no-git" # For local testing without a git repo initialized
        ]
        
        subprocess.run(cmd, capture_output=True, text=True)
        
        if os.path.exists(raw_json_path):
            with open(raw_json_path, 'r') as f:
                findings = json.load(f)
                
            for finding in findings:
                rule_id = finding.get("RuleID", "generic-secret")
                desc = finding.get("Description", "Secret detected")
                file_path = finding.get("File", "unknown")
                line_num = finding.get("StartLine", 1)
                
                # Gitleaks finds potential secrets, we mark them as HIGH
                sarif.add_result(
                    run=run,
                    rule_id=f"SECRET-{rule_id}",
                    message=f"Potential secret ({desc}) found in source code.",
                    severity="HIGH",
                    stage="SECRETS",
                    cwe="CWE-798",
                    file_path=file_path,
                    line=line_num,
                    remediation="Verify if this is a real secret. If yes: 1) Rotate it 2) Remove from history using BFG or git-filter-repo 3) Move to Vault.",
                    remediation_effort="High"
                )
                
    except FileNotFoundError:
        console.print("[yellow]⚠ Gitleaks CLI not found. Skipping execution.[/yellow]")
    except Exception as e:
        console.print(f"[red]❌ Error running Gitleaks: {str(e)}[/red]")
        
    log["runs"].append(run)
    os.makedirs("findings", exist_ok=True)
    sarif.save_sarif(log, sarif_path)
    
    crit_count = sarif.print_results_table(log, "Gitleaks")
    
    return 1 if crit_count > 0 else 0

if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "."
    sys.exit(run_gitleaks(target))
