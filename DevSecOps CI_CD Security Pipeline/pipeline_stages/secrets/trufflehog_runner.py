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

def run_trufflehog(target_dir="."):
    """Run Trufflehog secret scanner and convert to SARIF."""
    console.print(f"[bold blue]▶ Running Trufflehog Secret Scan on {target_dir}...[/bold blue]")
    
    sarif_path = "findings/secrets_trufflehog.sarif"
    log = sarif.create_sarif_log()
    run = sarif.create_run("Trufflehog", "3.63.7", "https://github.com/trufflesecurity/trufflehog")
    
    try:
        # Run Trufflehog (only verified secrets)
        cmd = [
            "trufflehog",
            "filesystem",
            "--only-verified",
            "--json",
            target_dir
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        # Parse Trufflehog JSONL output
        for line in result.stdout.strip().split('\n'):
            if not line:
                continue
                
            try:
                finding = json.loads(line)
                
                # Extract details
                detector = finding.get("DetectorName", "Unknown Secret")
                file_path = finding.get("SourceMetadata", {}).get("Data", {}).get("Filesystem", {}).get("file", "unknown")
                line_num = finding.get("SourceMetadata", {}).get("Data", {}).get("Filesystem", {}).get("line", 1)
                
                # A verified secret is always CRITICAL
                sarif.add_result(
                    run=run,
                    rule_id=f"SECRET-{detector.upper()}",
                    message=f"Verified {detector} secret found in codebase. This credential has active permissions.",
                    severity="CRITICAL",
                    stage="SECRETS",
                    cwe="CWE-798",
                    file_path=file_path,
                    line=line_num,
                    evidence=f"Detector: {detector}",
                    remediation="1) Immediately rotate the secret. 2) Remove from source code. 3) Move to HashiCorp Vault.",
                    remediation_effort="Medium"
                )
            except json.JSONDecodeError:
                continue
                
    except FileNotFoundError:
        console.print("[yellow]⚠ Trufflehog CLI not found. Skipping execution. (Mock data will be used if sample_findings exists)[/yellow]")
    except Exception as e:
        console.print(f"[red]❌ Error running Trufflehog: {str(e)}[/red]")
        
    log["runs"].append(run)
    os.makedirs("findings", exist_ok=True)
    sarif.save_sarif(log, sarif_path)
    
    crit_count = sarif.print_results_table(log, "Trufflehog")
    
    return 1 if crit_count > 0 else 0

if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "."
    sys.exit(run_trufflehog(target))
