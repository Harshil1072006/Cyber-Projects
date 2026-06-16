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

def run_docker_hardening(image_name):
    """Run Docker security checks (simulating CIS benchmarks)."""
    console.print(f"[bold blue]▶ Running Docker CIS Hardening Checks on {image_name}...[/bold blue]")
    
    sarif_path = "findings/container_hardening.sarif"
    log = sarif.create_sarif_log()
    run = sarif.create_run("Docker-Hardening", "1.0", "CIS Docker Benchmark")
    
    try:
        # We would normally run something like Docker Bench for Security here.
        # For this pipeline, we'll perform a quick `docker inspect` to check some basics.
        
        cmd = ["docker", "inspect", image_name]
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        if result.returncode != 0:
            console.print(f"[yellow]⚠ Could not inspect image {image_name}. Skipping checks.[/yellow]")
            return 0
            
        data = json.loads(result.stdout)[0]
        config = data.get("Config", {})
        
        # Check: User
        user = config.get("User", "")
        if not user or user == "root" or user == "0":
            sarif.add_result(
                run=run,
                rule_id="CIS-4.1",
                message="Image is configured to run as root. (CIS 4.1: Ensure a user for the container has been created)",
                severity="HIGH",
                stage="CONTAINER",
                cwe="CWE-250",
                file_path="Dockerfile",
                remediation="Add USER <username> instruction to Dockerfile.",
                remediation_effort="Low"
            )
            
        # Check: HEALTHCHECK
        healthcheck = config.get("Healthcheck", {})
        if not healthcheck:
            sarif.add_result(
                run=run,
                rule_id="CIS-4.6",
                message="Image does not contain HEALTHCHECK instruction. (CIS 4.6: Ensure HEALTHCHECK instructions have been added)",
                severity="LOW",
                stage="CONTAINER",
                file_path="Dockerfile",
                remediation="Add HEALTHCHECK instruction to Dockerfile.",
                remediation_effort="Low"
            )

    except Exception as e:
        console.print(f"[red]❌ Error running Docker hardening checks: {str(e)}[/red]")
        
    log["runs"].append(run)
    os.makedirs("findings", exist_ok=True)
    sarif.save_sarif(log, sarif_path)
    
    crit_count = sarif.print_results_table(log, "Docker Hardening")
    return 1 if crit_count > 0 else 0

if __name__ == "__main__":
    if len(sys.argv) < 2:
        console.print("[red]❌ Usage: python docker_hardening.py <image_name>[/red]")
        sys.exit(1)
    sys.exit(run_docker_hardening(sys.argv[1]))
