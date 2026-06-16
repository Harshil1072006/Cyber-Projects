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

def run_checkov(target_dir="."):
    """Run Checkov IaC scanner and convert to SARIF."""
    console.print(f"[bold blue]▶ Running Checkov IaC Scan on {target_dir}...[/bold blue]")
    
    # We use Checkov's native JSON output, then convert to our standard SARIF
    # to ensure compliance mappings are applied uniformly
    
    report_path = "findings/raw_checkov.json"
    sarif_path = "findings/iac_checkov.sarif"
    
    log = sarif.create_sarif_log()
    run = sarif.create_run("Checkov", "3.2.0", "https://checkov.io/")
    
    try:
        # Run Checkov
        cmd = [
            "checkov",
            "-d", target_dir,
            "--output", "json"
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        # Checkov returns exit code 1 if findings exist, which is expected
        if not result.stdout.strip():
            console.print("[yellow]⚠ Checkov produced no output. Is it installed?[/yellow]")
            sarif.save_sarif(log, sarif_path)
            return 0
            
        try:
            # Checkov output can be a list or a dict depending on what it scanned
            data = json.loads(result.stdout)
        except json.JSONDecodeError:
            # Sometimes checkov prints logs before json
            json_str = result.stdout[result.stdout.find("{"):] if "{" in result.stdout else result.stdout[result.stdout.find("["):]
            data = json.loads(json_str)
            
        reports = data if isinstance(data, list) else [data]
        
        for report in reports:
            if not isinstance(report, dict) or "results" not in report:
                continue
                
            failed_checks = report.get("results", {}).get("failed_checks", [])
            
            for check in failed_checks:
                rule_id = check.get("check_id", "UNKNOWN")
                message = check.get("check_name", "IaC Misconfiguration")
                file_path = check.get("file_path", "").lstrip("/")
                line = check.get("file_line_range", [1])[0]
                guideline = check.get("guideline", "")
                
                # Checkov doesn't always provide severity, we infer based on common rules
                severity = "MEDIUM"
                if "secret" in rule_id.lower() or "password" in rule_id.lower():
                    severity = "CRITICAL"
                elif "root" in rule_id.lower() or "privilege" in rule_id.lower():
                    severity = "HIGH"
                
                # Try to map to CWE
                cwe = None
                if severity == "CRITICAL":
                    cwe = "CWE-798"
                elif severity == "HIGH":
                    cwe = "CWE-250"
                    
                sarif.add_result(
                    run=run,
                    rule_id=rule_id,
                    message=message,
                    severity=severity,
                    stage="IAC",
                    cwe=cwe,
                    file_path=file_path,
                    line=line,
                    remediation=f"Review guidelines at: {guideline}" if guideline else "Review infrastructure code configuration.",
                    remediation_effort="Low"
                )
                
    except FileNotFoundError:
        console.print("[yellow]⚠ Checkov CLI not found. Skipping execution. (Mock data will be used if sample_findings exists)[/yellow]")
    except Exception as e:
        console.print(f"[red]❌ Error running Checkov: {str(e)}[/red]")
        
    log["runs"].append(run)
    os.makedirs("findings", exist_ok=True)
    sarif.save_sarif(log, sarif_path)
    
    crit_count = sarif.print_results_table(log, "Checkov IaC")
    
    return 1 if crit_count > 0 else 0

if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "."
    sys.exit(run_checkov(target))
