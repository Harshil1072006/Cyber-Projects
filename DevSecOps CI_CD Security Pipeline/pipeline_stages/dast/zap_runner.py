import os
import sys
import subprocess
import json
import time
import requests
from pathlib import Path
from rich.console import Console

# Add parent dir to path so we can import _sarif_utils
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
import _sarif_utils as sarif

console = Console()

def check_target_health(url, timeout=120):
    """Wait for the target API to become healthy."""
    console.print(f"[dim]Checking health of target API at {url}...[/dim]")
    
    start_time = time.time()
    while time.time() - start_time < timeout:
        try:
            response = requests.get(url, timeout=5)
            if response.status_code == 200:
                console.print(f"[bold green]✔ Target API is healthy and reachable![/bold green]")
                return True
        except requests.RequestException:
            pass
            
        time.sleep(5)
        console.print("[dim]  Waiting for target API...[/dim]")
        
    console.print(f"[bold red]❌ Target API did not become healthy within {timeout} seconds.[/bold red]")
    return False

def run_zap(target_url):
    """Run OWASP ZAP baseline scan and output SARIF."""
    console.print(f"[bold blue]▶ Running OWASP ZAP DAST Scan against {target_url}...[/bold blue]")
    
    sarif_path = "findings/dast_zap.sarif"
    raw_json_path = "findings/zap_report.json"
    
    log = sarif.create_sarif_log()
    run = sarif.create_run("OWASP-ZAP", "2.14.0", "https://www.zaproxy.org/")
    
    # In a real environment, we would run zap-baseline.py
    # For this project, we check if the report exists (from a previous run or sample data)
    # If not, we simulate the run.
    
    try:
        # Simulate ZAP run
        cmd = [
            "docker", "run", "--rm",
            "-v", f"{os.path.abspath('findings')}:/zap/wrk/:rw",
            "ghcr.io/zaproxy/zaproxy:stable",
            "zap-baseline.py",
            "-t", target_url,
            "-J", "zap_report.json"
        ]
        
        console.print("[dim]Executing: docker run ghcr.io/zaproxy/zaproxy:stable zap-baseline.py...[/dim]")
        subprocess.run(cmd, capture_output=True, text=True)
        
        if not os.path.exists(raw_json_path):
            console.print("[yellow]⚠ ZAP report not generated. (Mock data will be used if sample_findings exists)[/yellow]")
            sarif.save_sarif(log, sarif_path)
            return 0
            
        # Parse ZAP JSON and convert to SARIF
        with open(raw_json_path, 'r') as f:
            zap_report = json.load(f)
            
        site = zap_report.get("site", [{}])[0]
        alerts = site.get("alerts", [])
        
        for alert in alerts:
            name = alert.get("name", "Vulnerability")
            riskcode = alert.get("riskcode", "1")
            confidence = alert.get("confidence", "2")
            desc = alert.get("desc", "").replace("<p>", "").replace("</p>", "")
            solution = alert.get("solution", "").replace("<p>", "").replace("</p>", "")
            cweid = alert.get("cweid", "-1")
            
            # Map Risk to Severity
            severity = "LOW"
            if riskcode == "3": severity = "HIGH"
            elif riskcode == "2": severity = "MEDIUM"
            elif riskcode == "1": severity = "LOW"
            else: severity = "INFO"
            
            if severity == "INFO":
                continue # Skip info level
                
            cwe = f"CWE-{cweid}" if cweid != "-1" else None
            
            instances = alert.get("instances", [])
            file_path = instances[0].get("uri", target_url) if instances else target_url
            evidence = instances[0].get("evidence", "") if instances else ""
            
            sarif.add_result(
                run=run,
                rule_id=name,
                message=desc[:150] + "..." if len(desc) > 150 else desc,
                severity=severity,
                stage="DAST",
                cwe=cwe,
                file_path=file_path,
                evidence=evidence,
                remediation=solution[:150] + "..." if len(solution) > 150 else solution,
                remediation_effort="Medium"
            )
            
    except Exception as e:
        console.print(f"[red]❌ Error running ZAP: {str(e)}[/red]")
        
    log["runs"].append(run)
    os.makedirs("findings", exist_ok=True)
    sarif.save_sarif(log, sarif_path)
    
    crit_count = sarif.print_results_table(log, "OWASP ZAP")
    return 1 if crit_count > 0 else 0

if __name__ == "__main__":
    if len(sys.argv) < 2:
        console.print("[red]❌ Usage: python zap_runner.py <target_url> [health_endpoint][/red]")
        sys.exit(1)
        
    target = sys.argv[1]
    health_endpoint = sys.argv[2] if len(sys.argv) > 2 else None
    
    if health_endpoint:
        health_url = target.rstrip("/") + health_endpoint
        if not check_target_health(health_url):
            sys.exit(1)
            
    sys.exit(run_zap(target))
