import os
import sys
import subprocess
import argparse
import time
from pathlib import Path
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.panel import Panel

console = Console()

BANNER = """[bold cyan]
██████╗ ███████╗██╗   ██╗███████╗███████╗ ██████╗ ██████╗ ██████╗ ███████╗
██╔══██╗██╔════╝██║   ██║██╔════╝██╔════╝██╔════╝██╔═══██╗██╔══██╗██╔════╝
██║  ██║█████╗  ██║   ██║███████╗█████╗  ██║     ██║   ██║██████╔╝███████╗
██║  ██║██╔══╝  ╚██╗ ██╔╝╚════██║██╔══╝  ██║     ██║   ██║██╔═══╝ ╚════██║
██████╔╝███████╗ ╚████╔╝ ███████║███████╗╚██████╗╚██████╔╝██║     ███████║
╚═════╝ ╚══════╝  ╚═══╝  ╚══════╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝     ╚══════╝
[/bold cyan]
[bold white]CI/CD Security Pipeline Orchestrator v2.0[/bold white]
[dim]Integrating SAST, SCA, Secrets, IaC, Container, and DAST with Compliance Gates[/dim]
"""

def print_banner():
    console.print(BANNER)

def run_stage(name, command, cwd="."):
    """Run a pipeline stage with a spinner."""
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        transient=True,
    ) as progress:
        task = progress.add_task(f"[cyan]Running {name}...", total=None)
        
        try:
            # We use python -m to run the modules so we don't have to worry about PYTHONPATH
            if command[0] == "python":
                # Convert script path to module notation
                script_path = command[1]
                mod = script_path.replace("/", ".").replace("\\", ".").replace(".py", "")
                full_cmd = [sys.executable, "-m", mod] + command[2:]
                
                # Make sure parent dir is in path
                env = os.environ.copy()
                env["PYTHONPATH"] = os.path.abspath(".") + os.pathsep + env.get("PYTHONPATH", "")
                
                result = subprocess.run(full_cmd, cwd=cwd, capture_output=True, text=True, env=env)
            else:
                result = subprocess.run(command, cwd=cwd, capture_output=True, text=True)
            
            # Print the output (which contains the rich tables)
            console.print(result.stdout)
            
            if result.stderr:
                 # Print stderr but don't fail just for warnings
                 for line in result.stderr.splitlines():
                     if "WARN" in line.upper() or "INFO" in line.upper():
                         console.print(f"[dim]{line}[/dim]")
                     else:
                         pass # Skip other stderr noise to keep terminal clean
            
            if result.returncode != 0:
                # We don't fail the orchestrator here. The security gate does that.
                pass
                
            return True
        except Exception as e:
            console.print(f"[red]❌ Stage {name} failed: {str(e)}[/red]")
            return False

def main():
    parser = argparse.ArgumentParser(description="DevSecOps Pipeline Orchestrator")
    parser.add_argument("--source", default=".", help="Source code directory to scan")
    parser.add_argument("--target", help="Target URL for DAST scan (e.g., http://localhost:8080)")
    parser.add_argument("--image", help="Docker image to scan")
    parser.add_argument("--skip-sast", action="store_true", help="Skip SAST scanning")
    parser.add_argument("--skip-dast", action="store_true", help="Skip DAST scanning")
    parser.add_argument("--report", action="store_true", help="Generate HTML/PDF reports")
    parser.add_argument("--notify", action="store_true", help="Send Slack/Email notifications")
    parser.add_argument("--findings-only", action="store_true", help="Skip tool execution, only run gate + report on existing findings")
    parser.add_argument("--compliance-report", action="store_true", help="Ensure compliance heatmap is generated")
    
    args = parser.parse_args()
    
    print_banner()
    
    # Ensure directories exist
    os.makedirs("findings", exist_ok=True)
    os.makedirs("report/output", exist_ok=True)
    
    if not args.findings_only:
        console.print(Panel("[bold]Starting Pipeline Execution[/bold]", border_style="blue"))
        
        # 1. Secrets Scan
        run_stage("Trufflehog Secrets Scan", ["python", "pipeline_stages/secrets/trufflehog_runner.py", args.source])
        run_stage("Gitleaks History Scan", ["python", "pipeline_stages/secrets/gitleaks_runner.py", args.source])
        
        # 2. SAST
        if not args.skip_sast:
            run_stage("SonarQube SAST", ["python", "pipeline_stages/sast/sonarqube_runner.py", args.source])
            run_stage("Semgrep SAST", ["python", "pipeline_stages/sast/semgrep_runner.py", args.source])
            
        # 3. SCA
        run_stage("OWASP Dependency-Check", ["python", "pipeline_stages/sca/dependency_check.py", args.source])
        run_stage("Trivy SCA", ["python", "pipeline_stages/sca/trivy_runner.py", args.source])
        run_stage("SBOM Generation", ["python", "pipeline_stages/sca/sbom_generator.py", args.source])
        
        # 4. IaC
        run_stage("Checkov IaC Scan", ["python", "pipeline_stages/iac/checkov_runner.py", args.source])
        run_stage("Dockerfile Linter", ["python", "pipeline_stages/iac/dockerfile_linter.py", f"{args.source}/Dockerfile"])
        
        # 5. Container Security
        if args.image:
            run_stage("Trivy Image Scan", ["python", "pipeline_stages/container/trivy_image_scanner.py", args.image])
            run_stage("Docker CIS Hardening", ["python", "pipeline_stages/container/docker_hardening.py", args.image])
        else:
            console.print("[dim]Skipping container scans (no --image provided)[/dim]")
            
        # 6. DAST
        if not args.skip_dast and args.target:
            run_stage("OWASP ZAP DAST", ["python", "pipeline_stages/dast/zap_runner.py", args.target, "/actuator/health"])
        elif not args.skip_dast:
            console.print("[yellow]⚠ Skipping DAST (no --target provided)[/yellow]")
            
    # 7. Security Gate
    console.print(Panel("[bold]Evaluating Security Gates[/bold]", border_style="magenta"))
    # We use subprocess directly here to capture the exit code
    env = os.environ.copy()
    env["PYTHONPATH"] = os.path.abspath(".") + os.pathsep + env.get("PYTHONPATH", "")
    gate_cmd = [sys.executable, "-m", "pipeline_stages.gates.security_gate"]
    gate_result = subprocess.run(gate_cmd, env=env)
    
    # 8. Report Generation
    if args.report:
        console.print(Panel("[bold]Generating Compliance Reports[/bold]", border_style="green"))
        report_cmd = [sys.executable, "-m", "report.report_generator"]
        subprocess.run(report_cmd, env=env)
        
    # 9. Notifications
    if args.notify:
        console.print(Panel("[bold]Sending Notifications[/bold]", border_style="cyan"))
        subprocess.run([sys.executable, "-m", "notifications.slack_notifier"], env=env)
        subprocess.run([sys.executable, "-m", "notifications.email_notifier"], env=env)
        
    # Exit with the gate's decision code
    if gate_result.returncode != 0:
        console.print("\n[bold red]Pipeline failed security gates. Fix vulnerabilities and try again.[/bold red]")
    else:
        console.print("\n[bold green]Pipeline passed all security gates. Ready for deployment![/bold green]")
        
    sys.exit(gate_result.returncode)

if __name__ == "__main__":
    main()
