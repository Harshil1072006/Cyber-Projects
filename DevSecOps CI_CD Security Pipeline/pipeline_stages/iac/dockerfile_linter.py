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

def run_dockerfile_linter(target_file="Dockerfile"):
    """
    Pure Python Dockerfile security linter.
    Checks for: root user, exposed dangerous ports, latest tag, 
    ADD instead of COPY, missing HEALTHCHECK, secrets in ENV.
    """
    console.print(f"[bold blue]▶ Running Pure-Python Dockerfile Linter on {target_file}...[/bold blue]")
    
    log = sarif.create_sarif_log()
    run = sarif.create_run("Dockerfile-Linter", "1.0.0", "https://github.com/your-org/devsecops-pipeline")
    
    if not os.path.exists(target_file):
        console.print(f"[yellow]⚠ {target_file} not found. Skipping.[/yellow]")
        sarif.save_sarif(log, "findings/iac_dockerfile.sarif")
        return 0

    with open(target_file, 'r') as f:
        lines = f.readlines()

    has_user = False
    has_healthcheck = False

    for i, line in enumerate(lines):
        line = line.strip()
        if not line or line.startswith("#"):
            continue

        line_num = i + 1

        # Check: Running as root
        if line.startswith("USER "):
            has_user = True
            user_val = line.split(" ", 1)[1].strip()
            if user_val == "root" or user_val == "0":
                sarif.add_result(
                    run=run,
                    rule_id="DL-SEC-001",
                    message="Dockerfile explicitly sets USER to root. This violates the principle of least privilege.",
                    severity="HIGH",
                    stage="IAC",
                    cwe="CWE-250",
                    file_path=target_file,
                    line=line_num,
                    evidence=line,
                    remediation="Change to a non-root user: USER appuser"
                )

        # Check: Dangerous ports
        if line.startswith("EXPOSE "):
            ports = line.split(" ")[1:]
            for port in ports:
                port = port.split("/")[0] # remove /tcp
                if port in ["22", "3306", "5432", "27017", "6379", "11211"]:
                    sarif.add_result(
                        run=run,
                        rule_id="DL-SEC-002",
                        message=f"Dangerous port {port} exposed. Internal services should not expose ports directly.",
                        severity="MEDIUM",
                        stage="IAC",
                        cwe="CWE-284",
                        file_path=target_file,
                        line=line_num,
                        evidence=line,
                        remediation="Remove the EXPOSE directive and rely on Docker internal networking."
                    )

        # Check: Using latest tag
        if line.startswith("FROM "):
            image = line.split(" ")[1]
            if ":" not in image or image.endswith(":latest"):
                sarif.add_result(
                    run=run,
                    rule_id="DL-SEC-003",
                    message=f"Base image uses 'latest' tag ({image}). This can lead to unpredictable builds and breaks reproducibility.",
                    severity="MEDIUM",
                    stage="IAC",
                    file_path=target_file,
                    line=line_num,
                    evidence=line,
                    remediation="Pin to a specific version or SHA hash (e.g., python:3.11-slim)."
                )

        # Check: ADD instead of COPY
        if line.startswith("ADD "):
            if not line.endswith(".tar.gz") and "http" not in line:
                sarif.add_result(
                    run=run,
                    rule_id="DL-SEC-004",
                    message="Using ADD instead of COPY. ADD can unexpectedly extract archives or fetch remote files.",
                    severity="LOW",
                    stage="IAC",
                    file_path=target_file,
                    line=line_num,
                    evidence=line,
                    remediation="Use COPY for local files and directories."
                )

        # Check: Missing --no-cache
        if line.startswith("RUN ") and "apk add" in line and "--no-cache" not in line:
             sarif.add_result(
                run=run,
                rule_id="DL-SEC-005",
                message="apk add used without --no-cache. This leaves package indexes in the image, increasing size and potential attack surface.",
                severity="LOW",
                stage="IAC",
                file_path=target_file,
                line=line_num,
                evidence=line,
                remediation="Add --no-cache to apk add commands."
            )

        # Check: Secrets in ENV
        if line.startswith("ENV ") or line.startswith("ARG "):
            content = line[4:].lower()
            suspicious_keys = ["password", "secret", "token", "key", "cert", "credential"]
            if any(k in content for k in suspicious_keys):
                sarif.add_result(
                    run=run,
                    rule_id="DL-SEC-006",
                    message="Potential secret stored in ENV or ARG. These are baked into the image history and can be trivially extracted.",
                    severity="CRITICAL",
                    stage="IAC",
                    cwe="CWE-798",
                    file_path=target_file,
                    line=line_num,
                    evidence=line,
                    remediation="Use Docker secrets, HashiCorp Vault, or mount secrets at runtime. Never bake them into the image."
                )

        # Check: HEALTHCHECK
        if line.startswith("HEALTHCHECK "):
            has_healthcheck = True

    # Post-processing checks
    if not has_user:
        sarif.add_result(
            run=run,
            rule_id="DL-SEC-007",
            message="No USER directive found. The container will run as root by default.",
            severity="HIGH",
            stage="IAC",
            cwe="CWE-250",
            file_path=target_file,
            line=1,
            remediation="Create a dedicated user and add: USER appuser"
        )

    if not has_healthcheck:
        sarif.add_result(
            run=run,
            rule_id="DL-SEC-008",
            message="No HEALTHCHECK directive found. Orchestrators cannot determine if the application is truly healthy.",
            severity="LOW",
            stage="IAC",
            file_path=target_file,
            line=1,
            remediation="Add a HEALTHCHECK directive to test the application's core functionality."
        )

    log["runs"].append(run)
    
    os.makedirs("findings", exist_ok=True)
    sarif.save_sarif(log, "findings/iac_dockerfile.sarif")
    
    crit_count = sarif.print_results_table(log, "Dockerfile Linter")
    
    if crit_count > 0:
        return 1
    return 0

if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "Dockerfile"
    sys.exit(run_dockerfile_linter(target))
