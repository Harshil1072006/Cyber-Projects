import os
import sys
import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path
from rich.console import Console

# Add parent dir to path so we can import _sarif_utils
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
import _sarif_utils as sarif

console = Console()

def run_dependency_check(target_dir="."):
    """Run OWASP Dependency-Check and convert XML to SARIF."""
    console.print(f"[bold blue]▶ Running OWASP Dependency-Check on {target_dir}...[/bold blue]")
    
    sarif_path = "findings/sca_dependency.sarif"
    raw_xml_path = "findings/dependency-check-report.xml"
    
    log = sarif.create_sarif_log()
    run = sarif.create_run("OWASP-Dependency-Check", "9.0.9", "https://owasp.org/www-project-dependency-check/")
    
    try:
        cmd = [
            "dependency-check",
            "--project", "FinSecure",
            "--scan", target_dir,
            "--format", "XML",
            "--out", "findings"
        ]
        
        console.print("[dim]Executing: dependency-check... (this may take a while to update NVD)[/dim]")
        subprocess.run(cmd, capture_output=True, text=True)
        
        if not os.path.exists(raw_xml_path):
             console.print("[yellow]⚠ Dependency-check XML not found. Skipping execution. (Mock data will be used if sample_findings exists)[/yellow]")
             sarif.save_sarif(log, sarif_path)
             return 0
             
        # Parse XML
        ns = {'dc': 'https://jeremylong.github.io/DependencyCheck/dependency-check.2.5.xsd'}
        tree = ET.parse(raw_xml_path)
        root = tree.getroot()
        
        for dep in root.findall('.//dc:dependency', ns):
            file_name = dep.find('dc:fileName', ns)
            file_path = dep.find('dc:filePath', ns)
            
            if file_name is None:
                continue
                
            fname = file_name.text
            fpath = file_path.text if file_path is not None else fname
            
            vulnerabilities = dep.findall('.//dc:vulnerability', ns)
            for vuln in vulnerabilities:
                name = vuln.find('dc:name', ns).text
                severity_node = vuln.find('dc:severity', ns)
                cvss_node = vuln.find('.//dc:cvssV3/dc:baseScore', ns)
                
                # Determine Severity
                severity = "MEDIUM"
                if severity_node is not None:
                    sev_text = severity_node.text.upper()
                    if sev_text in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
                        severity = sev_text
                        
                cvss_score = float(cvss_node.text) if cvss_node is not None else 0.0
                if cvss_score >= 9.0: severity = "CRITICAL"
                elif cvss_score >= 7.0: severity = "HIGH"
                
                desc = vuln.find('dc:description', ns)
                description = desc.text if desc is not None else "Vulnerable dependency"
                
                sarif.add_result(
                    run=run,
                    rule_id=name,
                    message=f"{fname} is vulnerable to {name}. {description[:100]}...",
                    severity=severity,
                    stage="SCA",
                    cve=name if name.startswith("CVE") else None,
                    cvss_score=cvss_score,
                    file_path=fpath,
                    remediation=f"Update {fname} to a patched version.",
                    remediation_effort="Low"
                )
                
    except FileNotFoundError:
         console.print("[yellow]⚠ dependency-check CLI not found. Skipping.[/yellow]")
    except Exception as e:
         console.print(f"[red]❌ Error running dependency-check: {str(e)}[/red]")
         
    log["runs"].append(run)
    os.makedirs("findings", exist_ok=True)
    sarif.save_sarif(log, sarif_path)
    
    crit_count = sarif.print_results_table(log, "OWASP Dependency-Check")
    
    return 1 if crit_count > 0 else 0

if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "."
    sys.exit(run_dependency_check(target))
