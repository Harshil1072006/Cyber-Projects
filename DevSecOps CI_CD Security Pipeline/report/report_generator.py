import os
import sys
import json
import datetime
import urllib.parse
from pathlib import Path
from jinja2 import Environment, FileSystemLoader
from rich.console import Console
try:
    from weasyprint import HTML
except Exception as e:
    HTML = None
    # Weasyprint requires GTK3, which is often missing on Windows.
    # We fallback to HTML-only generation.

console = Console()

# Add parent dir to path so we can import _sarif_utils
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from pipeline_stages.gates.security_gate import load_all_findings

def urlencode_filter(s):
    if not s:
        return ""
    return urllib.parse.quote_plus(str(s))

def generate_report():
    """Generate HTML and PDF compliance security reports."""
    console.print("[bold blue]▶ Generating Executive Security Report...[/bold blue]")
    
    findings = load_all_findings()
    
    gate_decision = {"status": "UNKNOWN", "stats": {"TOTAL": {}}}
    if os.path.exists("findings/gate_decision.json"):
        with open("findings/gate_decision.json", 'r') as f:
            gate_decision = json.load(f)
            
    # Group findings by stage for the template
    findings_by_stage = {
        "SAST": [], "SCA": [], "SECRETS": [], 
        "IAC": [], "CONTAINER": [], "DAST": []
    }
    
    # Extract heatmap data
    owasp_heatmap = {}
    compliance_heatmap = {"PCI-DSS": set(), "ISO 27001": set(), "SOC 2": set()}
    
    # Ensure criticals/highs are sorted to top
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    findings.sort(key=lambda x: severity_order.get(x.get("properties", {}).get("severity", "LOW"), 99))
    
    for f in findings:
        props = f.get("properties", {})
        stage = props.get("stage", "UNKNOWN").upper()
        if stage in findings_by_stage:
            findings_by_stage[stage].append(f)
            
        owasp = props.get("owasp_category")
        if owasp:
            if owasp not in owasp_heatmap: owasp_heatmap[owasp] = 0
            owasp_heatmap[owasp] += 1
            
        comp = props.get("compliance", {})
        for control in comp.get("pci_dss", []):
            compliance_heatmap["PCI-DSS"].add(control.split(" - ")[0])
        for control in comp.get("iso_27001", []):
            compliance_heatmap["ISO 27001"].add(control.split(" - ")[0])
        for control in comp.get("soc2", []):
            compliance_heatmap["SOC 2"].add(control.split(" - ")[0])
            
    # Prepare template data
    env = Environment(loader=FileSystemLoader("report/templates"))
    env.filters['urlencode'] = urlencode_filter
    
    template = env.get_template("pipeline_report.html")
    
    html_out = template.render(
        date=datetime.datetime.now().strftime("%Y-%m-%d %H:%M UTC"),
        run_id=os.getenv("BUILD_NUMBER", "Local-Run"),
        branch=os.getenv("GIT_BRANCH", "main"),
        commit=os.getenv("GIT_COMMIT", "HEAD")[:7],
        gate=gate_decision,
        findings_by_stage=findings_by_stage,
        owasp_heatmap=owasp_heatmap,
        compliance_heatmap={k: list(v) for k, v in compliance_heatmap.items()},
        total_findings=len(findings)
    )
    
    os.makedirs("report/output", exist_ok=True)
    html_path = "report/output/pipeline_report.html"
    pdf_path = "report/output/pipeline_report.pdf"
    
    with open(html_path, 'w', encoding='utf-8') as f:
        f.write(html_out)
    console.print(f"[bold green]✔ HTML Report saved to {html_path}[/bold green]")
    
    if HTML:
        try:
            HTML(string=html_out).write_pdf(pdf_path)
            console.print(f"[bold green]✔ PDF Report saved to {pdf_path}[/bold green]")
        except Exception as e:
            console.print(f"[yellow]⚠ Could not generate PDF: {str(e)}[/yellow]")
    else:
        console.print("[yellow]⚠ weasyprint not installed. Skipping PDF generation.[/yellow]")
        
    return 0

if __name__ == "__main__":
    sys.exit(generate_report())
