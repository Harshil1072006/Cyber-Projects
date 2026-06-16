import os
import sys
import json
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.application import MIMEApplication
from rich.console import Console

# Add parent dir to path so we can import vault
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from pipeline_stages.secrets.vault_client import secrets

console = Console()

def send_email_notification(gate_decision_path="findings/gate_decision.json", report_pdf_path="report/output/pipeline_report.pdf"):
    """Send an HTML email notification with the pipeline report attached."""
    
    # Retrieve SMTP config from Vault (expecting a JSON string)
    smtp_config_str = secrets.get_secret("SMTP_CONFIG")
    
    if "--dry-run" in sys.argv:
        console.print("[cyan]Dry run mode. Email notification would be sent.[/cyan]")
        if not smtp_config_str:
             console.print("[yellow]Note: SMTP_CONFIG not found in Vault/Env.[/yellow]")
        return 0
        
    if not smtp_config_str:
        console.print("[yellow]⚠ SMTP_CONFIG not found in Vault/Env. Skipping email notification.[/yellow]")
        return 0
        
    try:
        smtp_config = json.loads(smtp_config_str)
    except json.JSONDecodeError:
        console.print("[red]❌ SMTP_CONFIG is not valid JSON.[/red]")
        return 1
        
    if not os.path.exists(gate_decision_path):
        console.print(f"[yellow]⚠ {gate_decision_path} not found. Run security gate first.[/yellow]")
        return 1
        
    with open(gate_decision_path, 'r') as f:
        decision = json.load(f)
        
    status = decision.get("status", "FAIL")
    stats = decision.get("stats", {}).get("TOTAL", {})
    reasons = decision.get("reasons", [])
    
    # Build HTML Email
    color = "#28a745" if status == "PASS" else "#dc3545"
    
    comp_list = stats.get("COMPLIANCE", [])
    comp_html = ""
    if comp_list:
        comp_html = f"""
        <div style="background-color: #fff3cd; color: #856404; padding: 10px; margin-top: 15px; border-radius: 4px; border-left: 4px solid #ffeeba;">
            <strong>⚠️ Compliance Violations Detected:</strong> {', '.join(comp_list)}
        </div>
        """
        
    reasons_html = ""
    if reasons:
        reasons_list = "".join([f"<li>{r}</li>" for r in reasons])
        reasons_html = f"""
        <div style="margin-top: 20px;">
            <h3 style="color: #333;">Blocking Reasons:</h3>
            <ul>{reasons_list}</ul>
        </div>
        """
        
    html = f"""
    <html>
    <head>
        <style>
            body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
            .container {{ max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #ddd; border-radius: 5px; }}
            .header {{ background-color: {color}; color: white; padding: 15px; text-align: center; border-radius: 5px 5px 0 0; }}
            .stats-table {{ width: 100%; border-collapse: collapse; margin-top: 20px; }}
            .stats-table th, .stats-table td {{ border: 1px solid #ddd; padding: 8px; text-align: center; }}
            .stats-table th {{ background-color: #f2f2f2; }}
            .crit {{ color: #dc3545; font-weight: bold; }}
            .high {{ color: #fd7e14; font-weight: bold; }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h2>DevSecOps Pipeline: {status}</h2>
            </div>
            
            <p>The automated security pipeline has completed execution.</p>
            
            <table class="stats-table">
                <tr>
                    <th>Critical</th>
                    <th>High</th>
                    <th>Medium</th>
                    <th>Low</th>
                </tr>
                <tr>
                    <td class="crit">{stats.get('CRITICAL', 0)}</td>
                    <td class="high">{stats.get('HIGH', 0)}</td>
                    <td>{stats.get('MEDIUM', 0)}</td>
                    <td>{stats.get('LOW', 0)}</td>
                </tr>
            </table>
            
            {comp_html}
            {reasons_html}
            
            <p style="margin-top: 30px; font-size: 0.9em; color: #666;">
                Please see the attached PDF report for full details and remediation guidance.
            </p>
        </div>
    </body>
    </html>
    """
    
    # Construct Email Message
    msg = MIMEMultipart()
    msg['From'] = smtp_config.get("from_address", "security@company.com")
    msg['To'] = smtp_config.get("to_address", "security-team@company.com")
    msg['Subject'] = f"[Security Pipeline] {status} - {stats.get('CRITICAL', 0)} Critical, {stats.get('HIGH', 0)} High"
    
    msg.attach(MIMEText(html, 'html'))
    
    # Attach PDF if exists
    if os.path.exists(report_pdf_path):
        with open(report_pdf_path, "rb") as f:
            pdf_attachment = MIMEApplication(f.read(), _subtype="pdf")
            pdf_attachment.add_header('Content-Disposition', 'attachment', filename=os.path.basename(report_pdf_path))
            msg.attach(pdf_attachment)
    else:
        console.print(f"[dim]PDF report {report_pdf_path} not found. Sending without attachment.[/dim]")
        
    # Send Email
    try:
        console.print("[dim]Connecting to SMTP server...[/dim]")
        server = smtplib.SMTP(smtp_config.get("host", "smtp.gmail.com"), smtp_config.get("port", 587))
        server.starttls()
        
        username = smtp_config.get("username")
        password = smtp_config.get("password")
        
        if username and password:
            server.login(username, password)
            
        server.send_message(msg)
        server.quit()
        console.print("[bold green]✔ Email notification sent successfully[/bold green]")
    except Exception as e:
        console.print(f"[red]❌ Error sending email: {str(e)}[/red]")
        return 1
        
    return 0

if __name__ == "__main__":
    sys.exit(send_email_notification())
