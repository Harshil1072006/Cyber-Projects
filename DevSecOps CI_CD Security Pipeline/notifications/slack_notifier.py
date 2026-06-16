import os
import sys
import json
import requests
from rich.console import Console

# Add parent dir to path so we can import vault
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from pipeline_stages.secrets.vault_client import secrets

console = Console()

def send_slack_notification(gate_decision_path="findings/gate_decision.json"):
    """Send a Slack notification with pipeline status and compliance violations."""
    
    webhook_url = secrets.get_secret("SLACK_WEBHOOK_URL")
    if not webhook_url:
        console.print("[yellow]⚠ SLACK_WEBHOOK_URL not found in Vault/Env. Skipping notification.[/yellow]")
        return 0
        
    if not os.path.exists(gate_decision_path):
        console.print(f"[yellow]⚠ {gate_decision_path} not found. Run security gate first.[/yellow]")
        return 1
        
    with open(gate_decision_path, 'r') as f:
        decision = json.load(f)
        
    status = decision.get("status", "FAIL")
    stats = decision.get("stats", {}).get("TOTAL", {})
    reasons = decision.get("reasons", [])
    
    # Check config to see if we should notify
    try:
        with open("gate_config.json", "r") as f:
            config = json.load(f)
            notify_pass = config.get("notifications", {}).get("notify_on_pass", False)
            if status == "PASS" and not notify_pass:
                console.print("[dim]Notification for PASS skipped per gate_config.json[/dim]")
                return 0
    except:
        pass
        
    color = "#36a64f" if status == "PASS" else "#ff0000"
    emoji = "✅" if status == "PASS" else "❌"
    
    # Build Block Kit message
    blocks = [
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": f"{emoji} DevSecOps Pipeline: {status}",
                "emoji": True
            }
        },
        {
            "type": "section",
            "fields": [
                {
                    "type": "mrkdwn",
                    "text": f"*Critical:* {stats.get('CRITICAL', 0)}"
                },
                {
                    "type": "mrkdwn",
                    "text": f"*High:* {stats.get('HIGH', 0)}"
                },
                {
                    "type": "mrkdwn",
                    "text": f"*Medium:* {stats.get('MEDIUM', 0)}"
                },
                {
                    "type": "mrkdwn",
                    "text": f"*Low:* {stats.get('LOW', 0)}"
                }
            ]
        }
    ]
    
    # Add Compliance Block
    comp_list = stats.get("COMPLIANCE", [])
    if comp_list:
        blocks.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"*⚠️ Compliance Violations Detected:*\n{', '.join(comp_list)}"
            }
        })
        
    # Add Failure Reasons
    if reasons:
        reason_text = "\n".join([f"• {r}" for r in reasons])
        blocks.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"*Blocking Reasons:*\n```\n{reason_text}\n```"
            }
        })
        
    # Add Actions
    blocks.append({
        "type": "actions",
        "elements": [
            {
                "type": "button",
                "text": {
                    "type": "plain_text",
                    "text": "View Full Report",
                    "emoji": True
                },
                "url": "https://jenkins.internal.company.com/job/DevSecOps-Pipeline/lastBuild/Security_Report/"
            }
        ]
    })
    
    payload = {
        "text": f"Pipeline {status}: {stats.get('CRITICAL', 0)} Critical, {stats.get('HIGH', 0)} High",
        "attachments": [
            {
                "color": color,
                "blocks": blocks
            }
        ]
    }
    
    if "--dry-run" in sys.argv:
        console.print("[cyan]Dry run mode. Slack payload:[/cyan]")
        console.print(json.dumps(payload, indent=2))
        return 0
        
    try:
        console.print("[dim]Sending Slack notification...[/dim]")
        response = requests.post(webhook_url, json=payload)
        if response.status_code == 200 or response.status_code == 201:
            console.print("[bold green]✔ Slack notification sent successfully[/bold green]")
        else:
            console.print(f"[red]❌ Failed to send Slack notification: {response.status_code} {response.text}[/red]")
            return 1
    except Exception as e:
        console.print(f"[red]❌ Error sending Slack notification: {str(e)}[/red]")
        return 1
        
    return 0

if __name__ == "__main__":
    sys.exit(send_slack_notification())
