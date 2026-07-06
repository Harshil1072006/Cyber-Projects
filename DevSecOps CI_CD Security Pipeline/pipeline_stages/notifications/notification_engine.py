"""
Notification Engine.
Routes and formats alerts to appropriate channels to reduce fatigue.
"""

from typing import List, Dict, Any
import logging
from .slack_advanced import SlackAdvanced
from .email_templates import EmailTemplates
from .pagerduty_integrator import PagerDutyIntegrator

logger = logging.getLogger(__name__)

class NotificationEngine:
    """Smart notification router."""
    
    def __init__(self):
        self.slack = SlackAdvanced()
        self.email = EmailTemplates()
        self.pagerduty = PagerDutyIntegrator()
        
    def dispatch_notifications(self, findings: List[Dict[str, Any]], gate_passed: bool) -> None:
        """
        Dispatches notifications based on findings severity and gate status.
        """
        criticals = [f for f in findings if f.get("severity") == "critical"]
        highs = [f for f in findings if f.get("severity") == "high"]
        
        # PagerDuty for Criticals
        if criticals:
            self.pagerduty.trigger_incident(criticals)
            
        # Slack for Gate Failures or Highs/Criticals
        if not gate_passed or criticals or highs:
            self.slack.send_alert(findings, gate_passed)
            
        # Email for digest and compliance
        self.email.send_executive_summary(findings, gate_passed)
