"""
Audit Logger.
Maintains an immutable log of compliance and gate decisions.
"""

import json
import logging
import os
from datetime import datetime
from typing import Dict, Any

logger = logging.getLogger(__name__)

class AuditLogger:
    """Logs critical pipeline decisions for auditing purposes."""
    
    def __init__(self, log_dir: str = "report/audit"):
        self.log_dir = log_dir
        os.makedirs(self.log_dir, exist_ok=True)
        # Use month-based rolling log file
        self.log_file = os.path.join(self.log_dir, f"audit_{datetime.now().strftime('%Y_%m')}.jsonl")

    def log_event(self, event_type: str, details: Dict[str, Any]) -> None:
        """
        Logs a structured event.
        """
        event = {
            "timestamp": datetime.now().isoformat(),
            "event_type": event_type,
            "details": details
        }
        
        try:
            with open(self.log_file, "a") as f:
                f.write(json.dumps(event) + "\n")
        except Exception as e:
            logger.error(f"Failed to write to audit log: {e}")
