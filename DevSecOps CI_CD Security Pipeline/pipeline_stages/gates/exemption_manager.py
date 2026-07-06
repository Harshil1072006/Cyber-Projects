"""
Exemption Manager.
Handles tracking, validating, and expiring risk exemptions.
"""

import json
import logging
from datetime import datetime
from typing import Dict, Any, List

logger = logging.getLogger(__name__)

class ExemptionManager:
    """Manages finding exemptions based on business justification."""
    
    def __init__(self, exemptions_file: str = "config/exemptions.json"):
        self.exemptions_file = exemptions_file
        self.exemptions = self._load_exemptions()
        
    def _load_exemptions(self) -> Dict[str, Any]:
        """Loads exemptions from JSON."""
        try:
            with open(self.exemptions_file, "r") as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            return {}
            
    def is_exempt(self, finding: Dict[str, Any]) -> bool:
        """
        Checks if a finding has an active exemption.
        """
        fingerprint = finding.get("fingerprint")
        if not fingerprint or fingerprint not in self.exemptions:
            return False
            
        exemption = self.exemptions[fingerprint]
        
        # Check expiry
        expiry_str = exemption.get("expires_at")
        if expiry_str:
            try:
                expiry = datetime.fromisoformat(expiry_str)
                if datetime.now() > expiry:
                    logger.warning(f"Exemption for {fingerprint} has expired.")
                    return False
            except ValueError:
                logger.error(f"Invalid date format in exemption: {expiry_str}")
                return False
                
        # Check approval status
        if exemption.get("status") != "approved":
            return False
            
        return True
