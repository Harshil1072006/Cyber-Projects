"""
Security Gate Validator.
Determines if a build should pass or fail based on findings and risk scores.
"""

import json
import logging
from typing import List, Dict, Any, Tuple
from .risk_scorer import RiskScorer
from .exemption_manager import ExemptionManager

logger = logging.getLogger(__name__)

class SecurityGate:
    """Evaluates findings against configured thresholds to block or pass builds."""
    
    def __init__(self, config_path: str = "gate_config.json"):
        self.config_path = config_path
        self.config = self._load_config()
        self.risk_scorer = RiskScorer()
        self.exemption_manager = ExemptionManager()
        
    def _load_config(self) -> Dict[str, Any]:
        """Loads gate configuration."""
        try:
            with open(self.config_path, "r") as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            logger.warning("Using default gate config.")
            return {
                "max_critical": 0,
                "max_high": 5,
                "max_medium": 20,
                "max_risk_score": 8.0,
                "fail_on_new_critical": True
            }
            
    def evaluate(self, findings: List[Dict[str, Any]], asset_context: Dict[str, Any] = None) -> Tuple[bool, str]:
        """
        Evaluates findings against the gate policy.
        
        Returns:
            Tuple of (passed, reason_message)
        """
        if asset_context is None:
            asset_context = {"asset_criticality": 5.0}
            
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        highest_risk = 0.0
        
        # Filter exempted findings and score the rest
        actionable_findings = []
        for finding in findings:
            if self.exemption_manager.is_exempt(finding):
                logger.info(f"Skipping exempt finding: {finding.get('fingerprint')}")
                continue
                
            score = self.risk_scorer.score_finding(finding, asset_context)
            finding["calculated_risk"] = score
            highest_risk = max(highest_risk, score)
            actionable_findings.append(finding)
            
            sev = finding.get("severity", "low").lower()
            if sev in counts:
                counts[sev] += 1
                
        # Evaluate against thresholds
        if counts["critical"] > self.config.get("max_critical", 0):
            return False, f"Gate failed: Found {counts['critical']} critical issues (Limit: {self.config.get('max_critical')})"
            
        if counts["high"] > self.config.get("max_high", 5):
            return False, f"Gate failed: Found {counts['high']} high issues (Limit: {self.config.get('max_high')})"
            
        if highest_risk > self.config.get("max_risk_score", 8.0):
            return False, f"Gate failed: Maximum risk score of {highest_risk} exceeds threshold {self.config.get('max_risk_score')}"
            
        return True, "Gate passed."
