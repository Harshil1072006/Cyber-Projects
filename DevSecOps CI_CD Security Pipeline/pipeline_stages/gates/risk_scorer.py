"""
Risk Scorer.
Implements a multi-factor risk calculation for vulnerabilities.
"""

from typing import Dict, Any, List

class RiskScorer:
    """Calculates comprehensive risk scores based on multiple factors."""
    
    def __init__(self):
        # Weights for different factors summing to 1.0
        self.weights = {
            "cvss_base": 0.40,
            "exploit_availability": 0.20,
            "asset_criticality": 0.20,
            "remediation_complexity": 0.10,
            "time_to_fix": 0.10
        }
        
    def score_finding(self, finding: Dict[str, Any], context: Dict[str, Any] = None) -> float:
        """
        Calculates a 0-10 risk score for a single finding.
        """
        if context is None:
            context = {}
            
        cvss_score = float(finding.get("cvss_score", 0.0))
        
        # Exploit availability (0.0 to 10.0 scale)
        exploit_score = 10.0 if finding.get("has_public_exploit") else 0.0
        
        # Asset criticality (0.0 to 10.0 scale)
        asset_score = float(context.get("asset_criticality", 5.0))
        
        # Remediation complexity (0.0 to 10.0 scale, inverted logic - higher complexity means lower immediate risk reduction, but here we treat it as risk modifier if it's hard to fix)
        # We'll assign a flat 5.0 unless specified
        complexity_score = float(context.get("remediation_complexity", 5.0))
        
        # Time to fix (0.0 to 10.0 scale)
        time_score = float(context.get("estimated_time_to_fix_days", 5.0))
        
        total_score = (
            (cvss_score * self.weights["cvss_base"]) +
            (exploit_score * self.weights["exploit_availability"]) +
            (asset_score * self.weights["asset_criticality"]) +
            (complexity_score * self.weights["remediation_complexity"]) +
            (time_score * self.weights["time_to_fix"])
        )
        
        return round(min(max(total_score, 0.0), 10.0), 2)
