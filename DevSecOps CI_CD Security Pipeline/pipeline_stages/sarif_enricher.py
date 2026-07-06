"""
SARIF Enricher.
Adds business context, compliance mapping, and risk ratings to findings.
"""

from typing import Dict, Any, List

class SarifEnricher:
    """Enriches SARIF findings with additional context."""
    
    # Mapping CWE to OWASP Top 10 (2021)
    OWASP_MAPPING = {
        "CWE-89": "A03:2021-Injection",
        "CWE-79": "A03:2021-Injection",
        "CWE-352": "A01:2021-Broken Access Control",
        "CWE-287": "A07:2021-Identification and Authentication Failures",
        "CWE-319": "A02:2021-Cryptographic Failures"
    }
    
    # Mapping to PCI-DSS 4.0
    PCI_MAPPING = {
        "CWE-89": "Requirement 6.2.4 (Injection)",
        "CWE-79": "Requirement 6.2.4 (Injection)",
        "CWE-319": "Requirement 4.2 (Encryption in transit)",
        "CWE-798": "Requirement 8.2 (Authentication)"
    }
    
    def enrich(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """Adds contextual enrichment to a normalized finding."""
        cwe = finding.get("cwe", "")
        
        # Add Mappings
        finding["compliance"] = {
            "owasp_top_10": self.OWASP_MAPPING.get(cwe, "Unmapped"),
            "pci_dss_4": self.PCI_MAPPING.get(cwe, "Unmapped")
        }
        
        # Calculate Risk Rating (Formula: CVSS * Context Multipliers)
        finding["risk_score"] = self._calculate_risk_score(finding)
        
        # Add color coding for dashboards
        finding["color_hex"] = self._get_severity_color(finding.get("severity", "low"))
        
        return finding
        
    def _calculate_risk_score(self, finding: Dict[str, Any]) -> float:
        """Calculates a custom risk score incorporating base CVSS."""
        base_score = float(finding.get("cvss_score") or 0.0)
        
        # In a real environment, we would fetch asset criticality from a CMDB.
        # For now, we apply a standard multiplier.
        asset_criticality_multiplier = 1.2 
        
        # If it's a known injection flaw, elevate risk
        if "Injection" in finding.get("compliance", {}).get("owasp_top_10", ""):
            asset_criticality_multiplier += 0.3
            
        risk_score = base_score * asset_criticality_multiplier
        return min(risk_score, 10.0) # Cap at 10.0
        
    def _get_severity_color(self, severity: str) -> str:
        """Returns standard hex colors for severity."""
        colors = {
            "critical": "#FF0000",
            "high": "#FF8C00",
            "medium": "#FFD700",
            "low": "#00FF00"
        }
        return colors.get(severity.lower(), "#808080")

    def enrich_all(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Enriches a list of findings."""
        return [self.enrich(f) for f in findings]
