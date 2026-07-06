"""
Compliance Reporter.
Generates specific compliance reports based on the findings.
"""

from typing import List, Dict, Any
from datetime import datetime

class ComplianceReporter:
    """Generates compliance status reports."""
    
    def generate_report(self, findings: List[Dict[str, Any]], framework: str = "PCI-DSS-4.0") -> Dict[str, Any]:
        """
        Generates a summary report for a specific compliance framework.
        """
        report = {
            "framework": framework,
            "generated_at": datetime.now().isoformat(),
            "status": "PASS",
            "violations": [],
            "controls_failed": set()
        }
        
        for finding in findings:
            framework_mapping = finding.get("compliance", {}).get(framework)
            if framework_mapping and framework_mapping != "Not Mapped":
                report["status"] = "FAIL"
                report["controls_failed"].add(framework_mapping)
                report["violations"].append({
                    "control": framework_mapping,
                    "finding_fingerprint": finding.get("fingerprint"),
                    "severity": finding.get("severity")
                })
                
        # Convert set to list for JSON serialization
        report["controls_failed"] = list(report["controls_failed"])
        return report
