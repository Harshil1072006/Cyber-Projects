"""
Control Validator.
Verifies that all required compliance controls are being tested by the pipeline.
"""

from typing import List, Dict, Any
import logging

logger = logging.getLogger(__name__)

class ControlValidator:
    """Validates that security tools are providing adequate control coverage."""
    
    # Define which controls MUST be checked for a given framework
    REQUIRED_CONTROLS = {
        "PCI-DSS-4.0": [
            "Requirement 6.2.4 (Injection)",
            "Requirement 4.2.1 (Strong Cryptography)"
        ]
    }
    
    def validate_coverage(self, mapped_findings: List[Dict[str, Any]], framework: str = "PCI-DSS-4.0") -> Dict[str, Any]:
        """
        Validates if the current scan effectively checked the required controls.
        Note: This simplistic check assumes that if a finding was found for a control, 
        the control is being tested. In a real scenario, you'd map tool capabilities to controls.
        """
        result = {
            "framework": framework,
            "fully_covered": True,
            "missing_controls": []
        }
        
        required = self.REQUIRED_CONTROLS.get(framework, [])
        if not required:
            return result
            
        # Extract all tested controls from findings
        tested_controls = set()
        for f in mapped_findings:
            control = f.get("compliance", {}).get(framework)
            if control and control != "Not Mapped":
                tested_controls.add(control)
                
        # Identify gaps
        for req in required:
            if req not in tested_controls:
                # We didn't find any vulnerabilities for this control. 
                # This could mean the tool is working and code is secure, 
                # OR it could mean the tool isn't testing for it.
                # A robust implementation would parse the tool's loaded rulesets.
                result["missing_controls"].append(req)
                
        if result["missing_controls"]:
            result["fully_covered"] = False
            logger.info(f"Compliance coverage gap for {framework}: {result['missing_controls']}")
            
        return result
