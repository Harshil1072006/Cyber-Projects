"""
Compliance Mapper.
Maps technical findings (CWE) to compliance framework controls.
"""

from typing import Dict, Any, List

class ComplianceMapper:
    """Maps findings to specific compliance frameworks."""
    
    # Advanced mappings
    FRAMEWORKS = {
        "PCI-DSS-4.0": {
            "CWE-89": "Requirement 6.2.4 (Injection)",
            "CWE-79": "Requirement 6.2.4 (Injection)",
            "CWE-319": "Requirement 4.2.1 (Strong Cryptography)",
            "CWE-798": "Requirement 8.2.2 (Authentication)",
            "CWE-287": "Requirement 8.3 (MFA)"
        },
        "SOC2-TypeII": {
            "CWE-89": "CC6.6 (External Threats)",
            "CWE-287": "CC6.1 (Logical Access)",
            "CWE-319": "CC6.7 (Data Transmission)"
        },
        "ISO-27001-2022": {
            "CWE-798": "A.5.17 (Authentication information)",
            "CWE-319": "A.8.24 (Use of cryptography)",
            "CWE-89": "A.8.28 (Secure coding)"
        }
    }

    def map_finding(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """Adds all supported compliance mappings to a finding."""
        cwe = finding.get("cwe", "CWE-Unknown")
        
        compliance_data = finding.get("compliance", {})
        
        for framework_name, mapping in self.FRAMEWORKS.items():
            control = mapping.get(cwe, "Not Mapped")
            compliance_data[framework_name] = control
            
        finding["compliance"] = compliance_data
        return finding
