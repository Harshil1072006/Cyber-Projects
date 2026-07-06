"""
SARIF Processor module for advanced finding normalization and deduplication.
"""

import hashlib
import json
import logging
from typing import Dict, Any, List

logger = logging.getLogger(__name__)

class SarifProcessor:
    """Processes and normalizes SARIF output from various tools."""
    
    def __init__(self):
        self.findings = []
        
    def process(self, sarif_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Processes SARIF JSON and normalizes findings."""
        if not sarif_data.get("runs"):
            return []
            
        normalized_findings = []
        for run in sarif_data.get("runs", []):
            tool_name = run.get("tool", {}).get("driver", {}).get("name", "unknown")
            rules = {rule.get("id"): rule for rule in run.get("tool", {}).get("driver", {}).get("rules", [])}
            
            for result in run.get("results", []):
                rule_id = result.get("ruleId")
                rule = rules.get(rule_id, {})
                
                finding = self._normalize_finding(result, rule, tool_name)
                normalized_findings.append(finding)
                
        self.findings.extend(normalized_findings)
        return normalized_findings
        
    def _normalize_finding(self, result: Dict[str, Any], rule: Dict[str, Any], tool_name: str) -> Dict[str, Any]:
        """Normalizes a single finding to a standard format."""
        
        # Extract location
        locations = result.get("locations", [])
        uri = ""
        line = 0
        if locations:
            phys_loc = locations[0].get("physicalLocation", {})
            uri = phys_loc.get("artifactLocation", {}).get("uri", "")
            line = phys_loc.get("region", {}).get("startLine", 0)
            
        # Extract CVSS/Severity
        severity = result.get("level", "warning")
        properties = rule.get("properties", {})
        cvss_score = properties.get("cvss_score", properties.get("security-severity", 0.0))
        
        # Determine universal severity based on standard CVSS v3.1 mapping if score exists
        if cvss_score:
            cvss_score = float(cvss_score)
            if cvss_score >= 9.0:
                severity = "critical"
            elif cvss_score >= 7.0:
                severity = "high"
            elif cvss_score >= 4.0:
                severity = "medium"
            else:
                severity = "low"
                
        # Generate fingerprint
        fingerprint_raw = f"{tool_name}:{rule.get('id')}:{uri}:{line}"
        fingerprint = hashlib.sha256(fingerprint_raw.encode()).hexdigest()
        
        return {
            "fingerprint": fingerprint,
            "tool": tool_name,
            "rule_id": rule.get("id"),
            "name": rule.get("name", rule.get("shortDescription", {}).get("text", "Unknown Vulnerability")),
            "description": result.get("message", {}).get("text", ""),
            "severity": severity,
            "cvss_score": cvss_score,
            "file_path": uri,
            "line_number": line,
            "cwe": self._extract_cwe(properties.get("tags", [])),
            "raw_result": result
        }
        
    def _extract_cwe(self, tags: List[str]) -> str:
        """Extracts CWE ID from tags if present."""
        for tag in tags:
            if tag.upper().startswith("CWE-"):
                return tag.upper()
        return "CWE-Unknown"

    def deduplicate(self) -> List[Dict[str, Any]]:
        """Deduplicates findings based on exact fingerprint match."""
        seen = set()
        deduped = []
        for finding in self.findings:
            if finding["fingerprint"] not in seen:
                seen.add(finding["fingerprint"])
                deduped.append(finding)
        
        self.findings = deduped
        return deduped
