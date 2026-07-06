"""
Noise Filter.
Suppresses known false positives and low-confidence findings.
"""

from typing import List, Dict, Any

class NoiseFilter:
    """Filters out findings likely to be false positives or noise."""
    
    def __init__(self, exclusions_file: str = "config/false_positives.json"):
        # In a full implementation, we would load known FP fingerprints from this file.
        self.exclusions = set()
        
    def filter(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Removes noisy findings.
        """
        filtered = []
        for finding in findings:
            if not self._is_noise(finding):
                filtered.append(finding)
        return filtered
        
    def _is_noise(self, finding: Dict[str, Any]) -> bool:
        """Heuristics for determining if a finding is noise."""
        if finding.get("fingerprint") in self.exclusions:
            return True
            
        # Example heuristic: Certain tools reporting generic low-severity informational items
        if finding.get("severity") == "info" or finding.get("severity") == "low":
            if finding.get("cwe") == "CWE-Unknown":
                return True
                
        # Example heuristic: Exclude test directories
        file_path = finding.get("file_path", "")
        if "test" in file_path.lower() or "mock" in file_path.lower():
            # Usually we don't care about security findings in test files unless they are secrets
            if finding.get("cwe") != "CWE-798": # 798 is Hardcoded Credentials
                return True
                
        return False
