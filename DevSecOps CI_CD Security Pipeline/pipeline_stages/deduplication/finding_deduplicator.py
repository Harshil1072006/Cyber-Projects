"""
Finding Deduplicator.
Implements fuzzy matching and fingerprint-based deduplication for findings.
"""

from typing import List, Dict, Any
import difflib

class FindingDeduplicator:
    """Intelligently removes duplicate findings across and within tools."""
    
    def __init__(self, similarity_threshold: float = 0.85):
        """
        Initialize the deduplicator.
        
        Args:
            similarity_threshold: Float between 0 and 1. How similar findings must be to merge.
        """
        self.similarity_threshold = similarity_threshold
        
    def deduplicate(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Deduplicates a list of findings.
        Groups identical/similar findings into a primary finding.
        """
        deduped = []
        
        for finding in findings:
            is_duplicate = False
            for existing in deduped:
                if self._is_match(finding, existing):
                    # Merge contextual data into the existing finding
                    self._merge_findings(existing, finding)
                    is_duplicate = True
                    break
                    
            if not is_duplicate:
                # Initialize tracking for merged tools
                if "detected_by" not in finding:
                    finding["detected_by"] = [finding.get("tool")]
                deduped.append(finding)
                
        return deduped

    def _is_match(self, f1: Dict[str, Any], f2: Dict[str, Any]) -> bool:
        """Determines if two findings represent the same underlying issue."""
        # Exact fingerprint match
        if f1.get("fingerprint") == f2.get("fingerprint"):
            return True
            
        # Same file, same line, same CWE category indicates high likelihood of same vulnerability
        same_location = (f1.get("file_path") == f2.get("file_path") and 
                         f1.get("line_number") == f2.get("line_number"))
                         
        same_cwe = f1.get("cwe") == f2.get("cwe")
        
        if same_location and same_cwe and f1.get("file_path"): # Ensure it's not a generic non-code finding
            return True
            
        # Fuzzy match on description if locations match but CWE differs slightly
        if same_location:
            desc1 = f1.get("description", "")
            desc2 = f2.get("description", "")
            if desc1 and desc2:
                ratio = difflib.SequenceMatcher(None, desc1, desc2).ratio()
                if ratio >= self.similarity_threshold:
                    return True
                    
        return False

    def _merge_findings(self, primary: Dict[str, Any], secondary: Dict[str, Any]) -> None:
        """Merges secondary finding data into the primary finding."""
        tool = secondary.get("tool")
        if tool and tool not in primary["detected_by"]:
            primary["detected_by"].append(tool)
            
        # Elevate severity if secondary found it to be worse
        severities = {"low": 1, "medium": 2, "high": 3, "critical": 4}
        s1 = severities.get(primary.get("severity", "low").lower(), 0)
        s2 = severities.get(secondary.get("severity", "low").lower(), 0)
        
        if s2 > s1:
            primary["severity"] = secondary.get("severity")
            primary["cvss_score"] = max(primary.get("cvss_score", 0), secondary.get("cvss_score", 0))
            
        # Track that this was merged
        if "merged_fingerprints" not in primary:
            primary["merged_fingerprints"] = []
        primary["merged_fingerprints"].append(secondary.get("fingerprint"))
