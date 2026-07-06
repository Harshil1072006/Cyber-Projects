"""
Remediation Engine.
Orchestrates automated fix suggestions for findings.
"""

from typing import List, Dict, Any
from .fix_suggester import FixSuggester

class RemediationEngine:
    """Adds auto-remediation suggestions to findings."""
    
    def __init__(self):
        self.suggester = FixSuggester()
        
    def enrich_with_fixes(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Iterates over findings and appends remediation guidance.
        """
        for finding in findings:
            cwe = finding.get("cwe")
            file_path = finding.get("file_path", "")
            
            # Determine language based on file extension
            language = "unknown"
            if file_path.endswith(".py"): language = "python"
            elif file_path.endswith(".js") or file_path.endswith(".ts"): language = "javascript"
            elif file_path.endswith(".java"): language = "java"
            elif file_path.endswith(".go"): language = "go"
            
            suggestion = self.suggester.get_suggestion(cwe, language)
            if suggestion:
                finding["remediation_suggestion"] = suggestion
                
        return findings
