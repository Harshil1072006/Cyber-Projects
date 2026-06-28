"""
Executive Summary Generator.
Generates the executive summary section of the report.
"""

from typing import List, Dict
from ..finding_manager import Finding


class ExecutiveSummary:
    """Helper class to generate summary statistics."""

    @staticmethod
    def generate_stats(findings: List[Finding]) -> Dict[str, int]:
        stats = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for f in findings:
            if f.severity in stats:
                stats[f.severity] += 1
        return stats
