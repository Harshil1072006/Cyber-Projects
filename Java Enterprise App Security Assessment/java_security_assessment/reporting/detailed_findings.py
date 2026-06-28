"""
Detailed Findings Formatter.
Formats individual findings for the report.
"""

from ..finding_manager import Finding


class DetailedFindings:
    """Helper class to format finding details."""

    @staticmethod
    def format_finding(finding: Finding) -> str:
        """Returns a string representation of a finding."""
        return f"{finding.title} ({finding.severity})"
