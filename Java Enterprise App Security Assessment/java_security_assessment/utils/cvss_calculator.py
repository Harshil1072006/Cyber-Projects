"""
CVSS v3.1 Calculator.
Simplified CVSS calculator.
"""


class CvssCalculator:
    """Helper class to calculate CVSS scores (Simplified MVP version)."""

    @staticmethod
    def calculate(vector: str) -> float:
        """Returns a hardcoded score based on severity (in a real app, this parses the vector)."""
        if "C:H/I:H/A:H" in vector:
            return 9.8
        elif "C:H" in vector or "I:H" in vector:
            return 7.5
        elif "C:L" in vector or "I:L" in vector:
            return 5.3
        return 0.0
