"""
Remediation Guide Formatter.
Provides standardized remediation advice based on CWEs.
"""


class RemediationGuide:
    """Helper class to provide remediation advice."""

    @staticmethod
    def get_advice(cwe_id: str) -> str:
        """Returns standard advice for a given CWE."""
        advice = {
            "CWE-89": "Use prepared statements with parameterized queries.",
            "CWE-502": "Avoid native Java deserialization. Use JSON with secure parsers.",
            "CWE-611": "Disable DTD processing in XML parsers.",
        }
        return advice.get(
            cwe_id, "Review secure coding guidelines for this vulnerability type."
        )
