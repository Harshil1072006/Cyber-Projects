"""
CWE Mapper.
Maps CWE IDs to descriptions.
"""


class CweMapper:
    """Helper class to map CWEs to their descriptions."""

    @staticmethod
    def get_description(cwe_id: str) -> str:
        """Returns the description for a CWE."""
        mapping = {
            "CWE-89": "Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')",
            "CWE-502": "Deserialization of Untrusted Data",
            "CWE-611": "Improper Restriction of XML External Entity Reference",
            "CWE-918": "Server-Side Request Forgery (SSRF)",
        }
        return mapping.get(cwe_id, "Unknown Vulnerability")
