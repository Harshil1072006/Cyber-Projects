"""
Test Case Builder.
Helper to cleanly define test cases.
"""

from typing import Dict, Any, List

class TestCaseBuilder:
    """Builds standard test case dictionaries."""

    @staticmethod
    def build(name: str, attack_type: str, parameters: Dict[str, Any], expected_alerts: List[str]) -> Dict[str, Any]:
        """
        Creates a test case definition.
        
        Args:
            name: Human readable name.
            attack_type: The attack registry key (e.g., 'ARP_SPOOF').
            parameters: Attack parameters.
            expected_alerts: List of expected Suricata signature substrings.
            
        Returns:
            Dictionary representing the test case.
        """
        return {
            "name": name,
            "type": attack_type,
            "parameters": parameters,
            "expected_alerts": expected_alerts
        }
