"""
Predefined attack test cases.
"""

from typing import List, Dict, Any
from .test_case_builder import TestCaseBuilder

def get_predefined_test_cases() -> List[Dict[str, Any]]:
    """Returns a list of predefined standard test cases."""
    return [
        TestCaseBuilder.build(
            name="ARP Spoofing Detection",
            attack_type="ARP_SPOOF",
            parameters={"count": 5},
            expected_alerts=["ARP spoofing", "ARP cache poisoning"]
        ),
        TestCaseBuilder.build(
            name="TCP SYN Scan Detection",
            attack_type="PORT_SCAN",
            parameters={"scan_type": "SYN", "ports": [22, 80, 443, 8080]},
            expected_alerts=["ET SCAN Potential SSH Scan", "ET SCAN NMAP OS Detection"]
        ),
        TestCaseBuilder.build(
            name="SYN Flood DoS Detection",
            attack_type="DOS",
            parameters={"dos_type": "SYN_FLOOD", "count": 100},
            expected_alerts=["ET DOS Possible SYN Flood"]
        ),
        TestCaseBuilder.build(
            name="Invalid TCP Flags Anomaly",
            attack_type="PROTOCOL_ANOMALY",
            parameters={"anomaly_type": "BAD_TCP_FLAGS"},
            expected_alerts=["SURICATA TCP invalid flag combination"]
        ),
    ]
