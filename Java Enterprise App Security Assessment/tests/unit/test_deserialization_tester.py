"""
Tests for Deserialization Tester.
"""

from java_security_assessment.api_testing.deserialization_tester import (
    DeserializationTester,
)


def test_deserialization_tester_init(finding_manager):
    tester = DeserializationTester(finding_manager, "http://localhost", {})
    assert tester.target_url == "http://localhost"
