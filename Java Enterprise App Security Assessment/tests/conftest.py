"""
Pytest configuration and shared fixtures.
"""

import pytest
from java_security_assessment.finding_manager import FindingManager
from java_security_assessment.enumeration.swagger_parser import ApiEndpoint


@pytest.fixture
def finding_manager():
    return FindingManager()


@pytest.fixture
def sample_endpoints():
    return [
        ApiEndpoint(path="/api/users", method="GET"),
        ApiEndpoint(path="/api/login", method="POST"),
    ]
