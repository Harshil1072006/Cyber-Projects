"""
Tests for Endpoint Discoverer.
"""

from java_security_assessment.enumeration.endpoint_discoverer import EndpointDiscoverer
from java_security_assessment.enumeration.swagger_parser import ApiEndpoint


def test_endpoint_discoverer_init():
    discoverer = EndpointDiscoverer(target_url="http://localhost:8080")
    assert discoverer.target_url == "http://localhost:8080"
    assert len(discoverer.endpoints) == 0


def test_endpoint_deduplication():
    discoverer = EndpointDiscoverer(target_url="http://localhost:8080")
    ep1 = ApiEndpoint(path="/users", method="GET")
    ep2 = ApiEndpoint(path="/users", method="GET")  # Duplicate

    discoverer.endpoints = [ep1, ep2]
    discoverer._deduplicate_endpoints()

    assert len(discoverer.endpoints) == 1
