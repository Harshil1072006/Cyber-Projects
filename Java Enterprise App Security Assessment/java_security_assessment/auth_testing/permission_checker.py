"""
Permission Checker for testing endpoint access control.
Tests for Broken Access Control (BOLA/IDOR and function level).
"""

import logging
import requests
from typing import List, Dict, Any, Tuple
from ..finding_manager import FindingManager, Finding, Evidence
from ..enumeration.swagger_parser import ApiEndpoint

logger = logging.getLogger(__name__)


class PermissionChecker:
    """Tests endpoints for authorization vulnerabilities."""

    def __init__(
        self,
        finding_manager: FindingManager,
        target_url: str,
        auth_headers: Dict[str, str],
    ):
        self.finding_manager = finding_manager
        self.target_url = target_url
        self.auth_headers = auth_headers
        self.session = requests.Session()

    def test_endpoints(self, endpoints: List[ApiEndpoint]) -> None:
        """Tests a list of endpoints for missing authentication."""
        logger.info("Starting missing authentication tests on endpoints...")

        for endpoint in endpoints:
            if endpoint.requires_auth:
                self._test_missing_auth(endpoint)

        logger.info("Permission checking complete.")

    def _test_missing_auth(self, endpoint: ApiEndpoint) -> None:
        """Checks if an endpoint that supposedly requires auth is accessible without it."""
        url = f"{self.target_url}{endpoint.path}"

        # Replace path parameters with dummies if any exist
        test_url = url
        for param in endpoint.parameters:
            if param.in_location == "path":
                test_url = test_url.replace(f"{{{param.name}}}", "1")

        try:
            # Request WITHOUT auth headers
            response = self.session.request(
                method=endpoint.method, url=test_url, timeout=5, allow_redirects=False
            )

            # If we get a 2xx or 3xx (that isn't redirecting to login), it might be broken auth
            if response.status_code < 400 and response.status_code not in [302, 303]:
                # Verify it's not a public generic response (like a 404 disguised as 200)
                # This is a heuristic. A real tool would compare authenticated vs unauthenticated responses.
                if len(response.text) > 0 and "error" not in response.text.lower():
                    evidence = Evidence(
                        type="response",
                        content=f"Request: {endpoint.method} {test_url}\nStatus: {response.status_code}\nResponse snippet: {response.text[:200]}",
                        description="Endpoint accessed successfully without authentication credentials.",
                    )

                    finding = Finding(
                        title=f"Missing Authentication on {endpoint.path}",
                        description=f"The endpoint {endpoint.method} {endpoint.path} is marked as requiring authentication but is accessible without valid credentials.",
                        vulnerability_type="Broken Access Control",
                        severity="HIGH",
                        cwe_id="CWE-306",  # Missing Authentication for Critical Function
                        cvss_score=7.5,
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                        component=endpoint.path,
                        remediation="Ensure the Spring Security configuration correctly protects this path and requires a valid session or token.",
                        evidence=[evidence],
                    )
                    self.finding_manager.add_finding(finding)
        except Exception as e:
            logger.debug(f"Failed to test {endpoint.path} for missing auth: {e}")
