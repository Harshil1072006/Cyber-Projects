"""
Validation Tester.
Tests Spring @Valid / Bean Validation implementations.
"""

import logging
import requests
from typing import Dict, Any, List
from ..finding_manager import FindingManager, Finding, Evidence
from ..enumeration.swagger_parser import ApiEndpoint

logger = logging.getLogger(__name__)


class ValidationTester:
    """Tests Spring Bean Validation (@Valid) implementations."""

    def __init__(
        self,
        finding_manager: FindingManager,
        target_url: str,
        auth_headers: Dict[str, str],
    ):
        self.finding_manager = finding_manager
        self.target_url = target_url.rstrip("/")
        self.session = requests.Session()
        self.session.headers.update(auth_headers)

    def test_endpoints(self, endpoints: List[ApiEndpoint]) -> None:
        """Tests endpoints for missing input validation."""
        logger.info("Starting Spring Bean Validation tests...")

        for endpoint in endpoints:
            # We focus on POST/PUT where complex objects are usually sent
            if endpoint.method in ["POST", "PUT", "PATCH"]:
                body_params = [
                    p for p in endpoint.parameters if p.in_location == "body"
                ]
                if body_params:
                    self._test_validation(endpoint, body_params)

        logger.info("Spring Bean Validation testing complete.")

    def _test_validation(self, endpoint: ApiEndpoint, body_params: List[Any]) -> None:
        """Sends empty/null payloads to test if @Valid is properly configured."""
        url = f"{self.target_url}{endpoint.path}"

        # Build an intentionally invalid payload (empty JSON object or nulls for required fields)
        invalid_payload = {}
        for param in body_params:
            if param.required:
                invalid_payload[param.name] = None  # Violates @NotNull

        if not invalid_payload:
            return  # No required parameters to test

        try:
            response = self.session.request(
                method=endpoint.method,
                url=url,
                json=invalid_payload,
                timeout=5,
                allow_redirects=False,
            )

            # Spring typically returns 400 Bad Request for validation failures.
            # If it returns 200, 201, or 500 (NullPointerException), validation might be missing.
            if response.status_code in [200, 201, 202, 500]:
                evidence = Evidence(
                    type="request_response",
                    content=f"Payload:\n{invalid_payload}\n\nStatus: {response.status_code}\nSnippet:\n{response.text[:200]}",
                    description="Endpoint accepted a payload missing required fields or threw an unhandled 500 error instead of a 400 validation error.",
                )

                finding = Finding(
                    title=f"Missing Input Validation on {endpoint.path}",
                    description=f"The endpoint {endpoint.method} {endpoint.path} does not properly validate incoming request bodies. Sending null values for required fields resulted in a {response.status_code} status instead of a 400 Bad Request. This indicates @Valid or constraints may be missing.",
                    vulnerability_type="Improper Input Handling",
                    severity="MEDIUM",
                    cwe_id="CWE-20",  # Improper Input Validation
                    cvss_score=5.3,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N",
                    component=endpoint.path,
                    remediation="Apply JSR-303/Bean Validation annotations (e.g., @NotNull, @Size, @Pattern) to the DTO class, and ensure the @Valid annotation is present on the @RequestBody parameter in the controller.",
                    evidence=[evidence],
                )
                self.finding_manager.add_finding(finding)

        except Exception as e:
            logger.debug(f"Validation test failed for {endpoint.path}: {e}")
