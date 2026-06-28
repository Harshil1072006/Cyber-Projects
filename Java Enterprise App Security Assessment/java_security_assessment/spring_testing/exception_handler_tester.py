"""
Exception Handler Tester.
Tests Spring @ControllerAdvice implementations for information disclosure.
"""

import logging
import requests
from typing import Dict, Any, List
from ..finding_manager import FindingManager, Finding, Evidence
from ..enumeration.swagger_parser import ApiEndpoint

logger = logging.getLogger(__name__)


class ExceptionHandlerTester:
    """Tests Spring Exception Handler configurations."""

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
        """Forces an error to test global exception handling."""
        if not endpoints:
            return

        logger.info("Starting Spring Exception Handler tests...")

        # Test on the first GET endpoint to trigger a TypeMismatch or generic 500
        # By sending a completely invalid type (e.g., an array where a string is expected)
        # or malformed JSON

        endpoint = endpoints[0]
        url = f"{self.target_url}{endpoint.path}"

        try:
            # Send deliberately malformed JSON to trigger HttpMessageNotReadableException
            headers = {"Content-Type": "application/json"}
            malformed_json = "{ invalid_json: "

            response = self.session.request(
                method=(
                    endpoint.method if endpoint.method in ["POST", "PUT"] else "POST"
                ),
                url=url,
                data=malformed_json,
                headers=headers,
                timeout=5,
                allow_redirects=False,
            )

            body = response.text

            # If the default Spring Boot error page/JSON is returned, the app might not have a @ControllerAdvice
            if '"status": 400' in body and '"error":' in body and '"trace":' in body:
                evidence = Evidence(
                    type="request_response",
                    content=f"Status: {response.status_code}\nSnippet:\n{body[:300]}",
                    description="Default Spring Boot error response with stack trace.",
                )

                finding = Finding(
                    title="Default Spring Error Response / Missing @ControllerAdvice",
                    description="The application uses the default Spring Boot BasicErrorController which may leak internal information (like stack traces) when server.error.include-stacktrace is enabled. A custom @ControllerAdvice is not handling this exception.",
                    vulnerability_type="Information Disclosure",
                    severity="LOW",
                    cwe_id="CWE-209",
                    cvss_score=3.7,
                    cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
                    component="Global Exception Handler",
                    remediation="Implement a global @ControllerAdvice with @ExceptionHandler methods to return standardized, safe error responses without leaking internal framework details.",
                    evidence=[evidence],
                )
                self.finding_manager.add_finding(finding)

        except Exception as e:
            logger.debug(f"Exception handler test failed: {e}")

        logger.info("Spring Exception Handler testing complete.")
