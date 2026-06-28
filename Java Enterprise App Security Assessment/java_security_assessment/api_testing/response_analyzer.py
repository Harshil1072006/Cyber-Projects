"""
Response Analyzer for inspecting HTTP responses.
Detects information disclosure, stack traces, and insecure headers.
"""

import re
import logging
import requests
from typing import Dict, Any, List
from ..finding_manager import FindingManager, Finding, Evidence

logger = logging.getLogger(__name__)


class ResponseAnalyzer:
    """Analyzes HTTP responses for generic vulnerabilities (Info Disclosure, Headers)."""

    def __init__(self, finding_manager: FindingManager):
        self.finding_manager = finding_manager

    def analyze(self, response: requests.Response, endpoint_path: str) -> None:
        """Analyzes a single response."""
        self._check_stack_traces(response, endpoint_path)
        self._check_security_headers(response, endpoint_path)
        self._check_server_header(response, endpoint_path)

    def _check_stack_traces(
        self, response: requests.Response, endpoint_path: str
    ) -> None:
        """Looks for Java stack traces in the response body."""
        # Common Java stack trace patterns
        patterns = [
            r"Exception in thread \".*?\" java\.[a-zA-Z0-9_.]+(Error|Exception)",
            r"at org\.springframework\.",
            r"at java\.base\/java\.lang\.",
            r"org\.hibernate\.exception\.",
            r"java\.sql\.SQLException",
        ]

        body = response.text

        for pattern in patterns:
            match = re.search(pattern, body, re.IGNORECASE)
            if match:
                evidence = Evidence(
                    type="response",
                    content=f"Status: {response.status_code}\nSnippet:\n...{body[max(0, match.start()-50):min(len(body), match.end()+200)]}...",
                    description="Java stack trace leaked in response.",
                )

                finding = Finding(
                    title="Information Disclosure: Stack Trace Leak",
                    description="The application leaks internal Java stack traces to the client. This reveals internal package names, framework versions, and potentially sensitive logic flow.",
                    vulnerability_type="Information Disclosure",
                    severity="MEDIUM",
                    cwe_id="CWE-209",  # Generation of Error Message Containing Sensitive Information
                    cvss_score=5.3,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                    component=endpoint_path,
                    remediation="Configure Spring Boot to disable stack traces in API responses (server.error.include-stacktrace=never) and use a global @ControllerAdvice to return generic error messages.",
                    evidence=[evidence],
                )
                self.finding_manager.add_finding(finding)
                break  # Only report once per response

    def _check_security_headers(
        self, response: requests.Response, endpoint_path: str
    ) -> None:
        """Checks for the presence of recommended security headers."""
        headers = {k.lower(): v for k, v in response.headers.items()}

        missing_headers = []
        if "content-type" not in headers:
            missing_headers.append("Content-Type")
        if "x-content-type-options" not in headers:
            missing_headers.append("X-Content-Type-Options")

        # Simplified header check for API (CORS, HSTS usually handled at gateway, but good to note)

        if missing_headers:
            evidence = Evidence(
                type="response",
                content=f"Headers received:\n{response.headers}",
                description=f"Missing headers: {', '.join(missing_headers)}",
            )

            finding = Finding(
                title=f"Missing Security Headers ({len(missing_headers)})",
                description=f"The response is missing the following recommended security headers: {', '.join(missing_headers)}.",
                vulnerability_type="Security Misconfiguration",
                severity="LOW",
                cwe_id="CWE-693",  # Protection Mechanism Failure
                cvss_score=3.7,
                cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N",
                component=endpoint_path,
                remediation="Configure Spring Security to inject standard security headers.",
                evidence=[evidence],
            )
            self.finding_manager.add_finding(finding)

    def _check_server_header(
        self, response: requests.Response, endpoint_path: str
    ) -> None:
        """Checks if the Server or X-Powered-By header leaks technology versions."""
        headers = {k.lower(): v for k, v in response.headers.items()}

        leaked = []
        if "server" in headers and any(char.isdigit() for char in headers["server"]):
            leaked.append(f"Server: {headers['server']}")
        if "x-powered-by" in headers:
            leaked.append(f"X-Powered-By: {headers['x-powered-by']}")

        if leaked:
            evidence = Evidence(
                type="response",
                content="\n".join(leaked),
                description="Headers leaking specific server or framework versions.",
            )

            finding = Finding(
                title="Information Disclosure: Server Version Leak",
                description="The server reveals its specific software version via HTTP headers.",
                vulnerability_type="Information Disclosure",
                severity="INFO",
                cwe_id="CWE-200",  # Exposure of Sensitive Information to an Unauthorized Actor
                cvss_score=0.0,
                cvss_vector="",
                component=endpoint_path,
                remediation="Configure the application server (e.g., Tomcat) to omit the Server header.",
                evidence=[evidence],
            )
            self.finding_manager.add_finding(finding)
