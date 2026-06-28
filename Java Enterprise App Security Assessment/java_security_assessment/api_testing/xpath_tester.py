"""
XPath Injection Tester.
Tests endpoints for XPath injection vulnerabilities.
"""

import logging
import requests
from typing import List, Dict, Any
from ..finding_manager import FindingManager, Finding, Evidence
from ..enumeration.swagger_parser import ApiEndpoint

logger = logging.getLogger(__name__)


class XpathTester:
    """Tests API endpoints for XPath Injection vulnerabilities."""

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

        # XPath Injection Payloads
        self.payloads = ["' or '1'='1", "'] | //user/* [ '1'='1", "1 or 1=1"]

    def test_endpoints(self, endpoints: List[ApiEndpoint]) -> None:
        """Runs XPath injection tests against candidates."""
        logger.info("Starting XPath Injection tests...")

        for endpoint in endpoints:
            candidates = [p for p in endpoint.parameters if p.data_type == "string"]
            for param in candidates:
                self._test_xpath_injection(endpoint, param)

        logger.info("XPath Injection testing complete.")

    def _test_xpath_injection(self, endpoint: ApiEndpoint, param) -> None:
        """Tests for XPath injection on a specific parameter."""
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
                if (
                    "javax.xml.xpath.xpathexpressionexception" in body
                    or "invalid xpath" in body
                ):
                    evidence = Evidence(
                        type="request_response",
                        content=f"Payload: {payload}\nStatus: {response.status_code}\nSnippet:\n{response.text[:200]}",
                        description="XPath specific error returned when injecting filter characters.",
                    )

                    finding = Finding(
                        title=f"XPath Injection on {param.name}",
                        description=f"The endpoint {endpoint.method} {endpoint.path} appears vulnerable to XPath Injection via the '{param.name}' parameter.",
                        vulnerability_type="XPath Injection",
                        severity="HIGH",
                        cwe_id="CWE-643",
                        cvss_score=7.5,
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                        component=f"{endpoint.path} [{param.name}]",
                        remediation="Avoid string concatenation when building XPath queries. Use parameterized XPath queries or pre-compiled XPath expressions with variable resolvers.",
                        evidence=[evidence],
                    )
                    self.finding_manager.add_finding(finding)
                    return
            except Exception as e:
                logger.debug(f"XPath test failed for {param.name}: {e}")
