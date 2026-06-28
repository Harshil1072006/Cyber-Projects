"""
LDAP Injection Tester.
Tests endpoints for LDAP injection vulnerabilities.
"""

import logging
import requests
from typing import List, Dict, Any
from ..finding_manager import FindingManager, Finding, Evidence
from ..enumeration.swagger_parser import ApiEndpoint

logger = logging.getLogger(__name__)


class LdapTester:
    """Tests API endpoints for LDAP Injection vulnerabilities."""

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

        # LDAP Injection Payloads
        self.payloads = [
            "*",
            ")(|(uid=*)",
            "*)(uid=*))(|(uid=*",
            "admin)(!(password=*))",
        ]

    def test_endpoints(self, endpoints: List[ApiEndpoint]) -> None:
        """Runs LDAP injection tests against candidates."""
        logger.info("Starting LDAP Injection tests...")

        for endpoint in endpoints:
            # We look for login or search endpoints, often tied to LDAP
            if (
                "login" in endpoint.path.lower()
                or "user" in endpoint.path.lower()
                or "search" in endpoint.path.lower()
            ):
                candidates = [p for p in endpoint.parameters if p.data_type == "string"]
                for param in candidates:
                    self._test_ldap_injection(endpoint, param)

        logger.info("LDAP Injection testing complete.")

    def _test_ldap_injection(self, endpoint: ApiEndpoint, param) -> None:
        """Tests for LDAP injection on a specific parameter."""
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

                # We look for specific LDAP errors or bypassing auth (status 200 on login with invalid pass but injected user)
                body = response.text.lower()
                if (
                    "javax.naming.directory.invalidsearchfilterexception" in body
                    or "ldap" in body
                    and "error" in body
                ):
                    evidence = Evidence(
                        type="request_response",
                        content=f"Payload: {payload}\nStatus: {response.status_code}\nSnippet:\n{response.text[:200]}",
                        description="LDAP specific error returned when injecting filter characters.",
                    )

                    finding = Finding(
                        title=f"LDAP Injection on {param.name}",
                        description=f"The endpoint {endpoint.method} {endpoint.path} appears vulnerable to LDAP Injection via the '{param.name}' parameter.",
                        vulnerability_type="LDAP Injection",
                        severity="HIGH",
                        cwe_id="CWE-90",
                        cvss_score=8.1,
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                        component=f"{endpoint.path} [{param.name}]",
                        remediation="Use escaping mechanisms (e.g., Spring Security LdapEncoder) before passing user input to LDAP search filters.",
                        evidence=[evidence],
                    )
                    self.finding_manager.add_finding(finding)
                    return
            except Exception as e:
                logger.debug(f"LDAP test failed for {param.name}: {e}")
