"""
Deserialization Tester for Java APIs.
Tests endpoints for Java insecure deserialization vulnerabilities.
"""

import base64
import logging
import requests
from typing import List, Dict, Any
from ..finding_manager import FindingManager, Finding, Evidence
from ..enumeration.swagger_parser import ApiEndpoint

logger = logging.getLogger(__name__)


class DeserializationTester:
    """Tests API endpoints for Insecure Deserialization (ObjectInputStream)."""

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

        # Magic bytes for Java serialized objects: ac ed 00 05
        # Base64 encoded: rO0AB
        self.java_magic_b64 = "rO0AB"

        # A benign serialized java.lang.String("TEST") to see if the server attempts to deserialize it
        self.benign_payload_b64 = "rO0ABXQABFRFU1Q="

    def test_endpoints(self, endpoints: List[ApiEndpoint]) -> None:
        """Runs deserialization tests against endpoints."""
        logger.info("Starting Java Deserialization tests...")

        for endpoint in endpoints:
            # We mostly care about endpoints that accept arbitrary bodies or specific headers
            if endpoint.method in ["POST", "PUT", "PATCH"]:
                self._test_body_deserialization(endpoint)

        logger.info("Java Deserialization testing complete.")

    def _test_body_deserialization(self, endpoint: ApiEndpoint) -> None:
        """Tests sending a serialized Java object in the request body."""
        url = f"{self.target_url}{endpoint.path}"

        try:
            # Send raw bytes (Content-Type: application/x-java-serialized-object is a strong indicator)
            headers = {"Content-Type": "application/x-java-serialized-object"}
            raw_bytes = base64.b64decode(self.benign_payload_b64)

            response = self.session.request(
                method=endpoint.method,
                url=url,
                data=raw_bytes,
                headers=headers,
                timeout=5,
                allow_redirects=False,
            )

            # If we get a 500 containing specific deserialization errors like ClassCastException,
            # it means the server tried to deserialize our object but couldn't cast it to expected type.
            # E.g., java.lang.ClassCastException: class java.lang.String cannot be cast to class ...

            body = response.text
            if "ClassCastException" in body or "java.io.InvalidClassException" in body:
                evidence = Evidence(
                    type="request_response",
                    content=f"Payload (Base64): {self.benign_payload_b64}\nStatus: {response.status_code}\nSnippet:\n{body[:200]}",
                    description="Server attempted to deserialize the provided Java object, resulting in a ClassCastException.",
                )

                finding = Finding(
                    title=f"Insecure Java Deserialization on {endpoint.path}",
                    description=f"The endpoint {endpoint.method} {endpoint.path} accepts and attempts to deserialize native Java objects. This can lead to Remote Code Execution (RCE) via gadget chains (e.g., Apache Commons Collections).",
                    vulnerability_type="Insecure Deserialization",
                    severity="CRITICAL",
                    cwe_id="CWE-502",
                    cvss_score=9.8,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    component=endpoint.path,
                    remediation="Avoid native Java serialization (ObjectInputStream). Use JSON or XML formats with secure parsers (e.g., Jackson or Gson). If native serialization is strictly required, use ValidatingObjectInputStream to allow-list specific classes.",
                    evidence=[evidence],
                )
                self.finding_manager.add_finding(finding)

        except Exception as e:
            logger.debug(f"Deserialization test failed for {endpoint.path}: {e}")
