"""
OAuth2 Analyzer for testing OAuth configurations and flows.
"""

import logging
import requests
from typing import Dict, Any, Optional
from urllib.parse import urlparse, parse_qs
from ..finding_manager import FindingManager, Finding, Evidence

logger = logging.getLogger(__name__)


class OAuthAnalyzer:
    """Analyzes OAuth2 endpoints and configurations."""

    def __init__(self, finding_manager: FindingManager, config: Dict[str, Any]):
        self.finding_manager = finding_manager
        self.client_id = config.get("client_id")
        self.token_url = config.get("oauth_token_url")
        self.auth_url = config.get("oauth_auth_url")  # Sometimes separate in config

    def analyze(self) -> None:
        """Runs checks against the OAuth configuration if endpoints are provided."""
        if not self.token_url:
            logger.debug("No OAuth token URL provided. Skipping OAuth analysis.")
            return

        logger.info("Starting OAuth2 Analysis...")
        self._check_token_endpoint_tls()
        self._check_client_enumeration()
        logger.info("OAuth2 Analysis complete.")

    def _check_token_endpoint_tls(self) -> None:
        """Verifies the token endpoint uses HTTPS."""
        parsed = urlparse(self.token_url)
        if parsed.scheme.lower() != "https":
            evidence = Evidence(
                type="config",
                content=f"Token URL: {self.token_url}",
                description="OAuth2 token endpoint using HTTP instead of HTTPS.",
            )
            finding = Finding(
                title="OAuth2 Token Endpoint over HTTP",
                description="The OAuth2 token endpoint is not using TLS (HTTPS). Credentials and tokens can be intercepted.",
                vulnerability_type="Insecure Transport",
                severity="CRITICAL",
                cwe_id="CWE-319",  # Cleartext Transmission of Sensitive Information
                cvss_score=9.8,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                component=self.token_url or "Unknown",
                remediation="Ensure the OAuth2 token endpoint strictly requires HTTPS.",
                evidence=[evidence],
            )
            self.finding_manager.add_finding(finding)

    def _check_client_enumeration(self) -> None:
        """Tests if the authorization server leaks valid client IDs."""
        if not self.auth_url:
            return

        test_client = "fake_invalid_client_id_12345"
        url = f"{self.auth_url}?response_type=code&client_id={test_client}&redirect_uri=https://example.com"

        try:
            # We don't want to follow redirects if it immediately redirects to login
            response = requests.get(url, allow_redirects=False, timeout=10)

            # If it returns 200 with an error page, check the body
            if "invalid_client" in response.text.lower() or response.status_code in [
                400,
                401,
            ]:
                # This means the server explicitly tells us the client is invalid.
                # If we had a valid client_id, we could see if it behaves differently (e.g. shows login).
                # This is a low severity finding (Username Enumeration equivalent for clients)

                evidence = Evidence(
                    type="response",
                    content=f"Status: {response.status_code}\nBody snippet: {response.text[:200]}",
                    description="Server verbosely rejected the invalid client ID.",
                )

                finding = Finding(
                    title="OAuth2 Client ID Enumeration",
                    description="The authorization server responds with specific error messages for invalid client IDs, allowing an attacker to enumerate valid client IDs.",
                    vulnerability_type="Information Disclosure",
                    severity="LOW",
                    cwe_id="CWE-203",  # Observable Discrepancy
                    cvss_score=3.7,
                    cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
                    component=self.auth_url or "Unknown",
                    remediation="Return generic error messages for invalid OAuth requests to prevent enumeration.",
                    evidence=[evidence],
                )
                self.finding_manager.add_finding(finding)
        except Exception as e:
            logger.debug(f"Failed to test client enumeration: {e}")
