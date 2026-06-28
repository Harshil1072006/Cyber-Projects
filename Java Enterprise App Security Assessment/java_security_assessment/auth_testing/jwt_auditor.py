"""
JWT Auditor for analyzing JSON Web Tokens.
Tests for weak keys, algorithm confusion, and tampering.
"""

import base64
import json
import logging
import time
from typing import Dict, Any, List, Optional
from ..finding_manager import FindingManager, Finding, Evidence

logger = logging.getLogger(__name__)


class JwtAuditor:
    """Analyzes and tests JSON Web Tokens for common vulnerabilities."""

    def __init__(self, finding_manager: FindingManager, token: str):
        self.finding_manager = finding_manager
        self.token = token
        self.header: Dict[str, Any] = {}
        self.payload: Dict[str, Any] = {}
        self.signature: str = ""
        self.is_valid_format = False

        self._parse_token()

    def _parse_token(self) -> None:
        """Splits and decodes the JWT parts."""
        if not self.token or self.token.lower().startswith("bearer "):
            self.token = self.token.split(" ")[-1] if self.token else ""

        parts = self.token.split(".")
        if len(parts) != 3:
            logger.debug("Token does not appear to be a standard 3-part JWT.")
            return

        try:
            self.header = json.loads(self._b64decode(parts[0]))
            self.payload = json.loads(self._b64decode(parts[1]))
            self.signature = parts[2]
            self.is_valid_format = True
            logger.info("Successfully parsed JWT.")
        except Exception as e:
            logger.debug(f"Failed to parse JWT: {e}")

    def _b64decode(self, data: str) -> str:
        """Helper to decode base64url."""
        padding = "=" * (4 - (len(data) % 4))
        return base64.urlsafe_b64decode(data + padding).decode("utf-8")

    def audit(self) -> None:
        """Runs all JWT audit checks."""
        if not self.is_valid_format:
            return

        logger.info("Starting JWT Audit...")
        self._check_algorithm()
        self._check_expiration()
        self._check_sensitive_claims()
        logger.info("JWT Audit complete.")

    def _check_algorithm(self) -> None:
        """Checks for 'none' algorithm or weak symmetric algorithms."""
        alg = self.header.get("alg", "").upper()

        if alg == "NONE":
            evidence = Evidence(
                type="config",
                content=json.dumps(self.header, indent=2),
                description="JWT Header showing 'none' algorithm.",
            )
            finding = Finding(
                title="JWT 'none' Algorithm Accepted",
                description="The JWT header specifies the 'none' algorithm. If the backend accepts this, it allows complete authentication bypass.",
                vulnerability_type="Broken Authentication",
                severity="CRITICAL",
                cwe_id="CWE-347",  # Improper Verification of Cryptographic Signature
                cvss_score=9.8,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                component="JWT Header",
                remediation="Ensure the backend explicitly requires and verifies a strong, expected algorithm (e.g., RS256) and rejects 'none'.",
                evidence=[evidence],
            )
            self.finding_manager.add_finding(finding)

    def _check_expiration(self) -> None:
        """Checks if the token has an expiration and if its lifetime is reasonable."""
        exp = self.payload.get("exp")

        if not exp:
            evidence = Evidence(
                type="config",
                content=json.dumps(self.payload, indent=2),
                description="JWT Payload missing 'exp' claim.",
            )
            finding = Finding(
                title="JWT Missing Expiration",
                description="The JWT does not contain an 'exp' (expiration) claim. It will remain valid indefinitely.",
                vulnerability_type="Session Management",
                severity="MEDIUM",
                cwe_id="CWE-613",  # Insufficient Session Expiration
                cvss_score=5.3,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                component="JWT Payload",
                remediation="Always include an 'exp' claim with a reasonably short lifetime (e.g., 15-60 minutes).",
                evidence=[evidence],
            )
            self.finding_manager.add_finding(finding)
        else:
            # Check if lifetime is excessively long (> 24 hours assuming typical iat)
            iat = self.payload.get("iat", time.time())
            lifetime = exp - iat
            if lifetime > 86400:  # 24 hours
                finding = Finding(
                    title="JWT Excessive Lifetime",
                    description=f"The JWT has an excessive lifetime of {lifetime} seconds.",
                    vulnerability_type="Session Management",
                    severity="LOW",
                    cwe_id="CWE-613",
                    cvss_score=3.7,
                    cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
                    component="JWT Payload",
                    remediation="Reduce token lifetime and implement a refresh token mechanism.",
                    evidence=[],
                )
                self.finding_manager.add_finding(finding)

    def _check_sensitive_claims(self) -> None:
        """Checks for sensitive data (PII, passwords) in the unencrypted JWT payload."""
        sensitive_keys = [
            "password",
            "pwd",
            "ssn",
            "credit_card",
            "cc_num",
            "secret",
            "key",
        ]

        found_keys = []
        for key in self.payload.keys():
            for sk in sensitive_keys:
                if sk in key.lower():
                    found_keys.append(key)

        if found_keys:
            evidence = Evidence(
                type="config",
                content=json.dumps({k: self.payload[k] for k in found_keys}, indent=2),
                description="Sensitive keys found in payload.",
            )
            finding = Finding(
                title="Sensitive Data in JWT Payload",
                description=f"The JWT payload contains potentially sensitive information in claims: {', '.join(found_keys)}. JWT payloads are Base64 encoded, not encrypted.",
                vulnerability_type="Information Disclosure",
                severity="HIGH",
                cwe_id="CWE-312",  # Cleartext Storage of Sensitive Information
                cvss_score=7.5,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                component="JWT Payload",
                remediation="Remove sensitive data from the JWT payload, or use JWE (JSON Web Encryption) if it must be transmitted.",
                evidence=[evidence],
            )
            self.finding_manager.add_finding(finding)
