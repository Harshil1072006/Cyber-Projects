"""
Spring Analyzer.
Tests for exposed Spring Boot Actuator endpoints and related misconfigurations.
"""

import logging
import requests
from typing import Dict, Any, List
from ..finding_manager import FindingManager, Finding, Evidence

logger = logging.getLogger(__name__)


class SpringAnalyzer:
    """Tests for exposed Spring Boot Actuator endpoints."""

    def __init__(self, finding_manager: FindingManager, target_url: str):
        self.finding_manager = finding_manager
        self.target_url = target_url.rstrip("/")
        self.session = requests.Session()

        # Common Actuator Paths
        self.actuator_paths = [
            "/actuator",
            "/actuator/env",
            "/actuator/beans",
            "/actuator/mappings",
            "/actuator/threaddump",
            "/actuator/heapdump",
            "/actuator/httptrace",
            "/actuator/loggers",
            "/actuator/shutdown",
            "/env",  # Spring Boot 1.x
            "/beans",  # Spring Boot 1.x
            "/mappings",  # Spring Boot 1.x
        ]

    def analyze(self) -> None:
        """Tests for exposed actuator endpoints."""
        logger.info("Starting Spring Boot Actuator tests...")

        exposed = []
        for path in self.actuator_paths:
            try:
                # We specifically don't use auth headers here to test public exposure
                response = self.session.get(
                    f"{self.target_url}{path}", timeout=5, allow_redirects=False
                )

                # Check for standard actuator responses (usually JSON)
                if (
                    response.status_code == 200
                    and "application/json"
                    in response.headers.get("Content-Type", "").lower()
                ):
                    # Quick heuristic to make sure it's actually an actuator, not a catch-all 200
                    body = response.text
                    if (
                        '"_links":' in body
                        or '"profiles":' in body
                        or '"contexts":' in body
                        or '"propertySources":' in body
                    ):
                        exposed.append((path, body[:200]))
            except Exception as e:
                logger.debug(f"Failed to test actuator {path}: {e}")

        if exposed:
            details = "\n".join([f"- {path}" for path, _ in exposed])
            evidence_content = "\n\n".join(
                [f"Path: {path}\nSnippet:\n{snippet}" for path, snippet in exposed]
            )

            evidence = Evidence(
                type="response",
                content=evidence_content,
                description="Exposed actuator endpoints and response snippets.",
            )

            # Determine severity based on what's exposed
            severity = "MEDIUM"
            description = f"Spring Boot Actuator endpoints are exposed without authentication.\n\nExposed endpoints:\n{details}"
            cwe_id = "CWE-425"  # Direct Request ('Forced Browsing')
            cvss_score = 5.3
            cvss_vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"

            if any(p in details for p in ["/env", "/heapdump", "/threaddump"]):
                severity = "HIGH"
                description += "\n\nCRITICAL: Highly sensitive endpoints like /env or /heapdump are exposed, which can leak secrets (passwords, API keys) or memory dumps."
                cwe_id = "CWE-200"  # Exposure of Sensitive Information
                cvss_score = 7.5
                cvss_vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"

            finding = Finding(
                title="Exposed Spring Boot Actuators",
                description=description,
                vulnerability_type="Security Misconfiguration",
                severity=severity,
                cwe_id=cwe_id,
                cvss_score=cvss_score,
                cvss_vector=cvss_vector,
                component="Spring Actuator",
                remediation="Disable unused actuator endpoints. For required endpoints, implement Spring Security to require strong authentication (e.g., admin role). Set management.endpoints.web.exposure.include=health,info only if others are not needed.",
                evidence=[evidence],
            )
            self.finding_manager.add_finding(finding)

        logger.info("Spring Boot Actuator testing complete.")
