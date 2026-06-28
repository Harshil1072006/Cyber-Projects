"""
SonarQube Analyzer for static analysis integration.
Fetches vulnerabilities and hotspots from a configured SonarQube instance.
"""

import logging
import requests
from typing import List, Dict, Any, Optional
from ..finding_manager import FindingManager, Finding, Evidence

logger = logging.getLogger(__name__)


class SonarQubeAnalyzer:
    """Integrates with SonarQube API to fetch security issues and hotspots."""

    def __init__(self, finding_manager: FindingManager, config: Dict[str, Any]):
        """
        Args:
            finding_manager: The central finding manager.
            config: SonarQube configuration (url, token, project_key).
        """
        self.finding_manager = finding_manager
        self.url = config.get("url", "http://localhost:9000").rstrip("/")
        self.token = config.get("token")
        self.project_key = config.get("project_key")
        self.enabled = config.get("enabled", False)

        self.session = requests.Session()
        if self.token:
            self.session.auth = (self.token, "")

    def analyze(self) -> None:
        """Executes the SonarQube analysis retrieval."""
        if not self.enabled or not self.url or not self.project_key:
            logger.info("SonarQube integration disabled or missing configuration.")
            return

        logger.info(f"Fetching SonarQube results for project: {self.project_key}")

        try:
            self._fetch_issues()
            self._fetch_hotspots()
            logger.info("SonarQube analysis retrieval complete.")
        except Exception as e:
            logger.error(f"Failed to fetch SonarQube results: {e}")

    def _fetch_issues(self) -> None:
        """Fetches confirmed vulnerabilities (VULNERABILITY type)."""
        api_endpoint = f"{self.url}/api/issues/search"
        params = {
            "componentKeys": self.project_key,
            "types": "VULNERABILITY",
            "statuses": "OPEN,REOPENED",
            "ps": 500,  # Page size
        }

        response = self.session.get(api_endpoint, params=params, timeout=15)
        response.raise_for_status()
        data = response.json()

        issues = data.get("issues", [])
        logger.info(f"Retrieved {len(issues)} open vulnerabilities from SonarQube.")

        # Map SonarQube issues to internal Finding structure
        for issue in issues:
            self._process_sonar_issue(issue, data.get("rules", []))

    def _fetch_hotspots(self) -> None:
        """Fetches security hotspots that require review."""
        api_endpoint = f"{self.url}/api/hotspots/search"
        params = {"projectKey": self.project_key, "status": "TO_REVIEW", "ps": 500}

        response = self.session.get(api_endpoint, params=params, timeout=15)
        if response.status_code == 404:
            # Older SonarQube versions might not support this endpoint, fallback or skip
            logger.debug("SonarQube Hotspots API not found. Skipping hotspots.")
            return

        response.raise_for_status()
        data = response.json()

        hotspots = data.get("hotspots", [])
        logger.info(f"Retrieved {len(hotspots)} security hotspots from SonarQube.")

        for hotspot in hotspots:
            self._process_sonar_hotspot(hotspot)

    def _process_sonar_issue(
        self, issue: Dict[str, Any], rules: List[Dict[str, Any]]
    ) -> None:
        """Converts a SonarQube issue into a Finding object."""
        rule_key = issue.get("rule")
        component = issue.get("component", "")
        message = issue.get("message", "")
        severity_sq = issue.get("severity", "INFO")

        # SonarQube to CVSS/Severity mapping (approximate)
        severity_map = {
            "BLOCKER": "CRITICAL",
            "CRITICAL": "HIGH",
            "MAJOR": "MEDIUM",
            "MINOR": "LOW",
            "INFO": "INFO",
        }
        severity = severity_map.get(severity_sq, "INFO")

        # Try to find CWE from the rule definitions
        cwe_id = "CWE-Unknown"
        rule_desc = "Vulnerability detected by SonarQube."
        for rule in rules:
            if rule.get("key") == rule_key:
                rule_desc = rule.get("name", rule_desc)
                # Parse CWE from Sonar tags or HTML description if possible (simplified here)
                # Real implementation would parse the rule details endpoint
                break

        evidence = Evidence(
            type="code_snippet",
            content=f"Component: {component}\nLine: {issue.get('textRange', {}).get('startLine', 'Unknown')}\nMessage: {message}",
        )

        finding = Finding(
            title=f"SAST: {rule_desc[:100]}",
            description=f"SonarQube detected a vulnerability in {component}. {message}",
            vulnerability_type="SAST Finding",
            severity=severity,
            cwe_id=cwe_id,
            cvss_score=0.0,  # SAST typically doesn't give CVSS base scores natively without context
            cvss_vector="",
            component=component,
            remediation="Review the code highlighted by SonarQube and implement the suggested fix.",
            evidence=[evidence],
        )

        self.finding_manager.add_finding(finding)

    def _process_sonar_hotspot(self, hotspot: Dict[str, Any]) -> None:
        """Converts a SonarQube hotspot into a Finding object (usually INFO/LOW)."""
        component = hotspot.get("component", "")
        message = hotspot.get("message", "")
        vulnerability_prob = hotspot.get("vulnerabilityProbability", "LOW")

        severity_map = {"HIGH": "MEDIUM", "MEDIUM": "LOW", "LOW": "INFO"}
        severity = severity_map.get(vulnerability_prob, "INFO")

        evidence = Evidence(
            type="code_snippet",
            content=f"Component: {component}\nLine: {hotspot.get('textRange', {}).get('startLine', 'Unknown')}\nMessage: {message}",
        )

        finding = Finding(
            title=f"SAST Hotspot: Manual Review Required",
            description=f"SonarQube flagged a security hotspot requiring manual review. {message}",
            vulnerability_type="Security Hotspot",
            severity=severity,
            cwe_id="CWE-Unknown",
            cvss_score=0.0,
            cvss_vector="",
            component=component,
            remediation="Manually review the code snippet to determine if it is a true positive vulnerability.",
            evidence=[evidence],
        )

        self.finding_manager.add_finding(finding)
