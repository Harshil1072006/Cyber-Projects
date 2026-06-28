"""
Semgrep Analyzer for custom Java security rules.
Executes Semgrep against the source code using defined rule sets.
"""

import os
import json
import logging
import subprocess
from typing import Dict, Any, List
from pathlib import Path
from ..finding_manager import FindingManager, Finding, Evidence

logger = logging.getLogger(__name__)


class SemgrepAnalyzer:
    """Executes Semgrep static analysis using custom Java rules."""

    def __init__(
        self, finding_manager: FindingManager, source_dir: str, rules_path: str
    ):
        self.finding_manager = finding_manager
        self.source_dir = source_dir
        self.rules_path = rules_path

    def analyze(self) -> None:
        """Runs the Semgrep CLI and parses the results."""
        if not self.source_dir or not os.path.exists(self.source_dir):
            logger.warning("Semgrep analysis skipped: Source directory not found.")
            return

        if not self.rules_path or not os.path.exists(self.rules_path):
            logger.warning(
                f"Semgrep rules not found at {self.rules_path}. Skipping Semgrep SAST."
            )
            return

        logger.info(
            f"Running Semgrep on {self.source_dir} using rules from {self.rules_path}"
        )

        try:
            # We output to JSON to parse it programmatically
            output_file = "semgrep_results.json"

            cmd = [
                "semgrep",
                "scan",
                "--config",
                self.rules_path,
                "--json",
                "--output",
                output_file,
                "--quiet",  # Don't flood stdout
                self.source_dir,
            ]

            # Run semgrep (it might exit with 1 if it finds issues, which is expected)
            process = subprocess.run(cmd, capture_output=True, text=True)

            if not os.path.exists(output_file):
                logger.error(
                    f"Semgrep failed to produce output. Error: {process.stderr}"
                )
                return

            self._parse_results(output_file)

            # Cleanup
            os.remove(output_file)
            logger.info("Semgrep analysis complete.")

        except FileNotFoundError:
            logger.error(
                "Semgrep is not installed or not in PATH. Please run: pip install semgrep"
            )
        except Exception as e:
            logger.error(f"Error during Semgrep analysis: {e}")

    def _parse_results(self, json_file: str) -> None:
        """Parses the Semgrep JSON output into Finding objects."""
        with open(json_file, "r", encoding="utf-8") as f:
            data = json.load(f)

        results = data.get("results", [])
        logger.info(f"Semgrep identified {len(results)} potential vulnerabilities.")

        for result in results:
            self._create_finding(result)

    def _create_finding(self, result: Dict[str, Any]) -> None:
        """Maps a Semgrep result to the internal Finding structure."""
        extra = result.get("extra", {})
        metadata = extra.get("metadata", {})

        # Extract rule info
        rule_id = result.get("check_id", "Unknown Rule")
        message = extra.get("message", "No description provided.")

        # Semgrep severity: ERROR, WARNING, INFO
        semgrep_sev = extra.get("severity", "INFO")
        severity_map = {"ERROR": "HIGH", "WARNING": "MEDIUM", "INFO": "LOW"}
        severity = severity_map.get(semgrep_sev, "INFO")

        # Override severity if specified in rule metadata
        if "severity" in metadata:
            severity = metadata["severity"].upper()

        # Extract CWE and CVSS if defined in custom rule metadata
        cwe_id = metadata.get("cwe", "CWE-Unknown")
        cvss_score = float(metadata.get("cvss_score", 0.0))
        cvss_vector = metadata.get("cvss_vector", "")
        vuln_type = metadata.get("vulnerability_type", "SAST Finding")
        remediation = metadata.get(
            "remediation", "Review code and apply secure coding practices."
        )

        # Extract location
        path = result.get("path", "Unknown file")
        start_line = result.get("start", {}).get("line", "?")
        component = f"{path}:{start_line}"

        # Extract code snippet evidence
        lines = extra.get("lines", "").strip()
        evidence = Evidence(
            type="code_snippet",
            content=f"File: {path}, Line {start_line}\nCode:\n{lines}",
        )

        finding = Finding(
            title=f"Static Analysis: {rule_id}",
            description=message,
            vulnerability_type=vuln_type,
            severity=severity,
            cwe_id=cwe_id,
            cvss_score=cvss_score,
            cvss_vector=cvss_vector,
            component=component,
            remediation=remediation,
            evidence=[evidence],
        )

        self.finding_manager.add_finding(finding)
