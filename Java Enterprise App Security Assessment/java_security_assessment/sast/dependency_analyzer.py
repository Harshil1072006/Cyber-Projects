"""
Dependency Analyzer for Software Composition Analysis (SCA).
Parses Maven and Gradle files to identify dependencies and uses OSV to find vulnerabilities.
"""

import os
import re
import json
import logging
import requests
from typing import List, Dict, Any, Tuple
from ..finding_manager import FindingManager, Finding, Evidence

logger = logging.getLogger(__name__)


class DependencyAnalyzer:
    """Analyzes Java project dependencies for known vulnerabilities."""

    def __init__(self, finding_manager: FindingManager, source_dir: str):
        self.finding_manager = finding_manager
        self.source_dir = source_dir
        self.dependencies: List[Dict[str, str]] = []

    def analyze(self) -> None:
        """Parses dependency files and queries vulnerability databases."""
        if not self.source_dir or not os.path.exists(self.source_dir):
            logger.warning("Dependency analysis skipped: Source directory not found.")
            return

        logger.info("Starting Software Composition Analysis (SCA)...")

        self._parse_maven_pom()
        self._parse_gradle_build()

        # Deduplicate
        unique_deps = {f"{d['group']}:{d['name']}": d for d in self.dependencies}
        self.dependencies = list(unique_deps.values())

        logger.info(
            f"Found {len(self.dependencies)} unique dependencies. Checking for vulnerabilities..."
        )

        if self.dependencies:
            self._check_osv_database()

        logger.info("Software Composition Analysis complete.")

    def _parse_maven_pom(self) -> None:
        """Basic parsing of pom.xml for dependencies."""
        pom_path = os.path.join(self.source_dir, "pom.xml")
        if not os.path.exists(pom_path):
            return

        logger.info(f"Parsing Maven dependencies from {pom_path}")
        try:
            with open(pom_path, "r", encoding="utf-8") as f:
                content = f.read()

            # Using regex instead of full XML parsing for simplicity and robustness against malformed files
            # Matches <dependency>...</dependency> blocks
            dep_blocks = re.findall(r"<dependency>[\s\S]*?</dependency>", content)

            for block in dep_blocks:
                group_match = re.search(r"<groupId>([^<]+)</groupId>", block)
                art_match = re.search(r"<artifactId>([^<]+)</artifactId>", block)
                ver_match = re.search(r"<version>([^<]+)</version>", block)

                if group_match and art_match and ver_match:
                    version = ver_match.group(1)
                    # Skip properties for now (e.g., ${spring.version})
                    if not version.startswith("${"):
                        self.dependencies.append(
                            {
                                "group": group_match.group(1),
                                "name": art_match.group(1),
                                "version": version,
                                "source": "pom.xml",
                            }
                        )
        except Exception as e:
            logger.error(f"Error parsing pom.xml: {e}")

    def _parse_gradle_build(self) -> None:
        """Basic parsing of build.gradle for dependencies."""
        gradle_path = os.path.join(self.source_dir, "build.gradle")
        if not os.path.exists(gradle_path):
            return

        logger.info(f"Parsing Gradle dependencies from {gradle_path}")
        try:
            with open(gradle_path, "r", encoding="utf-8") as f:
                content = f.read()

            # Matches standard gradle dependency formats: implementation 'group:name:version'
            pattern = re.compile(
                r'(?:implementation|compile|api|testImplementation)\s+[\'"]([^:]+):([^:]+):([^\'"]+)[\'"]'
            )
            for match in pattern.finditer(content):
                self.dependencies.append(
                    {
                        "group": match.group(1),
                        "name": match.group(2),
                        "version": match.group(3),
                        "source": "build.gradle",
                    }
                )
        except Exception as e:
            logger.error(f"Error parsing build.gradle: {e}")

    def _check_osv_database(self) -> None:
        """Queries the Google OSV database for known vulnerabilities."""
        osv_url = "https://api.osv.dev/v1/querybatch"

        # Prepare batch query for OSV API
        queries = []
        for dep in self.dependencies:
            # OSV Ecosystem for Java is Maven
            queries.append(
                {
                    "package": {
                        "ecosystem": "Maven",
                        "name": f"{dep['group']}:{dep['name']}",
                    },
                    "version": dep["version"],
                }
            )

        try:
            # OSV allows batching up to 1000 queries, but we'll do 100 at a time to be safe
            batch_size = 100
            for i in range(0, len(queries), batch_size):
                batch = queries[i : i + batch_size]
                response = requests.post(osv_url, json={"queries": batch}, timeout=20)
                response.raise_for_status()

                results = response.json().get("results", [])
                for idx, result in enumerate(results):
                    vulns = result.get("vulns", [])
                    if vulns:
                        dep_info = self.dependencies[i + idx]
                        self._process_osv_vulnerabilities(dep_info, vulns)

        except Exception as e:
            logger.error(f"Failed to query OSV database: {e}")

    def _process_osv_vulnerabilities(
        self, dep: Dict[str, str], vulns: List[Dict[str, Any]]
    ) -> None:
        """Creates Findings from OSV vulnerability data."""
        dep_id = f"{dep['group']}:{dep['name']}@{dep['version']}"
        logger.warning(f"Found {len(vulns)} vulnerabilities in {dep_id}")

        for vuln in vulns:
            osv_id = vuln.get("id", "Unknown")
            summary = vuln.get("summary", "Dependency vulnerability")
            details = vuln.get("details", "")

            # Extract aliases (CVEs)
            aliases = vuln.get("aliases", [])
            cve_id = next((a for a in aliases if a.startswith("CVE-")), osv_id)

            # Default values
            severity = "MEDIUM"
            cvss_score = 5.0
            cvss_vector = ""

            # Try to extract CVSS if available
            severity_list = vuln.get("severity", [])
            for sev in severity_list:
                if sev.get("type") == "CVSS_V3":
                    cvss_vector = sev.get("score", "")
                    # Very basic CVSS string parsing just to get the score if it's there
                    # Ideally we would use our cvss_calculator.py here, but OSV sometimes only provides vector
                    # We'll set a default high severity if it has a CVSS v3 vector
                    if cvss_vector:
                        severity = "HIGH"
                        cvss_score = 7.5

            # Get fixed version info if available
            remediation = f"Update the '{dep['name']}' dependency in {dep['source']} to a secure version."
            affected_list = vuln.get("affected", [])
            for affected in affected_list:
                for event in affected.get("ranges", [{}])[0].get("events", []):
                    if "fixed" in event:
                        remediation = f"Update '{dep['name']}' to version {event['fixed']} or higher in {dep['source']}."
                        break

            evidence = Evidence(
                type="config",
                content=f"Found vulnerable dependency definition in {dep['source']}:\n{dep['group']}:{dep['name']}:{dep['version']}",
                description=f"Identified {cve_id} in project dependencies.",
            )

            finding = Finding(
                title=f"SCA: Vulnerable Dependency - {dep['name']} ({cve_id})",
                description=f"The project uses a vulnerable version of {dep_id}. \n\n{summary}\n{details[:500]}...",
                vulnerability_type="Vulnerable Dependency",
                severity=severity,
                cwe_id="CWE-1035",  # Vulnerable Third Party Component
                cvss_score=cvss_score,
                cvss_vector=cvss_vector,
                component=dep_id,
                remediation=remediation,
                evidence=[evidence],
            )

            self.finding_manager.add_finding(finding)
