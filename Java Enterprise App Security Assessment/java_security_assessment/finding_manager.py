"""
Finding Manager for the Java Enterprise App Security Assessment tool.
Handles finding data structure, deduplication, scoring, and aggregation.
"""

from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field
import hashlib
from datetime import datetime
import json


@dataclass
class Evidence:
    type: str  # request, response, code_snippet, stack_trace, config
    content: str
    description: Optional[str] = None


@dataclass
class Finding:
    id: str = field(init=False)
    title: str
    description: str
    vulnerability_type: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    cwe_id: str
    cvss_score: float
    cvss_vector: str
    component: str  # e.g., endpoint URL, file path
    remediation: str
    evidence: List[Evidence] = field(default_factory=list)
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")

    def __post_init__(self):
        # Generate a unique ID based on core attributes for deduplication
        hash_input = f"{self.vulnerability_type}|{self.component}|{self.cwe_id}"
        self.id = hashlib.md5(hash_input.encode("utf-8")).hexdigest()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "vulnerability_type": self.vulnerability_type,
            "severity": self.severity,
            "cwe_id": self.cwe_id,
            "cvss_score": self.cvss_score,
            "cvss_vector": self.cvss_vector,
            "component": self.component,
            "remediation": self.remediation,
            "evidence": [
                {"type": e.type, "content": e.content, "description": e.description}
                for e in self.evidence
            ],
            "timestamp": self.timestamp,
        }


class FindingManager:
    """Manages the collection, deduplication, and aggregation of findings."""

    def __init__(self):
        self._findings: Dict[str, Finding] = {}

    def add_finding(self, finding: Finding) -> bool:
        """
        Adds a finding if it doesn't already exist (deduplication).
        Returns True if added, False if it was a duplicate.
        """
        if finding.id not in self._findings:
            self._findings[finding.id] = finding
            return True
        return False

    def get_all_findings(self) -> List[Finding]:
        """Returns all aggregated findings."""
        return list(self._findings.values())

    def get_findings_by_severity(self) -> Dict[str, List[Finding]]:
        """Groups findings by severity level."""
        grouped: Dict[str, List[Finding]] = {
            "CRITICAL": [],
            "HIGH": [],
            "MEDIUM": [],
            "LOW": [],
            "INFO": [],
        }
        for finding in self._findings.values():
            if finding.severity in grouped:
                grouped[finding.severity].append(finding)
            else:
                grouped["INFO"].append(finding)  # Fallback
        return grouped

    def export_json(self, file_path: str) -> None:
        """Exports all findings to a JSON file."""
        import os

        os.makedirs(os.path.dirname(file_path), exist_ok=True)
        findings_dict = [f.to_dict() for f in self._findings.values()]
        with open(file_path, "w", encoding="utf-8") as f:
            json.dump({"findings": findings_dict}, f, indent=2)
