"""
HTML Report Builder.
Generates an HTML report from findings.
"""

import os
from typing import List, Dict, Any
from ..finding_manager import FindingManager, Finding


class HtmlReportBuilder:
    """Builds an HTML report from the aggregated findings."""

    def __init__(self, finding_manager: FindingManager, output_dir: str):
        self.finding_manager = finding_manager
        self.output_dir = output_dir

    def generate(self) -> str:
        """Generates the HTML report and returns the filepath."""
        os.makedirs(self.output_dir, exist_ok=True)
        filepath = os.path.join(self.output_dir, "security_assessment_report.html")

        findings = self.finding_manager.get_all_findings()
        findings.sort(key=lambda x: x.cvss_score, reverse=True)

        html = [
            "<!DOCTYPE html>",
            "<html><head><title>Security Assessment Report</title>",
            "<style>",
            "body { font-family: Arial, sans-serif; margin: 40px; color: #333; }",
            "h1, h2, h3 { color: #2c3e50; }",
            ".summary { background-color: #f8f9fa; padding: 20px; border-radius: 5px; margin-bottom: 30px; }",
            ".finding { border: 1px solid #ddd; border-left: 5px solid #333; margin-bottom: 20px; padding: 15px; border-radius: 4px; }",
            ".CRITICAL { border-left-color: #d9534f; }",
            ".HIGH { border-left-color: #f0ad4e; }",
            ".MEDIUM { border-left-color: #5bc0de; }",
            ".LOW { border-left-color: #5cb85c; }",
            ".INFO { border-left-color: #ccc; }",
            ".badge { display: inline-block; padding: 3px 8px; font-size: 12px; font-weight: bold; border-radius: 3px; color: white; }",
            ".bg-CRITICAL { background-color: #d9534f; }",
            ".bg-HIGH { background-color: #f0ad4e; }",
            ".bg-MEDIUM { background-color: #5bc0de; }",
            ".bg-LOW { background-color: #5cb85c; }",
            ".bg-INFO { background-color: #777; }",
            "pre { background-color: #f4f4f4; padding: 10px; border-radius: 4px; overflow-x: auto; }",
            "</style>",
            "</head><body>",
            "<h1>Java Enterprise App Security Assessment Report</h1>",
        ]

        # Summary Section
        stats = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for f in findings:
            if f.severity in stats:
                stats[f.severity] += 1

        html.append("<div class='summary'><h2>Executive Summary</h2>")
        html.append(f"<p>Total Findings: {len(findings)}</p><ul>")
        for sev, count in stats.items():
            html.append(f"<li>{sev}: {count}</li>")
        html.append("</ul></div>")

        # Findings Section
        html.append("<h2>Detailed Findings</h2>")
        for f in findings:
            html.append(f"<div class='finding {f.severity}'>")
            html.append(
                f"<h3>{f.title} <span class='badge bg-{f.severity}'>{f.severity}</span></h3>"
            )
            html.append(f"<p><strong>Component:</strong> {f.component}<br/>")
            html.append(
                f"<strong>Vulnerability Type:</strong> {f.vulnerability_type}<br/>"
            )
            html.append(f"<strong>CWE:</strong> {f.cwe_id}<br/>")
            if f.cvss_score > 0:
                html.append(
                    f"<strong>CVSS Score:</strong> {f.cvss_score} ({f.cvss_vector})</p>"
                )

            html.append(
                f"<h4>Description</h4><p>{f.description.replace(chr(10), '<br/>')}</p>"
            )
            html.append(
                f"<h4>Remediation</h4><p>{f.remediation.replace(chr(10), '<br/>')}</p>"
            )

            if f.evidence:
                html.append("<h4>Evidence</h4>")
                for e in f.evidence:
                    if e.description:
                        html.append(f"<p><em>{e.description}</em></p>")
                    html.append(f"<pre><code>{e.content}</code></pre>")

            html.append("</div>")

        html.append("</body></html>")

        with open(filepath, "w", encoding="utf-8") as f:
            f.write("\n".join(html))

        return filepath
