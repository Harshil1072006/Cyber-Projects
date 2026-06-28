"""
Main Report Generator.
Orchestrates the generation of all requested report formats.
"""

import logging
import os
from typing import Dict, Any
from ..finding_manager import FindingManager
from .html_report_builder import HtmlReportBuilder
from .pdf_report_builder import PdfReportBuilder

logger = logging.getLogger(__name__)


class ReportGenerator:
    """Orchestrates the report generation process."""

    def __init__(self, finding_manager: FindingManager, config: Dict[str, Any]):
        self.finding_manager = finding_manager
        self.config = config
        self.output_dir = config.get("output_dir", "reports")
        self.format = config.get("format", "all").lower()

    def generate(self) -> None:
        """Generates the reports in the configured formats."""
        logger.info(f"Generating reports in {self.output_dir}...")

        # Always save JSON for programmatic consumption
        json_path = os.path.join(self.output_dir, "findings.json")
        self.finding_manager.export_json(json_path)
        logger.info(f"Exported JSON findings to {json_path}")

        html_path = None
        if self.format in ["html", "all"]:
            html_builder = HtmlReportBuilder(self.finding_manager, self.output_dir)
            html_path = html_builder.generate()
            logger.info(f"Exported HTML report to {html_path}")

        if self.format in ["pdf", "all"] and html_path:
            pdf_builder = PdfReportBuilder(self.output_dir)
            pdf_path = pdf_builder.generate(html_path)

        logger.info("Report generation complete.")
