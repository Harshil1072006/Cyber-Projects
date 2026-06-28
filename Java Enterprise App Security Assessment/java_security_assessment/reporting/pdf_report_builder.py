"""
PDF Report Builder.
Generates a PDF report using WeasyPrint (if available) or falls back to HTML.
"""

import os
import logging
from typing import Dict, Any

logger = logging.getLogger(__name__)


class PdfReportBuilder:
    """Builds a PDF report from an HTML source."""

    def __init__(self, output_dir: str):
        self.output_dir = output_dir

    def generate(self, html_filepath: str) -> str:
        """Converts the generated HTML report to a PDF."""
        pdf_filepath = os.path.join(self.output_dir, "security_assessment_report.pdf")

        try:
            # Import here to avoid failing if not installed
            from weasyprint import HTML

            logger.info("Generating PDF report using WeasyPrint...")
            HTML(filename=html_filepath).write_pdf(pdf_filepath)
            logger.info(f"PDF report generated successfully at {pdf_filepath}")
            return pdf_filepath

        except ImportError:
            logger.warning(
                "WeasyPrint is not installed. Skipping PDF generation. Install with: pip install weasyprint"
            )
            return html_filepath
        except Exception as e:
            logger.error(f"Failed to generate PDF: {e}")
            return html_filepath
