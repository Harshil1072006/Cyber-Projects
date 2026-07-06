"""
PDF Report Builder.
Generates static PDF security reports.
"""

import logging
from typing import List, Dict, Any

logger = logging.getLogger(__name__)

class PdfReportBuilder:
    """Builds static PDF reports."""
    
    def build_report(self, findings: List[Dict[str, Any]], metrics: Dict[str, Any], output_path: str = "report/report.pdf") -> str:
        """Mock implementation to generate PDF."""
        logger.info(f"Simulating PDF report generation to {output_path}")
        return output_path
