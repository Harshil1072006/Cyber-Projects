"""
Tests for Report Generator.
"""

from java_security_assessment.reporting.report_generator import ReportGenerator


def test_report_generator_init(finding_manager):
    config = {"output_dir": "test_reports", "format": "all"}
    generator = ReportGenerator(finding_manager, config)
    assert generator.output_dir == "test_reports"
    assert generator.format == "all"
