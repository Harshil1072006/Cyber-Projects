"""
Tests for Semgrep Analyzer.
"""

from java_security_assessment.sast.semgrep_analyzer import SemgrepAnalyzer


def test_semgrep_analyzer_init(finding_manager):
    analyzer = SemgrepAnalyzer(finding_manager, "src", "rules.yaml")
    assert analyzer.source_dir == "src"
    assert analyzer.rules_path == "rules.yaml"
