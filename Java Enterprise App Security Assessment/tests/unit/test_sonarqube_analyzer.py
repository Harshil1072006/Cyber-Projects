"""
Tests for SonarQube Analyzer.
"""

from java_security_assessment.sast.sonarqube_analyzer import SonarQubeAnalyzer


def test_sonarqube_analyzer_init(finding_manager):
    config = {"url": "http://test", "project_key": "test"}
    analyzer = SonarQubeAnalyzer(finding_manager, config)
    assert analyzer.url == "http://test"
    assert analyzer.project_key == "test"
