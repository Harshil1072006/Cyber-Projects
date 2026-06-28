"""
E2E Integration tests for the Assessment Orchestrator.
"""

from java_security_assessment.assessment_orchestrator import AssessmentOrchestrator
from java_security_assessment.config_manager import (
    AssessmentConfig,
    TargetConfig,
    ScanOptions,
)


def test_assessment_orchestrator_initialization():
    config = AssessmentConfig(
        target=TargetConfig(url="http://localhost:8080"),
        scan=ScanOptions(run_sast=False, run_sca=False, run_dast=False),
    )
    orchestrator = AssessmentOrchestrator(config)

    assert orchestrator.config.target.url == "http://localhost:8080"

    # Should run successfully without doing anything since all scans are disabled
    finding_manager = orchestrator.run_assessment()
    assert len(finding_manager.get_all_findings()) == 0
