"""
Tests for JWT Auditor.
"""

from java_security_assessment.auth_testing.jwt_auditor import JwtAuditor


def test_jwt_auditor_invalid_format(finding_manager):
    auditor = JwtAuditor(finding_manager, "not.a.jwt")
    assert not auditor.is_valid_format

    auditor.audit()
    assert len(finding_manager.get_all_findings()) == 0
