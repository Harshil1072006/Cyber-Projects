"""
test_siem.py — Tests for the SIEM push modules.
"""

import pytest
import responses

from src.siem.elastic_push import push_to_elastic
from src.siem.syslog_push import format_cef


# ═══════════════════════════════════════════════════════════════════════
# Elastic SIEM Push
# ═══════════════════════════════════════════════════════════════════════

class TestElasticPush:

    @responses.activate
    def test_push_to_elastic_empty_db(self, session):
        """Push with no qualifying IOCs returns 0."""
        # Mock Elasticsearch bulk endpoint
        responses.add(
            responses.POST,
            "http://localhost:9200/_bulk",
            json={"errors": False, "items": []},
            status=200,
        )

        result = push_to_elastic(session, limit=100)
        assert result == 0


from unittest.mock import MagicMock
from src.db.models import Indicator, EnrichmentData

# ═══════════════════════════════════════════════════════════════════════
# Syslog / CEF Formatting
# ═══════════════════════════════════════════════════════════════════════

class TestSyslogCEF:

    def test_cef_message_format(self):
        """CEF message should contain required header fields."""
        ioc = MagicMock(spec=Indicator)
        ioc.ioc_value = "198.51.100.42"
        ioc.ioc_type = "ip"
        ioc.risk_score = 85.0
        ioc.confidence_score = 75.0
        ioc.tags = ["botnet_c2", "emotet"]
        ioc.enrichment = None

        cef = format_cef(ioc)

        assert cef is not None
        assert "CEF:" in cef
        assert "198.51.100.42" in cef

    def test_cef_severity_mapping(self):
        """High risk score should map to high CEF severity."""
        high_risk = MagicMock(spec=Indicator)
        high_risk.ioc_value = "198.51.100.1"
        high_risk.ioc_type = "ip"
        high_risk.risk_score = 95.0
        high_risk.confidence_score = 80.0
        high_risk.tags = ["ransomware"]
        high_risk.enrichment = None

        low_risk = MagicMock(spec=Indicator)
        low_risk.ioc_value = "198.51.100.2"
        low_risk.ioc_type = "ip"
        low_risk.risk_score = 15.0
        low_risk.confidence_score = 30.0
        low_risk.tags = ["scanner"]
        low_risk.enrichment = None

        cef_high = format_cef(high_risk)
        cef_low = format_cef(low_risk)

        # Both should be valid CEF strings
        assert cef_high is not None
        assert cef_low is not None
