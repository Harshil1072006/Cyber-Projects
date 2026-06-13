"""
test_scoring.py — Tests for the confidence and risk scoring engines.

Uses the in-memory DB fixtures from conftest.py.
"""

import pytest
import uuid
from datetime import datetime, timezone, timedelta
from unittest.mock import MagicMock

from src.scoring.confidence import calculate_confidence
from src.scoring.risk import calculate_risk
from src.db.models import Indicator, IOCSource, EnrichmentData


# ═══════════════════════════════════════════════════════════════════════
# Confidence Score Tests
# ═══════════════════════════════════════════════════════════════════════

class TestConfidenceScoring:

    def _make_indicator(self, **kwargs):
        defaults = {
            "id": uuid.uuid4(),
            "ioc_value": "198.51.100.1",
            "ioc_type": "ip",
            "first_seen": datetime.now(timezone.utc),
            "last_seen": datetime.now(timezone.utc),
            "is_active": True,
            "confidence_score": 0.0,
            "risk_score": 0.0,
            "source_count": 1,
            "tags": [],
        }
        defaults.update(kwargs)
        return MagicMock(spec=Indicator, **defaults)

    def _make_source(self, name="feodo_tracker", confidence=90.0):
        return MagicMock(spec=IOCSource, source_name=name, source_confidence=confidence)

    def _make_enrichment(self, vt_detections=None, reputation_score=None):
        return MagicMock(
            spec=EnrichmentData,
            vt_detections=vt_detections,
            reputation_score=reputation_score,
        )

    def test_single_tier1_source(self):
        """Single Tier 1 source should give source_count(5) + tier(30) + lowFP(5) = 40."""
        ind = self._make_indicator()
        sources = [self._make_source("feodo_tracker")]

        score = calculate_confidence(ind, sources, None)

        assert 35 <= score <= 45  # 5 (count) + 30 (tier1) + 5 (low_fp) = 40

    def test_multiple_sources_increases_score(self):
        """More sources should increase confidence."""
        ind = self._make_indicator()
        sources_1 = [self._make_source("blocklist_de")]
        sources_3 = [
            self._make_source("feodo_tracker"),
            self._make_source("blocklist_de"),
            self._make_source("cins_army"),
        ]

        score_1 = calculate_confidence(ind, sources_1, None)
        score_3 = calculate_confidence(ind, sources_3, None)

        assert score_3 > score_1

    def test_vt_detections_boost(self):
        """VirusTotal detections should increase confidence."""
        ind = self._make_indicator()
        sources = [self._make_source("blocklist_de")]
        enrichment = self._make_enrichment(vt_detections=50)

        score_with_vt = calculate_confidence(ind, sources, enrichment)
        score_without_vt = calculate_confidence(ind, sources, None)

        assert score_with_vt > score_without_vt

    def test_age_penalty(self):
        """Old IOCs get a confidence penalty."""
        old_indicator = self._make_indicator(
            last_seen=datetime.now(timezone.utc) - timedelta(days=100)
        )
        new_indicator = self._make_indicator(
            last_seen=datetime.now(timezone.utc)
        )
        sources = [self._make_source("blocklist_de")]

        old_score = calculate_confidence(old_indicator, sources, None)
        new_score = calculate_confidence(new_indicator, sources, None)

        assert new_score > old_score

    def test_score_bounded_0_100(self):
        """Score should always be between 0 and 100."""
        ind = self._make_indicator(
            last_seen=datetime.now(timezone.utc) - timedelta(days=365)
        )
        sources = []

        score = calculate_confidence(ind, sources, None)
        assert 0 <= score <= 100


# ═══════════════════════════════════════════════════════════════════════
# Risk Score Tests
# ═══════════════════════════════════════════════════════════════════════

class TestRiskScoring:

    def _make_indicator(self, tags=None, **kwargs):
        defaults = {
            "id": uuid.uuid4(),
            "ioc_value": "198.51.100.1",
            "ioc_type": "ip",
            "first_seen": datetime.now(timezone.utc),
            "last_seen": datetime.now(timezone.utc),
            "is_active": True,
            "confidence_score": 0.0,
            "risk_score": 0.0,
            "source_count": 1,
            "tags": tags or [],
        }
        defaults.update(kwargs)
        return MagicMock(spec=Indicator, **defaults)

    def _make_enrichment(self, **kwargs):
        defaults = {
            "reputation_score": None,
            "open_ports": None,
            "whois_created": None,
        }
        defaults.update(kwargs)
        return MagicMock(spec=EnrichmentData, **defaults)

    def test_ransomware_tag_high_risk(self):
        """Ransomware category should yield high base risk (40 pts)."""
        ind = self._make_indicator(tags=["ransomware"])
        score = calculate_risk(ind, None)
        assert score >= 40

    def test_scanner_tag_low_risk(self):
        """Scanner category is lower risk than ransomware."""
        ransomware_ind = self._make_indicator(tags=["ransomware"])
        scanner_ind = self._make_indicator(tags=["scanner"])

        ransomware_risk = calculate_risk(ransomware_ind, None)
        scanner_risk = calculate_risk(scanner_ind, None)

        assert ransomware_risk > scanner_risk

    def test_abuse_reports_increase_risk(self):
        """High AbuseIPDB reputation score should increase risk."""
        ind = self._make_indicator(tags=["botnet_c2"])
        enrichment = self._make_enrichment(reputation_score=90.0)

        score_with = calculate_risk(ind, enrichment)
        score_without = calculate_risk(ind, None)

        assert score_with > score_without

    def test_dangerous_ports_increase_risk(self):
        """Open dangerous ports (4444, 3389) should boost risk."""
        ind = self._make_indicator(tags=["malware"])
        enrichment = self._make_enrichment(open_ports=[4444, 8080, 22])

        score = calculate_risk(ind, enrichment)
        assert score >= 45  # 30 (malware) + 15 (dangerous ports)

    def test_new_domain_higher_risk(self):
        """Domains registered less than 7 days ago get +15 risk pts."""
        ind = self._make_indicator(tags=["phishing"])
        enrichment = self._make_enrichment(
            whois_created=datetime.now(timezone.utc) - timedelta(days=3)
        )

        score = calculate_risk(ind, enrichment)
        assert score >= 35  # 20 (phishing) + 15 (new domain)

    def test_apt_attribution_bonus(self):
        """Known APT/threat actor tags should add +10 pts."""
        ind = self._make_indicator(tags=["c2", "emotet"])
        score = calculate_risk(ind, None)
        assert score >= 45  # 35 (c2) + 10 (emotet APT bonus)

    def test_no_tags_minimal_risk(self):
        """IOC with no tags gets minimal risk score."""
        ind = self._make_indicator(tags=[])
        score = calculate_risk(ind, None)
        assert score == 0

    def test_risk_bounded_0_100(self):
        """Risk score should always be between 0 and 100."""
        ind = self._make_indicator(tags=["ransomware", "emotet"])
        enrichment = self._make_enrichment(
            reputation_score=100.0,
            open_ports=[4444, 3389, 22],
            whois_created=datetime.now(timezone.utc) - timedelta(days=1),
        )

        score = calculate_risk(ind, enrichment)
        assert 0 <= score <= 100
