"""
test_collectors.py — Tests for the collector modules.

Uses the `responses` library to mock HTTP calls and verify that
each collector correctly parses feed data into standardized records.
"""

import pytest
import responses

from src.collectors.feodo_tracker import FeodoTrackerCollector
from src.collectors.blocklist_de import BlocklistDECollector
from src.collectors.cins_army import CINSArmyCollector
from src.collectors.emerging_threats import EmergingThreatsCollector


# ═══════════════════════════════════════════════════════════════════════
# Feodo Tracker
# ═══════════════════════════════════════════════════════════════════════

FEODO_CSV = """# Feodo Tracker Botnet C2 IP Blocklist
# Last updated: 2024-01-01 00:00:00 UTC
#
# <first_seen>,<dst_ip>,<dst_port>,<last_online>,<malware>
2024-01-01 12:00:00,198.51.100.1,447,2024-01-01,Dridex
2024-01-01 12:05:00,203.0.113.42,449,2024-01-01,TrickBot
# 192.168.1.1 should be skipped (private)
"""


class TestFeodoTrackerCollector:

    @responses.activate
    def test_parse_feodo_csv(self):
        """Feodo CSV is parsed into valid IOC records with correct fields."""
        responses.add(
            responses.GET,
            "https://feodotracker.abuse.ch/downloads/ipblocklist.csv",
            body=FEODO_CSV,
            status=200,
        )

        collector = FeodoTrackerCollector()
        records = collector.collect()

        assert len(records) >= 2
        rec = records[0]

        assert rec["ioc_value"] == "198.51.100.1"
        assert rec["ioc_type"] == "ip"
        assert rec["source_name"] == "feodo_tracker"
        assert "tags" in rec

    @responses.activate
    def test_feodo_empty_response(self):
        """Empty or comment-only feed returns an empty list."""
        responses.add(
            responses.GET,
            "https://feodotracker.abuse.ch/downloads/ipblocklist.csv",
            body="# Comment only\n# Another comment\n",
            status=200,
        )

        collector = FeodoTrackerCollector()
        records = collector.collect()
        assert records == [] or len(records) == 0

    @responses.activate
    def test_feodo_http_error(self):
        """Collector handles HTTP errors gracefully (returns empty list)."""
        responses.add(
            responses.GET,
            "https://feodotracker.abuse.ch/downloads/ipblocklist.csv",
            status=503,
        )

        collector = FeodoTrackerCollector()
        records = collector.collect()
        assert records == [] or records is None or len(records) == 0


# ═══════════════════════════════════════════════════════════════════════
# Blocklist.de
# ═══════════════════════════════════════════════════════════════════════

BLOCKLIST_DE_DATA = """198.51.100.10
203.0.113.20
198.51.100.30
"""


class TestBlocklistDECollector:

    @responses.activate
    def test_parse_blocklist_de(self):
        """Plain text IP list is parsed correctly."""
        responses.add(
            responses.GET,
            "https://lists.blocklist.de/lists/all.txt",
            body=BLOCKLIST_DE_DATA,
            status=200,
        )

        collector = BlocklistDECollector()
        records = collector.collect()

        assert len(records) == 3
        assert all(r["ioc_type"] == "ip" for r in records)
        assert all(r["source_name"] == "blocklist_de" for r in records)


# ═══════════════════════════════════════════════════════════════════════
# CINS Army
# ═══════════════════════════════════════════════════════════════════════

CINS_DATA = """198.51.100.50
203.0.113.60
"""


class TestCINSArmyCollector:

    @responses.activate
    def test_parse_cins_army(self):
        """CINS Army plain text IP list is parsed correctly."""
        responses.add(
            responses.GET,
            "https://cinsscore.com/list/ci-badguys.txt",
            body=CINS_DATA,
            status=200,
        )

        collector = CINSArmyCollector()
        records = collector.collect()

        assert len(records) == 2
        assert all(r["source_name"] == "cins_army" for r in records)


# ═══════════════════════════════════════════════════════════════════════
# Emerging Threats
# ═══════════════════════════════════════════════════════════════════════

ET_DATA = """# Emerging Threats compromised IPs
198.51.100.70
203.0.113.80
"""


class TestEmergingThreatsCollector:

    @responses.activate
    def test_parse_emerging_threats(self):
        """Emerging Threats list is parsed, comments skipped."""
        responses.add(
            responses.GET,
            "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
            body=ET_DATA,
            status=200,
        )

        collector = EmergingThreatsCollector()
        records = collector.collect()

        assert len(records) == 2
        assert all(r["source_name"] == "emerging_threats" for r in records)
