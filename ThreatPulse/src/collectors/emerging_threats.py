"""
emerging_threats.py — Collector for Emerging Threats compromised IPs.

Source: https://rules.emergingthreats.net/blockrules/compromised-ips.txt
Format: Plain text (one IP per line)
IOC Type: IP addresses
Update Frequency: Daily
API Key: Not required
Trust Tier: 2 (Medium — IDS/IPS rule sets)
"""

import logging
from typing import Any

import requests

from src.collectors.base_collector import BaseCollector
from src.config import FEED_URLS

logger = logging.getLogger(__name__)


class EmergingThreatsCollector(BaseCollector):
    """Collect compromised IPs from Emerging Threats."""

    @property
    def feed_name(self) -> str:
        return "emerging_threats"

    @property
    def feed_url(self) -> str:
        return FEED_URLS["emerging_threats"]

    def parse_response(self, response: requests.Response) -> list[dict[str, Any]]:
        """Parse plain text IP list (one IP per line)."""
        records = []

        for line in response.text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            # Basic IP format check
            parts = line.split(".")
            if len(parts) != 4:
                continue

            try:
                if all(0 <= int(p) <= 255 for p in parts):
                    record = self._make_record(
                        ioc_value=line,
                        ioc_type="ip",
                        tags=["compromised", "ids_rule"],
                        raw_data={"ip": line, "source_list": "compromised-ips"},
                    )
                    records.append(record)
            except ValueError:
                continue

        return records
