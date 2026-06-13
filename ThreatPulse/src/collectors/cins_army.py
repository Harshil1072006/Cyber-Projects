"""
cins_army.py — Collector for CINS Army scanner/brute-force IPs.

Source: https://cinsscore.com/list/ci-badguys.txt
Format: Plain text (one IP per line)
IOC Type: IP addresses
Update Frequency: Daily
API Key: Not required
Trust Tier: 3 (Lower — broad scanner list)
"""

import logging
from typing import Any

import requests

from src.collectors.base_collector import BaseCollector
from src.config import FEED_URLS

logger = logging.getLogger(__name__)


class CINSArmyCollector(BaseCollector):
    """Collect scanner and brute-force IPs from CINS Army."""

    @property
    def feed_name(self) -> str:
        return "cins_army"

    @property
    def feed_url(self) -> str:
        return FEED_URLS["cins_army"]

    def parse_response(self, response: requests.Response) -> list[dict[str, Any]]:
        """Parse plain text IP list (one IP per line)."""
        records = []

        for line in response.text.splitlines():
            line = line.strip()
            if not line or line.startswith("#") or line.startswith(";"):
                continue

            parts = line.split(".")
            if len(parts) != 4:
                continue

            try:
                if all(0 <= int(p) <= 255 for p in parts):
                    record = self._make_record(
                        ioc_value=line,
                        ioc_type="ip",
                        tags=["scanner", "brute_force"],
                        raw_data={"ip": line},
                    )
                    records.append(record)
            except ValueError:
                continue

        return records
