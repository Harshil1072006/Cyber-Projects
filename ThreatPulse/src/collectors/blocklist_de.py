"""
blocklist_de.py — Collector for Blocklist.de attack IPs.

Source: https://lists.blocklist.de/lists/all.txt
Format: Plain text (one IP per line)
IOC Type: IP addresses
Update Frequency: Daily
API Key: Not required
Trust Tier: 3 (Lower — SSH, FTP, SMTP attack IPs)
"""

import logging
from typing import Any

import requests

from src.collectors.base_collector import BaseCollector
from src.config import FEED_URLS

logger = logging.getLogger(__name__)


class BlocklistDECollector(BaseCollector):
    """Collect SSH/FTP/SMTP attack IPs from Blocklist.de."""

    @property
    def feed_name(self) -> str:
        return "blocklist_de"

    @property
    def feed_url(self) -> str:
        return FEED_URLS["blocklist_de"]

    def parse_response(self, response: requests.Response) -> list[dict[str, Any]]:
        """Parse plain text IP list (one IP per line)."""
        records = []

        for line in response.text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            parts = line.split(".")
            if len(parts) != 4:
                continue

            try:
                if all(0 <= int(p) <= 255 for p in parts):
                    record = self._make_record(
                        ioc_value=line,
                        ioc_type="ip",
                        tags=["brute_force", "attack"],
                        raw_data={"ip": line},
                    )
                    records.append(record)
            except ValueError:
                continue

        return records
