"""
abuseipdb.py — Collector for AbuseIPDB blacklisted IP addresses.

Source: https://api.abuseipdb.com/api/v2/blacklist
Format: REST API (JSON)
IOC Type: IP addresses
Update Frequency: Real-time
API Key: Required (free tier — 1,000 req/day)
Trust Tier: 2 (Medium — community-validated)
"""

import logging
from typing import Any

import requests

from src.collectors.base_collector import BaseCollector
from src.config import FEED_URLS, ABUSEIPDB_API_KEY

logger = logging.getLogger(__name__)


class AbuseIPDBCollector(BaseCollector):
    """Collect blacklisted IPs from AbuseIPDB."""

    @property
    def feed_name(self) -> str:
        return "abuseipdb"

    @property
    def feed_url(self) -> str:
        return FEED_URLS["abuseipdb"]

    @property
    def requires_api_key(self) -> bool:
        return True

    @property
    def api_headers(self) -> dict:
        return {
            "Key": ABUSEIPDB_API_KEY,
            "Accept": "application/json",
        }

    def collect(self) -> list[dict[str, Any]]:
        """Override to check for API key before collection."""
        if not ABUSEIPDB_API_KEY or ABUSEIPDB_API_KEY.startswith("your_"):
            logger.warning(
                f"[{self.feed_name}] No API key configured — skipping collection. "
                "Set ABUSEIPDB_API_KEY in your .env file."
            )
            return []
        return super().collect()

    def parse_response(self, response: requests.Response) -> list[dict[str, Any]]:
        """
        Parse AbuseIPDB blacklist JSON response.

        Response:
        {
            "data": [
                {
                    "ipAddress": "1.2.3.4",
                    "abuseConfidenceScore": 100,
                    "countryCode": "CN",
                    ...
                }
            ]
        }
        """
        records = []

        try:
            data = response.json()
        except ValueError:
            logger.error(f"[{self.feed_name}] Invalid JSON response")
            return []

        entries = data.get("data", [])
        for entry in entries:
            try:
                ip = entry.get("ipAddress", "").strip()
                if not ip:
                    continue

                abuse_score = entry.get("abuseConfidenceScore", 0)
                country = entry.get("countryCode", "")

                tags = ["abuse", "blacklist"]
                if abuse_score >= 90:
                    tags.append("high_confidence")

                record = self._make_record(
                    ioc_value=ip,
                    ioc_type="ip",
                    tags=tags,
                    raw_data={
                        "ipAddress": ip,
                        "abuseConfidenceScore": abuse_score,
                        "countryCode": country,
                        "lastReportedAt": entry.get("lastReportedAt", ""),
                    },
                )
                records.append(record)

            except Exception as e:
                logger.debug(f"[{self.feed_name}] Skipping entry: {e}")
                continue

        return records
