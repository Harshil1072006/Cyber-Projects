"""
feodo_tracker.py — Collector for Feodo Tracker botnet C2 IP list.

Source: https://feodotracker.abuse.ch/downloads/ipblocklist.csv
Format: CSV (comment lines start with #)
IOC Type: IP addresses
Update Frequency: Daily
API Key: Not required
Trust Tier: 1 (High — expert-curated botnet data)
"""

import csv
import io
import logging
from typing import Any

import requests

from src.collectors.base_collector import BaseCollector
from src.config import FEED_URLS

logger = logging.getLogger(__name__)


class FeodoTrackerCollector(BaseCollector):
    """Collect botnet C2 server IPs from Feodo Tracker (abuse.ch)."""

    @property
    def feed_name(self) -> str:
        return "feodo_tracker"

    @property
    def feed_url(self) -> str:
        return FEED_URLS["feodo_tracker"]

    def parse_response(self, response: requests.Response) -> list[dict[str, Any]]:
        """
        Parse Feodo Tracker CSV response.

        CSV columns: first_seen_utc, dst_ip, dst_port, c2_status, last_online, malware
        Lines starting with '#' are comments.
        """
        records = []
        content = response.text

        reader = csv.reader(io.StringIO(content))
        for row in reader:
            # Skip comment lines and empty rows
            if not row or row[0].strip().startswith("#"):
                continue

            try:
                # CSV columns: first_seen_utc, dst_ip, dst_port, c2_status, last_online, malware
                if len(row) < 4:
                    logger.debug(f"[{self.feed_name}] Skipping short row: {row}")
                    continue

                ip_address = row[1].strip()
                port = row[2].strip() if len(row) > 2 else ""
                malware = row[5].strip() if len(row) > 5 else "unknown"
                first_seen = row[0].strip() if row[0].strip() else None
                last_online = row[4].strip() if len(row) > 4 else None
                c2_status = row[3].strip() if len(row) > 3 else ""

                # Build tags from malware family
                tags = ["botnet", "c2"]
                if malware and malware.lower() != "unknown":
                    tags.append(malware.lower())

                record = self._make_record(
                    ioc_value=ip_address,
                    ioc_type="ip",
                    tags=tags,
                    raw_data={
                        "first_seen_utc": first_seen,
                        "dst_ip": ip_address,
                        "dst_port": port,
                        "c2_status": c2_status,
                        "last_online": last_online,
                        "malware": malware,
                    },
                )
                records.append(record)

            except (IndexError, ValueError) as e:
                logger.debug(f"[{self.feed_name}] Skipping malformed row: {row} — {e}")
                continue

        return records
